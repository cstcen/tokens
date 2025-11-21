package tokens

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"time"
)

// LogoutOption mutates parameters for the logout flow.
type LogoutOption func(*LogoutParams)

// LogoutParams holds inputs for revoking tokens and optionally clearing device mappings.
type LogoutParams struct {
	Ctx context.Context

	// Required: store implementing TokenStore; optional DeviceIndexStore support is detected via type assertion.
	Store TokenStore

	// Optional: keys and verification context used when a token string is provided instead of identifiers.
	EncPrivKey      interface{}
	FindSigKeyByKID func(string) crypto.PublicKey
	Iss             string
	Aud             string

	// Inputs: either provide token strings (preferred) or direct identifiers.
	// If a token is provided, it will be decrypted/verified to extract identifiers.
	AccessToken  string // JWE/JWS access token (to extract JTI)
	RefreshToken string // JWE/JWS refresh token (to extract RID, UID, DeviceID)
	JTI          string // Access JTI (if AccessToken not provided)
	RID          string // Refresh RID (if RefreshToken not provided)

	// Revocation tombstone TTLs (defaults: access 60m, refresh 24h).
	AccessRevokeTTL  time.Duration
	RefreshRevokeTTL time.Duration

	// Device index cleanup when RefreshToken provided and DeviceIndexStore is available.
	// If true, remove the (uid, deviceID) -> rid mapping on logout. Default true.
	ClearDeviceIndex bool
	// If true, also clear device-wide occupant mapping for deviceID. Default false.
	ClearDeviceOccupant bool
	// CascadeDeviceRefresh: when only an access token (or JTI) is provided, also revoke the current device's
	// active refresh token if DeviceIndexStore is available. Default false.
	CascadeDeviceRefresh bool
}

// WithLogoutStore sets the token store used for revocation and optional device index cleanup.
func WithLogoutStore(store TokenStore) LogoutOption { return func(p *LogoutParams) { p.Store = store } }

// WithLogoutDecryptKey sets the JWE decrypt private key used when a token string is provided.
func WithLogoutDecryptKey(priv interface{}) LogoutOption {
	return func(p *LogoutParams) { p.EncPrivKey = priv }
}

// WithLogoutFindSigKey sets a resolver to find the public signature key by KID for inner JWS verification.
func WithLogoutFindSigKey(f func(string) crypto.PublicKey) LogoutOption {
	return func(p *LogoutParams) { p.FindSigKeyByKID = f }
}

// WithLogoutKeys sets both signing lookup and encryption key context in one call.
func WithLogoutKeys(signKid string, signPriv *ecdsa.PrivateKey, encKid string, encPriv interface{}, algs KeyAlgs) LogoutOption {
	return func(p *LogoutParams) {
		// Only decrypt/verify is used here; we reuse the same option signature as other flows for familiarity.
		_ = signKid
		_ = signPriv
		_ = encKid
		_ = algs
		p.EncPrivKey = encPriv
	}
}

// WithLogoutAudience sets issuer/audience used for token verification (optional; empty means skip those checks).
func WithLogoutAudience(iss, aud string) LogoutOption {
	return func(p *LogoutParams) { p.Iss = iss; p.Aud = aud }
}

// WithLogoutAccessToken provides the access token JWE/JWS to extract JTI.
func WithLogoutAccessToken(token string) LogoutOption {
	return func(p *LogoutParams) { p.AccessToken = token }
}

// WithLogoutRefreshToken provides the refresh token JWE/JWS to extract RID and clear device mappings.
func WithLogoutRefreshToken(token string) LogoutOption {
	return func(p *LogoutParams) { p.RefreshToken = token }
}

// WithLogoutJTI sets the access JTI directly (if not providing AccessToken).
func WithLogoutJTI(jti string) LogoutOption { return func(p *LogoutParams) { p.JTI = jti } }

// WithLogoutRID sets the refresh RID directly (if not providing RefreshToken).
func WithLogoutRID(rid string) LogoutOption { return func(p *LogoutParams) { p.RID = rid } }

// WithLogoutRevokeTTLs sets TTLs for revocation tombstones.
func WithLogoutRevokeTTLs(accessTTL, refreshTTL time.Duration) LogoutOption {
	return func(p *LogoutParams) { p.AccessRevokeTTL = accessTTL; p.RefreshRevokeTTL = refreshTTL }
}

// WithLogoutClearDeviceIndex controls whether per-user per-device mapping is removed when possible. Default true.
func WithLogoutClearDeviceIndex(clear bool) LogoutOption {
	return func(p *LogoutParams) { p.ClearDeviceIndex = clear }
}

// WithLogoutClearDeviceOccupant controls whether device-wide occupant is removed. Default false.
func WithLogoutClearDeviceOccupant(clear bool) LogoutOption {
	return func(p *LogoutParams) { p.ClearDeviceOccupant = clear }
}

// WithLogoutCascadeDeviceRefresh enables revoking the device's refresh token when logging out via access token only.
func WithLogoutCascadeDeviceRefresh(enable bool) LogoutOption {
	return func(p *LogoutParams) { p.CascadeDeviceRefresh = enable }
}

// Logout revokes access/refresh by token or identifiers and optionally clears device mappings.
//
// Behavior:
//   - If AccessToken provided (preferred), decrypts/verifies to extract JTI and revokes access with AccessRevokeTTL.
//     Otherwise, if JTI provided, revokes by JTI directly.
//   - If RefreshToken provided (preferred), decrypts/verifies to extract RID (and UID/DeviceID), revokes refresh with
//     RefreshRevokeTTL and, when DeviceIndexStore is available and ClearDeviceIndex is true, clears (uid,deviceID) mapping;
//     optionally clears device occupant when ClearDeviceOccupant is true.
//     Otherwise, if RID provided, revokes by RID directly.
//   - If neither token nor identifier is provided for a type, that type is skipped.
func Logout(ctx context.Context, opts ...LogoutOption) error {
	// Default ClearDeviceIndex to true; options can override to false.
	p := LogoutParams{Ctx: ctx, ClearDeviceIndex: true}
	for _, o := range opts {
		o(&p)
	}

	if p.Store == nil {
		return errors.New("logout: Store is required")
	}
	if p.AccessRevokeTTL <= 0 {
		p.AccessRevokeTTL = 60 * time.Minute
	}
	if p.RefreshRevokeTTL <= 0 {
		p.RefreshRevokeTTL = 24 * time.Hour
	}
	var firstErr error

	// Access revocation (+ optional cascade to device refresh)
	if p.AccessToken != "" || p.JTI != "" {
		jti := p.JTI
		var ac AccessCustomClaims
		var acParsed bool
		if p.AccessToken != "" {
			if parsed, err := DecryptAndVerifyAccess(p.AccessToken, p.EncPrivKey, p.FindSigKeyByKID, p.Iss, p.Aud); err == nil {
				ac = parsed
				acParsed = true
				jti = ac.Claims.ID
			} else {
				firstErr = err
			}
		}
		if jti != "" {
			if err := p.Store.RevokeAccess(ctx, jti, p.AccessRevokeTTL); err != nil && firstErr == nil {
				firstErr = err
			}
			// Cascade refresh revocation only if enabled and no explicit refresh token/RID was provided
			if p.CascadeDeviceRefresh && acParsed && p.RefreshToken == "" && p.RID == "" {
				if rs, ok := p.Store.(DeviceIndexStore); ok && ac.DeviceID != "" && ac.Claims.Subject != "" {
					if rid, exists, _ := rs.GetDeviceRID(ctx, ac.Claims.Subject, ac.DeviceID); exists && rid != "" {
						if err := p.Store.RevokeRefresh(ctx, rid, p.RefreshRevokeTTL); err != nil && firstErr == nil {
							firstErr = err
						}
						// Clear device mapping if requested
						if p.ClearDeviceIndex {
							_ = rs.DelDeviceRID(ctx, ac.Claims.Subject, ac.DeviceID)
							if p.ClearDeviceOccupant {
								_ = rs.DelDeviceOccupant(ctx, ac.DeviceID)
							}
						}
					}
				}
			}
		}
	}

	// Refresh revocation and device cleanup
	if p.RefreshToken != "" || p.RID != "" {
		rid := p.RID
		var uid, deviceID string
		if p.RefreshToken != "" {
			if rc, err := DecryptAndVerifyRefresh(p.RefreshToken, p.EncPrivKey, p.FindSigKeyByKID, p.Iss, p.Aud); err == nil {
				rid = rc.RID
				uid = rc.UID
				deviceID = rc.DeviceID
				if err := p.Store.RevokeRefresh(ctx, rid, p.RefreshRevokeTTL); err != nil && firstErr == nil {
					firstErr = err
				}
				if rs, ok := p.Store.(DeviceIndexStore); ok && p.ClearDeviceIndex {
					_ = rs.DelDeviceRID(ctx, uid, deviceID)
					if p.ClearDeviceOccupant {
						_ = rs.DelDeviceOccupant(ctx, deviceID)
					}
				}
				// When using externalized payloads, we intentionally do not delete pl:r:<rid> here to keep the TokenStore API minimal.
			} else {
				if firstErr == nil {
					firstErr = err
				}
			}
		} else {
			if rid != "" {
				if err := p.Store.RevokeRefresh(ctx, rid, p.RefreshRevokeTTL); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
	}

	return firstErr
}
