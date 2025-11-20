package tokens

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"time"
)

// AutoLoginOption mutates parameters for auto-login via refresh.
type AutoLoginOption func(*AutoLoginParams)

// AutoLoginParams holds inputs required for auto-login/rotation.
type AutoLoginParams struct {
	Ctx             context.Context
	Store           TokenStore
	EncPrivKey      interface{}
	FindSigKeyByKID func(string) crypto.PublicKey

	// Issuing keys and algorithms
	SignKid   string
	SignPriv  *ecdsa.PrivateKey
	EncKid    string
	EncPubKey interface{}
	Algs      KeyAlgs

	// Verification context
	Iss string
	Aud string

	// New token TTL providers (computed from the verified refresh claims, e.g., by UID)
	AccessTTLFunc  func(RefreshCustomClaims) time.Duration
	RefreshTTLFunc func(RefreshCustomClaims) time.Duration

	// Input refresh token
	RefreshToken string

	// Optional: custom validator to check whether the uid from refresh claims is allowed to login.
	// Return ErrUserLoginForbidden (or any error) to block auto login.
	UIDValidator func(context.Context, string) error

	// Optional: refresh extra payload stored via PayloadStore (not embedded).
	RefreshExtra map[string]interface{}

	// Optional: mutator applied to existing externalized refresh payload BEFORE rotation.
	// If provided and store supports PayloadStore, the current payload is loaded (if any),
	// passed to mutator (map representation), then the result is saved for the new RID.
	RefreshPayloadMutator func(context.Context, map[string]interface{}) error
}

// WithAutoStore sets the TokenStore (optional; when present enables rotation persistence and cache checks).
func WithAutoStore(store TokenStore) AutoLoginOption {
	return func(p *AutoLoginParams) { p.Store = store }
}

// WithAutoDecryptKey sets the private key for JWE decryption of the refresh token.
func WithAutoDecryptKey(priv interface{}) AutoLoginOption {
	return func(p *AutoLoginParams) { p.EncPrivKey = priv }
}

// WithAutoFindSigKey provides the KID->public key resolver used to verify the inner JWS.
func WithAutoFindSigKey(f func(string) crypto.PublicKey) AutoLoginOption {
	return func(p *AutoLoginParams) { p.FindSigKeyByKID = f }
}

// WithAutoKeys sets signing/encryption keys and algorithms for issuing new tokens.
func WithAutoKeys(signKid string, signPriv *ecdsa.PrivateKey, encKid string, encPubKey interface{}, algs KeyAlgs) AutoLoginOption {
	return func(p *AutoLoginParams) {
		p.SignKid = signKid
		p.SignPriv = signPriv
		p.EncKid = encKid
		p.EncPubKey = encPubKey
		p.Algs = algs
	}
}

// WithAutoAudience sets issuer and audience used to validate the incoming refresh token.
func WithAutoAudience(iss, aud string) AutoLoginOption {
	return func(p *AutoLoginParams) { p.Iss = iss; p.Aud = aud }
}

// WithAutoTTL sets the new access/refresh TTLs.
func WithAutoTTL(accessTTL, refreshTTL time.Duration) AutoLoginOption {
	return func(p *AutoLoginParams) {
		p.AccessTTLFunc = func(_ RefreshCustomClaims) time.Duration { return accessTTL }
		p.RefreshTTLFunc = func(_ RefreshCustomClaims) time.Duration { return refreshTTL }
	}
}

// WithAutoAccessTTLFunc sets a function to compute access TTL from the incoming refresh claims.
func WithAutoAccessTTLFunc(f func(RefreshCustomClaims) time.Duration) AutoLoginOption {
	return func(p *AutoLoginParams) { p.AccessTTLFunc = f }
}

// WithAutoRefreshTTLFunc sets a function to compute refresh TTL from the incoming refresh claims.
func WithAutoRefreshTTLFunc(f func(RefreshCustomClaims) time.Duration) AutoLoginOption {
	return func(p *AutoLoginParams) { p.RefreshTTLFunc = f }
}

// WithAutoTTLFunc sets both access and refresh TTL providers at once.
func WithAutoTTLFunc(access func(RefreshCustomClaims) time.Duration, refresh func(RefreshCustomClaims) time.Duration) AutoLoginOption {
	return func(p *AutoLoginParams) { p.AccessTTLFunc = access; p.RefreshTTLFunc = refresh }
}

// WithAutoRefreshToken sets the incoming refresh token to be validated and rotated.
func WithAutoRefreshToken(token string) AutoLoginOption {
	return func(p *AutoLoginParams) { p.RefreshToken = token }
}

// WithAutoUIDValidator sets a custom validator to check if a uid is allowed to login.
// If the validator returns a non-nil error (e.g., ErrUserLoginForbidden), auto login will be aborted.
func WithAutoUIDValidator(f func(context.Context, string) error) AutoLoginOption {
	return func(p *AutoLoginParams) { p.UIDValidator = f }
}

// WithAutoPreSignRefreshExtra sets extra fields for the new refresh JWT (cached only).
func WithAutoPreSignRefreshExtra(extra map[string]interface{}) AutoLoginOption {
	return func(p *AutoLoginParams) { p.RefreshExtra = extra }
}

// WithAutoRefreshPayloadMutator sets a mutator to transform existing externalized payload.
// Ignored if the store does not implement PayloadStore.
func WithAutoRefreshPayloadMutator(mut func(context.Context, map[string]interface{}) error) AutoLoginOption {
	return func(p *AutoLoginParams) { p.RefreshPayloadMutator = mut }
}

// AutoLoginWithRefresh verifies a refresh token, rotates state (when store provided), and issues new tokens.
// AutoLoginPayloadInfo describes the externalized refresh payload state after rotation.
// Source indicates how the payload was determined: "mutator" | "extra" | "carry-forward" | "migrated" | "none".
type AutoLoginPayloadInfo struct {
	Found   bool   `json:"found"`
	Mutated bool   `json:"mutated"`
	Source  string `json:"source"`
	RawJSON []byte `json:"raw_json,omitempty"`
	// Raw holds the original payload bytes from the previous refresh RID before any mutator/override.
	// If no previous payload existed, Raw will be empty. RawJSON always reflects the final payload stored for the new RID.
	Raw  []byte                 `json:"raw,omitempty"`
	Data map[string]interface{} `json:"data,omitempty"`
}

// AutoLoginResult consolidates all outputs of AutoLoginWithRefresh.
type AutoLoginResult struct {
	AccessJWE     string               `json:"access_jwe"`
	RefreshJWE    string               `json:"refresh_jwe"`
	AccessClaims  AccessCustomClaims   `json:"access_claims"`
	RefreshClaims RefreshCustomClaims  `json:"refresh_claims"`
	Payload       AutoLoginPayloadInfo `json:"payload"`
}

func AutoLoginWithRefresh(ctx context.Context, opts ...AutoLoginOption) (res AutoLoginResult, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	p := AutoLoginParams{Ctx: ctx}
	for _, opt := range opts {
		if opt != nil {
			opt(&p)
		}
	}
	// Validate required inputs
	if p.EncPrivKey == nil {
		err = errors.New("decrypt private key required: WithAutoDecryptKey")
		return
	}
	if p.FindSigKeyByKID == nil {
		err = errors.New("findSigKeyByKID required: WithAutoFindSigKey")
		return
	}
	if p.SignPriv == nil || p.SignKid == "" || p.EncKid == "" || p.EncPubKey == nil {
		err = errors.New("sign/encrypt keys are required: WithAutoKeys")
		return
	}
	if p.Algs.SignAlg == "" || p.Algs.ContentEncryption == "" || p.Algs.KeyMgmtAlg == "" {
		err = errors.New("algs are required in WithAutoKeys")
		return
	}
	if p.Iss == "" || p.Aud == "" {
		err = errors.New("issuer and audience are required: WithAutoAudience")
		return
	}
	// TTL providers must be provided (use WithAutoTTL or TTLFunc variants)
	if p.AccessTTLFunc == nil || p.RefreshTTLFunc == nil {
		err = errors.New("TTL providers are required: WithAutoTTL or WithAutoTTLFunc")
		return
	}
	if p.RefreshToken == "" {
		err = errors.New("refresh token is required: WithAutoRefreshToken")
		return
	}

	// Always decrypt & verify refresh token (no in-Redis parsed cache)
	var rc RefreshCustomClaims
	rc, err = DecryptAndVerifyRefresh(p.RefreshToken, p.EncPrivKey, p.FindSigKeyByKID, p.Iss, p.Aud)
	if err != nil {
		return
	}

	// Optional state checks when Redis available
	if p.Store != nil {
		if _, found, _ := p.Store.GetRefresh(ctx, rc.RID); !found {
			err = ErrRefreshNotCurrent // closest sentinel for invalid state
			return
		}
		if cur, ok, _ := p.Store.GetFID(ctx, rc.FID); ok && cur != rc.RID {
			err = ErrRefreshNotCurrent
			return
		}
	}

	// Optional: custom UID validation (e.g., banned/disabled users)
	if p.UIDValidator != nil {
		if vErr := p.UIDValidator(ctx, rc.UID); vErr != nil {
			err = vErr
			return
		}
	}

	// Issue fresh tokens, preserving identity/device/client/scope
	// Compute TTLs based on verified refresh claims (e.g., by UID)
	accessTTL := p.AccessTTLFunc(rc)
	refreshTTL := p.RefreshTTLFunc(rc)
	if accessTTL <= 0 || refreshTTL <= 0 {
		err = errors.New("computed TTLs must be positive")
		return
	}

	accessJWE, refreshJWE, ac, newRC, err := IssueAccessAndRefreshJWEWithClaims(
		p.SignKid, p.SignPriv,
		p.EncKid, p.EncPubKey,
		p.Algs,
		rc.Claims.Issuer, rc.Claims.Audience[0], rc.UID, rc.UID, rc.DeviceID, rc.ClientID,
		accessTTL, refreshTTL,
		rc.Scope,
	)
	if err != nil {
		return
	}

	// Persist rotation and caches (refresh-only model)
	if p.Store != nil {
		oldTTL := 24 * time.Hour
		if rc.Claims.Expiry != nil {
			oldTTL = time.Until(rc.Claims.Expiry.Time())
			if oldTTL < 0 {
				oldTTL = 0
			}
		}
		rTTL := time.Duration(0)
		if newRC.Claims.Expiry != nil {
			rTTL = time.Until(newRC.Claims.Expiry.Time())
		}
		_ = p.Store.RotateRefreshAtomic(ctx,
			rc.RID, oldTTL,
			newRC.RID, newRC.FID, newRC, rTTL,
		)
		// No parsed claims cache; rely on direct verification on future use.
		// Externalized payload handling (mutator > explicit extra > copy existing)
		if ps, ok := p.Store.(PayloadStore); ok {
			var toSave interface{}
			payloadInfo := AutoLoginPayloadInfo{Found: false, Mutated: false, Source: "none"}
			// Load existing payload (original from OLD RID)
			oldRaw, oldFound, _ := ps.GetRefreshPayloadJSON(ctx, rc.RID)
			if oldFound && oldRaw != nil {
				payloadInfo.Found = true
				payloadInfo.Source = "migrated" // default before override
				payloadInfo.Raw = oldRaw
			}
			if p.RefreshPayloadMutator != nil {
				m := map[string]interface{}{}
				if oldFound && oldRaw != nil {
					_ = json.Unmarshal(oldRaw, &m)
				}
				if mErr := p.RefreshPayloadMutator(ctx, m); mErr == nil {
					toSave = m
					payloadInfo.Mutated = true
					payloadInfo.Source = "mutator"
				}
			}
			if toSave == nil && p.RefreshExtra != nil {
				toSave = p.RefreshExtra
				payloadInfo.Source = "extra"
			}
			if toSave == nil && oldFound {
				// carry forward previous payload unchanged (already migrated to new RID by RotateRefreshAtomic)
				payloadInfo.Source = "carry-forward"
				newRaw, newFound, _ := ps.GetRefreshPayloadJSON(ctx, newRC.RID)
				if newFound {
					payloadInfo.RawJSON = newRaw
				}
			} else if toSave != nil {
				// Save new override
				_ = ps.SaveRefreshPayload(ctx, newRC.RID, toSave, rTTL)
				b, _ := json.Marshal(toSave)
				payloadInfo.RawJSON = b
			}
			res.Payload = payloadInfo
		}
		// Update per-user device mapping to the new RID if device info present
		if rs, ok := p.Store.(DeviceIndexStore); ok {
			if rc.DeviceID != "" && rc.UID != "" && rTTL > 0 {
				_ = rs.SetDeviceRID(ctx, rc.UID, rc.DeviceID, newRC.RID, rTTL)
			}
		}
	}

	// Assemble result
	res.AccessJWE = accessJWE
	res.RefreshJWE = refreshJWE
	res.AccessClaims = ac
	res.RefreshClaims = newRC
	return
}
