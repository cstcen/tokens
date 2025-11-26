package tokens

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"time"
)

// RefreshOption mutates parameters for refresh via token rotation.
type RefreshOption func(*RefreshParams)

// RefreshParams holds inputs required for refresh/rotation.
type RefreshParams struct {
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
	UIDValidator func(context.Context, string) error

	// Optional: refresh extra payload stored via PayloadStore (not embedded).
	RefreshExtra map[string]interface{}

	// Optional: mutator applied to existing externalized refresh payload BEFORE rotation.
	RefreshPayloadMutator func(context.Context, map[string]interface{}) error
}

// WithRefreshStore sets the TokenStore (optional; when present enables rotation persistence and cache checks).
func WithRefreshStore(store TokenStore) RefreshOption {
	return func(p *RefreshParams) { p.Store = store }
}

// WithRefreshDecryptKey sets the private key for JWE decryption of the refresh token.
func WithRefreshDecryptKey(priv interface{}) RefreshOption {
	return func(p *RefreshParams) { p.EncPrivKey = priv }
}

// WithRefreshFindSigKey provides the KID->public key resolver used to verify the inner JWS.
func WithRefreshFindSigKey(f func(string) crypto.PublicKey) RefreshOption {
	return func(p *RefreshParams) { p.FindSigKeyByKID = f }
}

// WithRefreshKeys sets signing/encryption keys and algorithms for issuing new tokens.
func WithRefreshKeys(signKid string, signPriv *ecdsa.PrivateKey, encKid string, encPubKey interface{}, algs KeyAlgs) RefreshOption {
	return func(p *RefreshParams) {
		p.SignKid = signKid
		p.SignPriv = signPriv
		p.EncKid = encKid
		p.EncPubKey = encPubKey
		p.Algs = algs
	}
}

// WithRefreshAudience sets issuer and audience used to validate the incoming refresh token.
func WithRefreshAudience(iss, aud string) RefreshOption {
	return func(p *RefreshParams) { p.Iss = iss; p.Aud = aud }
}

// WithRefreshTTL sets the new access/refresh TTLs.
func WithRefreshTTL(accessTTL, refreshTTL time.Duration) RefreshOption {
	return func(p *RefreshParams) {
		p.AccessTTLFunc = func(_ RefreshCustomClaims) time.Duration { return accessTTL }
		p.RefreshTTLFunc = func(_ RefreshCustomClaims) time.Duration { return refreshTTL }
	}
}

// WithRefreshAccessTTLFunc sets a function to compute access TTL from the incoming refresh claims.
func WithRefreshAccessTTLFunc(f func(RefreshCustomClaims) time.Duration) RefreshOption {
	return func(p *RefreshParams) { p.AccessTTLFunc = f }
}

// WithRefreshRefreshTTLFunc sets a function to compute refresh TTL from the incoming refresh claims.
func WithRefreshRefreshTTLFunc(f func(RefreshCustomClaims) time.Duration) RefreshOption {
	return func(p *RefreshParams) { p.RefreshTTLFunc = f }
}

// WithRefreshTTLFunc sets both access and refresh TTL providers at once.
func WithRefreshTTLFunc(access func(RefreshCustomClaims) time.Duration, refresh func(RefreshCustomClaims) time.Duration) RefreshOption {
	return func(p *RefreshParams) { p.AccessTTLFunc = access; p.RefreshTTLFunc = refresh }
}

// WithRefreshToken sets the incoming refresh token to be validated and rotated.
func WithRefreshToken(token string) RefreshOption {
	return func(p *RefreshParams) { p.RefreshToken = token }
}

// WithRefreshUIDValidator sets a custom validator to check if a uid is allowed to login.
func WithRefreshUIDValidator(f func(context.Context, string) error) RefreshOption {
	return func(p *RefreshParams) { p.UIDValidator = f }
}

// WithRefreshPreSignRefreshExtra sets extra fields for the new refresh JWT (cached only).
func WithRefreshPreSignRefreshExtra(extra map[string]interface{}) RefreshOption {
	return func(p *RefreshParams) { p.RefreshExtra = extra }
}

// WithRefreshPayloadMutator sets a mutator to transform existing externalized payload.
func WithRefreshPayloadMutator(mut func(context.Context, map[string]interface{}) error) RefreshOption {
	return func(p *RefreshParams) { p.RefreshPayloadMutator = mut }
}

// RefreshPayloadInfo describes the externalized refresh payload state after rotation.
// Source indicates how the payload was determined: "mutator" | "extra" | "carry-forward" | "migrated" | "none".
type RefreshPayloadInfo struct {
	Found   bool                   `json:"found"`
	Mutated bool                   `json:"mutated"`
	Source  string                 `json:"source"`
	RawJSON []byte                 `json:"raw_json,omitempty"`
	Raw     []byte                 `json:"raw,omitempty"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

// RefreshResult consolidates all outputs of RefreshTokenWithRotation.
type RefreshResult struct {
	AccessJWE     string              `json:"access_jwe"`
	RefreshJWE    string              `json:"refresh_jwe"`
	AccessClaims  AccessCustomClaims  `json:"access_claims"`
	RefreshClaims RefreshCustomClaims `json:"refresh_claims"`
	Payload       RefreshPayloadInfo  `json:"payload"`
}

// RefreshTokenWithRotation verifies a refresh token, rotates state (when store provided), and issues new tokens.
func RefreshTokenWithRotation(ctx context.Context, opts ...RefreshOption) (res RefreshResult, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	p := RefreshParams{Ctx: ctx}
	for _, opt := range opts {
		if opt != nil {
			opt(&p)
		}
	}
	// Validate required inputs
	if p.EncPrivKey == nil {
		err = errors.New("decrypt private key required: WithRefreshDecryptKey")
		return
	}
	if p.FindSigKeyByKID == nil {
		err = errors.New("findSigKeyByKID required: WithRefreshFindSigKey")
		return
	}
	if p.SignPriv == nil || p.SignKid == "" || p.EncKid == "" || p.EncPubKey == nil {
		err = errors.New("sign/encrypt keys are required: WithRefreshKeys")
		return
	}
	if p.Algs.SignAlg == "" || p.Algs.ContentEncryption == "" || p.Algs.KeyMgmtAlg == "" {
		err = errors.New("algs are required in WithRefreshKeys")
		return
	}
	if p.Iss == "" || p.Aud == "" {
		err = errors.New("issuer and audience are required: WithRefreshAudience")
		return
	}
	// TTL providers must be provided (use WithRefreshTTL or TTLFunc variants)
	if p.AccessTTLFunc == nil || p.RefreshTTLFunc == nil {
		err = errors.New("TTL providers are required: WithRefreshTTL or WithRefreshTTLFunc")
		return
	}
	if p.RefreshToken == "" {
		err = errors.New("refresh token is required: WithRefreshToken")
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
			payloadInfo := RefreshPayloadInfo{Found: false, Mutated: false, Source: "none"}
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
