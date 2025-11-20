package tokens

import (
	"context"
	"crypto"
	"encoding/json"
)

// GetRefreshPayloadJSONByToken decrypts/verifies a refresh token to obtain its RID
// then fetches the externalized payload JSON (if any) via PayloadStore.
// Returns (payloadJSON, found, error).
func GetRefreshPayloadJSONByToken(
	ctx context.Context,
	store TokenStore,
	refreshToken string,
	encPrivKey interface{},
	findSigKeyByKID func(string) crypto.PublicKey,
	iss, aud string,
) ([]byte, bool, error) {
	rc, err := DecryptAndVerifyRefresh(refreshToken, encPrivKey, findSigKeyByKID, iss, aud)
	if err != nil {
		return nil, false, err
	}
	ps, ok := store.(PayloadStore)
	if !ok {
		return nil, false, nil
	}
	return ps.GetRefreshPayloadJSON(ctx, rc.RID)
}

// MutateRefreshPayloadByToken loads the existing payload (if any) for the given refresh token,
// applies a mutator to a map representation, and saves the updated payload JSON back under the same RID.
// If no existing payload, starts with an empty map.
func MutateRefreshPayloadByToken(
	ctx context.Context,
	store TokenStore,
	refreshToken string,
	encPrivKey interface{},
	findSigKeyByKID func(string) crypto.PublicKey,
	iss, aud string,
	mutator func(map[string]interface{}) error,
) error {
	if mutator == nil {
		return nil
	}
	rc, err := DecryptAndVerifyRefresh(refreshToken, encPrivKey, findSigKeyByKID, iss, aud)
	if err != nil {
		return err
	}
	ps, ok := store.(PayloadStore)
	if !ok {
		return nil
	}
	raw, found, err := ps.GetRefreshPayloadJSON(ctx, rc.RID)
	if err != nil {
		return err
	}
	data := map[string]interface{}{}
	if found && raw != nil {
		_ = json.Unmarshal(raw, &data) // best-effort; if error, start fresh
	}
	if err := mutator(data); err != nil {
		return err
	}
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	// TTL re-computed from refresh claims expiry
	ttl := ttlFromExpiry(rc.Claims.Expiry.Time(), 0)
	return ps.SaveRefreshPayload(ctx, rc.RID, json.RawMessage(b), ttl)
}
