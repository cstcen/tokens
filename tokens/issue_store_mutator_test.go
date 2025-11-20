package tokens

import (
	"context"
	"crypto"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v3"
)

// local minimal fake store for this test
type simpleStore struct {
	R map[string]RefreshCustomClaims
	F map[string]string
}

func newSimpleStore() *simpleStore {
	return &simpleStore{R: map[string]RefreshCustomClaims{}, F: map[string]string{}}
}
func (s *simpleStore) SaveRefresh(ctx context.Context, rid, fid string, claims RefreshCustomClaims, ttl time.Duration) error {
	s.R[rid] = claims
	s.F[fid] = rid
	return nil
}
func (s *simpleStore) GetRefresh(ctx context.Context, rid string) (RefreshCustomClaims, bool, error) {
	v, ok := s.R[rid]
	return v, ok, nil
}
func (s *simpleStore) GetFID(ctx context.Context, fid string) (string, bool, error) {
	v, ok := s.F[fid]
	return v, ok, nil
}
func (s *simpleStore) RevokeAccess(ctx context.Context, jti string, ttl time.Duration) error {
	return nil
}
func (s *simpleStore) RevokeRefresh(ctx context.Context, rid string, ttl time.Duration) error {
	return nil
}
func (s *simpleStore) RotateRefreshAtomic(ctx context.Context, oldRID string, oldTTL time.Duration, newRRID, fid string, newRClaims RefreshCustomClaims, newRTTL time.Duration) error {
	s.R[newRRID] = newRClaims
	s.F[fid] = newRRID
	delete(s.R, oldRID)
	return nil
}

// Removed cache methods; test store implements only required TokenStore subset.
func (s *simpleStore) IsAccessRevoked(ctx context.Context, jti string) (bool, error) {
	return false, nil
}

func TestIssueAndStoreClaimsMutator(t *testing.T) {
	signPriv, err := GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	encPriv, err := GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	var sigKeyPub crypto.PublicKey = &signPriv.PublicKey
	_ = sigKeyPub // reserved for possible verify use

	algs := KeyAlgs{SignAlg: jose.ES256, KeyMgmtAlg: jose.ECDH_ES_A256KW, ContentEncryption: jose.A256GCM}

	store := newSimpleStore()

	params := IssueAndStoreParams{
		Ctx:   context.Background(),
		Store: store,
		In: IssueInputs{
			SignKid:    "sig-1",
			SignPriv:   signPriv,
			EncKid:     "enc-1",
			EncPubKey:  &encPriv.PublicKey,
			Algs:       algs,
			Iss:        "https://auth.local",
			Aud:        "api://local",
			Sub:        "u1",
			UID:        "u1",
			DeviceID:   "dev1",
			ClientID:   "web",
			AccessTTL:  5 * time.Minute,
			RefreshTTL: 30 * time.Minute,
			Scope:      []string{"read"},
		},
		ClaimsMutator: func(ctx context.Context, ac *AccessCustomClaims, rc *RefreshCustomClaims) error {
			ac.ClientID = "mut"
			ac.Scope = append(ac.Scope, "extra")
			rc.ClientID = "mut"
			rc.Scope = append(rc.Scope, "extra-r")
			return nil
		},
	}

	res := IssueAndStore(params)
	if res.Err != nil {
		t.Fatalf("issue/store: %v", res.Err)
	}
	if res.AccessClaims.ClientID == "mut" {
		t.Fatalf("token claims should be pre-mutation; got mutated in result")
	}

	// Persisted refresh claims must be mutated (access not persisted in refresh-only mode)
	savedR, ok, _ := store.GetRefresh(context.Background(), res.RefreshClaims.RID)
	if !ok {
		t.Fatalf("saved refresh not found")
	}
	if savedR.ClientID != "mut" {
		t.Fatalf("mutator not applied to saved refresh: %+v", savedR)
	}
}
