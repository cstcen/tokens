package tokens

import (
	"crypto"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v3"
)

func TestRoundtripAccessRefresh(t *testing.T) {
	signPriv, err := GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	// Use EC key for JWE (ECDH-ES) instead of RSA
	encPriv, err := GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}

	// Switch JWE key management to ECDH-ES with A256KW and A256GCM content encryption
	algs := KeyAlgs{SignAlg: jose.ES256, KeyMgmtAlg: jose.ECDH_ES_A256KW, ContentEncryption: jose.A256GCM}
	accessJWE, refreshJWE, err := IssueAccessAndRefreshJWE(
		"sig-1", signPriv,
		"enc-1", &encPriv.PublicKey,
		algs,
		"https://auth.local", "api://local", "u1", "u1", "dev1", "web",
		10*time.Minute, 24*time.Hour,
		[]string{"read"},
	)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var sigKeyPub crypto.PublicKey = &signPriv.PublicKey
	find := func(k string) crypto.PublicKey {
		if k == "sig-1" {
			return sigKeyPub
		}
		return nil
	}

	ac, err := DecryptAndVerifyAccess(accessJWE, encPriv, find, "https://auth.local", "api://local")
	if err != nil {
		t.Fatalf("verify access: %v", err)
	}
	if ac.Claims.Subject != "u1" || ac.DeviceID != "dev1" {
		t.Fatalf("claims mismatch: %+v", ac)
	}

	rc, err := DecryptAndVerifyRefresh(refreshJWE, encPriv, find, "https://auth.local", "api://local")
	if err != nil {
		t.Fatalf("verify refresh: %v", err)
	}
	if rc.UID != "u1" || rc.DeviceID != "dev1" || rc.RID == "" || rc.FID == "" {
		t.Fatalf("claims mismatch: %+v", rc)
	}
}
