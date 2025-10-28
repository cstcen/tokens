package tokens

import (
	"crypto/ecdsa"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
)

// AccessCustomClaims defines access token claims (business + standard JWT claims)
type AccessCustomClaims struct {
	Scope    []string `json:"scope,omitempty"`
	DeviceID string   `json:"device_id,omitempty"`
	ClientID string   `json:"client_id,omitempty"`
	jwt.Claims
}

// RefreshCustomClaims defines refresh token claims
type RefreshCustomClaims struct {
	RID      string   `json:"rid"`
	FID      string   `json:"fid"`
	UID      string   `json:"uid"`
	DeviceID string   `json:"device_id,omitempty"`
	ClientID string   `json:"client_id,omitempty"`
	Scope    []string `json:"scope,omitempty"`
	jwt.Claims
}

// KeyAlgs defines signing and encryption algorithms to use
type KeyAlgs struct {
	// Inner JWS signature algorithm (e.g., jose.ES256)
	SignAlg jose.SignatureAlgorithm
	// Outer JWE key management algorithm (e.g., jose.RSA_OAEP_256 or jose.ECDH_ES_A256KW)
	KeyMgmtAlg jose.KeyAlgorithm
	// Outer JWE content encryption (e.g., jose.A256GCM)
	ContentEncryption jose.ContentEncryption
}

// IssueAccessAndRefreshJWE issues Access and Refresh as nested JWS->JWE
// signPriv: ECDSA private key for inner JWS (ES256)
// encPubKey: recipient encryption public key for outer JWE (RSA or EC depending on KeyMgmtAlg)
func IssueAccessAndRefreshJWE(
	signKid string,
	signPriv *ecdsa.PrivateKey,
	encKid string,
	encPubKey interface{},
	algs KeyAlgs,
	iss, aud, sub, uid, deviceID, clientID string,
	accessTTL, refreshTTL time.Duration,
	scope []string,
) (accessJWE, refreshJWE string, err error) {
	now := time.Now()

	// ---- Access claims -> JWS -> JWE ----
	accessJti := uuid.NewString()
	accessClaims := AccessCustomClaims{
		Scope:    scope,
		DeviceID: deviceID,
		ClientID: clientID,
		Claims: jwt.Claims{
			Issuer:    iss,
			Subject:   sub,
			Audience:  jwt.Audience{aud},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-60 * time.Second)),
			Expiry:    jwt.NewNumericDate(now.Add(accessTTL)),
			ID:        accessJti,
		},
	}
	innerAccessJWS, err := signJWT(signPriv, signKid, algs.SignAlg, accessClaims)
	if err != nil {
		return "", "", err
	}
	accessJWE, err = encryptAsJWE(innerAccessJWS, encKid, encPubKey, algs.KeyMgmtAlg, algs.ContentEncryption)
	if err != nil {
		return "", "", err
	}

	// ---- Refresh claims -> JWS -> JWE ----
	rid := uuid.NewString()
	fid := uuid.NewString()
	refreshJti := uuid.NewString()
	refreshClaims := RefreshCustomClaims{
		RID:      rid,
		FID:      fid,
		UID:      uid,
		DeviceID: deviceID,
		ClientID: clientID,
		Scope:    scope,
		Claims: jwt.Claims{
			Issuer:    iss,
			Subject:   uid,
			Audience:  jwt.Audience{aud},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-60 * time.Second)),
			Expiry:    jwt.NewNumericDate(now.Add(refreshTTL)),
			ID:        refreshJti,
		},
	}
	innerRefreshJWS, err := signJWT(signPriv, signKid, algs.SignAlg, refreshClaims)
	if err != nil {
		return "", "", err
	}
	refreshJWE, err = encryptAsJWE(innerRefreshJWS, encKid, encPubKey, algs.KeyMgmtAlg, algs.ContentEncryption)
	if err != nil {
		return "", "", err
	}

	return accessJWE, refreshJWE, nil
}
