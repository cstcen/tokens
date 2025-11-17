package tokens

import (
	"crypto"
	"errors"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

// DecryptAndVerifyAccess decrypts JWE -> verifies inner signed JWT -> returns parsed AccessCustomClaims
func DecryptAndVerifyAccess(
	tokenJWE string,
	encPrivKey interface{},
	findSigKeyByKID func(string) crypto.PublicKey,
	issuer, audience string,
) (AccessCustomClaims, error) {
	var out AccessCustomClaims

	obj, err := jose.ParseEncrypted(tokenJWE)
	if err != nil {
		return out, err
	}
	inner, err := obj.Decrypt(encPrivKey)
	if err != nil {
		return out, err
	}
	tok, err := jwt.ParseSigned(string(inner))
	if err != nil {
		return out, err
	}
	if len(tok.Headers) == 0 {
		return out, errors.New("missing jws header")
	}
	kid := tok.Headers[0].KeyID
	pub := findSigKeyByKID(kid)
	if pub == nil {
		return out, errors.New("unknown sig kid")
	}
	if err := tok.Claims(pub, &out); err != nil {
		return out, err
	}
	if err := out.Claims.Validate(jwt.Expected{Issuer: issuer, Audience: jwt.Audience{audience}, Time: time.Now()}); err != nil {
		return out, err
	}
	return out, nil
}

// DecryptAndVerifyRefresh mirrors DecryptAndVerifyAccess for refresh claims
func DecryptAndVerifyRefresh(
	tokenJWE string,
	encPrivKey interface{},
	findSigKeyByKID func(string) crypto.PublicKey,
	issuer, audience string,
) (RefreshCustomClaims, error) {
	var out RefreshCustomClaims

	obj, err := jose.ParseEncrypted(tokenJWE)
	if err != nil {
		return out, err
	}
	inner, err := obj.Decrypt(encPrivKey)
	if err != nil {
		return out, err
	}
	tok, err := jwt.ParseSigned(string(inner))
	if err != nil {
		return out, err
	}
	if len(tok.Headers) == 0 {
		return out, errors.New("missing jws header")
	}
	kid := tok.Headers[0].KeyID
	pub := findSigKeyByKID(kid)
	if pub == nil {
		return out, errors.New("unknown sig kid")
	}
	if err := tok.Claims(pub, &out); err != nil {
		return out, err
	}
	if err := out.Claims.Validate(jwt.Expected{Issuer: issuer, Audience: jwt.Audience{audience}, Time: time.Now()}); err != nil {
		return out, err
	}
	return out, nil
}
