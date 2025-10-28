package tokens

import (
	"crypto"
	"errors"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
)

// TokenKind represents the coarse token format we can recognize from structure.
type TokenKind int

const (
	TokenKindUnknown TokenKind = iota
	TokenKindJWS               // compact JWS (JWT) -> 3 segments
	TokenKindJWE               // compact JWE -> 5 segments
	TokenKindOpaque            // anything else (e.g., legacy AES ciphertext)
)

// GuessTokenKind tries to infer token kind from compact serialization structure.
// - JWS (JWT): header.payload.signature -> 3 segments
// - JWE: header.encrypted_key.iv.ciphertext.tag -> 5 segments
// - Otherwise: opaque
func GuessTokenKind(token string) TokenKind {
	t := TrimBearer(token)
	dot := strings.Count(t, ".")
	switch dot {
	case 2:
		return TokenKindJWS
	case 4:
		return TokenKindJWE
	default:
		return TokenKindOpaque
	}
}

// TrimBearer strips leading "Bearer " if present.
func TrimBearer(token string) string {
	token = strings.TrimSpace(token)
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		return strings.TrimSpace(token[7:])
	}
	return token
}

// VerifyAccessJWS verifies a compact JWS (JWT) access token without JWE.
func VerifyAccessJWS(token string, findSigKeyByKID func(string) crypto.PublicKey, issuer, audience string) (AccessCustomClaims, error) {
	var out AccessCustomClaims
	token = TrimBearer(token)
	tok, err := jwt.ParseSigned(token)
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

// VerifyRefreshJWS mirrors VerifyAccessJWS for refresh claims.
func VerifyRefreshJWS(token string, findSigKeyByKID func(string) crypto.PublicKey, issuer, audience string) (RefreshCustomClaims, error) {
	var out RefreshCustomClaims
	token = TrimBearer(token)
	tok, err := jwt.ParseSigned(token)
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

// Legacy decoders allow plugging in your AES/opaque token handling. Return an error if not applicable.
type LegacyAccessDecoder func(token string) (AccessCustomClaims, error)
type LegacyRefreshDecoder func(token string) (RefreshCustomClaims, error)

// VerifyAnyAccess tries (in order): structure guess -> JWE -> JWS -> legacy decoder.
// Provide encPrivKey for JWE, and findSigKeyByKID for JWS/JWE. Pass nil if a mode isn't needed.
func VerifyAnyAccess(token string, encPrivKey interface{}, findSigKeyByKID func(string) crypto.PublicKey, issuer, audience string, legacy LegacyAccessDecoder) (AccessCustomClaims, error) {
	var zero AccessCustomClaims
	token = TrimBearer(token)
	switch GuessTokenKind(token) {
	case TokenKindJWE:
		if encPrivKey != nil && findSigKeyByKID != nil {
			if ac, err := DecryptAndVerifyAccess(token, encPrivKey, findSigKeyByKID, issuer, audience); err == nil {
				return ac, nil
			}
		}
	case TokenKindJWS:
		if findSigKeyByKID != nil {
			return VerifyAccessJWS(token, findSigKeyByKID, issuer, audience)
		}
	}
	// Fallback attempts in robust order
	if encPrivKey != nil && findSigKeyByKID != nil {
		if ac, err := DecryptAndVerifyAccess(token, encPrivKey, findSigKeyByKID, issuer, audience); err == nil {
			return ac, nil
		}
	}
	if findSigKeyByKID != nil {
		if ac, err := VerifyAccessJWS(token, findSigKeyByKID, issuer, audience); err == nil {
			return ac, nil
		}
	}
	if legacy != nil {
		if ac, err := legacy(token); err == nil {
			return ac, nil
		}
	}
	return zero, errors.New("unsupported or invalid token format")
}

// VerifyAnyRefresh mirrors VerifyAnyAccess for refresh tokens.
func VerifyAnyRefresh(token string, encPrivKey interface{}, findSigKeyByKID func(string) crypto.PublicKey, issuer, audience string, legacy LegacyRefreshDecoder) (RefreshCustomClaims, error) {
	var zero RefreshCustomClaims
	token = TrimBearer(token)
	switch GuessTokenKind(token) {
	case TokenKindJWE:
		if encPrivKey != nil && findSigKeyByKID != nil {
			if rc, err := DecryptAndVerifyRefresh(token, encPrivKey, findSigKeyByKID, issuer, audience); err == nil {
				return rc, nil
			}
		}
	case TokenKindJWS:
		if findSigKeyByKID != nil {
			if rc, err := VerifyRefreshJWS(token, findSigKeyByKID, issuer, audience); err == nil {
				return rc, nil
			}
		}
	}
	// Fallback attempts
	if encPrivKey != nil && findSigKeyByKID != nil {
		if rc, err := DecryptAndVerifyRefresh(token, encPrivKey, findSigKeyByKID, issuer, audience); err == nil {
			return rc, nil
		}
	}
	if findSigKeyByKID != nil {
		if rc, err := VerifyRefreshJWS(token, findSigKeyByKID, issuer, audience); err == nil {
			return rc, nil
		}
	}
	if legacy != nil {
		if rc, err := legacy(token); err == nil {
			return rc, nil
		}
	}
	return zero, errors.New("unsupported or invalid token format")
}
