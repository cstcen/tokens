package tokens

import (
	jose "github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

// signJWT signs claims into a compact signed JWT (JWS) with typ=JWT and kid
func signJWT(priv interface{}, kid string, alg jose.SignatureAlgorithm, claims interface{}) (string, error) {
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: priv}, opts)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(claims).CompactSerialize()
}

// signJWTWithExtra signs a compact signed JWT (JWS) with additional top-level custom fields.
// The extra map is merged after the structured claims, so keys in extra can override.
func signJWTWithExtra(priv interface{}, kid string, alg jose.SignatureAlgorithm, claims interface{}, extra map[string]interface{}) (string, error) {
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: priv}, opts)
	if err != nil {
		return "", err
	}
	builder := jwt.Signed(signer).Claims(claims)
	if extra != nil {
		builder = builder.Claims(extra)
	}
	return builder.CompactSerialize()
}

// encryptAsJWE encrypts plaintext (usually a compact signed JWT) into compact JWE with cty=JWT and kid
func encryptAsJWE(plaintext string, kid string, encPubKey interface{}, keyAlg jose.KeyAlgorithm, enc jose.ContentEncryption) (string, error) {
	recipient := jose.Recipient{
		Algorithm: keyAlg,
		Key:       unwrapJWK(encPubKey),
		KeyID:     kid,
	}
	encrypter, err := jose.NewEncrypter(
		enc,
		recipient,
		(&jose.EncrypterOptions{}).WithContentType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		return "", err
	}
	obj, err := encrypter.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

func unwrapJWK(v interface{}) interface{} {
	if jwk, ok := v.(*jose.JSONWebKey); ok {
		return jwk.Key
	}
	return v
}
