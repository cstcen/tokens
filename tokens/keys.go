package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

// GenerateES256Key creates a new ECDSA P-256 private key
func GenerateES256Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateRSA2048 creates a new RSA 2048 private key
func GenerateRSA2048() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
