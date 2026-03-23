package cryptoutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// GenerateKeyPair generates a new Ed25519 key pair for digital signatures.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cryptoutil: failed to generate key pair: %w", err)
	}
	return pub, priv, nil
}

// Sign produces an Ed25519 signature of data using the given private key.
func Sign(privateKey ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(privateKey, data)
}

// Verify checks an Ed25519 signature against the given public key and data.
// It returns true if the signature is valid.
func Verify(publicKey ed25519.PublicKey, data, sig []byte) bool {
	return ed25519.Verify(publicKey, data, sig)
}
