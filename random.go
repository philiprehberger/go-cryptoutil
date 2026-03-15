// Package cryptoutil provides common cryptography helpers for Go.
// It offers safe defaults and uses only the standard library with zero external dependencies.
package cryptoutil

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// RandomBytes returns n cryptographically secure random bytes from crypto/rand.
func RandomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("cryptoutil: byte count must be non-negative, got %d", n)
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("cryptoutil: failed to generate random bytes: %w", err)
	}
	return b, nil
}

// RandomHex returns n random bytes encoded as a hexadecimal string (2*n characters).
func RandomHex(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RandomBase64 returns n random bytes encoded as a standard base64 string.
func RandomBase64(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// RandomURLSafe returns n random bytes encoded as a URL-safe base64 string with no padding.
func RandomURLSafe(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
