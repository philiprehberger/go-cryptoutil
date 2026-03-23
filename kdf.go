package cryptoutil

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

const (
	// DeriveKeyIterations is the default iteration count for DeriveKey,
	// aligned with OWASP recommendations.
	DeriveKeyIterations = 600000
)

// GenerateSalt generates n bytes of cryptographically secure random data
// suitable for use as a salt in key derivation.
func GenerateSalt(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("cryptoutil: salt length must be non-negative, got %d", n)
	}
	salt := make([]byte, n)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("cryptoutil: failed to generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a key from a password and salt using iterated HMAC-SHA256.
// It applies HMAC-SHA256 for 600,000 iterations (OWASP recommended) to produce
// a key of keyLen bytes. The same password, salt, and keyLen will always produce
// the same output.
func DeriveKey(password, salt []byte, keyLen int) []byte {
	if keyLen <= 0 {
		return nil
	}

	// Initial HMAC: key=salt, message=password
	mac := hmac.New(sha256.New, salt)
	mac.Write(password)
	result := mac.Sum(nil)

	// Iterate
	for i := 1; i < DeriveKeyIterations; i++ {
		mac.Reset()
		mac.Write(result)
		mac.Write(password)
		result = mac.Sum(nil)
	}

	// Truncate or return as needed
	if keyLen <= len(result) {
		return result[:keyLen]
	}

	// If more bytes are needed than one SHA-256 output, extend by hashing
	// with a counter suffix. This is a simple extension scheme.
	out := make([]byte, 0, keyLen)
	out = append(out, result...)
	counter := byte(1)
	for len(out) < keyLen {
		h := sha256.New()
		h.Write(result)
		h.Write([]byte{counter})
		out = append(out, h.Sum(nil)...)
		counter++
	}
	return out[:keyLen]
}
