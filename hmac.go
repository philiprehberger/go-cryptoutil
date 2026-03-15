package cryptoutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// HMACSign computes an HMAC-SHA256 of the payload using the given secret
// and returns the result as a hexadecimal string.
func HMACSign(secret []byte, payload []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// HMACVerify verifies an HMAC-SHA256 signature against the given payload and secret.
// It uses constant-time comparison to prevent timing attacks.
func HMACVerify(secret []byte, payload []byte, signature string) bool {
	expected := HMACSign(secret, payload)
	return ConstantTimeEqual(expected, signature)
}

// ConstantTimeEqual performs a constant-time comparison of two strings.
// It returns true if the strings are equal, false otherwise.
// This prevents timing attacks when comparing secret values.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
