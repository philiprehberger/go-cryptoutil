package cryptoutil

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
)

// SHA256 computes the SHA-256 hash of data and returns the result as a
// lowercase hexadecimal string (64 characters).
func SHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// SHA512 computes the SHA-512 hash of data and returns the result as a
// lowercase hexadecimal string (128 characters).
func SHA512(data []byte) string {
	h := sha512.Sum512(data)
	return hex.EncodeToString(h[:])
}
