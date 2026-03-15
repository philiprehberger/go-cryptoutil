package cryptoutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const (
	passwordVersion    = "v1"
	passwordIterations = 100000
	passwordSaltLen    = 16
	passwordHashLen    = 32
)

// HashPassword hashes a password using iterated HMAC-SHA256 with a random salt.
// The returned string has the format: $v1$iterations$salt_hex$hash_hex.
// Each call produces a unique hash due to random salt generation.
func HashPassword(password string) (string, error) {
	salt, err := RandomBytes(passwordSaltLen)
	if err != nil {
		return "", fmt.Errorf("cryptoutil: failed to generate salt: %w", err)
	}
	hash := deriveKey([]byte(password), salt, passwordIterations)
	return fmt.Sprintf("$%s$%d$%s$%s",
		passwordVersion,
		passwordIterations,
		hex.EncodeToString(salt),
		hex.EncodeToString(hash),
	), nil
}

// VerifyPassword checks whether the given password matches the hashed value
// produced by HashPassword. It uses constant-time comparison to prevent timing attacks.
func VerifyPassword(hashed, password string) (bool, error) {
	parts := strings.Split(hashed, "$")
	// Format: ["", version, iterations, salt_hex, hash_hex]
	if len(parts) != 5 || parts[0] != "" {
		return false, fmt.Errorf("cryptoutil: invalid hash format")
	}
	version := parts[1]
	if version != passwordVersion {
		return false, fmt.Errorf("cryptoutil: unsupported hash version: %s", version)
	}
	iterations, err := strconv.Atoi(parts[2])
	if err != nil {
		return false, fmt.Errorf("cryptoutil: invalid iteration count: %w", err)
	}
	salt, err := hex.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("cryptoutil: invalid salt encoding: %w", err)
	}
	expectedHash, err := hex.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("cryptoutil: invalid hash encoding: %w", err)
	}
	computed := deriveKey([]byte(password), salt, iterations)
	if subtle.ConstantTimeCompare(computed, expectedHash) == 1 {
		return true, nil
	}
	return false, nil
}

// deriveKey performs iterated HMAC-SHA256 key derivation.
// It repeatedly applies HMAC-SHA256(salt, previous_hash + password) for the given
// number of iterations to produce a derived key.
func deriveKey(password, salt []byte, iterations int) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(password)
	result := h.Sum(nil)

	for i := 1; i < iterations; i++ {
		h.Reset()
		h.Write(result)
		h.Write(password)
		result = h.Sum(nil)
	}
	return result
}
