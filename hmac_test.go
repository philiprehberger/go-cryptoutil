package cryptoutil

import (
	"testing"
)

func TestHMACSign(t *testing.T) {
	sig := HMACSign([]byte("secret"), []byte("payload"))
	if sig == "" {
		t.Error("HMACSign returned empty string")
	}
	// SHA256 HMAC hex is 64 characters
	if len(sig) != 64 {
		t.Errorf("HMACSign returned string of length %d, want 64", len(sig))
	}
}

func TestHMACVerify_Valid(t *testing.T) {
	secret := []byte("my-secret-key")
	payload := []byte("important data")
	sig := HMACSign(secret, payload)
	if !HMACVerify(secret, payload, sig) {
		t.Error("HMACVerify returned false for valid signature")
	}
}

func TestHMACVerify_Invalid(t *testing.T) {
	secret := []byte("my-secret-key")
	payload := []byte("important data")
	if HMACVerify(secret, payload, "invalidsignature") {
		t.Error("HMACVerify returned true for invalid signature")
	}
}

func TestHMACVerify_WrongPayload(t *testing.T) {
	secret := []byte("my-secret-key")
	sig := HMACSign(secret, []byte("original payload"))
	if HMACVerify(secret, []byte("different payload"), sig) {
		t.Error("HMACVerify returned true for wrong payload")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual("hello", "hello") {
		t.Error("ConstantTimeEqual returned false for equal strings")
	}
	if ConstantTimeEqual("hello", "world") {
		t.Error("ConstantTimeEqual returned true for different strings")
	}
	if ConstantTimeEqual("short", "longer string") {
		t.Error("ConstantTimeEqual returned true for different length strings")
	}
}
