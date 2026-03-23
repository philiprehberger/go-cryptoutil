package cryptoutil

import (
	"bytes"
	"testing"
)

func TestGenerateSalt_Length(t *testing.T) {
	for _, n := range []int{0, 1, 16, 32, 64} {
		salt, err := GenerateSalt(n)
		if err != nil {
			t.Fatalf("GenerateSalt(%d) error: %v", n, err)
		}
		if len(salt) != n {
			t.Errorf("GenerateSalt(%d) returned %d bytes", n, len(salt))
		}
	}
}

func TestGenerateSalt_Unique(t *testing.T) {
	a, err := GenerateSalt(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateSalt(32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("two GenerateSalt(32) calls returned identical values")
	}
}

func TestGenerateSalt_Negative(t *testing.T) {
	_, err := GenerateSalt(-1)
	if err == nil {
		t.Error("GenerateSalt(-1) should return error")
	}
}

func TestDeriveKey_Deterministic(t *testing.T) {
	password := []byte("my-password")
	salt := []byte("fixed-salt-value")
	key1 := DeriveKey(password, salt, 32)
	key2 := DeriveKey(password, salt, 32)
	if !bytes.Equal(key1, key2) {
		t.Error("DeriveKey is not deterministic: same inputs produced different outputs")
	}
}

func TestDeriveKey_DifferentSalts(t *testing.T) {
	password := []byte("my-password")
	key1 := DeriveKey(password, []byte("salt-one"), 32)
	key2 := DeriveKey(password, []byte("salt-two"), 32)
	if bytes.Equal(key1, key2) {
		t.Error("DeriveKey produced identical keys for different salts")
	}
}

func TestDeriveKey_DifferentPasswords(t *testing.T) {
	salt := []byte("same-salt")
	key1 := DeriveKey([]byte("password-a"), salt, 32)
	key2 := DeriveKey([]byte("password-b"), salt, 32)
	if bytes.Equal(key1, key2) {
		t.Error("DeriveKey produced identical keys for different passwords")
	}
}

func TestDeriveKey_Length(t *testing.T) {
	password := []byte("test")
	salt := []byte("salt")
	for _, keyLen := range []int{16, 32, 48, 64} {
		key := DeriveKey(password, salt, keyLen)
		if len(key) != keyLen {
			t.Errorf("DeriveKey with keyLen=%d returned %d bytes", keyLen, len(key))
		}
	}
}

func TestDeriveKey_ZeroLength(t *testing.T) {
	key := DeriveKey([]byte("pass"), []byte("salt"), 0)
	if key != nil {
		t.Error("DeriveKey with keyLen=0 should return nil")
	}
}

func TestDeriveKey_NegativeLength(t *testing.T) {
	key := DeriveKey([]byte("pass"), []byte("salt"), -1)
	if key != nil {
		t.Error("DeriveKey with negative keyLen should return nil")
	}
}
