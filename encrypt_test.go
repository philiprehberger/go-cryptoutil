package cryptoutil

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("hello, world!")
	ct, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}
	pt, err := Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("Decrypt returned %q, want %q", pt, plaintext)
	}
}

func TestEncryptDecrypt_String(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	original := "hello, encrypted world!"
	ct, err := EncryptString(key, original)
	if err != nil {
		t.Fatalf("EncryptString error: %v", err)
	}
	pt, err := DecryptString(key, ct)
	if err != nil {
		t.Fatalf("DecryptString error: %v", err)
	}
	if pt != original {
		t.Errorf("DecryptString returned %q, want %q", pt, original)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	ct, err := Encrypt(key1, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decrypt(key2, ct)
	if err == nil {
		t.Error("Decrypt with wrong key should return error")
	}
}

func TestDecrypt_Tampered(t *testing.T) {
	key, _ := GenerateKey()
	ct, err := Encrypt(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the ciphertext (flip a byte near the end)
	ct[len(ct)-1] ^= 0xff
	_, err = Decrypt(key, ct)
	if err == nil {
		t.Error("Decrypt with tampered ciphertext should return error")
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Errorf("GenerateKey returned %d bytes, want 32", len(key))
	}
}

func TestEncrypt_InvalidKeyLength(t *testing.T) {
	badKey := make([]byte, 15) // not 16, 24, or 32
	_, err := Encrypt(badKey, []byte("test"))
	if err == nil {
		t.Error("Encrypt with invalid key length should return error")
	}
}
