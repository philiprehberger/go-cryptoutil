package cryptoutil

import (
	"crypto/ed25519"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
}

func TestGenerateKeyPair_Unique(t *testing.T) {
	pub1, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if string(pub1) == string(pub2) {
		t.Error("two GenerateKeyPair calls returned identical public keys")
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("message to sign")
	sig := Sign(priv, data)
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if !Verify(pub, data, sig) {
		t.Error("Verify returned false for valid signature")
	}
}

func TestVerify_WrongData(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sig := Sign(priv, []byte("original message"))
	if Verify(pub, []byte("different message"), sig) {
		t.Error("Verify returned true for wrong data")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("message")
	sig := Sign(priv, data)
	if Verify(pub2, data, sig) {
		t.Error("Verify returned true for wrong public key")
	}
}

func TestSign_Deterministic(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("deterministic test")
	sig1 := Sign(priv, data)
	sig2 := Sign(priv, data)
	if string(sig1) != string(sig2) {
		t.Error("Sign produced different signatures for same key and data")
	}
}
