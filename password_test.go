package cryptoutil

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("mysecretpassword")
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	if hash == "" {
		t.Error("HashPassword returned empty string")
	}
}

func TestVerifyPassword_Correct(t *testing.T) {
	password := "correct-horse-battery-staple"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword(hash, password)
	if err != nil {
		t.Fatalf("VerifyPassword error: %v", err)
	}
	if !ok {
		t.Error("VerifyPassword returned false for correct password")
	}
}

func TestVerifyPassword_Wrong(t *testing.T) {
	hash, err := HashPassword("rightpassword")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword(hash, "wrongpassword")
	if err != nil {
		t.Fatalf("VerifyPassword error: %v", err)
	}
	if ok {
		t.Error("VerifyPassword returned true for wrong password")
	}
}

func TestHashPassword_Unique(t *testing.T) {
	password := "same-password"
	h1, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Error("HashPassword produced identical hashes for same password (salts should differ)")
	}
}
