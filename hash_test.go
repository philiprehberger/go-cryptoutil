package cryptoutil

import (
	"testing"
)

func TestSHA256_KnownVector(t *testing.T) {
	// SHA-256 of empty string
	got := SHA256([]byte(""))
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("SHA256(\"\") = %s, want %s", got, want)
	}
}

func TestSHA256_HelloWorld(t *testing.T) {
	got := SHA256([]byte("hello"))
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("SHA256(\"hello\") = %s, want %s", got, want)
	}
}

func TestSHA256_Length(t *testing.T) {
	got := SHA256([]byte("test"))
	if len(got) != 64 {
		t.Errorf("SHA256 returned string of length %d, want 64", len(got))
	}
}

func TestSHA512_KnownVector(t *testing.T) {
	// SHA-512 of empty string
	got := SHA512([]byte(""))
	want := "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	if got != want {
		t.Errorf("SHA512(\"\") = %s, want %s", got, want)
	}
}

func TestSHA512_HelloWorld(t *testing.T) {
	got := SHA512([]byte("hello"))
	want := "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
	if got != want {
		t.Errorf("SHA512(\"hello\") = %s, want %s", got, want)
	}
}

func TestSHA512_Length(t *testing.T) {
	got := SHA512([]byte("test"))
	if len(got) != 128 {
		t.Errorf("SHA512 returned string of length %d, want 128", len(got))
	}
}
