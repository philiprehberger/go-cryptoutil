package cryptoutil

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestRandomBytes_Length(t *testing.T) {
	for _, n := range []int{0, 1, 16, 32, 64} {
		b, err := RandomBytes(n)
		if err != nil {
			t.Fatalf("RandomBytes(%d) error: %v", n, err)
		}
		if len(b) != n {
			t.Errorf("RandomBytes(%d) returned %d bytes", n, len(b))
		}
	}
}

func TestRandomBytes_Unique(t *testing.T) {
	a, err := RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) == string(b) {
		t.Error("two RandomBytes(32) calls returned identical values")
	}
}

func TestRandomHex_Length(t *testing.T) {
	for _, n := range []int{0, 1, 16, 32} {
		s, err := RandomHex(n)
		if err != nil {
			t.Fatalf("RandomHex(%d) error: %v", n, err)
		}
		if len(s) != 2*n {
			t.Errorf("RandomHex(%d) returned string of length %d, want %d", n, len(s), 2*n)
		}
	}
}

func TestRandomHex_Valid(t *testing.T) {
	s, err := RandomHex(32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hex.DecodeString(s); err != nil {
		t.Errorf("RandomHex(32) returned invalid hex: %v", err)
	}
}

func TestRandomBase64(t *testing.T) {
	s, err := RandomBase64(32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base64.StdEncoding.DecodeString(s); err != nil {
		t.Errorf("RandomBase64(32) returned invalid base64: %v", err)
	}
}

func TestRandomURLSafe(t *testing.T) {
	s, err := RandomURLSafe(32)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(s, "+/=") {
		t.Errorf("RandomURLSafe(32) contains invalid characters: %s", s)
	}
	if _, err := base64.RawURLEncoding.DecodeString(s); err != nil {
		t.Errorf("RandomURLSafe(32) returned invalid URL-safe base64: %v", err)
	}
}
