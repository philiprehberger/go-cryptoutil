# go-cryptoutil

[![CI](https://github.com/philiprehberger/go-cryptoutil/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/go-cryptoutil/actions/workflows/ci.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/philiprehberger/go-cryptoutil.svg)](https://pkg.go.dev/github.com/philiprehberger/go-cryptoutil) [![License](https://img.shields.io/github/license/philiprehberger/go-cryptoutil)](LICENSE) [![Sponsor](https://img.shields.io/badge/sponsor-GitHub%20Sponsors-ec6cb9)](https://github.com/sponsors/philiprehberger)

Common cryptography helpers for Go. Safe defaults, zero dependencies

## Installation

```bash
go get github.com/philiprehberger/go-cryptoutil
```

## Usage

### Random Tokens

```go
import "github.com/philiprehberger/go-cryptoutil"

// Generate a 32-byte hex token (64 characters)
token, err := cryptoutil.RandomHex(32)

// Generate a URL-safe token (no +, /, or = characters)
urlToken, err := cryptoutil.RandomURLSafe(32)
```

### Password Hashing

```go
// Hash a password
hash, err := cryptoutil.HashPassword("my-secure-password")

// Verify a password
ok, err := cryptoutil.VerifyPassword(hash, "my-secure-password")
if ok {
    // password matches
}
```

### Encryption (AES-GCM)

```go
// Generate a 256-bit encryption key
key, err := cryptoutil.GenerateKey()

// Encrypt/decrypt bytes
ciphertext, err := cryptoutil.Encrypt(key, []byte("secret data"))
plaintext, err := cryptoutil.Decrypt(key, ciphertext)

// Encrypt/decrypt strings (base64 encoded)
encrypted, err := cryptoutil.EncryptString(key, "secret data")
decrypted, err := cryptoutil.DecryptString(key, encrypted)
```

### HMAC Signing

```go
secret := []byte("webhook-secret")
payload := []byte(`{"event": "push"}`)

// Sign
signature := cryptoutil.HMACSign(secret, payload)

// Verify
valid := cryptoutil.HMACVerify(secret, payload, signature)

// Constant-time string comparison
equal := cryptoutil.ConstantTimeEqual(a, b)
```

### Key Derivation

```go
// Generate a random salt
salt, err := cryptoutil.GenerateSalt(16)

// Derive a 32-byte key from a password and salt
// Uses 600,000 iterations of HMAC-SHA256 (OWASP recommended)
key := cryptoutil.DeriveKey([]byte("my-password"), salt, 32)
```

### Hashing

```go
// Compute SHA-256 hash (returns 64-character hex string)
hash256 := cryptoutil.SHA256([]byte("hello"))

// Compute SHA-512 hash (returns 128-character hex string)
hash512 := cryptoutil.SHA512([]byte("hello"))
```

### Digital Signatures (Ed25519)

```go
// Generate an Ed25519 key pair
pub, priv, err := cryptoutil.GenerateKeyPair()

// Sign data
sig := cryptoutil.Sign(priv, []byte("message to sign"))

// Verify signature
valid := cryptoutil.Verify(pub, []byte("message to sign"), sig)
```

## API

| Function | Description |
|---|---|
| `RandomBytes(n int) ([]byte, error)` | Generate n random bytes |
| `RandomHex(n int) (string, error)` | Generate n random bytes as hex string |
| `RandomBase64(n int) (string, error)` | Generate n random bytes as base64 string |
| `RandomURLSafe(n int) (string, error)` | Generate n random bytes as URL-safe base64 |
| `HashPassword(password string) (string, error)` | Hash password with random salt |
| `VerifyPassword(hashed, password string) (bool, error)` | Verify password against hash |
| `GenerateKey() ([]byte, error)` | Generate 32-byte AES-256 key |
| `Encrypt(key, plaintext []byte) ([]byte, error)` | AES-GCM encrypt |
| `Decrypt(key, ciphertext []byte) ([]byte, error)` | AES-GCM decrypt |
| `EncryptString(key []byte, plaintext string) (string, error)` | Encrypt string, return base64 |
| `DecryptString(key []byte, ciphertext string) (string, error)` | Decrypt base64 string |
| `HMACSign(secret, payload []byte) string` | HMAC-SHA256 sign, return hex |
| `HMACVerify(secret, payload []byte, signature string) bool` | Verify HMAC signature |
| `ConstantTimeEqual(a, b string) bool` | Constant-time string comparison |
| `DeriveKey(password, salt []byte, keyLen int) []byte` | Derive key using iterated HMAC-SHA256 |
| `GenerateSalt(n int) ([]byte, error)` | Generate n bytes of random salt |
| `SHA256(data []byte) string` | SHA-256 hash, return hex string |
| `SHA512(data []byte) string` | SHA-512 hash, return hex string |
| `GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error)` | Generate Ed25519 key pair |
| `Sign(privateKey ed25519.PrivateKey, data []byte) []byte` | Ed25519 sign |
| `Verify(publicKey ed25519.PublicKey, data, sig []byte) bool` | Ed25519 verify |

## Development

```bash
go test ./...
go vet ./...
```

## License

MIT
