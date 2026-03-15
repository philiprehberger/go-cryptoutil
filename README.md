# go-cryptoutil

Common cryptography helpers for Go. Safe defaults, zero dependencies.

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

## License

MIT
