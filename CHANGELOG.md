# Changelog

## 0.2.1

- Standardize README to 3-badge format with emoji Support section
- Update CI checkout action to v5 for Node.js 24 compatibility
- Add GitHub issue templates, dependabot config, and PR template

## 0.2.0

- Add key derivation: `DeriveKey` with 600,000 HMAC-SHA256 iterations, `GenerateSalt`
- Add hashing: `SHA256`, `SHA512` returning hex strings
- Add digital signatures: `GenerateKeyPair`, `Sign`, `Verify` using Ed25519

## 0.1.3

- Consolidate README badges onto single line, fix CHANGELOG format

## 0.1.2

- Add Development section to README

## 0.1.0

- Initial release
- Random token generation (hex, base64, URL-safe)
- Password hashing with bcrypt
- AES-GCM encryption/decryption
- HMAC-SHA256 sign/verify
- Constant-time string comparison
