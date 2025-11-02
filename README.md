# QasaGo

A secure Go cryptography utility library providing AES-256-GCM encryption with authenticated encryption and associated data (AEAD).

## Features

- **AES-256-GCM Encryption**: Industry-standard authenticated encryption
- **Secure Key Generation**: Cryptographically secure key generation utilities
- **Base64 Encoding**: Safe text storage and transmission of encrypted data
- **Comprehensive Error Handling**: Clear error messages for debugging
- **Zero Dependencies**: Uses only Go standard library
- **Production Ready**: Complete implementation with security best practices

## Requirements

- Go 1.25.3 or higher

## Installation

```bash
go get github.com/djwarf/qasago
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/djwarf/qasago"
)

func main() {
    // Generate a secure encryption key (do this once and store securely)
    key, err := qasago.GenerateEncryptionKey()
    if err != nil {
        log.Fatal(err)
    }

    // Encrypt data
    plaintext := "Secret message to encrypt"
    encrypted, err := qasago.Encrypt(plaintext, key)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Encrypted: %s\n", encrypted)

    // Decrypt data
    decrypted, err := qasago.Decrypt(encrypted, key)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Decrypted: %s\n", decrypted)
}
```

## API Documentation

### Encryption Functions

#### `Encrypt(plaintext string, key []byte) (string, error)`

Encrypts plaintext using AES-256-GCM with a random nonce.

- **Parameters:**
  - `plaintext`: The data to encrypt (cannot be empty)
  - `key`: Exactly 32 bytes for AES-256 encryption
- **Returns:**
  - Base64-encoded ciphertext with prepended nonce
  - Error if encryption fails

#### `Decrypt(encryptedData string, key []byte) (string, error)`

Decrypts a base64-encoded AES-256-GCM ciphertext.

- **Parameters:**
  - `encryptedData`: Base64-encoded nonce + ciphertext + auth tag
  - `key`: The same 32-byte key used for encryption
- **Returns:**
  - Decrypted plaintext
  - Error if decryption or authentication fails

### Key Management Functions

#### `GenerateEncryptionKey() ([]byte, error)`

Creates a cryptographically secure 256-bit key.

- **Returns:**
  - 32-byte encryption key
  - Error if generation fails

#### `ValidateEncryptionKey(key []byte) error`

Validates if a key is suitable for AES-256 encryption.

- **Parameters:**
  - `key`: The encryption key to validate
- **Returns:**
  - Error if key is invalid, nil otherwise

#### `EncodeKey(key []byte) string`

Converts a binary key to base64 for configuration storage.

- **Parameters:**
  - `key`: Binary encryption key
- **Returns:**
  - Base64-encoded key string

#### `DecodeKey(encoded string) ([]byte, error)`

Converts a base64-encoded key back to binary.

- **Parameters:**
  - `encoded`: Base64-encoded key string
- **Returns:**
  - Binary encryption key
  - Error if decoding fails

## Usage Examples

### Environment Variable Storage

```go
package main

import (
    "os"
    "log"

    "github.com/djwarf/qasago"
)

func main() {
    // Generate and encode a key for storage
    key, _ := qasago.GenerateEncryptionKey()
    encodedKey := qasago.EncodeKey(key)

    // Store in environment variable
    os.Setenv("ENCRYPTION_KEY", encodedKey)

    // Later, retrieve and decode the key
    encodedKey = os.Getenv("ENCRYPTION_KEY")
    key, err := qasago.DecodeKey(encodedKey)
    if err != nil {
        log.Fatal("Invalid encryption key:", err)
    }

    // Use the key for encryption/decryption
    encrypted, _ := qasago.Encrypt("sensitive data", key)
    decrypted, _ := qasago.Decrypt(encrypted, key)
}
```

### Database Field Encryption

```go
package main

import (
    "database/sql"
    "log"

    "github.com/djwarf/qasago"
)

type User struct {
    ID    int
    Email string
    // Store encrypted sensitive data
    EncryptedSSN string
}

func SaveUser(db *sql.DB, user User, encryptionKey []byte) error {
    // Encrypt sensitive data before storing
    encryptedSSN, err := qasago.Encrypt(user.EncryptedSSN, encryptionKey)
    if err != nil {
        return err
    }

    _, err = db.Exec(
        "INSERT INTO users (email, ssn_encrypted) VALUES (?, ?)",
        user.Email, encryptedSSN,
    )
    return err
}

func GetUser(db *sql.DB, id int, encryptionKey []byte) (*User, error) {
    var user User
    var encryptedSSN string

    err := db.QueryRow(
        "SELECT id, email, ssn_encrypted FROM users WHERE id = ?",
        id,
    ).Scan(&user.ID, &user.Email, &encryptedSSN)

    if err != nil {
        return nil, err
    }

    // Decrypt sensitive data after retrieval
    ssn, err := qasago.Decrypt(encryptedSSN, encryptionKey)
    if err != nil {
        return nil, err
    }
    user.EncryptedSSN = ssn

    return &user, nil
}
```

### Error Handling

```go
package main

import (
    "errors"
    "fmt"
    "log"

    "github.com/djwarf/qasago"
)

func main() {
    key := make([]byte, 16) // Wrong size key

    _, err := qasago.Encrypt("data", key)
    if errors.Is(err, qasago.ErrInvalidKeySize) {
        log.Printf("Key size error: %v", err)
        // Handle invalid key size
    }

    _, err = qasago.Decrypt("invalid-base64!", key)
    if errors.Is(err, qasago.ErrInvalidCiphertext) {
        log.Printf("Ciphertext error: %v", err)
        // Handle invalid ciphertext
    }
}
```

## Security Considerations

1. **Key Storage**: Never hard-code encryption keys in source code. Use environment variables or secure key management systems.

2. **Key Rotation**: Implement key rotation policies for long-term data storage.

3. **Nonce Uniqueness**: The library automatically generates unique nonces for each encryption operation.

4. **Authentication**: GCM mode provides built-in authentication, detecting any tampering with the ciphertext.

5. **Error Messages**: The library returns generic error messages for security-sensitive operations to prevent information leakage.

## Performance

- AES-256-GCM is hardware-accelerated on most modern CPUs
- Encryption: ~500 ns/op with 1728 B/op and 7 allocs/op
- Decryption: ~386 ns/op with 1536 B/op and 5 allocs/op
- Base64 encoding adds ~33% overhead to ciphertext size
- Suitable for encrypting small to medium-sized data (< 1MB)
- For large files, consider streaming encryption approaches

## Testing

The library has comprehensive test coverage (89.7%) including:
- Unit tests for all functions
- Edge case testing
- Tamper detection validation
- Concurrent operation safety
- Performance benchmarks

Run the test suite:

```bash
go test ./...
```

Run with coverage:

```bash
go test -cover ./...
```

Run benchmarks:

```bash
go test -bench=. -benchmem ./...
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Uses Go's standard `crypto/aes` and `crypto/cipher` packages
- Follows NIST recommendations for GCM mode operation
- Implements OWASP cryptographic storage best practices

## Support

For issues, questions, or suggestions, please open an issue on GitHub.