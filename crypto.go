// Package qasago contains secure cryptographic utility functions
// This file provides secure encryption and decryption using AES-256-GCM
// AES-256-GCM provides authenticated encryption with associated data (AEAD)
package qasago

import (
    "crypto/aes"           // Advanced Encryption Standard implementation
    "crypto/cipher"        // Cryptographic cipher implementations
    "crypto/rand"          // Cryptographically secure random number generator
    "encoding/base64"      // Base64 encoding for text-safe storage
    "errors"               // Error creation and handling
    "fmt"                  // Formatted I/O operations
)

// Constants for encryption configuration
const (
    // KeySize is the required size for AES-256 encryption (256 bits = 32 bytes)
    KeySize = 32
    // NonceSize is the size of the nonce for GCM mode (96 bits = 12 bytes)
    // GCM recommends 96-bit nonces for optimal performance
    NonceSize = 12
)

// Common errors returned by encryption functions
var (
    // ErrInvalidKeySize indicates the encryption key is not 32 bytes
    ErrInvalidKeySize = errors.New("encryption key must be exactly 32 bytes for AES-256")
    // ErrEmptyPlaintext indicates attempt to encrypt empty data
    ErrEmptyPlaintext = errors.New("plaintext cannot be empty")
    // ErrInvalidCiphertext indicates the ciphertext is too short or corrupted
    ErrInvalidCiphertext = errors.New("invalid ciphertext format or length")
    // ErrDecryptionFailed indicates authentication tag verification failed
    ErrDecryptionFailed = errors.New("decryption failed: data may be corrupted or tampered")
)

// Encrypt securely encrypts plaintext using AES-256-GCM with a random nonce.
// The function prepends the nonce to the ciphertext for self-contained storage.
// The result is base64-encoded for safe storage in text fields.
//
// Parameters:
//   - plaintext: The data to encrypt (cannot be empty)
//   - key: Exactly 32 bytes for AES-256 encryption
//
// Returns:
//   - string: Base64-encoded nonce + ciphertext + auth tag
//   - error: Any encryption error
//
// Format: base64(nonce[12] || ciphertext[...] || authTag[16])
func Encrypt(plaintext string, key []byte) (string, error) {
    // Validate inputs
    if len(key) != KeySize {
        return "", ErrInvalidKeySize
    }
    if plaintext == "" {
        return "", ErrEmptyPlaintext
    }

    // Create AES cipher block with the provided key
    // NewCipher returns a cipher.Block for the key size (AES-128/192/256)
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", fmt.Errorf("failed to create AES cipher: %w", err)
    }

    // Create GCM (Galois/Counter Mode) wrapper for authenticated encryption
    // GCM provides both confidentiality and authenticity
    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", fmt.Errorf("failed to create GCM cipher: %w", err)
    }

    // Generate a random nonce (number used once)
    // Each encryption MUST use a unique nonce to maintain security
    // Reusing a nonce with the same key breaks GCM security completely
    nonce := make([]byte, NonceSize)
    if _, err := rand.Read(nonce); err != nil {
        return "", fmt.Errorf("failed to generate nonce: %w", err)
    }

    // Encrypt the plaintext
    // Seal appends the ciphertext and authentication tag to dst (nonce in this case)
    // Format: nonce || ciphertext || authTag
    // The authentication tag (16 bytes) is automatically appended by GCM
    // #nosec G407 -- This is a false positive. The nonce is randomly generated above, not hardcoded
    ciphertext := aesgcm.Seal(nonce, nonce, []byte(plaintext), nil)

    // Encode to base64 for text-safe storage
    // Standard encoding uses +/ characters (URL-unsafe)
    // Use StdEncoding since this is for database storage, not URLs
    encoded := base64.StdEncoding.EncodeToString(ciphertext)

    return encoded, nil
}

// Decrypt decrypts a base64-encoded AES-256-GCM ciphertext.
// The function expects the nonce to be prepended to the ciphertext.
// Authentication tag verification ensures data integrity.
//
// Parameters:
//   - encryptedData: Base64-encoded nonce + ciphertext + auth tag
//   - key: The same 32-byte key used for encryption
//
// Returns:
//   - string: The decrypted plaintext
//   - error: Any decryption or authentication error
//
// Security: Returns error if authentication fails (tampering detected)
func Decrypt(encryptedData string, key []byte) (string, error) {
    // Validate inputs
    if len(key) != KeySize {
        return "", ErrInvalidKeySize
    }
    if encryptedData == "" {
        return "", ErrInvalidCiphertext
    }

    // Decode from base64
    ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
        return "", fmt.Errorf("failed to decode base64: %w", err)
    }

    // Check minimum length (nonce + at least 1 byte + auth tag)
    // Minimum: 12 (nonce) + 16 (auth tag) = 28 bytes
    if len(ciphertext) < NonceSize+16 {
        return "", ErrInvalidCiphertext
    }

    // Create AES cipher block
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", fmt.Errorf("failed to create AES cipher: %w", err)
    }

    // Create GCM wrapper
    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", fmt.Errorf("failed to create GCM cipher: %w", err)
    }

    // Extract nonce from the beginning of ciphertext
    nonce := ciphertext[:NonceSize]
    // Extract actual ciphertext (includes auth tag at the end)
    ciphertext = ciphertext[NonceSize:]

    // Decrypt and verify authentication tag
    // Open returns an error if the authentication tag doesn't match (tampering)
    plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        // Don't expose internal error details for security
        return "", ErrDecryptionFailed
    }

    return string(plaintext), nil
}

// GenerateEncryptionKey creates a cryptographically secure 256-bit key.
// This should be called once during initial setup and the key stored securely.
//
// Returns:
//   - []byte: 32-byte encryption key
//   - error: Any generation error
//
// Security: Store this key securely (environment variable, secrets manager)
// WARNING: Losing this key means encrypted data cannot be recovered
func GenerateEncryptionKey() ([]byte, error) {
    key := make([]byte, KeySize)
    if _, err := rand.Read(key); err != nil {
        return nil, fmt.Errorf("failed to generate encryption key: %w", err)
    }
    return key, nil
}

// ValidateEncryptionKey checks if a key is suitable for AES-256 encryption.
// This helps catch configuration errors early.
//
// Parameters:
//   - key: The encryption key to validate
//
// Returns:
//   - error: nil if valid, error describing the issue otherwise
func ValidateEncryptionKey(key []byte) error {
    if len(key) != KeySize {
        return fmt.Errorf("key must be exactly %d bytes, got %d bytes", KeySize, len(key))
    }

    // Check if key is all zeros (common mistake)
    allZeros := true
    for _, b := range key {
        if b != 0 {
            allZeros = false
            break
        }
    }
    if allZeros {
        return errors.New("encryption key cannot be all zeros")
    }

    return nil
}

// EncodeKey converts a binary key to base64 for configuration storage.
// Use this when storing keys in environment variables or config files.
//
// Parameters:
//   - key: Binary encryption key
//
// Returns:
//   - string: Base64-encoded key safe for text storage
func EncodeKey(key []byte) string {
    return base64.StdEncoding.EncodeToString(key)
}

// DecodeKey converts a base64-encoded key back to binary.
// Use this when loading keys from environment variables or config files.
//
// Parameters:
//   - encoded: Base64-encoded key string
//
// Returns:
//   - []byte: Binary encryption key
//   - error: Any decoding error
func DecodeKey(encoded string) ([]byte, error) {
    key, err := base64.StdEncoding.DecodeString(encoded)
    if err != nil {
        return nil, fmt.Errorf("failed to decode encryption key: %w", err)
    }
    if err := ValidateEncryptionKey(key); err != nil {
        return nil, err
    }
    return key, nil
}