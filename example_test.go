package qasago_test

import (
    "fmt"
    "log"
    "os"

    "github.com/djwarf/qasago"
)

// Example demonstrates basic encryption and decryption
func Example() {
    // Generate a new encryption key
    key, err := qasago.GenerateEncryptionKey()
    if err != nil {
        log.Fatal(err)
    }

    // Encrypt some sensitive data
    plaintext := "my-secret-password"
    ciphertext, err := qasago.Encrypt(plaintext, key)
    if err != nil {
        log.Fatal(err)
    }

    // Decrypt the data
    decrypted, err := qasago.Decrypt(ciphertext, key)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Original: %s\nDecrypted: %s\n", plaintext, decrypted)
    // Output:
    // Original: my-secret-password
    // Decrypted: my-secret-password
}

// ExampleGenerateEncryptionKey demonstrates key generation
func ExampleGenerateEncryptionKey() {
    key, err := qasago.GenerateEncryptionKey()
    if err != nil {
        log.Fatal(err)
    }

    // Key is 32 bytes for AES-256
    fmt.Printf("Key length: %d bytes\n", len(key))
    // Output:
    // Key length: 32 bytes
}

// ExampleEncrypt demonstrates encrypting data
func ExampleEncrypt() {
    // In production, generate or retrieve your key securely
    key := make([]byte, 32)
    // ... populate key from secure storage ...

    plaintext := "sensitive information"
    ciphertext, err := qasago.Encrypt(plaintext, key)
    if err != nil {
        log.Fatal(err)
    }

    // The ciphertext is base64 encoded and safe to store as text
    fmt.Printf("Ciphertext is base64 encoded: %t\n", len(ciphertext) > 0)
    // Output:
    // Ciphertext is base64 encoded: true
}

// ExampleDecrypt demonstrates decrypting data
func ExampleDecrypt() {
    // In production, retrieve your key securely
    key := make([]byte, 32)

    // Example ciphertext (in practice, this would be retrieved from storage)
    // This is just for demonstration - it won't actually decrypt
    ciphertext := "base64-encoded-ciphertext-here"

    _, err := qasago.Decrypt(ciphertext, key)
    if err != nil {
        // Handle decryption error
        fmt.Println("Decryption failed: invalid ciphertext or wrong key")
    }
    // Output:
    // Decryption failed: invalid ciphertext or wrong key
}

// ExampleConfig demonstrates using the Config type
func ExampleConfig() {
    // Generate a new key
    key, err := qasago.GenerateEncryptionKey()
    if err != nil {
        log.Fatal(err)
    }

    // Create a config instance
    config := qasago.Config{
        Key: key,
    }

    // Use the config for encryption
    plaintext := "database-connection-string"
    ciphertext, err := config.Encrypt(plaintext)
    if err != nil {
        log.Fatal(err)
    }

    // Use the same config for decryption
    decrypted, err := config.Decrypt(ciphertext)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Successfully encrypted and decrypted: %s\n", decrypted)
    // Output:
    // Successfully encrypted and decrypted: database-connection-string
}

// ExampleEncodeKey demonstrates encoding a key for storage
func ExampleEncodeKey() {
    key, err := qasago.GenerateEncryptionKey()
    if err != nil {
        log.Fatal(err)
    }

    // Encode for storage (e.g., in environment variable)
    encoded := qasago.EncodeKey(key)

    // The encoded key is base64
    fmt.Printf("Encoded key ready for storage: %t\n", len(encoded) > 0)
    // Output:
    // Encoded key ready for storage: true
}

// ExampleDecodeKey demonstrates decoding a stored key
func ExampleDecodeKey() {
    // In practice, this would come from an environment variable
    encodedKey := os.Getenv("ENCRYPTION_KEY")
    if encodedKey == "" {
        // For example purposes, use a dummy value
        // This is a valid 32-byte key encoded in base64
        key := make([]byte, 32)
        for i := range key {
            key[i] = byte(i)
        }
        encodedKey = qasago.EncodeKey(key)
    }

    key, err := qasago.DecodeKey(encodedKey)
    if err != nil {
        fmt.Printf("Failed to decode key: %v\n", err)
        return
    }

    fmt.Printf("Key decoded successfully, length: %d bytes\n", len(key))
    // Output:
    // Key decoded successfully, length: 32 bytes
}

// Example_keyRotation demonstrates how to rotate encryption keys
func Example_keyRotation() {
    // Generate old and new keys
    oldKey, _ := qasago.GenerateEncryptionKey()
    newKey, _ := qasago.GenerateEncryptionKey()

    // Encrypt with old key
    plaintext := "sensitive data"
    ciphertext, _ := qasago.Encrypt(plaintext, oldKey)

    // Rotate: decrypt with old key, re-encrypt with new key
    decrypted, _ := qasago.Decrypt(ciphertext, oldKey)
    newCiphertext, _ := qasago.Encrypt(decrypted, newKey)

    // Verify with new key
    verified, _ := qasago.Decrypt(newCiphertext, newKey)

    fmt.Printf("Data successfully rotated: %s\n", verified)
    // Output:
    // Data successfully rotated: sensitive data
}

// Example_errorHandling demonstrates proper error handling
func Example_errorHandling() {
    // Wrong key size
    wrongKey := make([]byte, 16) // Should be 32 bytes

    _, err := qasago.Encrypt("data", wrongKey)
    if err == qasago.ErrInvalidKeySize {
        fmt.Println("Error: Key must be 32 bytes for AES-256")
    }

    // Invalid ciphertext
    validKey := make([]byte, 32)
    _, err = qasago.Decrypt("not-valid-base64!", validKey)
    if err != nil {
        fmt.Println("Error: Invalid ciphertext format")
    }

    // Output:
    // Error: Key must be 32 bytes for AES-256
    // Error: Invalid ciphertext format
}