package qasago

import (
    "bytes"
    "encoding/base64"
    "strings"
    "testing"
)

// TestEncryptDecrypt tests the basic encryption and decryption flow
func TestEncryptDecrypt(t *testing.T) {
    // Generate a valid encryption key
    key, err := GenerateEncryptionKey()
    if err != nil {
        t.Fatalf("Failed to generate key: %v", err)
    }

    testCases := []struct {
        name      string
        plaintext string
    }{
        {"Simple text", "Hello, World!"},
        {"Password", "SuperSecretPassword123!@#"},
        {"Unicode", "Hello 世界 🔐"},
        {"Long text", strings.Repeat("A", 1000)},
        {"Special chars", "!@#$%^&*()_+-=[]{}|;:'\",.<>?/\\"},
        {"Database connection string", "postgres://user:pass@localhost:5432/db?sslmode=require"},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // Encrypt the plaintext
            encrypted, err := Encrypt(tc.plaintext, key)
            if err != nil {
                t.Fatalf("Encryption failed: %v", err)
            }

            // Encrypted text should be different from plaintext
            if encrypted == tc.plaintext {
                t.Error("Encrypted text is same as plaintext")
            }

            // Encrypted text should be base64 (no spaces or special chars except +/=)
            for _, r := range encrypted {
                if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
                    (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=') {
                    t.Errorf("Invalid character in base64: %c", r)
                }
            }

            // Decrypt the ciphertext
            decrypted, err := Decrypt(encrypted, key)
            if err != nil {
                t.Fatalf("Decryption failed: %v", err)
            }

            // Verify the decrypted text matches original
            if decrypted != tc.plaintext {
                t.Errorf("Decrypted text doesn't match. Got %q, want %q", decrypted, tc.plaintext)
            }
        })
    }
}

// TestEncryptionUniqueness verifies that each encryption produces unique output
func TestEncryptionUniqueness(t *testing.T) {
    key, err := GenerateEncryptionKey()
    if err != nil {
        t.Fatalf("Failed to generate key: %v", err)
    }

    plaintext := "Same text encrypted multiple times"
    results := make(map[string]bool)

    // Encrypt the same text multiple times
    for i := 0; i < 10; i++ {
        encrypted, err := Encrypt(plaintext, key)
        if err != nil {
            t.Fatalf("Encryption failed on iteration %d: %v", i, err)
        }

        // Check if we've seen this ciphertext before
        if results[encrypted] {
            t.Error("Encryption produced duplicate ciphertext (nonce reuse)")
        }
        results[encrypted] = true
    }
}

// TestInvalidKey tests encryption/decryption with invalid keys
func TestInvalidKey(t *testing.T) {
    plaintext := "Test data"

    testCases := []struct {
        name string
        key  []byte
    }{
        {"Empty key", []byte{}},
        {"Too short", []byte("short")},
        {"Too long", make([]byte, 33)},
        {"16 bytes (AES-128)", make([]byte, 16)},
        {"24 bytes (AES-192)", make([]byte, 24)},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // Encryption should fail with invalid key
            _, err := Encrypt(plaintext, tc.key)
            if err != ErrInvalidKeySize {
                t.Errorf("Expected ErrInvalidKeySize, got %v", err)
            }

            // Decryption should also fail
            _, err = Decrypt("dummy", tc.key)
            if err != ErrInvalidKeySize {
                t.Errorf("Expected ErrInvalidKeySize, got %v", err)
            }
        })
    }
}

// TestEmptyPlaintext tests encryption of empty string
func TestEmptyPlaintext(t *testing.T) {
    key, _ := GenerateEncryptionKey()

    _, err := Encrypt("", key)
    if err != ErrEmptyPlaintext {
        t.Errorf("Expected ErrEmptyPlaintext, got %v", err)
    }
}

// TestInvalidCiphertext tests decryption of corrupted data
func TestInvalidCiphertext(t *testing.T) {
    key, _ := GenerateEncryptionKey()

    testCases := []struct {
        name       string
        ciphertext string
    }{
        {"Empty", ""},
        {"Invalid base64", "not-base64!@#"},
        {"Too short", "YQ=="}, // Just "a" in base64
        {"Random base64", "dGhpcyBpcyBub3QgZW5jcnlwdGVkIGRhdGE="}, // "this is not encrypted data"
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            _, err := Decrypt(tc.ciphertext, key)
            if err == nil {
                t.Error("Expected decryption to fail but it succeeded")
            }
        })
    }
}

// TestTamperedCiphertext tests detection of modified ciphertext
func TestTamperedCiphertext(t *testing.T) {
    key, _ := GenerateEncryptionKey()
    plaintext := "Sensitive data"

    // Encrypt the data
    encrypted, err := Encrypt(plaintext, key)
    if err != nil {
        t.Fatalf("Encryption failed: %v", err)
    }

    // Decode the base64
    ciphertext, _ := base64.StdEncoding.DecodeString(encrypted)

    // Tamper with the last byte (auth tag area)
    ciphertext[len(ciphertext)-1] ^= 0xFF

    // Re-encode
    tampered := base64.StdEncoding.EncodeToString(ciphertext)

    // Decryption should fail due to auth tag mismatch
    _, err = Decrypt(tampered, key)
    if err != ErrDecryptionFailed {
        t.Errorf("Expected ErrDecryptionFailed for tampered data, got %v", err)
    }
}

// TestWrongKey tests decryption with wrong key
func TestWrongKey(t *testing.T) {
    key1, _ := GenerateEncryptionKey()
    key2, _ := GenerateEncryptionKey()

    plaintext := "Secret data"

    // Encrypt with key1
    encrypted, err := Encrypt(plaintext, key1)
    if err != nil {
        t.Fatalf("Encryption failed: %v", err)
    }

    // Try to decrypt with key2
    _, err = Decrypt(encrypted, key2)
    if err != ErrDecryptionFailed {
        t.Errorf("Expected ErrDecryptionFailed when using wrong key, got %v", err)
    }
}

// TestGenerateEncryptionKey tests key generation
func TestGenerateEncryptionKey(t *testing.T) {
    // Generate multiple keys
    keys := make([][]byte, 5)
    for i := range keys {
        key, err := GenerateEncryptionKey()
        if err != nil {
            t.Fatalf("Key generation failed: %v", err)
        }

        // Check key length
        if len(key) != KeySize {
            t.Errorf("Key length is %d, expected %d", len(key), KeySize)
        }

        // Check uniqueness
        for j := 0; j < i; j++ {
            if bytes.Equal(key, keys[j]) {
                t.Error("Generated duplicate key")
            }
        }

        keys[i] = key
    }
}

// TestValidateEncryptionKey tests key validation
func TestValidateEncryptionKey(t *testing.T) {
    testCases := []struct {
        name    string
        key     []byte
        wantErr bool
    }{
        {"Valid key", make([]byte, 32), false}, // Will be filled with random data
        {"Too short", make([]byte, 16), true},
        {"Too long", make([]byte, 64), true},
        {"All zeros", make([]byte, 32), true}, // Already zeros
        {"Nil key", nil, true},
    }

    // Fill the valid key with random data
    validKey, _ := GenerateEncryptionKey()
    testCases[0].key = validKey

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            err := ValidateEncryptionKey(tc.key)
            if (err != nil) != tc.wantErr {
                t.Errorf("ValidateEncryptionKey() error = %v, wantErr %v", err, tc.wantErr)
            }
        })
    }
}

// TestKeyEncodeDecode tests base64 encoding/decoding of keys
func TestKeyEncodeDecode(t *testing.T) {
    // Generate a key
    originalKey, err := GenerateEncryptionKey()
    if err != nil {
        t.Fatalf("Failed to generate key: %v", err)
    }

    // Encode the key
    encoded := EncodeKey(originalKey)

    // Check that it's valid base64
    if encoded == "" {
        t.Error("Encoded key is empty")
    }

    // Decode the key
    decodedKey, err := DecodeKey(encoded)
    if err != nil {
        t.Fatalf("Failed to decode key: %v", err)
    }

    // Verify keys match
    if !bytes.Equal(originalKey, decodedKey) {
        t.Error("Decoded key doesn't match original")
    }
}

// TestDecodeInvalidKey tests decoding of invalid base64 keys
func TestDecodeInvalidKey(t *testing.T) {
    testCases := []struct {
        name    string
        encoded string
    }{
        {"Invalid base64", "not-base64!@#"},
        {"Wrong length", base64.StdEncoding.EncodeToString([]byte("short"))},
        {"All zeros", base64.StdEncoding.EncodeToString(make([]byte, 32))},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            _, err := DecodeKey(tc.encoded)
            if err == nil {
                t.Error("Expected error decoding invalid key")
            }
        })
    }
}

// BenchmarkEncrypt measures encryption performance
func BenchmarkEncrypt(b *testing.B) {
    key, _ := GenerateEncryptionKey()
    plaintext := "postgres://user:password@localhost:5432/tenant_db?sslmode=require"

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := Encrypt(plaintext, key)
        if err != nil {
            b.Fatal(err)
        }
    }
}

// BenchmarkDecrypt measures decryption performance
func BenchmarkDecrypt(b *testing.B) {
    key, _ := GenerateEncryptionKey()
    plaintext := "postgres://user:password@localhost:5432/tenant_db?sslmode=require"
    encrypted, _ := Encrypt(plaintext, key)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := Decrypt(encrypted, key)
        if err != nil {
            b.Fatal(err)
        }
    }
}