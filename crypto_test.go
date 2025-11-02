package qasago

import (
    "bytes"
    "encoding/base64"
    "strings"
    "testing"
)

// TestEncryptDecrypt verifies basic encryption and decryption functionality
func TestEncryptDecrypt(t *testing.T) {
    key, err := GenerateEncryptionKey()
    if err != nil {
        t.Fatalf("Failed to generate key: %v", err)
    }

    testCases := []struct {
        name      string
        plaintext string
    }{
        {"Simple text", "Hello, World!"},
        {"Numbers", "1234567890"},
        {"Special characters", "!@#$%^&*()_+-={}[]|:\";<>?,./"},
        {"Unicode", "Hello 世界 🌍"},
        {"Long text", strings.Repeat("A", 1000)},
        {"Single character", "X"},
        {"Whitespace", "   spaces   and\ttabs\nand\nnewlines   "},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            encrypted, err := Encrypt(tc.plaintext, key)
            if err != nil {
                t.Fatalf("Encryption failed: %v", err)
            }

            // Verify encrypted data is base64
            _, err = base64.StdEncoding.DecodeString(encrypted)
            if err != nil {
                t.Errorf("Encrypted data is not valid base64: %v", err)
            }

            // Verify encrypted data is different from plaintext
            if encrypted == tc.plaintext {
                t.Error("Encrypted data matches plaintext")
            }

            decrypted, err := Decrypt(encrypted, key)
            if err != nil {
                t.Fatalf("Decryption failed: %v", err)
            }

            if decrypted != tc.plaintext {
                t.Errorf("Decrypted text doesn't match original. Got %q, want %q",
                    decrypted, tc.plaintext)
            }
        })
    }
}

// TestEncryptionUniqueness verifies that each encryption produces unique ciphertext
func TestEncryptionUniqueness(t *testing.T) {
    key, _ := GenerateEncryptionKey()
    plaintext := "Test message"

    encrypted1, err := Encrypt(plaintext, key)
    if err != nil {
        t.Fatalf("First encryption failed: %v", err)
    }

    encrypted2, err := Encrypt(plaintext, key)
    if err != nil {
        t.Fatalf("Second encryption failed: %v", err)
    }

    if encrypted1 == encrypted2 {
        t.Error("Two encryptions of the same plaintext produced identical ciphertext")
    }

    // Both should decrypt to the same plaintext
    decrypted1, _ := Decrypt(encrypted1, key)
    decrypted2, _ := Decrypt(encrypted2, key)

    if decrypted1 != plaintext || decrypted2 != plaintext {
        t.Error("Decryption of unique ciphertexts failed")
    }
}

// TestInvalidKeySize verifies key size validation
func TestInvalidKeySize(t *testing.T) {
    plaintext := "Test message"

    testCases := []struct {
        name    string
        keySize int
    }{
        {"Empty key", 0},
        {"Too short", 16},
        {"Too long", 64},
        {"Off by one", 31},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            key := make([]byte, tc.keySize)

            _, err := Encrypt(plaintext, key)
            if err != ErrInvalidKeySize {
                t.Errorf("Expected ErrInvalidKeySize, got %v", err)
            }

            _, err = Decrypt("dummy", key)
            if err != ErrInvalidKeySize {
                t.Errorf("Expected ErrInvalidKeySize for decrypt, got %v", err)
            }
        })
    }
}

// TestEmptyPlaintext verifies empty plaintext handling
func TestEmptyPlaintext(t *testing.T) {
    key, _ := GenerateEncryptionKey()

    _, err := Encrypt("", key)
    if err != ErrEmptyPlaintext {
        t.Errorf("Expected ErrEmptyPlaintext, got %v", err)
    }
}

// TestInvalidCiphertext verifies invalid ciphertext handling
func TestInvalidCiphertext(t *testing.T) {
    key, _ := GenerateEncryptionKey()

    testCases := []struct {
        name       string
        ciphertext string
        wantErr    error
    }{
        {"Empty ciphertext", "", ErrInvalidCiphertext},
        {"Invalid base64", "not-valid-base64!", nil},
        {"Too short", base64.StdEncoding.EncodeToString([]byte("short")), ErrInvalidCiphertext},
        {"Corrupted", "SGVsbG8gV29ybGQ=", ErrInvalidCiphertext},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            _, err := Decrypt(tc.ciphertext, key)
            if err == nil {
                t.Error("Expected error for invalid ciphertext")
            }

            // Check for specific error if specified
            if tc.wantErr != nil && err != tc.wantErr {
                t.Errorf("Expected error %v, got %v", tc.wantErr, err)
            }
        })
    }
}

// TestTamperedData verifies tampering detection
func TestTamperedData(t *testing.T) {
    key, _ := GenerateEncryptionKey()
    plaintext := "Secret message"

    encrypted, _ := Encrypt(plaintext, key)

    // Decode, tamper, and re-encode
    data, _ := base64.StdEncoding.DecodeString(encrypted)

    // Tamper with different parts of the ciphertext
    testCases := []struct {
        name   string
        tamper func([]byte) []byte
    }{
        {
            "Flip bit in nonce",
            func(d []byte) []byte {
                modified := make([]byte, len(d))
                copy(modified, d)
                modified[0] ^= 0x01
                return modified
            },
        },
        {
            "Flip bit in ciphertext",
            func(d []byte) []byte {
                modified := make([]byte, len(d))
                copy(modified, d)
                if len(modified) > NonceSize {
                    modified[NonceSize+1] ^= 0x01
                }
                return modified
            },
        },
        {
            "Flip bit in auth tag",
            func(d []byte) []byte {
                modified := make([]byte, len(d))
                copy(modified, d)
                modified[len(modified)-1] ^= 0x01
                return modified
            },
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            tampered := tc.tamper(data)
            tamperedEncoded := base64.StdEncoding.EncodeToString(tampered)

            _, err := Decrypt(tamperedEncoded, key)
            if err != ErrDecryptionFailed {
                t.Errorf("Expected ErrDecryptionFailed for tampered data, got %v", err)
            }
        })
    }
}

// TestWrongKey verifies decryption fails with wrong key
func TestWrongKey(t *testing.T) {
    key1, _ := GenerateEncryptionKey()
    key2, _ := GenerateEncryptionKey()

    plaintext := "Secret message"
    encrypted, _ := Encrypt(plaintext, key1)

    _, err := Decrypt(encrypted, key2)
    if err != ErrDecryptionFailed {
        t.Errorf("Expected ErrDecryptionFailed with wrong key, got %v", err)
    }
}

// TestGenerateEncryptionKey verifies key generation
func TestGenerateEncryptionKey(t *testing.T) {
    key1, err := GenerateEncryptionKey()
    if err != nil {
        t.Fatalf("Failed to generate key: %v", err)
    }

    if len(key1) != KeySize {
        t.Errorf("Generated key has wrong size: got %d, want %d", len(key1), KeySize)
    }

    key2, _ := GenerateEncryptionKey()
    if bytes.Equal(key1, key2) {
        t.Error("Generated keys are not unique")
    }

    // Verify key is not all zeros
    allZeros := true
    for _, b := range key1 {
        if b != 0 {
            allZeros = false
            break
        }
    }
    if allZeros {
        t.Error("Generated key is all zeros")
    }
}

// TestValidateEncryptionKey verifies key validation
func TestValidateEncryptionKey(t *testing.T) {
    testCases := []struct {
        name    string
        key     []byte
        wantErr bool
    }{
        {"Valid key", make([]byte, KeySize), false}, // Will be filled with random data
        {"Empty key", []byte{}, true},
        {"Too short", make([]byte, 16), true},
        {"Too long", make([]byte, 64), true},
        {"All zeros", make([]byte, KeySize), true},
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

// TestEncodeDecodeKey verifies key encoding/decoding
func TestEncodeDecodeKey(t *testing.T) {
    originalKey, _ := GenerateEncryptionKey()

    encoded := EncodeKey(originalKey)

    // Verify it's valid base64
    _, err := base64.StdEncoding.DecodeString(encoded)
    if err != nil {
        t.Errorf("Encoded key is not valid base64: %v", err)
    }

    decoded, err := DecodeKey(encoded)
    if err != nil {
        t.Fatalf("Failed to decode key: %v", err)
    }

    if !bytes.Equal(originalKey, decoded) {
        t.Error("Decoded key doesn't match original")
    }
}

// TestDecodeInvalidKey verifies invalid key decoding
func TestDecodeInvalidKey(t *testing.T) {
    testCases := []struct {
        name    string
        encoded string
    }{
        {"Invalid base64", "not-valid-base64!"},
        {"Wrong size", base64.StdEncoding.EncodeToString([]byte("too short"))},
        {"All zeros", base64.StdEncoding.EncodeToString(make([]byte, KeySize))},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            _, err := DecodeKey(tc.encoded)
            if err == nil {
                t.Error("Expected error for invalid encoded key")
            }
        })
    }
}

// TestConcurrentEncryption verifies thread safety
func TestConcurrentEncryption(t *testing.T) {
    key, _ := GenerateEncryptionKey()
    plaintext := "Concurrent test message"

    // Run multiple goroutines encrypting and decrypting
    done := make(chan bool, 10)

    for i := 0; i < 10; i++ {
        go func() {
            encrypted, err := Encrypt(plaintext, key)
            if err != nil {
                t.Errorf("Concurrent encryption failed: %v", err)
            }

            decrypted, err := Decrypt(encrypted, key)
            if err != nil {
                t.Errorf("Concurrent decryption failed: %v", err)
            }

            if decrypted != plaintext {
                t.Errorf("Concurrent operation produced incorrect result")
            }

            done <- true
        }()
    }

    // Wait for all goroutines
    for i := 0; i < 10; i++ {
        <-done
    }
}

// Benchmarks

func BenchmarkEncrypt(b *testing.B) {
    key, _ := GenerateEncryptionKey()
    plaintext := "Benchmark test message with some reasonable length content"

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := Encrypt(plaintext, key)
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkDecrypt(b *testing.B) {
    key, _ := GenerateEncryptionKey()
    plaintext := "Benchmark test message with some reasonable length content"
    encrypted, _ := Encrypt(plaintext, key)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := Decrypt(encrypted, key)
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkGenerateKey(b *testing.B) {
    for i := 0; i < b.N; i++ {
        _, err := GenerateEncryptionKey()
        if err != nil {
            b.Fatal(err)
        }
    }
}