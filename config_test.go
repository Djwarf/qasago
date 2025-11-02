package qasago

import (
	"testing"
)

// TestConfig tests the Config type and its methods
func TestConfig(t *testing.T) {
	// Generate a key
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create config
	config, err := NewConfig(key)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Test encryption and decryption
	plaintext := "Test message for Config"
	ciphertext, err := config.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Config encryption failed: %v", err)
	}

	// Verify ciphertext is not empty
	if ciphertext == "" {
		t.Error("Config encrypted to empty string")
	}

	// Decrypt
	decrypted, err := config.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Config decryption failed: %v", err)
	}

	// Verify decryption matches original
	if string(decrypted) != plaintext {
		t.Errorf("Config decryption mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// TestConfigInvalidKey tests Config with invalid key
func TestConfigInvalidKey(t *testing.T) {
	invalidKey := make([]byte, 16) // Too short

	_, err := NewConfig(invalidKey)
	if err == nil {
		t.Error("Expected error for invalid key size")
	}
}

// TestEncryptionKeyMethods tests EncryptionKey type methods
func TestEncryptionKeyMethods(t *testing.T) {
	key, _ := GenerateEncryptionKey()
	encKey := EncryptionKey(key)

	// Test Validate
	if err := encKey.Validate(); err != nil {
		t.Errorf("Valid key failed validation: %v", err)
	}

	// Test String
	encoded := encKey.String()
	if encoded == "" {
		t.Error("EncryptionKey.String() returned empty")
	}

	// Test Bytes
	bytes := encKey.Bytes()
	if len(bytes) != KeySize {
		t.Errorf("EncryptionKey.Bytes() wrong size: got %d, want %d", len(bytes), KeySize)
	}
}

// TestTypeSafety tests that types provide proper safety
func TestTypeSafety(t *testing.T) {
	key, _ := GenerateEncryptionKey()
	config, _ := NewConfig(key)

	// This demonstrates type safety - CipherText and PlainText are distinct types
	plaintext := "Secret"
	ciphertext, _ := config.Encrypt(plaintext)

	// Types are explicitly different
	_ = CipherText(ciphertext)
	_ = PlainText(plaintext)

	// Decrypt returns PlainText
	decrypted, _ := config.Decrypt(ciphertext)
	if decrypted.String() != plaintext {
		t.Error("Type safety test failed")
	}
}