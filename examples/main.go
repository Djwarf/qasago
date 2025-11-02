package main

import (
    "fmt"
    "log"
    "os"

    "github.com/djwarf/qasago"
)

func main() {
    fmt.Println("QasaGo Encryption Examples")
    fmt.Println("==========================\n")

    // Example 1: Generate and use a new encryption key
    example1()

    // Example 2: Store and retrieve key from environment
    example2()

    // Example 3: Encrypt sensitive user data
    example3()

    // Example 4: Error handling demonstration
    example4()
}

// example1 demonstrates basic encryption and decryption
func example1() {
    fmt.Println("Example 1: Basic Encryption and Decryption")
    fmt.Println("-----------------------------------------")

    // Generate a new encryption key
    key, err := qasago.GenerateEncryptionKey()
    if err != nil {
        log.Fatal("Failed to generate key:", err)
    }

    // Data to encrypt
    sensitiveData := "My secret password: P@ssw0rd123!"

    // Encrypt the data
    encrypted, err := qasago.Encrypt(sensitiveData, key)
    if err != nil {
        log.Fatal("Encryption failed:", err)
    }

    fmt.Printf("Original data: %s\n", sensitiveData)
    fmt.Printf("Encrypted (base64): %s\n", encrypted)

    // Decrypt the data
    decrypted, err := qasago.Decrypt(encrypted, key)
    if err != nil {
        log.Fatal("Decryption failed:", err)
    }

    fmt.Printf("Decrypted data: %s\n", decrypted)
    fmt.Println()
}

// example2 demonstrates key storage in environment variables
func example2() {
    fmt.Println("Example 2: Environment Variable Key Storage")
    fmt.Println("-------------------------------------------")

    // Generate a key and encode it for storage
    key, _ := qasago.GenerateEncryptionKey()
    encodedKey := qasago.EncodeKey(key)

    // Simulate storing in environment
    os.Setenv("MY_APP_ENCRYPTION_KEY", encodedKey)
    fmt.Printf("Stored key in environment: MY_APP_ENCRYPTION_KEY\n")

    // Later, retrieve and decode the key
    storedKey := os.Getenv("MY_APP_ENCRYPTION_KEY")
    decodedKey, err := qasago.DecodeKey(storedKey)
    if err != nil {
        log.Fatal("Failed to decode key:", err)
    }

    // Use the decoded key
    testData := "Testing with retrieved key"
    encrypted, _ := qasago.Encrypt(testData, decodedKey)
    decrypted, _ := qasago.Decrypt(encrypted, decodedKey)

    fmt.Printf("Test encryption/decryption successful: %s\n", decrypted)
    fmt.Println()
}

// example3 demonstrates encrypting user data structure
func example3() {
    fmt.Println("Example 3: Encrypting User Data")
    fmt.Println("--------------------------------")

    // Generate encryption key
    key, _ := qasago.GenerateEncryptionKey()

    // User data structure
    type User struct {
        ID              int
        Username        string
        Email           string
        CreditCard      string // Sensitive - will be encrypted
        SocialSecurity  string // Sensitive - will be encrypted
    }

    // Create a user with sensitive data
    user := User{
        ID:              1001,
        Username:        "johndoe",
        Email:           "john@example.com",
        CreditCard:      "4532-1234-5678-9012",
        SocialSecurity:  "123-45-6789",
    }

    fmt.Printf("Original User Data:\n")
    fmt.Printf("  ID: %d\n", user.ID)
    fmt.Printf("  Username: %s\n", user.Username)
    fmt.Printf("  Email: %s\n", user.Email)
    fmt.Printf("  Credit Card: %s\n", user.CreditCard)
    fmt.Printf("  SSN: %s\n", user.SocialSecurity)

    // Encrypt sensitive fields
    encryptedCC, err := qasago.Encrypt(user.CreditCard, key)
    if err != nil {
        log.Fatal("Failed to encrypt credit card:", err)
    }

    encryptedSSN, err := qasago.Encrypt(user.SocialSecurity, key)
    if err != nil {
        log.Fatal("Failed to encrypt SSN:", err)
    }

    // Store encrypted data (simulate database storage)
    fmt.Printf("\nStored in Database:\n")
    fmt.Printf("  ID: %d\n", user.ID)
    fmt.Printf("  Username: %s\n", user.Username)
    fmt.Printf("  Email: %s\n", user.Email)
    fmt.Printf("  Credit Card (encrypted): %s...\n", encryptedCC[:20])
    fmt.Printf("  SSN (encrypted): %s...\n", encryptedSSN[:20])

    // Decrypt when retrieving from database
    decryptedCC, _ := qasago.Decrypt(encryptedCC, key)
    decryptedSSN, _ := qasago.Decrypt(encryptedSSN, key)

    fmt.Printf("\nDecrypted User Data:\n")
    fmt.Printf("  Credit Card: %s\n", decryptedCC)
    fmt.Printf("  SSN: %s\n", decryptedSSN)
    fmt.Println()
}

// example4 demonstrates error handling
func example4() {
    fmt.Println("Example 4: Error Handling")
    fmt.Println("-------------------------")

    // Try to use an invalid key size
    invalidKey := make([]byte, 16) // Should be 32 bytes
    _, err := qasago.Encrypt("test", invalidKey)
    if err != nil {
        fmt.Printf("Invalid key error (expected): %v\n", err)
    }

    // Try to encrypt empty data
    validKey, _ := qasago.GenerateEncryptionKey()
    _, err = qasago.Encrypt("", validKey)
    if err != nil {
        fmt.Printf("Empty plaintext error (expected): %v\n", err)
    }

    // Try to decrypt invalid base64
    _, err = qasago.Decrypt("not-valid-base64!", validKey)
    if err != nil {
        fmt.Printf("Invalid ciphertext error (expected): %v\n", err)
    }

    // Try to decrypt with wrong key
    rightKey, _ := qasago.GenerateEncryptionKey()
    wrongKey, _ := qasago.GenerateEncryptionKey()

    encrypted, _ := qasago.Encrypt("secret", rightKey)
    _, err = qasago.Decrypt(encrypted, wrongKey)
    if err != nil {
        fmt.Printf("Wrong key error (expected): %v\n", err)
    }

    // Validate key
    err = qasago.ValidateEncryptionKey(validKey)
    if err == nil {
        fmt.Printf("Key validation passed\n")
    }

    fmt.Println("\nAll error handling examples completed successfully!")
}