package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	// Generate encryption key
	key := generateKey("mySecretKey")

	// Example of how to use the encryption and decryption functions
	encryptedMessage := encryptMessage("Hello, World!", key)
	fmt.Println("Encrypted:", encryptedMessage)
	decryptedMessage := decryptMessage(encryptedMessage, key)
	fmt.Println("Decrypted:", decryptedMessage)

	// Start a chat session
	startChat(key)
}

func startChat(key []byte) {
	// Open standard input
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("SecureChat - Type 'exit' to quit")

	for {
		fmt.Print("You: ")
		message, _ := reader.ReadString('\n')

		// Remove newline character
		message = message[:len(message)-1]

		// Exit loop if user types 'exit'
		if message == "exit" {
			fmt.Println("Goodbye!")
			return
		}

		// Encrypt message
		encryptedMessage := encryptMessage(message, key)

		// Send encrypted message (you would send it over a network connection)
		// Here, we'll just print it out
		fmt.Println("Encrypted:", encryptedMessage)

		// Now, you would receive the encrypted message and decrypt it
		// For this example, we'll just use the same encrypted message as input
		decryptedMessage := decryptMessage(encryptedMessage, key)
		fmt.Println("Decrypted:", decryptedMessage)
	}
}

func generateKey(passphrase string) []byte {
	// Generate a 32-byte key using SHA-256 from the passphrase
	hasher := sha256.New()
	hasher.Write([]byte(passphrase))
	return hasher.Sum(nil)
}

func encryptMessage(message string, key []byte) string {
	// Convert key to 32 bytes
	key = key[:32]

	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	// Generate initialization vector
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal(err)
	}

	// Encrypt message
	ciphertext := make([]byte, aes.BlockSize+len(message))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(message))

	// Combine IV and ciphertext and encode as base64
	finalMessage := append(iv, ciphertext...)
	return base64.URLEncoding.EncodeToString(finalMessage)
}

func decryptMessage(encryptedMessage string, key []byte) string {
	// Convert key to 32 bytes
	key = key[:32]

	// Decode base64
	decodedMessage, err := base64.URLEncoding.DecodeString(encryptedMessage)
	if err != nil {
		log.Fatal(err)
	}

	// Extract IV
	iv := decodedMessage[:aes.BlockSize]

	// Extract ciphertext
	ciphertext := decodedMessage[aes.BlockSize:]

	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt message
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return string(plaintext)
}
