package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// BlockSize is the AES block size in bytes.
	BlockSize = aes.BlockSize // 16

	// NonceSize is the AES-GCM nonce size in bytes.
	NonceSize = 12

	// TagSize is the AES-GCM authentication tag size appended to ciphertext.
	tagSize = 16
)

// PBKDF2 parameters.
const (
	pbkdf2Salt       = "minisocket-v1-kdf"
	pbkdf2Iterations = 100_000
	pbkdf2KeyLen     = 32 // AES-256
)

// SHA256Digest returns the SHA-256 hash of data as a 32-byte array.
func SHA256Digest(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// DeriveKey derives an AES-256 session key from a shared secret using PBKDF2.
// The salt is a fixed string, matching the original binary's behaviour.
func DeriveKey(sharedSecret []byte) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("deriveKey: empty shared secret")
	}
	return pbkdf2.Key(sharedSecret, []byte(pbkdf2Salt), pbkdf2Iterations, pbkdf2KeyLen, sha256.New), nil
}

// Encrypt encrypts plaintext with AES-256-GCM using a random 12-byte nonce.
// Returns nonce || ciphertext || tag.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("encrypt: new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("encrypt: new gcm: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("encrypt: rand iv: %w", err)
	}

	// Seal appends ciphertext to nonce: nonce || ciphertext || tag
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts ciphertext produced by Encrypt (nonce || ciphertext || tag).
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("decrypt: new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("decrypt: new gcm: %w", err)
	}

	if len(ciphertext) < NonceSize {
		return nil, fmt.Errorf("decrypt: ciphertext too short (%d bytes)", len(ciphertext))
	}

	nonce := ciphertext[:NonceSize]
	encrypted := ciphertext[NonceSize:]

	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: gcm open: %w", err)
	}
	return plaintext, nil
}

// secretChars is the alphabet for generated secrets: alphanumeric, 22 chars.
const secretChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const secretLen = 22

// GenRandomSecret generates a cryptographically random 22-character secret
// using the same alphabet and length as the original binary.
func GenRandomSecret() (string, error) {
	result := make([]byte, secretLen)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(secretChars))))
		if err != nil {
			return "", fmt.Errorf("gen random secret: %w", err)
		}
		result[i] = secretChars[n.Int64()]
	}
	return string(result), nil
}
