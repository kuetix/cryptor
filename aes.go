package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"github.com/google/uuid"
	uuid2 "github.com/kuetix/uuid"
)

// DeriveKey generates a 32-byte AES-256 key from the ID
func (c *Cryptor) deriveKey(id string) []byte {
	h := hmac.New(sha256.New, []byte(id))
	return h.Sum(nil)[:32] // Use the first 32 bytes for the key
}

// DeriveIV generates a 16-byte IV from the ID
func (c *Cryptor) deriveIV(id string) []byte {
	h := hmac.New(sha256.New, []byte("iv"+id)) // Use a modified HMAC for the IV
	return h.Sum(nil)[:16]                     // Use the first 16 bytes for the IV
}

func (c *Cryptor) SetSecret(id string) *Cryptor {
	c.Secret = id
	c.Key = c.deriveKey(id)
	c.IV = c.deriveIV(id)
	return c
}

// EncryptAESBytes encrypts plaintext using AES-256 in CTR mode with a derived key and IV
func (c *Cryptor) EncryptAESBytes(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, c.IV) // Use AES in CTR mode (no padding needed)
	stream.XORKeyStream(ciphertext, ciphertext)

	// Return the base64 encoded ciphertext
	return ciphertext, nil
}

// EncryptAES encrypts plaintext using AES-256 in CTR mode with a derived key and IV
func (c *Cryptor) EncryptAES(plaintext string) ([]byte, error) {
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, c.IV) // Use AES in CTR mode (no padding needed)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, []byte(plaintext))

	// Return the base64 encoded ciphertext
	return ciphertext, nil
}

// DecryptAES decrypts the base64-encoded ciphertext using AES-256 in CTR mode with a derived key and IV
func (c *Cryptor) DecryptAES(ciphertext []byte) (string, error) {
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, c.IV) // Use AES in CTR mode
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return string(plaintext), nil
}

func (c *Cryptor) EncryptAESBase64(message string) (string, error) {
	encryptAES, err := c.EncryptAES(message)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptAES), nil
}

func (c *Cryptor) EncryptAESBase64UUID(message string) (string, error) {
	id := uuid.MustParse(message)
	encryptAES, err := c.EncryptAESBytes(id[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptAES), nil
}

func (c *Cryptor) DecryptAESBase64UUID(message string) (string, error) {
	decryptAES, err := c.DecryptAESBase64(message)
	if err != nil {
		return "", err
	}
	id, err := uuid.FromBytes([]byte(decryptAES))
	if err != nil {
		return "", err
	}

	idString := id.String()
	return uuid2.UId(idString), nil
}

func (c *Cryptor) DecryptAESBase64(ciphertext string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	decryptAES, err := c.DecryptAES(bytes)
	if err != nil {
		return "", err
	}
	return decryptAES, nil
}
