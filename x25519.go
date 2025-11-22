package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// LoadX25519PrivateKey loads an X25519 private key from a PEM file (PKCS#8 "PRIVATE KEY").
func (c *Cryptor) LoadX25519PrivateKey(filename string) (*ecdh.PrivateKey, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file: %v", err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing PKCS8 private key: %v", err)
	}
	priv, ok := k.(*ecdh.PrivateKey)
	if !ok {
		return nil, errors.New("not an X25519 private key")
	}
	// Ensure it is X25519 curve
	if priv.Curve() != ecdh.X25519() {
		return nil, errors.New("private key is not X25519 curve")
	}
	return priv, nil
}

// LoadX25519PublicKey loads an X25519 public key from a PEM file (PKIX "PUBLIC KEY").
func (c *Cryptor) LoadX25519PublicKey(filename string) (*ecdh.PublicKey, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %v", err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}
	pub, ok := pubAny.(*ecdh.PublicKey)
	if !ok {
		return nil, errors.New("not an X25519 public key")
	}
	if pub.Curve() != ecdh.X25519() {
		return nil, errors.New("public key is not X25519 curve")
	}
	return pub, nil
}

// SetX25519 loads and sets X25519 keys into the Cryptor.
func (c *Cryptor) SetX25519(publicKeyPath string, privateKeyPath string) error {
	priv, err := c.LoadX25519PrivateKey(privateKeyPath)
	if err != nil {
		return err
	}
	pub, err := c.LoadX25519PublicKey(publicKeyPath)
	if err != nil {
		return err
	}
	c.X25519Private = priv
	c.X25519Public = pub
	return nil
}

// X25519Encrypt encrypts a plaintext string using recipient's X25519 public key via ECDH + AES-256-GCM.
// Output format: ephPub(32 bytes) || nonce(12 bytes) || ciphertext+tag.
func (c *Cryptor) X25519Encrypt(message string) ([]byte, error) {
	if c.X25519Public == nil {
		return nil, errors.New("X25519 public key not set")
	}

	curve := ecdh.X25519()
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating ephemeral key: %v", err)
	}
	ephPub := ephPriv.PublicKey()
	shared, err := ephPriv.ECDH(c.X25519Public)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %v", err)
	}

	// Derive a 32-byte key using SHA-256 over the shared secret and recipient pub
	h := sha256.New()
	h.Write(shared)
	h.Write(c.X25519Public.Bytes())
	key := h.Sum(nil) // 32 bytes

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher init failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM init failed: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce gen failed: %v", err)
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(message), nil)

	ephPubBytes := ephPub.Bytes() // 32 bytes for X25519
	out := make([]byte, 0, len(ephPubBytes)+len(nonce)+len(ciphertext))
	out = append(out, ephPubBytes...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// X25519Decrypt decrypts data produced by X25519Encrypt using our X25519 private key.
func (c *Cryptor) X25519Decrypt(data []byte) (string, error) {
	if c.X25519Private == nil {
		return "", errors.New("X25519 private key not set")
	}
	curve := ecdh.X25519()
	pubSize := 32 // X25519 public keys are 32 bytes
	if len(data) < pubSize+12 {
		return "", errors.New("ciphertext too short")
	}
	ephPubBytes := data[:pubSize]
	nonce := data[pubSize : pubSize+12]
	ct := data[pubSize+12:]

	ephPub, err := curve.NewPublicKey(ephPubBytes)
	if err != nil {
		return "", fmt.Errorf("invalid ephemeral public key: %v", err)
	}
	shared, err := c.X25519Private.ECDH(ephPub)
	if err != nil {
		return "", fmt.Errorf("ECDH failed: %v", err)
	}
	h := sha256.New()
	h.Write(shared)
	h.Write(c.X25519Private.PublicKey().Bytes())
	key := h.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("AES cipher init failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM init failed: %v", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt failed: %v", err)
	}
	return string(plaintext), nil
}

// X25519EncryptBase64 helper returns base64 string.
func (c *Cryptor) X25519EncryptBase64(message string) (string, error) {
	b, err := c.X25519Encrypt(message)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// X25519DecryptBase64 helper accepts base64.
func (c *Cryptor) X25519DecryptBase64(b64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return c.X25519Decrypt(b)
}
