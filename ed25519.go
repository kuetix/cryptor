package crypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadEd25519PrivateKey loads an Ed25519 private key from a PEM file (PKCS#8 "PRIVATE KEY").
func (c *Cryptor) LoadEd25519PrivateKey(filename string) (ed25519.PrivateKey, error) {
	keyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file: %v", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil || (block.Type != "PRIVATE KEY" && block.Type != "ED25519 PRIVATE KEY") {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	// Try PKCS#8 first
	if block.Type == "PRIVATE KEY" {
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing PKCS8 private key: %v", err)
		}
		priv, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("not an Ed25519 private key")
		}
		return priv, nil
	}

	// Some tools might still emit raw Ed25519 private keys (non-standard). Try parsing as PKCS#8 fallback only.
	return nil, errors.New("unsupported Ed25519 private key PEM type")
}

// LoadEd25519PublicKey loads an Ed25519 public key from a PEM file (PKIX "PUBLIC KEY").
func (c *Cryptor) LoadEd25519PublicKey(filename string) (ed25519.PublicKey, error) {
	keyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %v", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 public key")
	}
	return pub, nil
}

// SetEd25519 loads and sets Ed25519 keys into the Cryptor.
func (c *Cryptor) SetEd25519(publicKeyPath string, privateKeyPath string) error {
	priv, err := c.LoadEd25519PrivateKey(privateKeyPath)
	if err != nil {
		return err
	}
	pub, err := c.LoadEd25519PublicKey(publicKeyPath)
	if err != nil {
		return err
	}
	c.Ed25519Private = priv
	c.Ed25519Public = pub
	return nil
}

// Ed25519Sign signs a message using the loaded Ed25519 private key.
func (c *Cryptor) Ed25519Sign(message []byte) ([]byte, error) {
	if c.Ed25519Private == nil || len(c.Ed25519Private) == 0 {
		return nil, errors.New("Ed25519 private key not set")
	}
	return ed25519.Sign(c.Ed25519Private, message), nil
}

// Ed25519Verify verifies a signature using the loaded Ed25519 public key.
func (c *Cryptor) Ed25519Verify(message []byte, sig []byte) (bool, error) {
	if c.Ed25519Public == nil || len(c.Ed25519Public) == 0 {
		return false, errors.New("Ed25519 public key not set")
	}
	ok := ed25519.Verify(c.Ed25519Public, message, sig)
	return ok, nil
}

// Ed25519SignBase64 signs a string message and returns a base64-encoded signature.
func (c *Cryptor) Ed25519SignBase64(message string) (string, error) {
	sig, err := c.Ed25519Sign([]byte(message))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Ed25519VerifyBase64 verifies a base64 signature for the given message.
func (c *Cryptor) Ed25519VerifyBase64(message string, sigB64 string) (bool, error) {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, err
	}
	return c.Ed25519Verify([]byte(message), sig)
}
