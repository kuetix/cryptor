package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadPrivateKey Load RSA private key from a file
func (c *Cryptor) LoadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	privateKeyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file: %v", err)
	}

	block, _ := pem.Decode(privateKeyBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	var privateKey *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing PKCS1 private key: %v", err)
		}
	} else if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing PKCS8 private key: %v", err)
		}

		var ok bool
		if privateKey, ok = key.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
	}
	return privateKey, nil
}

// LoadPublicKey Load RSA public key from a file
func (c *Cryptor) LoadPublicKey(filename string) (*rsa.PublicKey, error) {
	publicKeyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %v", err)
	}

	block, _ := pem.Decode(publicKeyBytes)

	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}

	rsaPubKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPubKey, nil
}

// RSAEncrypt a message using an RSA public key
func (c *Cryptor) RSAEncrypt(publicKey *rsa.PublicKey, message string) ([]byte, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(message))
	if err != nil {
		return nil, fmt.Errorf("error encrypting message: %v", err)
	}

	return ciphertext, nil
}

// RSADecrypt a message using an RSA private key
func (c *Cryptor) RSADecrypt(privateKey *rsa.PrivateKey, ciphertext []byte) (string, error) {
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return "", fmt.Errorf("error decrypting message: %v", err)
	}

	return string(plaintext), nil
}

func (c *Cryptor) SetRSA(options ...string) (err error) {
	c.PublicKey, err = c.LoadPublicKey(options[0])
	c.PrivateKey, err = c.LoadPrivateKey(options[1])
	if err != nil {
		return err

	}

	return nil
}

func (c *Cryptor) Encrypt(message string) ([]byte, error) {
	encrypted, err := c.RSAEncrypt(c.PublicKey, message)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

func (c *Cryptor) Decrypt(ciphertext []byte) (string, error) {
	decrypted, err := c.RSADecrypt(c.PrivateKey, ciphertext)
	if err != nil {
		return "", err
	}

	return decrypted, nil
}

func (c *Cryptor) EncryptBase64(message string) (string, error) {
	encrypted, err := c.Encrypt(message)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (c *Cryptor) DecryptBase64(ciphertext string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	decrypted, err := c.RSADecrypt(c.PrivateKey, decoded)
	if err != nil {
		return "", err
	}

	return decrypted, nil
}
