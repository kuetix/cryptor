package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rsa"
)

type Cryptor struct {
	Secret     string
	Key        []byte
	IV         []byte
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey

	// Ed25519 (sign/verify)
	Ed25519Public  ed25519.PublicKey
	Ed25519Private ed25519.PrivateKey

	// X25519 (encrypt/decrypt)
	X25519Public  *ecdh.PublicKey
	X25519Private *ecdh.PrivateKey
}

//goland:noinspection GoUnusedExportedFunction
func NewCryptor() *Cryptor {
	cryptor := &Cryptor{}

	return cryptor
}

//goland:noinspection GoUnusedExportedFunction
func NewCryptorRSA(publicKey string, privateKey string) *Cryptor {
	cryptor := &Cryptor{}
	err := cryptor.SetRSA(publicKey, privateKey)
	if err != nil {
		panic(err)
	}

	return cryptor
}

//goland:noinspection GoUnusedExportedFunction
func NewCryptorAES(key string) *Cryptor {
	cryptor := &Cryptor{}
	cryptor.SetSecret(key)

	return cryptor
}

//goland:noinspection GoUnusedExportedFunction
func NewCryptorEd25519(publicKey string, privateKey string) *Cryptor {
	cryptor := &Cryptor{}
	if err := cryptor.SetEd25519(publicKey, privateKey); err != nil {
		panic(err)
	}
	return cryptor
}

//goland:noinspection GoUnusedExportedFunction
func NewCryptorX25519(publicKey string, privateKey string) *Cryptor {
	cryptor := &Cryptor{}
	if err := cryptor.SetX25519(publicKey, privateKey); err != nil {
		panic(err)
	}
	return cryptor
}
