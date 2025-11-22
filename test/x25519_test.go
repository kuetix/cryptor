package crypto_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	cryptoPkg "github.com/kuetix/cryptor"
	"os"
	"path/filepath"
	"testing"
)

func writePEMX25519(path string, block *pem.Block, t *testing.T) string {
	t.Helper()
	f := filepath.Join(path, block.Type+".pem")
	if err := os.WriteFile(f, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	return f
}

func TestX25519_EncryptDecrypt_Roundtrip(t *testing.T) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("x25519 generate: %v", err)
	}
	pub := priv.PublicKey()

	// Try to marshal to PKCS#8 and PKIX for our loaders
	privDer, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Skipf("skipping: cannot marshal X25519 private key to PKCS#8 on this Go/toolchain: %v", err)
	}
	pubDer, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Skipf("skipping: cannot marshal X25519 public key to PKIX on this Go/toolchain: %v", err)
	}

	tmp := t.TempDir()
	privPath := writePEMX25519(tmp, &pem.Block{Type: "PRIVATE KEY", Bytes: privDer}, t)
	pubPath := writePEMX25519(tmp, &pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}, t)

	c := cryptoPkg.NewCryptorX25519(pubPath, privPath)

	msg := "elliptic secrets"
	ct, err := c.X25519Encrypt(msg)
	if err != nil {
		t.Fatalf("x25519 encrypt: %v", err)
	}
	pt, err := c.X25519Decrypt(ct)
	if err != nil {
		t.Fatalf("x25519 decrypt: %v", err)
	}
	if pt != msg {
		t.Fatalf("x25519 roundtrip mismatch: got %q want %q", pt, msg)
	}

	// Base64 helpers
	b64, err := c.X25519EncryptBase64(msg)
	if err != nil {
		t.Fatalf("x25519 encrypt b64: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(b64); err != nil {
		t.Fatalf("invalid base64 output: %v", err)
	}
	pt2, err := c.X25519DecryptBase64(b64)
	if err != nil {
		t.Fatalf("x25519 decrypt b64: %v", err)
	}
	if pt2 != msg {
		t.Fatalf("x25519 b64 roundtrip mismatch: got %q want %q", pt2, msg)
	}
}
