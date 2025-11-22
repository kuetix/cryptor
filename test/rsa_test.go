package crypto_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	cryptoPkg "github.com/kuetix/cryptor"
	"os"
	"path/filepath"
	"testing"
)

func writePEM(path string, block *pem.Block, t *testing.T) string {
	t.Helper()
	f := filepath.Join(path, block.Type+".pem")
	if err := os.WriteFile(f, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	return f
}

func TestRSA_EncryptDecrypt_Roundtrip(t *testing.T) {
	tmp := t.TempDir()

	// Generate RSA keypair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}

	// Marshal private (PKCS#8) and public (PKIX)
	privDer, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pubDer, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}

	privPath := writePEM(tmp, &pem.Block{Type: "PRIVATE KEY", Bytes: privDer}, t)
	pubPath := writePEM(tmp, &pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}, t)

	c := cryptoPkg.NewCryptorRSA(pubPath, privPath)

	msg := "hello world"
	ct, err := c.Encrypt(msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := c.Decrypt(ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if pt != msg {
		t.Fatalf("roundtrip mismatch: got %q want %q", pt, msg)
	}

	// Base64 helpers
	b64, err := c.EncryptBase64(msg)
	if err != nil {
		t.Fatalf("encrypt b64: %v", err)
	}
	pt2, err := c.DecryptBase64(b64)
	if err != nil {
		t.Fatalf("decrypt b64: %v", err)
	}
	if pt2 != msg {
		t.Fatalf("roundtrip b64 mismatch: got %q want %q", pt2, msg)
	}
}
