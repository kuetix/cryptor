package cryptor_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	cryptoPkg "github.com/kuetix/cryptor"
	"os"
	"path/filepath"
	"testing"
)

func writePEMEd25519(path string, block *pem.Block, t *testing.T) string {
	t.Helper()
	f := filepath.Join(path, block.Type+".pem")
	if err := os.WriteFile(f, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	return f
}

func TestEd25519_SignVerify(t *testing.T) {
	tmp := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 generate: %v", err)
	}

	privDer, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pubDer, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}

	privPath := writePEMEd25519(tmp, &pem.Block{Type: "PRIVATE KEY", Bytes: privDer}, t)
	pubPath := writePEMEd25519(tmp, &pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}, t)

	c := cryptoPkg.NewCryptorEd25519(pubPath, privPath)

	msg := "sign-this"
	sigB64, err := c.Ed25519SignBase64(msg)
	if err != nil {
		t.Fatalf("sign b64: %v", err)
	}
	ok, err := c.Ed25519VerifyBase64(msg, sigB64)
	if err != nil {
		t.Fatalf("verify b64: %v", err)
	}
	if !ok {
		t.Fatal("expected signature to verify")
	}
}
