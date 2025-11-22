package cryptor_test

import (
	"encoding/base64"
	"testing"

	cryptoPkg "github.com/kuetix/cryptor"
)

func TestAES_EncryptDecrypt_Roundtrip(t *testing.T) {
	c := cryptoPkg.NewCryptorAES("test-secret-key")

	msg := "attack at dawn"
	ct, err := c.EncryptAES(msg)
	if err != nil {
		t.Fatalf("encrypt aes: %v", err)
	}
	pt, err := c.DecryptAES(ct)
	if err != nil {
		t.Fatalf("decrypt aes: %v", err)
	}
	if pt != msg {
		t.Fatalf("aes roundtrip mismatch: got %q want %q", pt, msg)
	}
}

func TestAES_Base64_Helpers(t *testing.T) {
	c := cryptoPkg.NewCryptorAES("another-secret")

	msg := "lorem ipsum"
	b64, err := c.EncryptAESBase64(msg)
	if err != nil {
		t.Fatalf("encrypt aes b64: %v", err)
	}
	// sanity: should be valid base64
	if _, err := base64.StdEncoding.DecodeString(b64); err != nil {
		t.Fatalf("invalid base64 output: %v", err)
	}
	plain, err := c.DecryptAESBase64(b64)
	if err != nil {
		t.Fatalf("decrypt aes b64: %v", err)
	}
	if plain != msg {
		t.Fatalf("aes b64 roundtrip mismatch: got %q want %q", plain, msg)
	}
}
