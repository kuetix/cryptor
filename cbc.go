package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

//goland:noinspection GoUnusedExportedFunction
func DecryptCBC(password string, ciphertext []byte) (plaintext []byte, err error) {
	iterations := 10000
	keyLen := 32

	// Derive the key and IV from the password
	keyIv := pbkdf2.Key([]byte(password), nil, iterations, keyLen+aes.BlockSize, sha256.New)
	key := keyIv[:keyLen]
	iv := keyIv[keyLen : keyLen+aes.BlockSize]

	// Create the AES block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Check the length of the ciphertext
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	// Decrypt the data
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext = make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove padding if necessary (PKCS7 padding)
	plaintext, err = pkcs7UnPad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func pkcs7UnPad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("data is empty")
	}
	if length%blockSize != 0 {
		return nil, fmt.Errorf("data is not a multiple of the block size")
	}
	padLen := int(data[length-1])
	if padLen > blockSize || padLen == 0 {
		return nil, fmt.Errorf("padding size is invalid")
	}
	if padLen > length {
		return nil, fmt.Errorf("padding size is larger than data length")
	}
	for i := 0; i < padLen; i++ {
		if data[length-1-i] != byte(padLen) {
			return nil, fmt.Errorf("padding byte is invalid")
		}
	}
	return data[:length-padLen], nil
}
