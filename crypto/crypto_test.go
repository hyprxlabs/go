package crypto_test

import (
	"testing"

	"github.com/hyprxlabs/go/crypto"
	"github.com/stretchr/testify/assert"
)

func TestAes256CBC(t *testing.T) {
	cipher := crypto.NewAes256CBC()

	plaintext := []byte("Hello, World!")
	key := []byte("0123456789abcdef0123456789abcdef")
	encrypted, err := cipher.Encrypt(key, plaintext)

	println(len(encrypted), len(plaintext))

	if err != nil {
		t.Fatalf("Failed to encrypt plaintext: %v", err)
	}

	decrypted, err := cipher.Decrypt(key, encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt plaintext: %v", err)
	}

	a := assert.New(t)
	a.Equal(plaintext, decrypted)
}
