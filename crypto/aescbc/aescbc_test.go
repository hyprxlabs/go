package aescbc_test

import (
	"testing"

	"github.com/hyprxlabs/go/crypto/aescbc"
	"github.com/hyprxlabs/go/crypto/hashes"
	"github.com/stretchr/testify/assert"
)

func Test256(t *testing.T) {
	cipher := aescbc.New256()

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

func TestBlake2b256(t *testing.T) {
	cipher := aescbc.New256()
	cipher.KdfHash = hashes.BLAKE2B_256
	cipher.HmacHash = hashes.BLAKE2B_256

	plaintext := []byte("Hello, World!")
	key := []byte("0123456789abcdef0123456789abcdef")
	encrypted, err := cipher.Encrypt(key, plaintext)

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
