# crypto

## Overview

The crypto package provides cryptographic functions and algorithms for Go.

The main module contains interfaces for symmetric encryption.

## AesCBC

The `aescbc` package implements AES encryption in CBC mode. It supports both AES-128 and AES-256 encryption
and uses PBKDF2 for key derivation to generate the symmetric key from a password and the hmac key for integrity checks.

It provides methods for encrypting and decrypting data, ensuring that the data is securely handled with proper padding and integrity checks.

There are methods for just encrypting and decrypting data or including additional metadata with the encrypted data.

## Usage

To use `crypto`, import the module in your Go project:

```go
import "github.com/hyprxlabs/go/crypto/aescbc"

func main() {
    cipher := aescbc.New256() // or aescbc.New128() for AES-128

    key := []byte("your-secret-key") // For AES-256

    data := []byte("your-data-to-encrypt")
    encryptedData, err := cipher.Encrypt(key, data)
    if err != nil {
        panic(err)
    }

    decryptedData, err := cipher.Decrypt(key, encryptedData)
    if err != nil {
        panic(err)
    }

    fmt.Println("Decrypted data:", string(decryptedData))
    // Output: Decrypted data: your-data-to-encrypt
}

```
