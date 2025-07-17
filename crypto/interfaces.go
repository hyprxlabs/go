package crypto

type SymmetricCipher interface {
	Encrypt(key []byte, data []byte) (encryptedData []byte, err error)

	EncryptWithMetadata(key []byte, data []byte, metadata []byte) (encryptedData []byte, err error)

	Decrypt(key []byte, encryptedData []byte) (data []byte, err error)

	DecryptWithMetadata(key []byte, encryptedData []byte) (data []byte, metadata []byte, err error)
}
