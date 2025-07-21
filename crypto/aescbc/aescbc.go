package aescbc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"encoding/binary"
	"fmt"

	"github.com/hyprxlabs/go/crypto"
	"github.com/hyprxlabs/go/crypto/hashes"
)

// AesCBC implements AES encryption in CBC mode with PKCS#7 padding.
// It supports key derivation using PBKDF2 to generate the actual symmetric key
// for aes and the HMAC key for integrity verification.
//
// An encrypt-then-mac approach is used, where the data is encrypted first,
// and then an HMAC is computed over the ciphertext to ensure integrity.
type AesCBC struct {
	Iterations  int32
	KeySize     int
	Version     int16
	KdfSaltSize int16
	KdfHash     hashes.HashType
	HmacHash    hashes.HashType
}

func New256() *AesCBC {
	return &AesCBC{
		Iterations:  60000,
		KeySize:     32,
		Version:     1,
		KdfSaltSize: 8,
		KdfHash:     hashes.SHA256,
		HmacHash:    hashes.SHA256,
	}
}

func New128() *AesCBC {
	return &AesCBC{
		Iterations:  60000,
		KeySize:     16,
		Version:     1,
		KdfSaltSize: 8,
		KdfHash:     hashes.SHA256,
		HmacHash:    hashes.SHA256,
	}
}

func (a *AesCBC) Encrypt(key []byte, data []byte) (encryptedData []byte, err error) {
	return a.EncryptWithMetadata(key, data, nil)
}

func (a *AesCBC) EncryptWithMetadata(key []byte, data []byte, metadata []byte) (encryptedData []byte, err error) {
	// 1.  version  (short)
	// 2.  salt size (short)
	// 3.  key size (short)
	// 4.  kdf hash algorithm (short)
	// 5.  hmac hash type (short)
	// 6.  meta data size (int)
	// 7.  iterations (int)
	// 8. salt (byte[])
	// 9. iv (byte[])
	// 10. tag salt (byte[])
	// 11. meta data (byte[])
	// 12. tag (byte[])
	// 13. encrypted data (byte[])

	if a.Version != 1 {
		return nil, fmt.Errorf("unsupported version: %d", a.Version)
	}

	saltSize := a.KdfSaltSize
	var keySize int16

	// 1. version
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, a.Version)
	if err != nil {
		return nil, err
	}

	// 2. salt size
	err = binary.Write(buf, binary.LittleEndian, a.KdfSaltSize)
	if err != nil {
		return nil, err
	}

	// 3. key size
	err = binary.Write(buf, binary.LittleEndian, keySize)
	if err != nil {
		return nil, err
	}

	// 4. pbkdf2 algo type for symmetric key
	err = binary.Write(buf, binary.LittleEndian, a.KdfHash.Id())
	if err != nil {
		return nil, err
	}

	// 5. pbkdf2 algo type for hmac/tag key
	err = binary.Write(buf, binary.LittleEndian, a.HmacHash.Id())
	if err != nil {
		return nil, err
	}

	// 7. metadata size
	metadataSize := int32(len(metadata))
	err = binary.Write(buf, binary.LittleEndian, metadataSize)
	if err != nil {
		return nil, err
	}

	// 8. iterations
	err = binary.Write(buf, binary.LittleEndian, a.Iterations)
	if err != nil {
		return nil, err
	}

	// 9. salt
	symetricSalt, err := crypto.RandBytes(int(saltSize))
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, symetricSalt)
	if err != nil {
		return nil, err
	}

	// 10. iv
	iv, err := crypto.RandBytes(16)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, iv)
	if err != nil {
		return nil, err
	}

	tagSalt, err := crypto.RandBytes(int(a.KdfSaltSize))
	if err != nil {
		return nil, err
	}

	// 11. tag salt
	err = binary.Write(buf, binary.LittleEndian, tagSalt)
	if err != nil {
		return nil, err
	}

	// 12. meta data
	if metadataSize > 0 {
		buf.Write(metadata)
	}

	cdr, err := pbkdf2.Key(a.KdfHash.HashNew(), string(key), symetricSalt, int(a.Iterations), a.KeySize)
	if err != nil {
		return nil, err
	}
	paddedData := pad(data)
	ciphertext := make([]byte, len(paddedData))
	c, _ := aes.NewCipher(cdr)
	ctr := cipher.NewCBCEncrypter(c, iv)
	ctr.CryptBlocks(ciphertext, paddedData)

	hdr, err := pbkdf2.Key(a.KdfHash.HashNew(), string(key), tagSalt, int(a.Iterations), a.KeySize)
	if err != nil {
		return nil, err
	}
	h := a.HmacHash.NewHmac(hdr)
	h.Write(ciphertext)
	hash := h.Sum(nil)

	bufLen := buf.Len()
	hashLen := len(hash)
	ciphertextLen := len(ciphertext)

	println("bufLen:", bufLen, "hashLen:", hashLen, "ciphertextLen:", ciphertextLen)
	result := make([]byte, bufLen+hashLen+ciphertextLen)
	// 1 - 12
	copy(result, buf.Bytes())

	// 13 - tag/hash
	copy(result[bufLen:], hash)

	// 14 - encrypted data
	copy(result[bufLen+hashLen:], ciphertext)

	return result, nil
}

func pad(in []byte) []byte {
	padding := 16 - (len(in) % 16)
	for i := 0; i < padding; i++ {
		in = append(in, byte(padding))
	}
	return in
}

func unpad(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}

	padding := in[len(in)-1]
	if int(padding) > len(in) || padding > aes.BlockSize {
		return nil
	} else if padding == 0 {
		return nil
	}

	for i := len(in) - 1; i > len(in)-int(padding)-1; i-- {
		if in[i] != padding {
			return nil
		}
	}
	return in[:len(in)-int(padding)]
}

func (a *AesCBC) Decrypt(key []byte, encryptedData []byte) (data []byte, err error) {
	decryptedData, _, err := a.DecryptWithMetadata(key, encryptedData)
	return decryptedData, err
}

func (a *AesCBC) DecryptWithMetadata(key []byte, encryptedData []byte) (data []byte, metadata []byte, err error) {
	// 1.  version  (short) 2
	// 2.  salt size (short) 2
	// 3.  key size (short) 2
	// 4.  key pdk2 hash algorithm (short) 2
	// 5.  hmac hash type (short) 2
	// 6.  meta data size (int) 4
	// 7. iterations (int) 4
	// 8. salt (byte[])
	// 9. iv (byte[])
	// 10. hmac salt (byte[])
	// 11. meta data (byte[])
	// 12. tag (byte[])
	// 13. encrypted data (byte[])

	keySize := a.KeySize

	// 1. version
	var version int16
	reader := bytes.NewReader(encryptedData)
	err = binary.Read(reader, binary.LittleEndian, &version)
	if err != nil {
		return nil, nil, err
	}

	if version != a.Version {
		return nil, nil, fmt.Errorf("invalid version %d for Aes256CBC", version)
	}

	// 2. salt size (short)
	var saltSize int16
	err = binary.Read(reader, binary.LittleEndian, &saltSize)
	if err != nil {
		return nil, nil, err
	}

	// 3. key size (short)
	var keySizeShort int16
	err = binary.Read(reader, binary.LittleEndian, &keySizeShort)
	if err != nil {
		return nil, nil, err
	}

	// 4. hash algo (short)
	var kdfHashId int16
	err = binary.Read(reader, binary.LittleEndian, &kdfHashId)
	if err != nil {
		return nil, nil, err
	}

	// 5. tag hash algo (short)
	var hmacHashId int16
	err = binary.Read(reader, binary.LittleEndian, &hmacHashId)
	if err != nil {
		return nil, nil, err
	}
	// 7. metadata size (int)
	var metadataSize int32
	err = binary.Read(reader, binary.LittleEndian, &metadataSize)
	if err != nil {
		return nil, nil, err
	}

	// 8. iterations (int)
	var iterations int32
	err = binary.Read(reader, binary.LittleEndian, &iterations)
	if err != nil {
		return nil, nil, err
	}

	sliceStart := 18

	// 9. salt
	symmetricSalt := encryptedData[sliceStart : sliceStart+int(saltSize)]
	sliceStart += int(saltSize)

	// 10. iv
	iv := encryptedData[sliceStart : sliceStart+16]
	sliceStart += 16

	// 11. hmac salt
	hmacSalt := encryptedData[sliceStart : sliceStart+int(saltSize)]
	sliceStart += int(saltSize)

	// 12. metadata
	if metadataSize > 0 {
		metadata = encryptedData[sliceStart : sliceStart+int(metadataSize)]
		sliceStart += int(metadataSize)
	}

	// 13. tag/hmac
	hash := encryptedData[sliceStart : sliceStart+a.HmacHash.Size()]
	sliceStart += len(hash)

	// 14. encrypted data
	ciphertext := encryptedData[sliceStart:]

	hdr, err := pbkdf2.Key(a.KdfHash.HashNew(), string(key), hmacSalt, int(iterations), keySize)
	if err != nil {
		return nil, nil, err
	}
	h := a.HmacHash.NewHmac(hdr)
	h.Write(ciphertext)
	expectedHash := h.Sum(nil)

	if !hmac.Equal(hash, expectedHash) {
		return nil, nil, fmt.Errorf("hash mismatch")
	}

	cdr, err := pbkdf2.Key(a.KdfHash.HashNew(), string(key), symmetricSalt, int(iterations), keySize)
	if err != nil {
		return nil, nil, err
	}
	c, _ := aes.NewCipher(cdr)
	ctr := cipher.NewCBCDecrypter(c, iv)
	plaintext := make([]byte, len(ciphertext))
	ctr.CryptBlocks(plaintext, ciphertext)

	return unpad(plaintext), metadata, nil
}
