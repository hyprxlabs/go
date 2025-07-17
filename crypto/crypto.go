package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"

	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

const (
	SHA1     = "SHA1"
	SHA224   = "SHA224"
	SHA256   = "SHA256"
	SHA384   = "SHA384"
	SHA512   = "SHA512"
	SHA3_256 = "SHA3-256"
	SHA3_384 = "SHA3-384"
	SHA3_512 = "SHA3-512"

	hash_sha1     = 1
	hash_sha256   = 2
	hash_sha384   = 3
	hash_sha512   = 4
	hash_sha3_256 = 5
	hash_sha3_384 = 6
	hash_sha3_512 = 7
	hash_sha224   = 8
)

type Aes256CBC struct {
	Iterations  int32
	KeySize     int
	version     int16
	saltSize    int16
	hashAlgo    string
	tagSaltSize int16
	tagHashAlgo string
}

func NewAes256CBC() *Aes256CBC {
	return &Aes256CBC{
		Iterations:  60000,
		KeySize:     32,
		version:     1,
		saltSize:    8,
		tagSaltSize: 8,
		hashAlgo:    SHA256,
		tagHashAlgo: SHA256,
	}
}

func (a *Aes256CBC) SetHashAlgo(hashAlgo string) error {
	switch hashAlgo {
	case SHA224:
		a.hashAlgo = SHA224
	case SHA256:
		a.hashAlgo = SHA256
	case SHA384:
		a.hashAlgo = SHA384
	case SHA512:
		a.hashAlgo = SHA512
	case SHA3_256:
		a.hashAlgo = SHA3_256
	case SHA3_384:
		a.hashAlgo = SHA3_384
	case SHA3_512:
		a.hashAlgo = SHA3_512
	case SHA1:
		a.hashAlgo = SHA1
	default:
		return fmt.Errorf("invalid hash algo")
	}

	return nil
}

func (a *Aes256CBC) GetHashAlgo() string {
	return a.hashAlgo
}

func (a *Aes256CBC) GetHashAlgoId() int16 {
	switch a.hashAlgo {
	case SHA1:
		return hash_sha1
	case SHA224:
		return hash_sha224
	case SHA256:
		return hash_sha256
	case SHA384:
		return hash_sha384
	case SHA512:
		return hash_sha512
	default:
		return hash_sha256
	}
}

func (a *Aes256CBC) SetTagHashAlgo(tagHashAlgo string) error {
	switch tagHashAlgo {
	case SHA1:
		a.tagHashAlgo = SHA1
	case SHA224:
		a.tagHashAlgo = SHA224
	case SHA256:
		a.tagHashAlgo = SHA256
	case SHA384:
		a.tagHashAlgo = SHA384
	case SHA512:
		a.tagHashAlgo = SHA512
	case SHA3_256:
		a.tagHashAlgo = SHA3_256
	case SHA3_384:
		a.tagHashAlgo = SHA3_384
	case SHA3_512:
		a.tagHashAlgo = SHA3_512
	default:
		return fmt.Errorf("invalid tag hash algo")
	}

	return nil
}

func (a *Aes256CBC) GetTagHashAlgo() string {
	return a.tagHashAlgo
}

func (a *Aes256CBC) Encrypt(key []byte, data []byte) (encryptedData []byte, err error) {
	return a.EncryptWithMetadata(key, data, nil)
}

func (a *Aes256CBC) EncryptWithMetadata(key []byte, data []byte, metadata []byte) (encryptedData []byte, err error) {
	// 1.  version  (short)
	// 2.  salt size (short)
	// 3.  key size (short)
	// 4.  pdk2 hash algorithm (short)
	// 5.  tag hash type (short)
	// 6.  tag salt size (short)
	// 7.  meta data size (int)
	// 8. iterations (int)
	// 9. salt (byte[])
	// 10. iv (byte[])
	// 11. tag salt (byte[])
	// 12. meta data (byte[])
	// 13. tag (byte[])
	// 14. encrypted data (byte[])

	saltSize := a.saltSize
	hashAlgo := hashId(a.hashAlgo)
	tagSaltSize := a.tagSaltSize
	tagAlgo := hashId(a.tagHashAlgo)
	var keySize int16

	// 1. version
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, a.version)
	if err != nil {
		return nil, err
	}

	// 2. salt size
	err = binary.Write(buf, binary.LittleEndian, a.saltSize)
	if err != nil {
		return nil, err
	}

	// 3. key size
	err = binary.Write(buf, binary.LittleEndian, keySize)
	if err != nil {
		return nil, err
	}

	// 4. pbkdf2 algo type for symmetric key
	err = binary.Write(buf, binary.LittleEndian, hashAlgo)
	if err != nil {
		return nil, err
	}

	// 5. pbkdf2 algo type for hmac/tag key
	err = binary.Write(buf, binary.LittleEndian, tagAlgo)
	if err != nil {
		return nil, err
	}

	// 6. tag/hmac salt size
	err = binary.Write(buf, binary.LittleEndian, tagSaltSize)
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
	symetricSalt, err := RandBytes(int(saltSize))
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, symetricSalt)
	if err != nil {
		return nil, err
	}

	// 10. iv
	iv, err := RandBytes(16)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, iv)
	if err != nil {
		return nil, err
	}

	tagSalt, err := RandBytes(int(tagSaltSize))
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

	cdr := pbkdf2.Key(key, symetricSalt, int(a.Iterations), a.KeySize, newHash(a.hashAlgo))
	paddedData := pad(data)
	ciphertext := make([]byte, len(paddedData))
	c, _ := aes.NewCipher(cdr)
	ctr := cipher.NewCBCEncrypter(c, iv)
	ctr.CryptBlocks(ciphertext, paddedData)

	hdr := pbkdf2.Key(key, tagSalt, int(a.Iterations), a.KeySize, newHash(a.tagHashAlgo))
	h := a.NewHmac(hdr)
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

func (a *Aes256CBC) Decrypt(key []byte, encryptedData []byte) (data []byte, err error) {
	decryptedData, _, err := a.DecryptWithMetadata(key, encryptedData)
	return decryptedData, err
}

func (a *Aes256CBC) DecryptWithMetadata(key []byte, encryptedData []byte) (data []byte, metadata []byte, err error) {
	// 1.  version  (short) 2
	// 2.  salt size (short) 2
	// 3.  key size (short) 2
	// 4.  key pdk2 hash algorithm (short) 2
	// 5.  tag hash type (short) 2
	// 6.  tag salt size (short) 2
	// 7.  meta data size (int) 4
	// 8. iterations (int) 4
	// 9. salt (byte[])
	// 10. iv (byte[])
	// 11. tag salt (byte[])
	// 12. meta data (byte[])
	// 13. tag (byte[])
	// 14. encrypted data (byte[])

	keySize := a.KeySize

	// 1. version
	var version int16
	reader := bytes.NewReader(encryptedData)
	err = binary.Read(reader, binary.LittleEndian, &version)
	if err != nil {
		return nil, nil, err
	}

	if version != a.version {
		return nil, nil, fmt.Errorf("invalid version for Aes256CBC")
	}

	// 2. salt size (short)
	var symmetricSaltSize int16
	err = binary.Read(reader, binary.LittleEndian, &symmetricSaltSize)
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
	var hashAlgoShort int16
	err = binary.Read(reader, binary.LittleEndian, &hashAlgoShort)
	if err != nil {
		return nil, nil, err
	}

	// 5. tag hash algo (short)
	var tagHashAlgoShort int16
	err = binary.Read(reader, binary.LittleEndian, &tagHashAlgoShort)
	if err != nil {
		return nil, nil, err
	}

	// 6. tag salt size (short)
	var tagSaltSize int16
	err = binary.Read(reader, binary.LittleEndian, &tagSaltSize)
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

	sliceStart := 20

	// 9. salt
	symmetricSalt := encryptedData[sliceStart : sliceStart+int(symmetricSaltSize)]
	sliceStart += int(symmetricSaltSize)

	// 10. iv
	iv := encryptedData[sliceStart : sliceStart+16]
	sliceStart += 16

	// 11. tag salt
	tagSalt := encryptedData[sliceStart : sliceStart+int(tagSaltSize)]
	sliceStart += int(tagSaltSize)

	// 12. metadata
	if metadataSize > 0 {
		metadata = encryptedData[sliceStart : sliceStart+int(metadataSize)]
		sliceStart += int(metadataSize)
	}

	// 13. tag/hmac
	hash := encryptedData[sliceStart : sliceStart+hashSize(a.GetHashAlgo())]
	sliceStart += len(hash)

	// 14. encrypted data
	ciphertext := encryptedData[sliceStart:]

	hdr := pbkdf2.Key(key, tagSalt, int(iterations), keySize, newHash(a.tagHashAlgo))
	h := a.NewHmac(hdr)
	h.Write(ciphertext)
	expectedHash := h.Sum(nil)

	if !hmac.Equal(hash, expectedHash) {
		return nil, nil, fmt.Errorf("hash mismatch")
	}

	cdr := pbkdf2.Key(key, symmetricSalt, int(iterations), keySize, sha256.New)
	c, _ := aes.NewCipher(cdr)
	ctr := cipher.NewCBCDecrypter(c, iv)
	plaintext := make([]byte, len(ciphertext))
	ctr.CryptBlocks(plaintext, ciphertext)

	return unpad(plaintext), metadata, nil
}

func newHash(hashAlgo string) func() hash.Hash {
	switch hashAlgo {
	case SHA3_256:
		return sha3.New256
	case SHA256:
		return sha256.New
	case SHA384:
		return sha512.New384
	case SHA512:
		return sha512.New
	case SHA3_384:
		return sha3.New384
	case SHA3_512:
		return sha3.New512
	case SHA224:
		return sha256.New224
	case SHA1:
		return sha1.New
	default:
		return sha256.New
	}
}

func (a *Aes256CBC) NewHmac(key []byte) hash.Hash {
	switch a.hashAlgo {
	case SHA256:
		return hmac.New(sha256.New, key)
	case SHA384:
		return hmac.New(sha512.New384, key)
	case SHA512:
		return hmac.New(sha512.New, key)
	case SHA3_256:
		return hmac.New(sha3.New256, key)
	case SHA3_384:
		return hmac.New(sha3.New384, key)
	case SHA3_512:
		return hmac.New(sha3.New512, key)
	case SHA224:
		return hmac.New(sha256.New224, key)
	case SHA1:
		return hmac.New(sha1.New, key)
	default:
		return hmac.New(sha512.New384, key)
	}
}

func hashId(hash string) int16 {
	switch hash {
	case SHA256:
		return hash_sha256
	case SHA384:
		return hash_sha384
	case SHA512:
		return hash_sha512
	case SHA3_256:
		return hash_sha3_256
	case SHA3_384:
		return hash_sha3_384
	case SHA3_512:
		return hash_sha3_512
	case SHA224:
		return hash_sha224
	case SHA1:
		return hash_sha1
	default:
		return hash_sha256
	}
}

func hashSize(hashAlgo string) int {
	switch hashAlgo {
	case SHA1:
		return sha1.Size
	case SHA224:
		return sha256.Size224
	case SHA256:
		return sha256.Size
	case SHA384:
		return sha512.Size384
	case SHA512:
		return sha512.Size
	case SHA3_256:
		return sha3.New256().Size()
	case SHA3_384:
		return sha3.New384().Size()
	case SHA3_512:
		return sha3.New512().Size()
	default:
		return sha256.Size
	}
}
