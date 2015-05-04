package sed

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"io"
)

const (
	BASE32 = iota
	BASE64
	HEX
)

func createKey(key string) (thekey []byte) {
	// create 32 bytes
	thekey = make([]byte, 32)
	// copy key string to thekey
	copy(thekey, key)
	// returning thekey
	return
}

func createPlainText(plaintext string) (text []byte) {
	// count length of plaintext
	plaintextLength := len(plaintext)
	// count modulus of length of plaintext
	// against aes blocksize
	modulus := plaintextLength % aes.BlockSize

	// this length is should
	// for the next encrypt
	shouldLength := plaintextLength + (aes.BlockSize - modulus)
	// create empty bytes with shouldlength
	text = make([]byte, shouldLength)
	// copy text to plaintext
	copy(text, plaintext)
	return
}

func Encrypt(text string, k string, output int) string {
	// generate safe key from k
	key := createKey(k)
	// generate safe plaintext from text
	plaintext := createPlainText(text)

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext[:])

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	var ciphered string
	switch output {
	case BASE32:
		ciphered = base32.StdEncoding.EncodeToString(ciphertext)
	case BASE64:
		ciphered = base64.StdEncoding.EncodeToString(ciphertext)
	case HEX:
		ciphered = hex.EncodeToString(ciphertext)
	default:
		ciphered = hex.EncodeToString(ciphertext)
	}

	return ciphered
}

func Decrypt(text string, k string, output int) string {
	// generate safe key from k
	key := createKey(k)
	var ciphertext []byte
	switch output {
	case BASE32:
		ciphertext, _ = base32.StdEncoding.DecodeString(text)
	case BASE64:
		ciphertext, _ = base64.StdEncoding.DecodeString(text)
	case HEX:
		ciphertext, _ = hex.DecodeString(text)
	default:
		ciphertext, _ = hex.DecodeString(text)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	// delete null characters
	ciphertext = bytes.Trim(ciphertext, "\x00")

	return string(ciphertext)
}
