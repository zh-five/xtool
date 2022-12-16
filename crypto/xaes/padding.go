package xaes

import (
	"bytes"
	"crypto/aes"
)

// --- pkcs7 ------
func pkcs7Padding(plaintext []byte) []byte {
	blockSize := aes.BlockSize
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}
func pkcs7UnPadding(plaintext []byte) []byte {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	return plaintext[:(length - unpadding)]
}

// --- zeropadding ---
func zeroPadding(plaintext []byte) []byte {
	blockSize := aes.BlockSize
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(0)}, padding)
	return append(plaintext, padtext...)
}

func zeroUnPadding(plaintext []byte) []byte {
	return bytes.TrimRight(plaintext, string([]byte{0}))
}
