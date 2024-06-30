package xaes

import (
	"bytes"
	"crypto/aes"
)

type Padinger interface {
	Pading([]byte) []byte
	UnPading([]byte) []byte
}

type PKCS7Pading struct{}

func (p *PKCS7Pading) Pading(plaintext []byte) []byte {
	blockSize := aes.BlockSize
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}
func (p *PKCS7Pading) UnPading(plaintext []byte) []byte {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	if length < unpadding {
		return plaintext[:0]
	}
	return plaintext[:(length - unpadding)]
}

type ZeroPading struct{}

func (p *ZeroPading) Pading(plaintext []byte) []byte {
	blockSize := aes.BlockSize
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(0)}, padding)
	return append(plaintext, padtext...)
}
func (p *ZeroPading) UnPading(plaintext []byte) []byte {
	return bytes.TrimRight(plaintext, string([]byte{0}))
}
