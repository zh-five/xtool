package xaes

import "bytes"

// --- pkcs7 ------
func pkcs7Padding(b []byte) []byte {

	return b
}
func pkcs7UnPadding(b []byte) []byte {
	return b
}

// --- pkcs5 ------
func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
