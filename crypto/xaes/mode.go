package xaes

import (
	"crypto/aes"
	"crypto/cipher"
)

// 5种加密模式 （CBC、ECB、CTR、OCF、CFB）
// https://www.cnblogs.com/starwolf/p/3365834.html

func AesEncryptCBC(plaintext []byte, key, iv []byte) (ciphertext []byte) {
	// NewCipher该函数限制了输入k的长度必须为16, 24或者32
	block, _ := aes.NewCipher(key)
	blockMode := cipher.NewCBCEncrypter(block, iv) // 加密模式
	ciphertext = make([]byte, len(plaintext))      // 创建数组
	blockMode.CryptBlocks(ciphertext, plaintext)   // 加密
	return ciphertext
}
func AesDecryptCBC(ciphertext []byte, key, iv []byte) (plaintext []byte) {
	block, _ := aes.NewCipher(key)                 // 分组秘钥
	blockMode := cipher.NewCBCDecrypter(block, iv) // 加密模式
	plaintext = make([]byte, len(ciphertext))      // 创建数组
	blockMode.CryptBlocks(plaintext, ciphertext)   // 解密
	return plaintext
}
