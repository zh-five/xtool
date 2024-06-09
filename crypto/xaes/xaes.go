package xaes

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

type SetOption func(*XAES)

var _salt = []byte{37, 112, 39, 97, 86, 35, 118, 22, 43, 78, 111, 123, 17, 48, 19, 29}

//加密模式

type XAES struct {
	iv              []byte          // 若无iv, 将自动随机生成iv,并把iv拼接在结果之前
	formatKey       bool            //是否格式化key的位数
	keySize         int             //key位数, 128,192,256
	ciphertextCoder CiphertextCoder //加密结果编码器
	paddinger       Padinger        //填充方法
}

func NewAES(options ...SetOption) *XAES {
	x := &XAES{
		iv:              []byte{},
		formatKey:       true,
		keySize:         256 / 8,
		ciphertextCoder: nil,
		paddinger:       new(PKCS7Pading),
	}

	x.option(options)

	if len(x.iv) > 0 {
		x.iv = x.toFormatKey(x.iv, aes.BlockSize)
	}

	return x
}

func (x *XAES) option(options []SetOption) {
	for _, set := range options {
		set(x)
	}
}

func (x *XAES) getIVForEncrypt() ([]byte, bool) {
	if len(x.iv) > 0 {
		return x.iv, false
	}

	bytes := make([]byte, aes.BlockSize)
	rand.Read(bytes)

	return bytes, true
}

func (x *XAES) getIVForDecrypt(ciphertext []byte) (iv []byte, cip []byte) {
	if len(x.iv) > 0 {
		return x.iv, ciphertext
	}
	size := len(ciphertext) - aes.BlockSize
	return ciphertext[size:], ciphertext[:size]
}

// 加密
func (x *XAES) Encrypt(key, plaintext []byte) ([]byte, error) {
	// 格式化key
	if x.formatKey {
		key = x.toFormatKey(key, x.keySize)
	}

	// 处理iv
	iv, autoIV := x.getIVForEncrypt()

	// 填充
	plaintext = x.paddinger.Pading(plaintext)

	// 加密
	ciphertext := AesEncryptCBC(plaintext, key, iv)

	// 附加iv
	if autoIV {
		ciphertext = append(ciphertext, iv...)
	}

	// 编码结果
	if x.ciphertextCoder != nil {
		ciphertext, _ = x.ciphertextCoder.Encode(ciphertext)
	}

	return ciphertext, nil
}

// 解密
func (x *XAES) Decrypt(key, ciphertext []byte) ([]byte, error) {
	// 格式化key
	if x.formatKey {
		key = x.toFormatKey(key, x.keySize)
	}

	// 解码加密结果
	if x.ciphertextCoder != nil {
		ciphertext, _ = x.ciphertextCoder.Decode(ciphertext)
	}

	// 处理iv
	iv, ciphertext := x.getIVForDecrypt(ciphertext)

	// 解密
	plaintext := AesDecryptCBC(ciphertext, key, iv)

	// 移除填充
	plaintext = x.paddinger.UnPading(plaintext)

	return plaintext, nil
}

func (x *XAES) toFormatKey(key []byte, size int) []byte {
	if len(key) == size {
		return key
	}

	return pbkdf2.Key(key, _salt, 15, size, sha256.New)
}
