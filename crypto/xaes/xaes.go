package xaes

import (
	"crypto/aes"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

type SetOption func(*XAES)

var _salt = []byte{37, 112, 39, 97, 86, 35, 118, 22, 43, 78, 111, 123, 17, 48, 19, 29}

//加密模式

type XAES struct {
	iv            []byte              // 若无iv, 将自动随机生成iv,并把iv拼接在结果之前
	formatKey     bool                //是否格式化key的位数
	keySize       int                 //key位数, 128,192,256
	resultEncoder func([]byte) []byte //加密结果编码器
	padding       func([]byte) []byte //填充方法
	unPadding     func([]byte) []byte //移除填充方法
	//model     func()              //加密模式 （CBC、ECB、CTR、OCF、CFB）
}

func NewAES(options ...SetOption) (*XAES, error) {
	x := &XAES{
		iv:            []byte{},
		formatKey:     true,
		keySize:       256 / 8,
		resultEncoder: nil,
	}
	x.padding = pkcs7Padding
	x.unPadding = pkcs7UnPadding

	x.option(options)

	return x, nil
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

	return pbkdf2.Key(_salt, _salt, 1, aes.BlockSize, sha256.New), true
}

func (x *XAES) getIVForDecrypt(ciphertext []byte) ([]byte, []byte) {
	if len(x.iv) > 0 {
		return x.iv, ciphertext
	}
	size := aes.BlockSize
	return ciphertext[:size], ciphertext[size:]
}

// 加密
func (x *XAES) Encrypt(key, plaintext []byte, options ...SetOption) []byte {
	x.option(options)

	// 格式化key
	if x.formatKey {
		key = x.toFormatKey(key)
	}

	// 处理iv
	iv, autoIV := x.getIVForEncrypt()

	// 填充
	plaintext = x.padding(plaintext)

	// 加密
	ciphertext := AesEncryptCBC(plaintext, key, iv)

	// 附加iv
	if autoIV {
		ciphertext = append(iv, ciphertext...)
	}

	// 编码结果
	if x.resultEncoder != nil {
		ciphertext = x.resultEncoder(ciphertext)
	}

	return ciphertext
}

// 解密
func (x *XAES) Decrypt(key, ciphertext []byte, options ...SetOption) []byte {
	x.option(options)

	// 格式化key
	if x.formatKey {
		key = x.toFormatKey(key)
	}

	// 处理iv
	iv, ciphertext := x.getIVForDecrypt(ciphertext)

	// 解密
	plaintext := AesDecryptCBC(ciphertext, key, iv)

	// 移除填充
	plaintext = x.unPadding(plaintext)

	return plaintext
}

func (x *XAES) toFormatKey(key []byte) []byte {
	if len(key) == x.keySize {
		return key
	}

	return pbkdf2.Key(key, _salt, 1, x.keySize, sha256.New)
}
