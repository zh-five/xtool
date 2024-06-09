package main

import (
	"fmt"

	"github.com/zh-five/xtool/crypto/xaes"
)

func main() {
	text := "xaes 加密解密示例"
	key := "23rgfdewa" // 任意长度。若长度不等于AES算法的位数，会使用pbkdf2算法格式化对应长度

	xa := xaes.NewAES()
	/*
		   `xa := xaes.NewAES()` 等价于：
		   ```go
				xa := xaes.NewAES(
					SetAES256(),                  // AES位数。另外还有 SetAES192(), SetAES128()
					SetPaddinger(&PKCS7Pading{}), // 填充算法。另外还有 SetPaddinger(&ZeroPading{}) 或自定义
					SetCiphertextCoder(nil),      // 密文编码器。另外还有 SetCiphertextCoder(&CiphertextBase64{}) 或自定义

					// 设置iv，任意长度，长度不等于 aes.BlockSize 时，会格式化为 aes.BlockSize
					// 若不设置iv， 加密时会随机生成iv，并把iv附在密文之后；解密时从密文末尾截取iv
					// SetIv([]byte("adsfasda")),
				)
		   ````
	*/

	// 加密
	b, _ := xa.Encrypt([]byte(key), []byte(text))

	// 解密
	b2, _ := xa.Decrypt([]byte(key), b)
	text2 := string(b2)

	fmt.Printf("text : %s\ntext1: %s\n", text, text2)
}
