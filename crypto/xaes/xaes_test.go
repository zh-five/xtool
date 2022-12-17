package xaes

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"
)

func TestXAES(t *testing.T) {
	x, _ := NewAES(
		SetAES128(),
		//SetCiphertextNil(),
	)
	type args struct {
		name      string
		key       []byte
		plaintext []byte
		x         *XAES
	}

	// 加密位数
	mSize := map[string]SetOption{
		"128": SetAES128(),
		"192": SetAES192(),
		"256": SetAES256(),
	}
	// 填充方式
	mPadding := map[string]SetOption{
		"PKCS7Pading": SetPaddinger(&PKCS7Pading{}),
		"ZeroPading":  SetPaddinger(&ZeroPading{}),
	}
	// 结果编码方式
	mResult := map[string]SetOption{
		"ciphertextBase64": SetCiphertextBase64(),
		"ciphertextNil":    SetCiphertextNil(),
	}
	// 是否随机生成iv
	mIV := map[string]SetOption{
		"iv16":  SetIv(randBytes(aes.BlockSize)),
		"ivNil": SetIv(nil),
	}
	tests := []args{}
	for size := range mSize {
		for pad := range mPadding {
			for code := range mResult {
				for iv := range mIV {
					for i := 0; i < 4; i++ {
						x, _ := NewAES(mSize[size], mPadding[pad], mResult[code], mIV[iv])

						tests = append(tests, args{
							name:      fmt.Sprintf("AES%s/%s/%s/%s-%d", size, pad, code, iv, i),
							key:       randBytes(int(randInt(6, 20))),
							plaintext: randBytes(int(randInt(6, 2659))),
							x:         x,
						})
					}
				}
			}
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cip, err := x.Encrypt(tt.key, tt.plaintext)
			if err != nil {
				t.Errorf("XAES.Encrypt() error = %v, wantErr nil", err)
				return
			}
			got, err := x.Decrypt(tt.key, cip)
			if err != nil {
				t.Errorf("XAES.Decrypt() error = %v, wantErr nil", err)
				return
			}
			//fmt.Printf("%s\n%s\n", cip, got)
			if !reflect.DeepEqual(got, tt.plaintext) {
				t.Errorf("XAES.Decrypt(Encrypt()) = %v, want %v", got, tt.plaintext)
			}
		})
	}
}

func randBytes(n int) []byte {
	bytes := make([]byte, n)
	rand.Read(bytes)
	return bytes
}

func randInt(min, max int64) int64 {
	p, _ := rand.Prime(rand.Reader, 32)
	return p.Int64()%(max-min) + min
}
