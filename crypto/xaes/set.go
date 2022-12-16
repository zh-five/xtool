package xaes

import "encoding/base64"

func SetIv(iv []byte) SetOption {
	return func(aes *XAES) {
		aes.iv = iv
	}
}

func SetPKCS7Padding() SetOption {
	return func(x *XAES) {
		x.padding = pkcs7Padding
		x.unPadding = pkcs7UnPadding
	}
}

// NoPadding 和 ZeroPadding
func SetZeroPadding() SetOption {
	return func(x *XAES) {
		x.padding = zeroPadding
		x.unPadding = zeroUnPadding
	}
}

func setAESSize(size int) SetOption {
	return func(x *XAES) {
		x.keySize = size
	}
}

func SetAES128() SetOption {
	return setAESSize(128 / 8)
}
func SetAES192() SetOption {
	return setAESSize(192 / 8)
}
func SetAES256() SetOption {
	return setAESSize(256 / 8)
}

// 加密结果使用base64编码
func SetResultBase64() SetOption {
	return func(x *XAES) {
		x.resultEncoder = func(b []byte) []byte {
			dst := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
			base64.StdEncoding.Encode(dst, b)
			return dst
		}
	}
}

// 加密结果不编码
func SetResultNil() SetOption {
	return func(x *XAES) {
		x.resultEncoder = nil
	}
}
