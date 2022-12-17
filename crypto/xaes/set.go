package xaes

func SetIv(iv []byte) SetOption {
	return func(aes *XAES) {
		aes.iv = iv
	}
}

func SetPaddinger(p Padinger) SetOption {
	return func(x *XAES) {
		x.paddinger = p
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
func SetCiphertextBase64() SetOption {
	return func(x *XAES) {
		x.ciphertextCoder = &CiphertextBase64{}
	}
}

// 加密结果不编码
func SetCiphertextNil() SetOption {
	return func(x *XAES) {
		x.ciphertextCoder = nil
	}
}
