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

func SetCiphertextCoder(coder CiphertextCoder) SetOption {
	return func(x *XAES) {
		x.ciphertextCoder = coder
	}
}
