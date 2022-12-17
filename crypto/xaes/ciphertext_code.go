package xaes

import "encoding/base64"

// 密文编码器
type CiphertextCoder interface {
	Encode([]byte) ([]byte, error)
	Decode([]byte) ([]byte, error)
}

type CiphertextBase64 struct{}

func (c *CiphertextBase64) Encode(b []byte) ([]byte, error) {
	out := base64.StdEncoding.EncodeToString(b)

	return []byte(out), nil
}
func (c *CiphertextBase64) Decode(b []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(b))
}
