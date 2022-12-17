package xaes

import (
	"reflect"
	"testing"
)

func TestCiphertextBase64(t *testing.T) {

	tests := []struct {
		name string
		text []byte
	}{
		{
			name: "a",
			text: []byte("sfsdafsafsdfsd"),
		},
		{
			name: "b",
			text: []byte("sfsdafasdfsdfsafsdfsd"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CiphertextBase64{}
			cip, _ := c.Encode(tt.text)
			got, err := c.Decode(cip)
			if err != nil {
				t.Errorf("CiphertextBase64.Encode() error = %v, wantErr nil", err)
				return
			}
			if !reflect.DeepEqual(got, tt.text) {
				t.Errorf("CiphertextBase64.Encode() = %v, want %v", got, tt.text)
			}
		})
	}
}
