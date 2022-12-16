package xaes

import (
	"reflect"
	"testing"
)

func TestXAES(t *testing.T) {
	x, _ := NewAES(
		SetAES128(),
	)
	type args struct {
		key       []byte
		plaintext []byte
		x         *XAES
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "test-1",
			args: args{
				key:       []byte("qwerfewgfewgwewee"),
				plaintext: []byte("abcdef测试文本"),
				x:         x,
			},
		},
		{
			name: "test-2",
			args: args{
				key:       []byte("qwerfewgfewgwewee"),
				plaintext: []byte("abcdefghijklmno"),
				x:         x,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cip := x.Encrypt(tt.args.key, tt.args.plaintext)
			got := x.Decrypt(tt.args.key, cip)
			//fmt.Printf("%v\n%v\n", cip, got)
			if !reflect.DeepEqual(got, tt.args.plaintext) {
				t.Errorf("XAES.Decrypt(Encrypt()) = %v, want %v", got, tt.args.plaintext)
			}
		})
	}
}
