package ntske

import (
	"encoding/hex"
	"strconv"

	"go.uber.org/zap/zapcore"
)

type CookieArrayMarshaler struct {
	Cookies [][]byte
}

func (m CookieArrayMarshaler) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	for i, c := range m.Cookies {
		enc.AddString(strconv.Itoa(i), hex.EncodeToString(c))
	}
	return nil
}
