package ntske

import (
	"encoding/hex"

	"go.uber.org/zap/zapcore"
)

type CookieArrayMarshaler struct {
	Cookies [][]byte
}

func (m CookieArrayMarshaler) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for _, c := range m.Cookies {
		enc.AppendString(hex.EncodeToString(c))
	}
	return nil
}
