package ntske

import (
	"encoding/hex"

	"go.uber.org/zap"
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

func logNTSKEMetadata(log *zap.Logger, meta Data) {
	log.Debug("NTSKE Metadata",
		zap.String("c2s", hex.EncodeToString(meta.C2sKey)),
		zap.String("s2c", hex.EncodeToString(meta.S2cKey)),
		zap.String("server", meta.Server),
		zap.Uint16("port", meta.Port),
		zap.Uint16("algo", meta.Algo),
		zap.Array("cookies", CookieArrayMarshaler{Cookies: meta.Cookie}))
}
