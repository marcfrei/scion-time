//go:build !linux

package service

import (
	"context"
	"log/slog"
)

func StartNTLCTSOff(log *slog.Logger, config string) {
	if config != "" {
		log.LogAttrs(context.Background(), slog.LevelInfo, "NTL CTS offset service not supported on this platform")
	}
}
