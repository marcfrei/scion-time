//go:build !linux

package service

import (
	"context"
	"log/slog"
	"time"
)

func StartNTLCTSOff(log *slog.Logger, config string, sink func(off time.Duration)) {
	if config != "" {
		log.LogAttrs(context.Background(), slog.LevelInfo, "NTL CTS offset service not supported on this platform")
	}
}
