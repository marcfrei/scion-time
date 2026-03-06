//go:build !linux

package service

import (
	"context"
	"log/slog"
)

func StartNTLMCSSync(log *slog.Logger, config string) {
	if config != "" {
		log.LogAttrs(context.Background(), slog.LevelInfo, "NTL MCS sync not supported on this platform")
	}
}
