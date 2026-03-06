//go:build !linux

package service

import (
	"context"
	"log/slog"
)

func StartPHCSync(log *slog.Logger, config string) {
	if config != "" {
		log.LogAttrs(context.Background(), slog.LevelInfo, "PHC sync not supported on this platform")
	}
}
