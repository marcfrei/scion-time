//go:build !linux

package service

import (
	"context"
	"log/slog"
)

func StartPHCSync(log *slog.Logger, spec string) {
	if spec != "" {
		log.LogAttrs(context.Background(), slog.LevelInfo, "PHC sync not supported on this platform")
	}
}
