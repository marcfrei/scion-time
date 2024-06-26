//go:build !linux

package adjustments

import (
	"context"
	"log/slog"
	"time"
)

type PIController struct {
	KP            float64
	KI            float64
	StepThreshold time.Duration
}

var _ Adjustment = (*PIController)(nil)

func (a *PIController) Do(offset time.Duration) {
	ctx := context.Background()
	log := slog.Default()
	log.LogAttrs(ctx, slog.LevelDebug, "PIController.Do, not yet implemented",
		slog.Duration("offset", offset))
}
