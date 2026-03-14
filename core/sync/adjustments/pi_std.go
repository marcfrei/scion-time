//go:build !linux

package adjustments

import (
	"context"
	"log/slog"
	"time"
)

type PIController struct {
	// Clock defaults to CLOCK_REALTIME when empty. On Linux, a device path such
	// as /dev/ptp0 selects a PTP hardware clock.
	Clock string

	// Ratio (gain factor) of the proportional control output value (applied to
	// the measured offset).
	KP float64

	// Ratio of the integral control output value. The integral value is applied
	// by reverting only a part of the previous adjustment. This ratio defines the
	// part of the previous adjustment that is to be kept. That means, that the
	// size of the integral control output depends on both of the configurable
	// ratios of the PI controller.
	KI float64

	// Offset threshold indicating that, if reached, a clock step is to be applied.
	StepThreshold time.Duration
}

var _ Adjustment = (*PIController)(nil)

func (a *PIController) Do(offset time.Duration) {
	ctx := context.Background()
	log := slog.Default()
	log.LogAttrs(ctx, slog.LevelDebug, "PIController.Do, not yet implemented",
		slog.Duration("offset", offset))
}
