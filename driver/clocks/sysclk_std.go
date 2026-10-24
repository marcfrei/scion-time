//go:build !linux

package clocks

import (
	"context"
	"log/slog"
	"math"
	"time"

	"example.com/scion-time/base/timebase"
)

type SystemClock struct {
	log *slog.Logger
}

var _ timebase.SystemClock = (*SystemClock)(nil)

func NewSystemClock(log *slog.Logger, drift time.Duration) *SystemClock {
	return &SystemClock{
		log: log,
	}
}

func (c *SystemClock) Epoch() uint64 {
	return 0
}

func (c *SystemClock) Now() time.Time {
	return time.Now().UTC()
}

func (c *SystemClock) Drift(duration time.Duration) time.Duration {
	return math.MaxInt64
}

func (c *SystemClock) Sleep(duration time.Duration) {
	c.log.LogAttrs(context.Background(), slog.LevelDebug,
		"SystemClock.Sleep",
		slog.Duration("duration", duration),
	)
	time.Sleep(duration)
}
