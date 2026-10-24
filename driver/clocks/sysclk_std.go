//go:build !linux

package clocks

import (
	"context"
	"log/slog"
	"time"

	"example.com/scion-time/base/timebase"
)

type SystemClock struct {
	log *slog.Logger
}

var _ timebase.SystemClock = (*SystemClock)(nil)

func NewSystemClock(log *slog.Logger) *SystemClock {
	return &SystemClock{
		log: log,
	}
}

func (c *SystemClock) Epoch() uint64 {
	return epoch.Load()
}

func (c *SystemClock) Now() time.Time {
	return time.Now().UTC()
}

func (c *SystemClock) Sleep(duration time.Duration) {
	c.log.LogAttrs(context.Background(), slog.LevelDebug,
		"SystemClock.Sleep",
		slog.Duration("duration", duration),
	)
	time.Sleep(duration)
}
