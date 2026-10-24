//go:build !linux

package clocks

import (
	"context"
	"log/slog"
	"time"
)

type AdjustableClock struct {
	log *slog.Logger
}

func NewAdjustableClock(log *slog.Logger, dev string) *AdjustableClock {
	return &AdjustableClock{
		log: log,
	}
}

func (c *AdjustableClock) MaxFrequency() float64 {
	return 0
}

func (c *AdjustableClock) Frequency() float64 {
	return 0
}

func (c *AdjustableClock) SetFrequency(frequency float64) {
	c.log.LogAttrs(context.Background(), slog.LevelDebug,
		"AdjustableClock.SetFrequency, not yet implemented",
		slog.Float64("frequency", frequency),
	)
}

func (c *AdjustableClock) Step(offset time.Duration) {
	c.log.LogAttrs(context.Background(), slog.LevelDebug,
		"AdjustableClock.Step, not yet implemented",
		slog.Duration("offset", offset),
	)
}
