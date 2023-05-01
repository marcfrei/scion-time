//go:build !linux

package clock

import (
	"math"
	"time"

	"go.uber.org/zap"

	"example.com/scion-time/base/timebase"
)

type SystemClock struct {
	Log *zap.Logger
}

var _ timebase.LocalClock = (*SystemClock)(nil)

func (c *SystemClock) Epoch() uint64 {
	return 0
}

func (c *SystemClock) Now() time.Time {
	return time.Now().UTC()
}

func (c *SystemClock) MaxDrift(duration time.Duration) time.Duration {
	return math.MaxInt64
}

func (c *SystemClock) Step(offset time.Duration) {
	c.Log.Debug("SystemClock.Step, not yet implemented", zap.Duration("offset", offset))
}

func (c *SystemClock) Adjust(offset, duration time.Duration, frequency float64) {
	c.Log.Debug("SystemClock.Adjust, not yet implemented",
		zap.Duration("offset", offset),
		zap.Duration("duration", duration),
		zap.Float64("frequency", frequency),
	)
}

func (c *SystemClock) AdjustWithTick(frequencyPPM float64) {
	c.Log.Debug("SystemClock.AdjustWithTick, not yet implemented",
		zap.Float64("frequency (ppm)", frequencyPPM),
	)
}

func (c *SystemClock) Sleep(duration time.Duration) {
	c.Log.Debug("SystemClock.Sleep", zap.Duration("duration", duration))
	time.Sleep(duration)
}
