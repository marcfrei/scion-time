package timebase

import (
	"time"
)

type LocalClock interface {
	Epoch() uint64
	Now() time.Time
	MaxDrift(duration time.Duration) time.Duration
	Step(offset time.Duration)
	Adjust(offset, duration time.Duration, frequency float64)
	AdjustWithTick(frequency float64)
	Sleep(duration time.Duration)
}
