package timebase

import (
	"time"
)

type SystemClock interface {
	Epoch() uint64
	Now() time.Time
	Drift(duration time.Duration) time.Duration
	Sleep(duration time.Duration)
}
