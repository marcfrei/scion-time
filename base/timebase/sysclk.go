package timebase

import (
	"time"
)

type SystemClock interface {
	Epoch() uint64
	Now() time.Time
	Sleep(duration time.Duration)
}
