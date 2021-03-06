package timebase

import (
	"time"
)

type LocalClock interface {
	Now() time.Time
	MaxDrift(duration time.Duration) time.Duration
	Step(offset time.Duration)
	Adjust(offset, duration time.Duration) // TODO: add argument 'frequency float64'
	Sleep(duration time.Duration)
}

var localClock LocalClock

func RegisterClock(c LocalClock) {
	if c == nil {
		panic("Local clock must not be nil")
	}
	if localClock != nil {
		panic("Local clock already registered")
	}
	localClock = c
}

func Now() time.Time {
	if localClock == nil {
		panic("No local clock registered")
	}
	return localClock.Now()
}
