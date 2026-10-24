//go:build linux

package clocks

// Based on Ntimed by Poul-Henning Kamp, https://github.com/bsdphk/Ntimed

import (
	"context"
	"log/slog"
	"math"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/base/timebase"
	"example.com/scion-time/base/timemath"
)

type SystemClock struct {
	log   *slog.Logger
	drift float64
	mu    sync.Mutex
	epoch uint64
}

var _ timebase.SystemClock = (*SystemClock)(nil)

func NewSystemClock(log *slog.Logger, drift time.Duration) *SystemClock {
	return &SystemClock{
		log:   log,
		drift: drift.Seconds(),
	}
}

func now(log *slog.Logger) time.Time {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_REALTIME, &ts)
	if err != nil {
		logbase.Fatal(log, "unix.ClockGettime failed", slog.Any("error", err))
	}
	return time.Unix(ts.Unix()).UTC()
}

func sleep(log *slog.Logger, duration time.Duration) {
	fd, err := unix.TimerfdCreate(unix.CLOCK_REALTIME, unix.TFD_NONBLOCK)
	if err != nil {
		logbase.Fatal(log, "unix.TimerfdCreate failed", slog.Any("error", err))
	}
	ts, err := unix.TimeToTimespec(now(log).Add(duration))
	if err != nil {
		logbase.Fatal(log, "unix.TimeToTimespec failed", slog.Any("error", err))
	}
	err = unix.TimerfdSettime(fd, unix.TFD_TIMER_ABSTIME, &unix.ItimerSpec{Value: ts}, nil /* oldValue */)
	if err != nil {
		logbase.Fatal(log, "unix.TimerfdSettime failed", slog.Any("error", err))
	}
	if fd < math.MinInt32 || math.MaxInt32 < fd {
		logbase.Fatal(log, "unix.TimerfdCreate returned unexpected value")
	}
	pollFds := []unix.PollFd{
		{Fd: int32(fd), Events: unix.POLLIN},
	}
	for {
		_, err := unix.Poll(pollFds, -1 /* timeout */)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			logbase.Fatal(log, "unix.Poll failed", slog.Any("error", err))
		}
		break
	}
	_ = unix.Close(fd)
}

func (c *SystemClock) Epoch() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch
}

func (c *SystemClock) Now() time.Time {
	return now(c.log)
}

func (c *SystemClock) Drift(duration time.Duration) time.Duration {
	if c.drift == UnknownDrift {
		return math.MaxInt64
	}
	return timemath.Duration(duration.Seconds() * c.drift)
}

func (c *SystemClock) Sleep(duration time.Duration) {
	c.log.LogAttrs(context.Background(), slog.LevelDebug,
		"sleeping", slog.Duration("duration", duration))
	if duration < 0 {
		panic("invalid duration value")
	}
	sleep(c.log, duration)
}
