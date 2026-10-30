//go:build linux

package clocks

import (
	"log/slog"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/base/timebase"
	"example.com/scion-time/base/unixutil"
)

var maxFrequency = unixutil.FreqFromScaledPPM(32768000)

type AdjustableClock struct {
	log     *slog.Logger
	clockID int32
	epoch   *atomic.Uint64
}

func NewAdjustableClock(log *slog.Logger, dev string) *AdjustableClock {
	c := &AdjustableClock{
		log:     log,
		clockID: unix.CLOCK_REALTIME,
	}
	if dev != "" {
		fd, err := unix.Open(dev, unix.O_RDWR, 0)
		if err != nil {
			logbase.Fatal(log, "failed to open clock device",
				slog.String("dev", dev), slog.Any("error", err))
		}
		c.clockID = (^int32(fd) << 3) | 3
	}
	var err error
	c.epoch, err = timebase.ClockEpoch(c.clockID)
	if err != nil {
		logbase.Fatal(log, "failed to get clock epoch",
			slog.String("dev", dev), slog.Any("error", err))
	}
	return c
}

func (c *AdjustableClock) MaxFrequency() float64 {
	return maxFrequency
}

func (c *AdjustableClock) Frequency() float64 {
	tx := unix.Timex{}
	_, err := unix.ClockAdjtime(c.clockID, &tx)
	if err != nil {
		logbase.Fatal(c.log, "unix.ClockAdjtime failed", slog.Any("error", err))
	}
	return unixutil.FreqFromScaledPPM(tx.Freq)
}

func (c *AdjustableClock) SetFrequency(frequency float64) {
	tx := unix.Timex{
		Modes: unix.ADJ_FREQUENCY,
		Freq:  unixutil.ScaledPPMFromFreq(frequency),
	}
	_, err := unix.ClockAdjtime(c.clockID, &tx)
	if err != nil {
		logbase.Fatal(c.log, "unix.ClockAdjtime failed", slog.Any("error", err))
	}
}

func (c *AdjustableClock) Step(offset time.Duration) {
	tx := unix.Timex{
		Modes: unix.ADJ_SETOFFSET | unix.ADJ_NANO,
		Time:  unixutil.TimevalFromNsec(offset.Nanoseconds()),
	}
	_, err := unix.ClockAdjtime(c.clockID, &tx)
	if err != nil {
		logbase.Fatal(c.log, "unix.ClockAdjtime failed", slog.Any("error", err))
	}
	c.epoch.Add(1)
}
