package shm

import (
	"context"
	"errors"
	"log/slog"

	"time"
)

const ReferenceClockType = "ntpshm"

type ReferenceClock struct {
	log  *slog.Logger
	unit int
	shm  segment
}

var errNoSample = errors.New("SHM sample temporarily unavailable")

func NewReferenceClock(log *slog.Logger, unit int) *ReferenceClock {
	return &ReferenceClock{log: log, unit: unit}
}

func (c *ReferenceClock) MeasureClockOffset(ctx context.Context) (
	time.Time, time.Duration, error) {
	deadline, deadlineIsSet := ctx.Deadline()
	const maxNumRetries = 8
	numRetries := 0
	for {
		if !c.shm.initialized {
			err := initSegment(&c.shm, c.unit)
			if err != nil {
				if numRetries != maxNumRetries && deadlineIsSet && time.Now().UTC().Before(deadline) {
					time.Sleep(0)
					numRetries++
					continue
				}
				return time.Time{}, 0, err
			}
		}

		t := *c.shm.time

		// SHM client logic based on analogous code in chrony

		if (t.mode == 1 && t.count != c.shm.time.count) ||
			!(t.mode == 0 || t.mode == 1) || t.valid == 0 {
			c.log.LogAttrs(ctx, slog.LevelError,
				"SHM sample temporarily unavailable",
				slog.Int64("mode", int64(t.mode)),
				slog.Int64("count", int64(t.count)),
				slog.Int64("valid", int64(t.valid)),
			)
			if numRetries != maxNumRetries && deadlineIsSet && time.Now().UTC().Before(deadline) {
				time.Sleep(0)
				numRetries++
				continue
			}
			return time.Time{}, 0, errNoSample
		}

		c.shm.time.valid = 0

		receiveTimeSeconds := t.receiveTimeStampSec
		clockTimeSeconds := t.clockTimeStampSec

		var receiveTimeNanoseconds, clockTimeNanoseconds int64
		if t.clockTimeStampNSec/1000 == uint32(t.clockTimeStampUSec) &&
			t.receiveTimeStampNSec/1000 == uint32(t.receiveTimeStampUSec) {
			receiveTimeNanoseconds = int64(t.receiveTimeStampNSec)
			clockTimeNanoseconds = int64(t.clockTimeStampNSec)
		} else {
			receiveTimeNanoseconds = 1000 * int64(t.receiveTimeStampUSec)
			clockTimeNanoseconds = 1000 * int64(t.clockTimeStampUSec)
		}

		receiveTime := time.Unix(receiveTimeSeconds, receiveTimeNanoseconds).UTC()
		clockTime := time.Unix(clockTimeSeconds, clockTimeNanoseconds).UTC()
		offset := clockTime.Sub(receiveTime)

		c.log.LogAttrs(ctx, slog.LevelDebug,
			"SHM clock sample",
			slog.Time("receiveTime", receiveTime),
			slog.Time("clockTime", clockTime),
			slog.Duration("offset", offset),
		)

		return receiveTime, offset, nil
	}
}
