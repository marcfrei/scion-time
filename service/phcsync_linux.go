//go:build linux

package service

import (
	"context"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/core/sync/adjustments"
	"example.com/scion-time/driver/phc"
)

func StartPHCSync(log *slog.Logger, config string) {
	if config == "" {
		return
	}

	t := strings.Split(config, ",")
	if len(t) != 1 && len(t) != 3 {
		logbase.Fatal(log, "unexpected PHC sync config format",
			slog.String("config", config))
	}
	dev := t[0]
	var o, i int
	if len(t) == 3 {
		var err error
		o, err = strconv.Atoi(t[1])
		if err != nil {
			logbase.Fatal(log, "unexpected PHC sync offset",
				slog.String("config", config), slog.Any("error", err))
		}
		i, err = strconv.Atoi(t[2])
		if err != nil {
			logbase.Fatal(log, "unexpected PHC sync poll exponent",
				slog.String("config", config), slog.Any("error", err))
		}
	}
	offset := time.Duration(o) * time.Second
	interval := time.Duration(math.Pow(2, float64(i)) * float64(time.Second))

	fd, err := unix.Open(dev, unix.O_RDWR, 0)
	if err != nil {
		logbase.Fatal(log, "failed to open PHC device",
			slog.String("dev", dev), slog.Any("error", err))
	}

	clockID := (^int32(fd) << 3) | 3

	refClk := phc.NewReferenceClock(log, dev, offset)

	adj := &adjustments.PIController{
		ClockID:       clockID,
		KP:            0.05,
		KI:            0.15,
		StepThreshold: 250 * time.Nanosecond,
	}

	go func() {
		for {
			ctx := context.Background()
			_, offset, err := refClk.MeasureClockOffset(ctx)
			if err != nil {
				log.LogAttrs(ctx, slog.LevelError, "PHC sync measurement failed",
					slog.String("dev", dev), slog.Any("error", err))
			} else {
				adj.Do(-offset)
			}
			time.Sleep(interval)
		}
	}()
}
