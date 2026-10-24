//go:build linux

package service

import (
	"context"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/core/sync"
	"example.com/scion-time/driver/clocks"
	"example.com/scion-time/driver/phc"
)

const (
	phcSyncClockRealtime = "CLOCK_REALTIME"
)

func StartPHCSync(log *slog.Logger, config string) {
	if config == "" {
		return
	}

	t := strings.Split(config, ",")
	if len(t) != 5 {
		logbase.Fatal(log, "unexpected PHC sync config format",
			slog.String("config", config))
	}
	src, dst := t[0], t[1]
	if (src == phcSyncClockRealtime) == (dst == phcSyncClockRealtime) {
		logbase.Fatal(log, "unexpected PHC sync clocks",
			slog.String("config", config))
	}
	o, err := strconv.Atoi(t[2])
	if err != nil {
		logbase.Fatal(log, "unexpected PHC sync offset",
			slog.String("config", config), slog.Any("error", err))
	}
	i, err := strconv.Atoi(t[3])
	if err != nil {
		logbase.Fatal(log, "unexpected PHC sync poll exponent",
			slog.String("config", config), slog.Any("error", err))
	}
	s, err := strconv.Atoi(t[4])
	if err != nil {
		logbase.Fatal(log, "unexpected PHC sync step threshold",
			slog.String("config", config), slog.Any("error", err))
	}
	offset := time.Duration(o) * time.Second
	interval := time.Duration(math.Pow(2, float64(i)) * float64(time.Second))
	stepThreshold := time.Duration(s) * time.Nanosecond

	dstRealtime := dst == phcSyncClockRealtime
	var dev, clk string
	if dstRealtime {
		dev, clk = src, ""
	} else {
		dev, clk = dst, dst
	}

	refClk := phc.NewReferenceClock(log, dev, offset)

	adj := &sync.PIController{
		Clock:         clocks.NewAdjustableClock(log, clk),
		KP:            0.02,
		KI:            0.005,
		StepThreshold: stepThreshold,
	}

	go func() {
		for {
			ctx := context.Background()
			_, offset, err := refClk.MeasureClockOffset(ctx)
			if err != nil {
				log.LogAttrs(ctx, slog.LevelError, "PHC sync measurement failed",
					slog.String("dev", dev), slog.Any("error", err))
			} else {
				if !dstRealtime {
					offset = -offset
				}
				adj.Do(offset)
			}
			time.Sleep(interval)
		}
	}()
}
