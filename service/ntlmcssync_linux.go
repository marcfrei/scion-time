//go:build linux

package service

// References:
// https://github.com/NetTimeLogic-Release/eth

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/base/unixutil"
	"example.com/scion-time/driver/ntl"
)

const (
	ntlMCSPFactor = 3.0 / 4.0
	ntlMCSIFactor = 3.0 / 16.0

	ntlMCSDefaultPollInterval = 1000 * time.Millisecond
	ntlMCSMinPollInterval     = time.Millisecond
	ntlMCSMaxPollInterval     = 2000 * time.Millisecond

	ntlMCSMaxDriftPPB int64 = 50_000_000

	ntlMCSModeAll      = 0x1
	ntlMCSModeInSync   = 0x2
	ntlMCSModeHoldover = 0x4
)

type ntlMCSAdjustment struct {
	offset time.Duration
	drift  int64
}

type ntlMCSCalculator struct {
	mode     uint32
	integral float64
	drift    int64
}

var errNoValidTimestamps = errors.New("no valid timestamp found")
var errTimestampDeltaSumOverflow = errors.New("timestamp delta sum overflow")

func newNTLMCSCalculator(initialDriftPPB int64) *ntlMCSCalculator {
	return &ntlMCSCalculator{
		mode:     ntlMCSModeAll,
		integral: float64(initialDriftPPB) / ntlMCSIFactor,
		drift:    initialDriftPPB,
	}
}

func (c *ntlMCSCalculator) Do(tss []ntl.CrossTimestamp, target int) (ntlMCSAdjustment, error) {
	if target < 0 || target >= len(tss) {
		panic("invalid target index")
	}
	if !tss[target].Valid() {
		return ntlMCSAdjustment{}, errors.New("target timestamp not valid")
	}

	targetTime := tss[target].Time
	var sum int64
	n := 0
	for i, ts := range tss {
		if i != target && ts.Valid() && (c.mode&ntlMCSModeAll == ntlMCSModeAll ||
			c.mode&ntlMCSModeInSync == ntlMCSModeInSync && ts.InSync() ||
			c.mode&ntlMCSModeHoldover == ntlMCSModeHoldover && ts.InHoldover()) {
			off := ts.Time.Sub(targetTime).Nanoseconds()
			if off > 0 && sum > math.MaxInt64-off ||
				off < 0 && sum < math.MinInt64-off {
				return ntlMCSAdjustment{}, errTimestampDeltaSumOverflow
			}
			sum += off
			n++
		}
	}
	if n == 0 {
		return ntlMCSAdjustment{}, errNoValidTimestamps
	}

	n64 := int64(n)
	off := sum / n64
	rem := sum % n64
	if rem > 0 {
		if 2*rem >= n64 {
			off++
		}
	} else if rem < 0 {
		if -2*rem >= n64 {
			off--
		}
	}

	adj := ntlMCSAdjustment{
		drift: c.drift,
	}

	if off > ntlMCSMaxDriftPPB || off < -ntlMCSMaxDriftPPB {
		adj.offset = time.Duration(off)
		return adj, nil
	}

	c.integral += float64(off)
	pi := ntlMCSPFactor*float64(off) + ntlMCSIFactor*c.integral
	if pi > float64(ntlMCSMaxDriftPPB) {
		pi = float64(ntlMCSMaxDriftPPB)
	} else if pi < -float64(ntlMCSMaxDriftPPB) {
		pi = -float64(ntlMCSMaxDriftPPB)
	}

	adj.drift = int64(math.Round(pi))
	c.drift = adj.drift

	return adj, nil
}

func ntlMCSSetOffset(clockID int32, offset time.Duration) error {
	tx := unix.Timex{
		Modes: unix.ADJ_SETOFFSET | unix.ADJ_NANO,
		Time:  unixutil.TimevalFromNsec(offset.Nanoseconds()),
	}
	_, err := unix.ClockAdjtime(clockID, &tx)
	return err
}

func ntlMCSSetDrift(clockID int32, driftPPB int64) error {
	tx := unix.Timex{
		Modes: unix.ADJ_FREQUENCY,
		Freq:  unixutil.ScaledPPMFromFreq(float64(driftPPB) * 1e-9),
	}
	_, err := unix.ClockAdjtime(clockID, &tx)
	return err
}

func ntlMCSConfig(log *slog.Logger, config string) (phcDev, ctsDev string, target int, initialDriftPPB int64, interval time.Duration) {
	t := strings.Split(config, ",")
	if len(t) < 3 || len(t) > 5 {
		logbase.Fatal(log, "unexpected NTL MCS sync config format",
			slog.String("config", config))
	}

	phcDev = t[0]
	ctsDev = t[1]
	if phcDev == "" || ctsDev == "" {
		logbase.Fatal(log, "unexpected NTL MCS sync config format",
			slog.String("config", config))
	}

	var err error
	target, err = strconv.Atoi(t[2])
	if err != nil {
		logbase.Fatal(log, "unexpected NTL MCS sync target index",
			slog.String("config", config), slog.Any("error", err))
	}

	initialDriftPPB = 0
	if len(t) > 3 {
		initialDriftPPB, err = strconv.ParseInt(t[3], 0, 64)
		if err != nil {
			logbase.Fatal(log, "unexpected NTL MCS sync initial drift",
				slog.String("config", config), slog.Any("error", err))
		}
		if initialDriftPPB < -ntlMCSMaxDriftPPB || initialDriftPPB > ntlMCSMaxDriftPPB {
			logbase.Fatal(log, "NTL MCS initial drift out of range",
				slog.String("config", config),
				slog.Int64("initialDriftPPB", initialDriftPPB),
				slog.Int64("maxDriftPPB", ntlMCSMaxDriftPPB))
		}
	}

	interval = ntlMCSDefaultPollInterval
	if len(t) > 4 {
		intervalMS, err := strconv.Atoi(t[4])
		if err != nil {
			logbase.Fatal(log, "unexpected NTL MCS sync poll interval",
				slog.String("config", config), slog.Any("error", err))
		}
		interval = time.Duration(intervalMS) * time.Millisecond
		if interval < ntlMCSMinPollInterval {
			interval = ntlMCSMinPollInterval
		} else if interval > ntlMCSMaxPollInterval {
			interval = ntlMCSMaxPollInterval
		}
	}

	return phcDev, ctsDev, target, initialDriftPPB, interval
}

func StartNTLMCSSync(log *slog.Logger, config string) {
	if config == "" {
		return
	}

	phcDev, ctsDev, target, initialDriftPPB, interval := ntlMCSConfig(log, config)

	fd, err := unix.Open(phcDev, unix.O_RDWR, 0)
	if err != nil {
		logbase.Fatal(log, "failed to open PHC device",
			slog.String("dev", phcDev), slog.Any("error", err))
	}

	cts, err := ntl.OpenCrossTimestamper(log, ctsDev)
	if err != nil {
		logbase.Fatal(log, "failed to open NTL cross timestamper",
			slog.String("dev", ctsDev), slog.Any("error", err))
	}

	n, err := cts.NumSources()
	if err != nil {
		logbase.Fatal(log, "failed to get NTL source count",
			slog.String("dev", ctsDev), slog.Any("error", err))
	}
	if n <= 0 {
		logbase.Fatal(log, "invalid NTL source count",
			slog.String("dev", ctsDev), slog.Int("count", n))
	}
	if n > 1<<8 {
		logbase.Fatal(log, "too many NTL sources",
			slog.String("dev", ctsDev), slog.Int("count", n))
	}
	if target < 0 || target >= n {
		logbase.Fatal(log, "NTL target index out of range",
			slog.String("dev", ctsDev),
			slog.Int("target", target),
			slog.Int("count", n))
	}

	clockID := (^int32(fd) << 3) | 3
	calc := newNTLMCSCalculator(initialDriftPPB)

	log.LogAttrs(context.Background(), slog.LevelInfo,
		"starting NTL MCS sync",
		slog.String("phc", phcDev),
		slog.String("cts", ctsDev),
		slog.Int("target", target),
		slog.Int64("initialDriftPPB", initialDriftPPB),
		slog.Duration("interval", interval),
	)

	go func() {
		tss := make([]ntl.CrossTimestamp, n)

		for {
			time.Sleep(interval)

			err := cts.Trigger()
			if err != nil {
				log.LogAttrs(context.Background(), slog.LevelError, "NTL MCS trigger failed",
					slog.String("dev", ctsDev), slog.Any("error", err))
				continue
			}

			tss = tss[:cap(tss)]
			ok := true
			for i := range tss {
				ts, err := cts.Timestamp(i)
				if err != nil {
					log.LogAttrs(context.Background(), slog.LevelError, "NTL MCS timestamp failed",
						slog.String("dev", ctsDev),
						slog.Int("index", i),
						slog.Any("error", err))
					ok = false
					break
				}
				tss[i] = ts
			}
			if !ok {
				continue
			}

			adj, err := calc.Do(tss, target)
			if err != nil {
				log.LogAttrs(context.Background(), slog.LevelError, "NTL MCS calculation failed",
					slog.String("phc", phcDev),
					slog.String("cts", ctsDev),
					slog.Any("error", err))
				continue
			}

			if err := ntlMCSSetOffset(clockID, adj.offset); err != nil {
				log.LogAttrs(context.Background(), slog.LevelError, "NTL MCS offset adjustment failed",
					slog.String("phc", phcDev),
					slog.Duration("offset", adj.offset),
					slog.Any("error", err))
			}

			if err := ntlMCSSetDrift(clockID, adj.drift); err != nil {
				log.LogAttrs(context.Background(), slog.LevelError, "NTL MCS drift adjustment failed",
					slog.String("phc", phcDev),
					slog.Int64("driftPPB", adj.drift),
					slog.Any("error", err))
				continue
			}

			log.LogAttrs(context.Background(), slog.LevelDebug, "NTL MCS sample",
				slog.String("phc", phcDev),
				slog.String("cts", ctsDev),
				slog.Int("sources", n),
				slog.Int("target", target),
				slog.Duration("offset", adj.offset),
				slog.Int64("driftPPB", adj.drift),
			)
		}
	}()
}
