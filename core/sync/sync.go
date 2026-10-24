package sync

import (
	"context"
	"log/slog"
	"math"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"example.com/scion-time/base/metrics"
	"example.com/scion-time/base/timebase"
	"example.com/scion-time/base/timemath"

	"example.com/scion-time/core/client"
	"example.com/scion-time/core/measurements"
)

type Config struct {
	// Maximum drift of the synchronized clock per second, 0 if unknown.
	ClockDrift           time.Duration
	ReferenceClockImpact float64
	PeerClockImpact      float64
	PeerClockCutoff      time.Duration
	SyncTimeout          time.Duration
	SyncInterval         time.Duration
}

type localReferenceClock struct{}

func (c *localReferenceClock) MeasureClockOffset(context.Context) (
	time.Time, time.Duration, error) {
	return time.Time{}, 0, nil
}

func measureOffsetToRefClks(refClkClient client.ReferenceClockClient,
	refClks []client.ReferenceClock, refClkOffsets []measurements.Measurement,
	timeout time.Duration) (time.Time, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	refClkClient.MeasureClockOffsets(ctx, refClks, refClkOffsets)
	m := measurements.FaultTolerantMidpoint(refClkOffsets)
	return m.Timestamp, m.Offset
}

func Run(log *slog.Logger, cfg Config,
	clk timebase.SystemClock, adj *PIController,
	refClks, peerClks []client.ReferenceClock) {
	ctx := context.Background()
	if cfg.ReferenceClockImpact <= 1.0 {
		panic("invalid local reference clock impact factor")
	}
	if cfg.PeerClockImpact <= 1.0 {
		panic("invalid peer clock impact factor")
	}
	if cfg.PeerClockImpact-1.0 <= cfg.ReferenceClockImpact {
		panic("invalid peer clock impact factor")
	}
	if cfg.SyncInterval <= 0 {
		panic("invalid sync interval")
	}
	if cfg.SyncTimeout < 0 || cfg.SyncTimeout > cfg.SyncInterval/2 {
		panic("invalid sync timeout")
	}
	drift := time.Duration(math.MaxInt64)
	if cfg.ClockDrift != 0 {
		drift = timemath.Duration(cfg.SyncInterval.Seconds() * cfg.ClockDrift.Seconds())
	}
	refClkMaxCorr := cfg.ReferenceClockImpact * float64(drift)
	if refClkMaxCorr <= 0 {
		panic("invalid clock drift")
	}
	peerClkMaxCorr := cfg.PeerClockImpact * float64(drift)
	if peerClkMaxCorr <= 0 {
		panic("invalid clock drift")
	}
	if len(refClks) == 0 && len(peerClks) == 0 {
		// nothing to synchronize to, leave the clock alone
		return
	}
	var refClkClient client.ReferenceClockClient
	refClkOffsets := make([]measurements.Measurement, len(refClks))
	refClkOffCh := make(chan time.Duration)
	if len(peerClks) != 0 {
		peerClks = append(peerClks, &localReferenceClock{})
	}
	var peerClkClient client.ReferenceClockClient
	peerClkOffsets := make([]measurements.Measurement, len(peerClks))
	peerClkOffCh := make(chan time.Duration)
	corrGauge := promauto.NewGauge(prometheus.GaugeOpts{
		Name: metrics.SyncCorrN,
		Help: metrics.SyncCorrH,
	})
	corrGauge.Set(0)
	for {
		go func() {
			var refClkOff time.Duration
			if len(refClks) != 0 {
				_, refClkOff = measureOffsetToRefClks(
					refClkClient, refClks, refClkOffsets, cfg.SyncTimeout)
			}
			refClkOffCh <- refClkOff
		}()
		go func() {
			var peerClkOff time.Duration
			if len(peerClks) != 0 {
				_, peerClkOff = measureOffsetToRefClks(
					peerClkClient, peerClks, peerClkOffsets, cfg.SyncTimeout)
			}
			peerClkOffCh <- peerClkOff
		}()
		refClkOff, peerClkOff := <-refClkOffCh, <-peerClkOffCh
		refClkCorr, peerClkCorr := refClkOff, peerClkOff
		var refClkOk bool
		if float64(refClkCorr.Abs()) > refClkMaxCorr {
			refClkCorr = time.Duration(
				float64(timemath.Sgn(refClkCorr)) * refClkMaxCorr)
		}
		refClkOk = len(refClks) != 0
		var peerClkOk bool
		if peerClkCorr.Abs() > cfg.PeerClockCutoff {
			if float64(peerClkCorr.Abs()) > peerClkMaxCorr {
				peerClkCorr = time.Duration(
					float64(timemath.Sgn(peerClkCorr)) * peerClkMaxCorr)
			}
			peerClkOk = len(peerClks) != 0
		}
		var corr time.Duration
		switch {
		case refClkOk && !peerClkOk:
			corr = refClkCorr
		case !refClkOk && peerClkOk:
			corr = peerClkCorr
		case refClkOk && peerClkOk:
			corr = timemath.Midpoint(refClkCorr, peerClkCorr)
		}
		log.LogAttrs(ctx, slog.LevelInfo, "correcting clock",
			slog.Float64("corr", corr.Seconds()),
			slog.Bool("refClkOk", refClkOk),
			slog.Float64("refClkOff", refClkOff.Seconds()),
			slog.Float64("refClkCorr", refClkCorr.Seconds()),
			slog.Float64("refClkMaxCorr", float64(refClkMaxCorr)/1e9),
			slog.Bool("peerClkOk", peerClkOk),
			slog.Float64("peerClkOff", peerClkOff.Seconds()),
			slog.Float64("peerClkCorr", peerClkCorr.Seconds()),
			slog.Float64("peerClkMaxCorr", float64(peerClkMaxCorr)/1e9))
		adj.Do(corr)
		corrGauge.Set(float64(corr))
		clk.Sleep(cfg.SyncInterval)
	}
}
