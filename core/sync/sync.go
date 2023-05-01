package sync

import (
	"context"
	"math"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"go.uber.org/zap"

	"example.com/scion-time/base/metrics"
	"example.com/scion-time/base/timebase"
	"example.com/scion-time/base/timemath"

	"example.com/scion-time/core/client"
)

const (
	refClkImpact   = 1.25
	refClkCutoff   = 0
	refClkTimeout  = 1 * time.Second
	refClkInterval = 2 * time.Second
	netClkImpact   = 2.5
	netClkCutoff   = time.Microsecond
	netClkTimeout  = 5 * time.Second
	netClkInterval = 60 * time.Second
)

type localReferenceClock struct{}

var (
	refClks       []client.ReferenceClock
	refClkOffsets []time.Duration
	refClkClient  client.ReferenceClockClient
	netClks       []client.ReferenceClock
	netClkOffsets []time.Duration
	netClkClient  client.ReferenceClockClient
)

func (c *localReferenceClock) MeasureClockOffset(context.Context, *zap.Logger) (
	time.Duration, error) {
	return 0, nil
}

func RegisterClocks(refClocks, netClocks []client.ReferenceClock) {
	if refClks != nil || netClks != nil {
		panic("reference clocks already registered")
	}

	refClks = refClocks
	refClkOffsets = make([]time.Duration, len(refClks))

	netClks = netClocks
	if len(netClks) != 0 {
		netClks = append(netClks, &localReferenceClock{})
	}
	netClkOffsets = make([]time.Duration, len(netClks))
}

func measureOffsetToRefClocks(log *zap.Logger, timeout time.Duration) time.Duration {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	refClkClient.MeasureClockOffsets(ctx, log, refClks, refClkOffsets)
	return timemath.Median(refClkOffsets)
}

func SyncToRefClocks(log *zap.Logger, lclk timebase.LocalClock) {
	corr := measureOffsetToRefClocks(log, refClkTimeout)
	if corr != 0 {
		lclk.Step(corr)
	}
}

func RunLocalClockSync(log *zap.Logger, lclk timebase.LocalClock, useTheilSen bool) {
	if refClkImpact <= 1.0 {
		panic("invalid reference clock impact factor")
	}
	if refClkInterval <= 0 {
		panic("invalid reference clock sync interval")
	}
	if refClkTimeout < 0 || refClkTimeout > refClkInterval/2 {
		panic("invalid reference clock sync timeout")
	}
	maxCorr := refClkImpact * float64(lclk.MaxDrift(refClkInterval))
	if maxCorr <= 0 {
		panic("invalid reference clock max correction")
	}
	corrGauge := promauto.NewGauge(prometheus.GaugeOpts{
		Name: metrics.SyncLocalCorrN,
		Help: metrics.SyncLocalCorrH,
	})
	theilSen := newTheilSen(log, lclk)
	pll := newPLL(log, lclk)
	for {
		corrGauge.Set(0)
		corr := measureOffsetToRefClocks(log, refClkTimeout)
		if timemath.Abs(corr) > refClkCutoff {
			if float64(timemath.Abs(corr)) > maxCorr {
				corr = time.Duration(float64(timemath.Sign(corr)) * maxCorr)
			}
			// lclk.Adjust(corr, refClkInterval, 0)
			if useTheilSen {
				theilSen.AddSample(corr)
				frequencyPPM := theilSen.GetFrequencyPPM()

				if math.Abs(frequencyPPM) > 0 {
					lclk.AdjustWithTick(frequencyPPM)
				}
			} else {
				pll.Do(corr, 1000.0 /* weight */)
			}
			corrGauge.Set(float64(corr))
		}
		lclk.Sleep(refClkInterval)
	}
}

func measureOffsetToNetClocks(log *zap.Logger, timeout time.Duration) time.Duration {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	netClkClient.MeasureClockOffsets(ctx, log, netClks, netClkOffsets)
	return timemath.FaultTolerantMidpoint(netClkOffsets)
}

func RunGlobalClockSync(log *zap.Logger, lclk timebase.LocalClock, useTheilSen bool) {
	if netClkImpact <= 1.0 {
		panic("invalid network clock impact factor")
	}
	if netClkImpact-1.0 <= refClkImpact {
		panic("invalid network clock impact factor")
	}
	if netClkInterval < refClkInterval {
		panic("invalid network clock sync interval")
	}
	if netClkTimeout < 0 || netClkTimeout > netClkInterval/2 {
		panic("invalid network clock sync timeout")
	}
	maxCorr := netClkImpact * float64(lclk.MaxDrift(netClkInterval))
	if maxCorr <= 0 {
		panic("invalid network clock max correction")
	}
	corrGauge := promauto.NewGauge(prometheus.GaugeOpts{
		Name: metrics.SyncGlobalCorrN,
		Help: metrics.SyncGlobalCorrH,
	})
	theilSen := newTheilSen(log, lclk)
	pll := newPLL(log, lclk)
	for {
		corrGauge.Set(0)
		corr := measureOffsetToNetClocks(log, netClkTimeout)
		if timemath.Abs(corr) > netClkCutoff {
			if float64(timemath.Abs(corr)) > maxCorr {
				corr = time.Duration(float64(timemath.Sign(corr)) * maxCorr)
			}
			// lclk.Adjust(corr, netClkInterval, 0)
			if useTheilSen {
				theilSen.AddSample(corr)
				frequencyPPM := theilSen.GetFrequencyPPM()

				if math.Abs(frequencyPPM) > 0 {
					lclk.AdjustWithTick(frequencyPPM)
				}
			} else {
				pll.Do(corr, 1000.0 /* weight */)
			}
			corrGauge.Set(float64(corr))
		}
		lclk.Sleep(netClkInterval)
	}
}
