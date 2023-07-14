package sync

import (
	"sort"
	"time"

	"go.uber.org/zap"

	"example.com/scion-time/base/timebase"
)

type theilSen struct {
	log      *zap.Logger
	clk      timebase.LocalClock
	samples  []sample
	baseFreq float64
}

// If the buffer size is too large, the system is likely to oscillate heavily.
const maxSamples = 4

const baseFreqGainFactor = 0.005

func newTheilSen(log *zap.Logger, clk timebase.LocalClock) *theilSen {
	return &theilSen{log: log, clk: clk, samples: make([]sample, 0), baseFreq: 0.0}
}

type sample struct {
	x time.Time
	y time.Time
}

type point struct {
	x int64
	y int64
}

func median(v []float64) float64 {
	n := len(v)
	if n == 0 {
		panic("unexpected number of values")
	}

	sort.Float64s(v)

	var m float64
	i := n / 2
	if n%2 != 0 {
		m = v[i]
	} else {
		m = v[i-1] + (v[i]-v[i-1])/2
	}
	return m
}

func slope(pts []point) float64 {
	if len(pts) == 1 {
		return 1.0
	}

	var medians []float64
	for i, a := range pts {
		for _, b := range (pts)[i+1:] {
			// Like in the original paper by Sen (1968), ignore pairs with the same x coordinate
			if a.x != b.x {
				medians = append(medians, float64(a.y-b.y)/float64(a.x-b.x))
			}
		}
	}

	if len(medians) == 0 {
		panic("unexpected input: all inputs have the same x coordinate")
	}

	return median(medians)
}

func intercept(slope float64, inputs []point) float64 {
	var medians []float64
	for _, point := range inputs {
		medians = append(medians, float64(point.y)-slope*float64(point.x))
	}

	return median(medians)
}

func prediction(slope float64, intercept float64, x float64) float64 {
	return slope*x + intercept
}

func (ts *theilSen) AddSample(offset time.Duration) {
	ts.baseFreq += float64(offset.Nanoseconds()) * baseFreqGainFactor
	now := ts.clk.Now()

	if len(ts.samples) == maxSamples {
		ts.samples = ts.samples[1:]
	}
	ts.samples = append(ts.samples, sample{x: now, y: now.Add(offset)})
}

func regressionPts(samples []sample) []point {
	startTime := samples[0].x
	var regressionPts []point
	for _, pt := range samples {
		regressionPts = append(regressionPts, point{x: pt.x.Sub(startTime).Nanoseconds(), y: pt.y.Sub(startTime).Nanoseconds()})
	}
	return regressionPts
}

func (ts *theilSen) Offset() (time.Duration, bool) {
	if len(ts.samples) == 0 {
		return time.Duration(0), false
	}

	now := ts.clk.Now()
	regressionPts := regressionPts(ts.samples)
	slope := slope(regressionPts)
	intercept := intercept(slope, regressionPts)
	predictedTime := prediction(slope, intercept, float64(now.Sub(ts.samples[0].x).Nanoseconds()))
	predictedOffset := predictedTime - float64(now.Sub(ts.samples[0].x).Nanoseconds())

	ts.log.Debug("Theil-Sen estimate",
		zap.Int("# of samples", len(ts.samples)),
		zap.Float64("slope", slope),
		zap.Float64("intercept", intercept),
		zap.Float64("predicted offset (ns)", predictedOffset),
	)

	return time.Duration(predictedOffset * float64(time.Nanosecond)), true
}
