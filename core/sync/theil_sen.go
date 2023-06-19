package sync

import (
	"sort"
	"time"

	"go.uber.org/zap"

	"example.com/scion-time/base/timebase"
)

type theilSen struct {
	log *zap.Logger
	clk timebase.LocalClock
	pts []timePoint
}

// If the buffer size is too large, the system is likely to oscillate heavily.
const MeasurementBufferSize = 4

func newTheilSen(log *zap.Logger, clk timebase.LocalClock) *theilSen {
	return &theilSen{log: log, clk: clk, pts: make([]timePoint, 0)}
}

type timePoint struct {
	x time.Time
	y time.Time
}

type point struct {
	x int64
	y int64
}

func median(ds []float64) float64 {
	n := len(ds)
	if n == 0 {
		panic("unexpected number of slopes")
	}

	sort.Float64s(ds)

	var m float64
	i := n / 2
	if n%2 != 0 {
		m = ds[i]
	} else {
		m = ds[i-1] + (ds[i]-ds[i-1])/2
	}
	return m
}

func slope(inputs []point) float64 {
	if len(inputs) == 1 {
		return 1.0
	}

	var medians []float64
	for idxA, pointA := range inputs {
		for _, pointB := range (inputs)[idxA+1:] {
			// Like in the original paper by Sen (1968), ignore pairs with the same x coordinate
			if pointA.x != pointB.x {
				medians = append(medians, (float64(pointA.y-pointB.y))/(float64(pointA.x-pointB.x)))
			}
		}
	}

	if len(medians) == 0 {
		panic("invalid inputs: all inputs have the same x coordinate")
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

func (l *theilSen) AddSample(offset time.Duration) {
	now := l.clk.Now()

	if len(l.pts) == MeasurementBufferSize {
		l.pts = l.pts[1:]
	}
	l.pts = append(l.pts, timePoint{x: now, y: now.Add(offset)})
}

func getRegressionPts(pts []timePoint) []point {
	startTime := pts[0].x
	var regressionPts []point
	for _, pt := range pts {
		regressionPts = append(regressionPts, point{x: pt.x.Sub(startTime).Nanoseconds(), y: pt.y.Sub(startTime).Nanoseconds()})
	}
	return regressionPts
}

func (l *theilSen) GetOffsetNs() float64 {
	now := l.clk.Now()
	regressionPts := getRegressionPts(l.pts)
	slope := slope(regressionPts)
	intercept := intercept(slope, regressionPts)
	predictedTime := prediction(slope, intercept, float64(now.Sub(l.pts[0].x).Nanoseconds()))
	predictedOffset := predictedTime - float64(now.Sub(l.pts[0].x).Nanoseconds())

	l.log.Debug("Theil-Sen estimate",
		zap.Int("# of data points", len(l.pts)),
		zap.Float64("slope", slope),
		zap.Float64("intercept", intercept),
		zap.Float64("predicted offset (ns)", predictedOffset),
	)

	return predictedOffset
}
