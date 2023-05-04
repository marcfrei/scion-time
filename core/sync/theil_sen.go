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
	pts []point
}

const MeasurementBufferSize = 64

func newTheilSen(log *zap.Logger, clk timebase.LocalClock) *theilSen {
	return &theilSen{log: log, clk: clk, pts: make([]point, 0)}
}

type point struct {
	x float64
	y float64
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
		return (inputs)[0].y / (inputs)[0].x
	}

	var medians []float64
	for idxA, pointA := range inputs {
		for _, pointB := range (inputs)[idxA+1:] {
			// Like in the original paper by Sen (1968), ignore pairs with the same x coordinate
			if pointA.x != pointB.x {
				medians = append(medians, (pointA.y-pointB.y)/(pointA.x-pointB.x))
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
		medians = append(medians, point.y-slope*point.x)
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
	l.pts = append(l.pts, point{x: float64(now.UnixNano()), y: float64(offset.Nanoseconds() + now.UnixNano())})
}

func (l *theilSen) GetOffsetNs() float64 {
	now := l.clk.Now()
	slope := slope(l.pts)
	intercept := intercept(slope, l.pts)
	predictedTime := prediction(slope, intercept, float64(now.UnixNano()))
	predictedOffset := predictedTime - float64(now.UnixNano())

	l.log.Debug("Theil-Sen estimate",
		zap.Int("# of data points", len(l.pts)),
		zap.Float64("slope", slope),
		zap.Float64("intercept", intercept),
		zap.Float64("predicted offset (ns)", predictedOffset),
	)

	return predictedOffset
}
