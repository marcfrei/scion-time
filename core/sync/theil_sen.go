package sync

import (
	"sort"
	"time"

	"go.uber.org/zap"

	"example.com/scion-time/base/timebase"
)

type theilSen struct {
	log        *zap.Logger
	clk        timebase.LocalClock
	datapoints []point
}

func newTheilSen(log *zap.Logger, clk timebase.LocalClock) *theilSen {
	return &theilSen{log: log, clk: clk, datapoints: make([]point, 64)}
}

type point struct {
	x float64
	y float64
}

func sortAndGetMedian(data []float64) float64 {
	var length = len(data)
	if length == 0 {
		panic("invalid argument: array is empty, median undefined")
	}

	sort.Float64s(data)

	if length%2 == 0 {
		return (data[length/2-1] + data[length/2]) / 2
	} else {
		return data[length/2]
	}
}

func getSlope(inputs *[]point) float64 {
	if len(*inputs) == 1 {
		return (*inputs)[0].y / (*inputs)[0].x
	}

	var medians []float64
	for idxA, pointA := range *inputs {
		for _, pointB := range (*inputs)[idxA+1:] {
			// Like in the original paper by Sen (1968), ignore pairs with the same x coordinate
			if pointA.x != pointB.x {
				medians = append(medians, (pointA.y-pointB.y)/(pointA.x-pointB.x))
			}
		}
	}

	if len(medians) == 0 {
		panic("invalid inputs: all inputs have the same x coordinate")
	}

	return sortAndGetMedian(medians)
}

func getIntercept(slope float64, inputs *[]point) float64 {
	var medians []float64
	for _, point := range *inputs {
		medians = append(medians, point.y-slope*point.x)
	}

	return sortAndGetMedian(medians)
}

func makePrediction(slope float64, intercept float64, x float64) float64 {
	return slope*x + intercept
}

func (l *theilSen) Do(offset time.Duration) {
	now := l.clk.Now()

	l.datapoints = l.datapoints[1:]
	l.datapoints = append(l.datapoints, point{x: float64(now.Second()), y: float64(offset.Seconds())})

	var slope = getSlope(&l.datapoints)
	var intercept = getIntercept(slope, &l.datapoints)
	predictedOffset := makePrediction(slope, intercept, float64(now.Nanosecond()))

	l.log.Debug("Theil-Sen estimate",
		zap.Int("# of data points", len(l.datapoints)),
		zap.Float64("slope", slope),
		zap.Float64("intercept", intercept),
		zap.Float64("predicted offset", predictedOffset),
	)

	if predictedOffset > 0 {
		// TODO: Find out what frequency to pass
		// Option 1: Do the same calculation as the PLL. Probably bad idea, since
		// the PLL is not fully understood.
		// Option 2: Read the current frequency via a call to adjtimex.
		// Option 3: Offer a second Adjust() interface that does not require a frequency.
		// l.clk.Adjust(timemath.Duration(1), timemath.Duration(predictedOffset))
	}
}
