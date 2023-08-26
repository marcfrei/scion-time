package sync

import (
	"math"
	"time"

	"example.com/scion-time/base/timebase"
	"go.uber.org/zap"
)

const LADMeasurementBufferSize = 64

type lad struct {
	log *zap.Logger
	clk timebase.LocalClock
	pts []sample
}

func newLAD(log *zap.Logger, clk timebase.LocalClock) *lad {
	return &lad{log: log, clk: clk, pts: make([]sample, 0)}
}

func criticalRuns(i int) int {
	return [...]int{
		0, 0, 0, 0, 0, 0, 0, 0, 2, 3,
		3, 3, 4, 4, 5, 5, 5, 6, 6, 7,
		7, 7, 8, 8, 9, 9, 9, 10, 10, 11,
		11, 11, 12, 12, 13, 13, 14, 14, 14, 15,
		15, 16, 16, 17, 17, 18, 18, 18, 19, 19,
		20, 20, 21, 21, 21, 22, 22, 23, 23, 24,
		24, 25, 25, 26, 26, 26, 27, 27, 28, 28,
		29, 29, 30, 30, 30, 31, 31, 32, 32, 33,
		33, 34, 34, 35, 35, 35, 36, 36, 37, 37,
		38, 38, 39, 39, 40, 40, 40, 41, 41, 42,
		42, 43, 43, 44, 44, 45, 45, 46, 46, 46,
		47, 47, 48, 48, 49, 49, 50, 50, 51, 51,
		52, 52, 52, 53, 53, 54, 54, 55, 55, 56,
	}[i]
}

func nRunsFromResiduals(residuals []float64, n int) int {
	nruns := 1
	for i := 1; i < n; i++ {
		if (residuals[i-1] < 0.0 && residuals[i] < 0.0) ||
			(residuals[i-1] > 0.0 && residuals[i] > 0.0) {
			// Do nothing, both residuals have the same sign
		} else {
			nruns++
		}
	}

	return nruns
}

// Implementation taken from Numerical Recipes for C, Third Edition, page 704
func medfit(inputs []point, log *zap.Logger) (float64, float64, int) {
	var slope, intercept float64
	// var b1, b2, f, f1, f2 float64
	var sumX, sumY float64
	var sxy, sxx float64
	// var chisq, sigb float64
	var chisq float64

	n := len(inputs)
	x := make([]float64, n)
	y := make([]float64, n)
	residuals := make([]float64, n)

	for i := 0; i < n; i++ {
		x[i] = float64(inputs[i].x) / 10_000.0
		y[i] = float64(inputs[i].y) / 10_000.0
	}

	startIndex := 0

	for {
		nCurrentIteration := float64(n - startIndex)
		// As first guess for slope / intercept, find least squares solution
		sumX = 0.0
		sumY = 0.0
		for i := startIndex; i < n; i++ {
			sumX += x[i]
			sumY += y[i]
		}

		meanX := sumX / nCurrentIteration
		meanY := sumY / nCurrentIteration

		sxy = 0.0
		sxx = 0.0
		for i := startIndex; i < n; i++ {
			dx := x[i] - meanX
			dy := y[i] - meanY
			sxy += dx * dy
			sxx += dx * dx
		}

		// Least squares solution
		slope = sxy / sxx
		intercept = meanY - slope*meanX

		chisq = 0.0
		for i := startIndex; i < n; i++ {
			residual := y[i] - (intercept + slope*x[i])
			chisq += residual * residual
		}

		incr := math.Max(chisq, 1e-8)
		var rlow, rmid, rhigh float64
		var blow, bmid, bhigh float64

		for rlow*rhigh >= 0.0 {
			incr *= 2

			blow = slope - incr
			bhigh = slope + incr

			_, rlow = getRobustResidual(blow, inputs[startIndex:])
			_, rhigh = getRobustResidual(bhigh, inputs[startIndex:])
		}

		for bhigh-blow > 1e-8 {
			bmid = 0.5 * (blow + bhigh)
			if !(blow < bmid && bmid < bhigh) {
				break
			}

			intercept, rmid = getRobustResidual(bmid, inputs[startIndex:])

			if rmid == 0.0 {
				break
			} else if rmid*rlow > 0.0 {
				blow = bmid
				rlow = rmid
			} else if rmid*rhigh > 0.0 {
				bhigh = bmid
				rhigh = rmid
			}
		}

		slope = bmid

		if nCurrentIteration == 3 {
			break
		}

		for i := startIndex; i < n; i++ {
			residuals[i] = y[i] - (intercept + slope*x[i])
		}

		nruns := nRunsFromResiduals(residuals[startIndex:], int(nCurrentIteration))

		if nruns > criticalRuns(int(nCurrentIteration)) {
			break
		} else {
			startIndex++
		}
	}

	return slope, intercept, startIndex
}

// Evaluate right-hand side of equation for given intercept
func getRobustResidual(slope float64, inputs []point) (float64, float64) {
	const EPS float64 = 1e-7

	n := len(inputs)
	arr := make([]float64, n)
	var sum int64

	for i := 0; i < n; i++ {
		arr[i] = float64(inputs[i].y) - slope*float64(inputs[i].x)
	}

	intercept := median(arr)

	for i := 0; i < n; i++ {
		d := float64(inputs[i].y) - (slope*float64(inputs[i].x) + intercept)
		if inputs[i].y != 0.0 {
			d /= math.Abs(float64(inputs[i].y))
		}
		if math.Abs(d) > EPS {
			if d >= 0.0 {
				sum += inputs[i].x
			} else {
				sum -= inputs[i].x
			}
		}
	}

	return intercept, float64(sum)
}

func (l *lad) AddSample(offset time.Duration) {
	now := l.clk.Now()

	if len(l.pts) == LADMeasurementBufferSize {
		l.pts = l.pts[1:]
	}
	l.pts = append(l.pts, sample{x: now, y: now.Add(offset)})
}

func (l *lad) Offset() (time.Duration, bool) {
	if len(l.pts) < 3 {
		l.log.Debug("LAD - Not enough points yet")
		return time.Duration(0.0), false
	}

	now := l.clk.Now()
	regressionPts := regressionPts(l.pts)
	slope, intercept, bestStartIndex := medfit(regressionPts, l.log)
	predictedTime := prediction(slope, intercept, float64(now.Sub(l.pts[0].x).Nanoseconds()))
	predictedOffset := predictedTime - float64(now.Sub(l.pts[0].x).Nanoseconds())

	if bestStartIndex > 0 {
		l.pts = l.pts[bestStartIndex:]
	}

	l.log.Debug("LAD estimate",
		zap.Int("# of data points", len(l.pts)),
		zap.Float64("slope", slope),
		zap.Float64("intercept", intercept),
		zap.Float64("predicted offset (ns)", predictedOffset),
	)

	return time.Duration(predictedOffset * float64(time.Nanosecond)), true
}
