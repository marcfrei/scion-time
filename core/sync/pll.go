package sync

// Based on Ntimed by Poul-Henning Kamp, https://github.com/bsdphk/Ntimed

import (
	"math"
	"time"

	"go.uber.org/zap"

	"example.com/scion-time/base/timebase"
	"example.com/scion-time/base/timemath"
)

type pll struct {
	log     *zap.Logger
	clk     timebase.LocalClock
	epoch   uint64
	mode    uint64
	t0, t   time.Time
	a, b, i float64
}

func newPLL(log *zap.Logger, clk timebase.LocalClock) *pll {
	return &pll{log: log, clk: clk}
}

func (l *pll) Do(offset time.Duration, weight float64) (float64, float64, float64) {
	offset = timemath.Inv(offset)
	if l.epoch != l.clk.Epoch() {
		l.epoch = l.clk.Epoch()
		l.mode = 0
	}
	var dt, p, d, a, b float64
	now := l.clk.Now()
	switch l.mode {
	case 0: // startup
		l.t0 = now
		l.mode++
	case 1: // awaiting step
		mdt := now.Sub(l.t0)
		if mdt < 0 {
			panic("unexpected clock behavior")
		}
		if mdt > 2*time.Second && weight > 3 {
			if timemath.Abs(offset) > 1*time.Millisecond {
				l.clk.Step(timemath.Inv(offset))
			}
			l.t0 = now
			l.mode++
		}
	case 2: // awaiting PLL
		mdt := now.Sub(l.t0)
		if mdt < 0 {
			panic("unexpected clock behavior")
		}
		if mdt > 6*time.Second {
			const (
				pInit = 0.33 // initial proportional term
				iInit = 60   // initial p/i ratio
			)
			l.a = pInit
			l.b = l.a / iInit
			l.t0 = now
			l.mode++
		}
	case 3: // tracking
		mdt := now.Sub(l.t0)
		if mdt < 0 {
			panic("unexpected clock behavior")
		}
		dt := timemath.Seconds(now.Sub(l.t))
		if dt < 0.0 {
			panic("unexpected clock behavior")
		}
		if weight < 50 {
			a = 3e-2
			b = 5e-4
		} else if weight < 150 {
			a = 6e-2
			b = 1e-3
		} else {
			const (
				captureTime = 300 * time.Second
				stiffenRate = 0.999
				pLimit      = 0.03
			)
			if mdt > captureTime && l.a > pLimit {
				l.a *= math.Pow(stiffenRate, dt)
				l.b *= math.Pow(stiffenRate, dt)
			}
			a = l.a
			b = l.b
		}
		p = timemath.Seconds(timemath.Inv(offset)) * a
		d = math.Ceil(dt)
		l.i += p * b
		if p > d*500e-6 {
			p = d * 500e-6
		}
		if p < d*-500e-6 {
			p = d * -500e-6
		}
	default:
		panic("unexpected PLL mode")
	}
	l.t = now
	l.log.Debug("PLL iteration",
		zap.Uint64("mode", l.mode),
		zap.Float64("dt", dt),
		zap.Float64("offset", timemath.Seconds(offset)),
		zap.Float64("weight", weight),
		zap.Float64("p", p),
		zap.Float64("d", d),
		zap.Float64("l.i", l.i),
		zap.Float64("a", a),
		zap.Float64("b", b),
	)

	return p, d, l.i
}
