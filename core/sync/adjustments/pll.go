package adjustments

// Based on Ntimed by Poul-Henning Kamp, https://github.com/bsdphk/Ntimed
// See also https://phk.freebsd.dk/time/

import (
	"context"
	"log/slog"
	"math"
	"time"

	"example.com/scion-time/base/timebase"
	"example.com/scion-time/base/timemath"
)

type Pll struct {
	log     *slog.Logger
	logCtx  context.Context
	clk     timebase.SystemClock
	epoch   uint64
	mode    uint64
	t0, t   time.Time
	a, b, i float64
}

func NewPLL(log *slog.Logger, clk timebase.SystemClock) *Pll {
	return &Pll{log: log, logCtx: context.Background(), clk: clk}
}

func (l *Pll) Do(offset time.Duration, weight float64) {
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
			if offset.Abs() > 1*time.Millisecond {
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
		dt = now.Sub(l.t).Seconds()
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
		p = timemath.Inv(offset).Seconds() * a
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
	l.log.LogAttrs(l.logCtx, slog.LevelDebug,
		"PLL iteration",
		slog.Uint64("mode", l.mode),
		slog.Float64("dt", dt),
		slog.Float64("offset", offset.Seconds()),
		slog.Float64("weight", weight),
		slog.Float64("p", p),
		slog.Float64("d", d),
		slog.Float64("l.i", l.i),
		slog.Float64("a", a),
		slog.Float64("b", b),
	)
	if d > 0.0 {
		l.clk.Adjust(timemath.Duration(p), timemath.Duration(d), l.i)
	}
}
