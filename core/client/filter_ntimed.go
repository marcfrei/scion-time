package client

import (
	"context"
	"log/slog"
	"math"
	"time"

	"example.com/scion-time/base/timemath"
	"example.com/scion-time/core/timebase"

	"example.com/scion-time/core/measurements"
)

type NtimedFilter struct {
	log            *slog.Logger
	logCtx         context.Context
	epoch          uint64
	alo, amid, ahi float64
	alolo, ahihi   float64
	navg           float64
}

var _ measurements.Filter = (*NtimedFilter)(nil)

func NewNtimedFilter(log *slog.Logger) *NtimedFilter {
	return &NtimedFilter{log: log, logCtx: context.Background()}
}

func combine(lo, mid, hi time.Duration, trust float64) (offset time.Duration, weight float64) {
	offset = mid
	weight = 0.001 + trust*2.0/(hi-lo).Seconds()
	if weight < 1.0 {
		weight = 1.0
	}
	return
}

func (f *NtimedFilter) Do(cTxTime, sRxTime, sTxTime, cRxTime time.Time) (
	offset time.Duration) {

	// Based on Ntimed by Poul-Henning Kamp, https://github.com/bsdphk/Ntimed

	var weight float64

	lo := cTxTime.Sub(sRxTime).Seconds()
	hi := cRxTime.Sub(sTxTime).Seconds()
	mid := (lo + hi) / 2

	if f.epoch != timebase.Epoch() {
		f.Reset()
	}

	const (
		filterAverage   = 20.0
		filterThreshold = 3.0
	)

	if f.navg < filterAverage {
		f.navg += 1.0
	}

	var loNoise, hiNoise float64
	if f.navg > 2.0 {
		loNoise = math.Sqrt(max(0.0, f.alolo-f.alo*f.alo))
		hiNoise = math.Sqrt(max(0.0, f.ahihi-f.ahi*f.ahi))
	}

	loLim := f.alo - loNoise*filterThreshold
	hiLim := f.ahi + hiNoise*filterThreshold

	var branch int
	failLo := lo < loLim
	failHi := hi > hiLim
	if failLo && failHi {
		branch = 1
	} else if f.navg > 3.0 && failLo {
		mid = f.amid + (hi - f.ahi)
		branch = 2
	} else if f.navg > 3.0 && failHi {
		mid = f.amid + (lo - f.alo)
		branch = 3
	} else {
		branch = 4
	}

	r := f.navg
	if f.navg > 2.0 && branch != 4 {
		r *= r
	}

	f.alo += (lo - f.alo) / r
	f.amid += (mid - f.amid) / r
	f.ahi += (hi - f.ahi) / r
	f.alolo += (lo*lo - f.alolo) / r
	f.ahihi += (hi*hi - f.ahihi) / r

	trust := 1.0

	offset, weight = combine(timemath.Duration(lo), timemath.Duration(f.amid), timemath.Duration(hi), trust)

	if f.log != nil {
		f.log.LogAttrs(f.logCtx, slog.LevelDebug, "filtered response",
			slog.Int("branch", branch),
			slog.Float64("lo [s]", lo),
			slog.Float64("mid [s]", mid),
			slog.Float64("hi [s]", hi),
			slog.Float64("loLim [s]", loLim),
			slog.Float64("amid [s]", f.amid),
			slog.Float64("hiLim [s]", hiLim),
			slog.Float64("offset [s]", offset.Seconds()),
			slog.Float64("weight", weight),
		)
	}

	return timemath.Inv(offset)
}

func (f *NtimedFilter) Reset() {
	f.epoch = timebase.Epoch()
	f.alo = 0.0
	f.amid = 0.0
	f.ahi = 0.0
	f.alolo = 0.0
	f.ahihi = 0.0
	f.navg = 0.0
}
