package client

import (
	"context"
	"log/slog"
	"math"
	"time"

	"example.com/scion-time/base/timemath"
	"example.com/scion-time/core/timebase"

	"example.com/scion-time/core/measurement"
)

type filterState struct {
	epoch          uint64
	alo, amid, ahi float64
	alolo, ahihi   float64
	navg           float64
}

type filter struct {
	log    *slog.Logger
	logCtx context.Context
	state  map[string]filterState
}

var _ measurement.Filter = (*filter)(nil)

func newFilter(log *slog.Logger) *filter {
	return &filter{log: log, logCtx: context.Background()}
}

func combine(lo, mid, hi time.Duration, trust float64) (offset time.Duration, weight float64) {
	offset = mid
	weight = 0.001 + trust*2.0/timemath.Seconds(hi-lo)
	if weight < 1.0 {
		weight = 1.0
	}
	return
}

func (f *filter) Do(reference string, cTxTime, sRxTime, sTxTime, cRxTime time.Time) (
	offset time.Duration) {

	// Based on Ntimed by Poul-Henning Kamp, https://github.com/bsdphk/Ntimed

	var weight float64

	fs := f.state[reference]

	lo := timemath.Seconds(cTxTime.Sub(sRxTime))
	hi := timemath.Seconds(cRxTime.Sub(sTxTime))
	mid := (lo + hi) / 2

	if fs.epoch != timebase.Epoch() {
		fs.epoch = timebase.Epoch()
		fs.alo = 0.0
		fs.amid = 0.0
		fs.ahi = 0.0
		fs.alolo = 0.0
		fs.ahihi = 0.0
		fs.navg = 0.0
	}

	const (
		filterAverage   = 20.0
		filterThreshold = 3.0
	)

	if fs.navg < filterAverage {
		fs.navg += 1.0
	}

	var loNoise, hiNoise float64
	if fs.navg > 2.0 {
		loNoise = math.Sqrt(fs.alolo - fs.alo*fs.alo)
		hiNoise = math.Sqrt(fs.ahihi - fs.ahi*fs.ahi)
	}

	loLim := fs.alo - loNoise*filterThreshold
	hiLim := fs.ahi + hiNoise*filterThreshold

	var branch int
	failLo := lo < loLim
	failHi := hi > hiLim
	if failLo && failHi {
		branch = 1
	} else if fs.navg > 3.0 && failLo {
		mid = fs.amid + (hi - fs.ahi)
		branch = 2
	} else if fs.navg > 3.0 && failHi {
		mid = fs.amid + (lo - fs.alo)
		branch = 3
	} else {
		branch = 4
	}

	r := fs.navg
	if fs.navg > 2.0 && branch != 4 {
		r *= r
	}

	fs.alo += (lo - fs.alo) / r
	fs.amid += (mid - fs.amid) / r
	fs.ahi += (hi - fs.ahi) / r
	fs.alolo += (lo*lo - fs.alolo) / r
	fs.ahihi += (hi*hi - fs.ahihi) / r

	if f.state == nil {
		f.state = make(map[string]filterState)
	}
	f.state[reference] = fs

	trust := 1.0

	offset, weight = combine(timemath.Duration(lo), timemath.Duration(mid), timemath.Duration(hi), trust)

	f.log.LogAttrs(f.logCtx, slog.LevelDebug, "filtered response",
		slog.String("from", reference),
		slog.Int("branch", branch),
		slog.Float64("lo [s]", lo),
		slog.Float64("mid [s]", mid),
		slog.Float64("hi [s]", hi),
		slog.Float64("loLim [s]", loLim),
		slog.Float64("amid [s]", fs.amid),
		slog.Float64("hiLim [s]", hiLim),
		slog.Float64("offset [s]", timemath.Seconds(offset)),
		slog.Float64("weight", weight),
	)

	return timemath.Inv(offset)
}
