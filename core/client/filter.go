package client

import (
	"math"
	"sync"
	"time"

	"go.uber.org/zap"

	"example.com/scion-time/base/timemath"
	"example.com/scion-time/core/timebase"
)

const (
	maxNumRetries = 1
)

type filterContext struct {
	epoch          uint64
	alo, amid, ahi float64
	alolo, ahihi   float64
	navg           float64
}

var (
	filters   = make(map[string]filterContext)
	filtersMu = sync.Mutex{}
)

func combine(lo, mid, hi time.Duration, trust float64) (offset time.Duration, weight float64) {
	offset = mid
	weight = 0.001 + trust*2.0/timemath.Seconds(hi-lo)
	if weight < 1.0 {
		weight = 1.0
	}
	return
}

func filter(log *zap.Logger, reference string, cTxTime, sRxTime, sTxTime, cRxTime time.Time) (
	offset time.Duration, weight float64) {

	// Based on Ntimed by Poul-Henning Kamp, https://github.com/bsdphk/Ntimed

	filtersMu.Lock()
	f := filters[reference]

	lo := timemath.Seconds(cTxTime.Sub(sRxTime))
	hi := timemath.Seconds(cRxTime.Sub(sTxTime))
	mid := (lo + hi) / 2

	if f.epoch != timebase.Epoch() {
		f.epoch = timebase.Epoch()
		f.alo = 0.0
		f.amid = 0.0
		f.ahi = 0.0
		f.alolo = 0.0
		f.ahihi = 0.0
		f.navg = 0.0
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
		loNoise = math.Sqrt(f.alolo - f.alo*f.alo)
		hiNoise = math.Sqrt(f.ahihi - f.ahi*f.ahi)
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

	filters[reference] = f
	filtersMu.Unlock()

	trust := 1.0

	offset, weight = combine(timemath.Duration(lo), timemath.Duration(mid), timemath.Duration(hi), trust)

	log.Debug("filtered response",
		zap.String("from", reference),
		zap.Int("branch", branch),
		zap.Float64("lo [s]", lo),
		zap.Float64("mid [s]", mid),
		zap.Float64("hi [s]", hi),
		zap.Float64("loLim [s]", loLim),
		zap.Float64("amid [s]", f.amid),
		zap.Float64("hiLim [s]", hiLim),
		zap.Float64("offset [s]", timemath.Seconds(offset)),
		zap.Float64("weight", weight),
	)

	return timemath.Inv(offset), weight
}
