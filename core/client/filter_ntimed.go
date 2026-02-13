package client

import (
	"cmp"
	"context"
	"log/slog"
	"math"
	"slices"
	"time"

	"example.com/scion-time/base/timemath"
	"example.com/scion-time/core/timebase"

	"example.com/scion-time/core/measurements"
)

type sample struct {
	cTx, sRx, sTx, cRx time.Time
}

type NtimedFilter struct {
	log            *slog.Logger
	logCtx         context.Context
	epoch          uint64
	buf            []sample
	pick           int
	alo, amid, ahi float64
	alolo, ahihi   float64
	navg           float64
}

var _ measurements.Filter = (*NtimedFilter)(nil)

func NewNtimedFilter(log *slog.Logger, size, pick int) *NtimedFilter {
	if size < 1 {
		panic("lucky packet window size must be >= 1")
	}
	if pick < 1 || pick > size {
		panic("lucky packet pick must be >= 1 and <= size")
	}
	return &NtimedFilter{
		log:    log,
		logCtx: context.Background(),
		buf:    make([]sample, 0, size),
		pick:   pick,
	}
}

func (f *NtimedFilter) Do(cTxTime, sRxTime, sTxTime, cRxTime time.Time) (
	offset time.Duration, ok bool) {

	if f.epoch != timebase.Epoch() {
		f.Reset()
	}

	f.buf = append(f.buf, sample{cTxTime, sRxTime, sTxTime, cRxTime})
	if len(f.buf) < cap(f.buf) {
		return 0, false
	}

	slices.SortStableFunc(f.buf, func(a, b sample) int { return cmp.Compare(a.rtd(), b.rtd()) })
	f.buf = f.buf[:f.pick]
	slices.SortStableFunc(f.buf, func(a, b sample) int { return a.cTx.Compare(b.cTx) })
	var off time.Duration
	for _, s := range f.buf {
		off = f.filter(s.cTx, s.sRx, s.sTx, s.cRx)
	}
	f.buf = f.buf[:0]

	return off, true
}

func (s *sample) rtd() time.Duration {
	return s.cRx.Sub(s.cTx) - s.sTx.Sub(s.sRx)
}

func (f *NtimedFilter) filter(cTxTime, sRxTime, sTxTime, cRxTime time.Time) (
	offset time.Duration) {

	// Based on Ntimed by Poul-Henning Kamp, https://github.com/bsdphk/Ntimed

	var weight float64

	lo := cTxTime.Sub(sRxTime).Seconds()
	hi := cRxTime.Sub(sTxTime).Seconds()
	mid := (lo + hi) / 2

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

	offset = timemath.Duration(mid)
	weight = max(1.0, 0.001+2.0/(hi-lo))

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
	f.buf = f.buf[:0]
	f.alo = 0.0
	f.amid = 0.0
	f.ahi = 0.0
	f.alolo = 0.0
	f.ahihi = 0.0
	f.navg = 0.0
}
