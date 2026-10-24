package client

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ntp"
)

// A lucky packet is rejected if its round trip delay deviates by more than
// maxRTDExcess from the floor, the 10th percentile of the round trip delays of
// the lucky packets picked within the preceding window. Queuing in either
// direction, or a timestamp error in a single direction, then contributes at
// most maxRTDExcess/2 to an accepted clock offset. Unlike the minimum, the
// percentile is not shifted by a single sample with such an error.
const luckyPacketWindow = 5 * time.Minute

type sample struct {
	cTx, sRx, sTx, cRx time.Time
	rtd                time.Duration
}

type pick struct {
	t   time.Time
	rtd time.Duration
}

type Filter struct {
	log          *slog.Logger
	logCtx       context.Context
	maxRTDExcess time.Duration
	epoch        uint64
	buf          []sample
	picks        []pick
}

func NewFilter(log *slog.Logger, size int, maxRTDExcess time.Duration) *Filter {
	if size < 1 {
		panic("lucky packet window size must be >= 1")
	}
	if maxRTDExcess <= 0 {
		panic("lucky packet maximum round trip delay excess must be > 0")
	}
	return &Filter{
		log:          log,
		logCtx:       context.Background(),
		maxRTDExcess: maxRTDExcess,
		buf:          make([]sample, 0, size),
	}
}

func (f *Filter) Do(cTx, sRx, sTx, cRx time.Time) (
	offset time.Duration, err error) {
	if f.epoch != timebase.Epoch() {
		f.epoch = timebase.Epoch()
		f.buf = f.buf[:0]
	}

	f.buf = append(f.buf, sample{
		cTx: cTx, sRx: sRx, sTx: sTx, cRx: cRx,
		rtd: ntp.RoundTripDelay(cTx, sRx, sTx, cRx),
	})
	if len(f.buf) < cap(f.buf) {
		return 0, errFilterPending
	}

	return f.pickLucky()
}

func (f *Filter) Flush() (offset time.Duration, err error) {
	if f.epoch != timebase.Epoch() {
		f.epoch = timebase.Epoch()
		f.buf = f.buf[:0]
	}

	if len(f.buf) == 0 {
		return 0, errFilterPending
	}

	return f.pickLucky()
}

func (f *Filter) pickLucky() (time.Duration, error) {
	x := f.buf[0]
	for _, s := range f.buf[1:] {
		if s.rtd < x.rtd {
			x = s
		}
	}
	f.buf = f.buf[:0]

	now := time.Now()
	i := 0
	for i != len(f.picks) && now.Sub(f.picks[i].t) > luckyPacketWindow {
		i++
	}
	f.picks = append(f.picks[i:], pick{t: now, rtd: x.rtd})
	rtds := make([]time.Duration, len(f.picks))
	for j, p := range f.picks {
		rtds[j] = p.rtd
	}
	slices.Sort(rtds)
	floor := rtds[len(rtds)/10]

	off := ntp.ClockOffset(x.cTx, x.sRx, x.sTx, x.cRx)
	if f.log != nil {
		f.log.LogAttrs(f.logCtx, slog.LevelInfo, "picked lucky packet",
			slog.Duration("clock offset", off),
			slog.Duration("round trip delay", x.rtd),
			slog.Duration("round trip delay floor", floor),
		)
	}
	if (x.rtd - floor).Abs() > f.maxRTDExcess {
		return 0, errFilterRejected
	}
	return off, nil
}

func (f *Filter) Reset() {
	f.epoch = timebase.Epoch()
	f.buf = f.buf[:0]
	f.picks = f.picks[:0]
}
