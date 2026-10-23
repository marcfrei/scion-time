package server

import (
	"container/heap"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"example.com/scion-time/base/metrics"

	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ntp"
)

const (
	serverRefID = 0x58535453

	tssCap     = 1 << 20
	tssItemCap = 8
)

type tssItem struct {
	key string
	buf [tssItemCap]struct {
		rxt, txt ntp.Time64
	}
	len  int
	qval ntp.Time64
	qidx int
}

type tssQueue []*tssItem

var (
	tss        = make(map[string]*tssItem)
	tssQ       = make(tssQueue, 0, tssCap)
	tssMetrics = struct {
		reqsServedInterleaved prometheus.Counter
		rxtIncrements         prometheus.Counter
		txtIncrementsBefore   prometheus.Counter
		txtIncrementsAfter    prometheus.Counter
		tssItems              prometheus.Gauge
		tssValues             prometheus.Gauge
	}{
		reqsServedInterleaved: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.ServerReqsServedInterleavedN,
			Help: metrics.ServerReqsServedInterleavedH,
		}),
		rxtIncrements: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.ServerRxtIncrementsN,
			Help: metrics.ServerRxtIncrementsH,
		}),
		txtIncrementsBefore: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.ServerTxtIncrementsBeforeN,
			Help: metrics.ServerTxtIncrementsBeforeH,
		}),
		txtIncrementsAfter: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.ServerTxtIncrementsAfterN,
			Help: metrics.ServerTxtIncrementsAfterH,
		}),
		tssItems: promauto.NewGauge(prometheus.GaugeOpts{
			Name: metrics.ServerTssItemsN,
			Help: metrics.ServerTssItemsH,
		}),
		tssValues: promauto.NewGauge(prometheus.GaugeOpts{
			Name: metrics.ServerTssValuesN,
			Help: metrics.ServerTssValuesH,
		}),
	}
	tssMu sync.Mutex
)

func (q tssQueue) Len() int { return len(q) }

func (q tssQueue) Less(i, j int) bool {
	return q[i].qval.Before(q[j].qval)
}

func (q tssQueue) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].qidx = i
	q[j].qidx = j
}

func (q *tssQueue) Push(x any) {
	tssi := x.(*tssItem)
	tssi.qidx = len(*q)
	*q = append(*q, tssi)
}

func (q *tssQueue) Pop() any {
	n := len(*q)
	tssi := (*q)[n-1]
	(*q)[n-1] = nil
	*q = (*q)[0 : n-1]
	return tssi
}

func handleRequest(clientID string, req *ntp.Packet, rxt, txt *time.Time, resp *ntp.Packet) {
	resp.SetVersion(ntp.VersionMax)
	resp.SetMode(ntp.ModeServer)
	resp.Stratum = 1
	resp.Poll = req.Poll
	resp.Precision = -32
	resp.RootDispersion = ntp.Time32{Seconds: 0, Fraction: 10}
	resp.ReferenceID = serverRefID

	*txt = timebase.Now()

	rxt64 := ntp.Time64FromTime(*rxt)
	txt64 := ntp.Time64FromTime(*txt)

	tssMu.Lock()
	defer tssMu.Unlock()

	var o, min, max int
	tssi, ok := tss[clientID]
	if ok {
		for {
			var i int
			for i, o, min, max = 0, -1, -1, -1; i != tssi.len; i++ {
				if tssi.buf[i].rxt == rxt64 {
					break
				}
				if tssi.buf[i].rxt == req.OriginTime {
					o = i
				}
				if min == -1 || tssi.buf[i].rxt.Before(tssi.buf[min].rxt) {
					min = i
				}
				if max == -1 || !tssi.buf[i].rxt.Before(tssi.buf[max].rxt) {
					max = i
				}
			}
			if i != tssi.len {
				// ensure uniqueness of rx timestamps per clientID
				*rxt = rxt.Add(1)
				rxt64 = ntp.Time64FromTime(*rxt)
				tssMetrics.rxtIncrements.Inc()
				if !rxt.Before(*txt) {
					// ensure strict monotonicity of rx/tx timestamps
					*txt = *rxt
					*txt = txt.Add(1)
					txt64 = ntp.Time64FromTime(*txt)
					tssMetrics.txtIncrementsBefore.Inc()
				}
				continue
			}
			break
		}
	} else {
		if len(tss) == tssCap && !tssQ[0].qval.After(rxt64) {
			// remove minimum timestamp queue item
			x := heap.Pop(&tssQ).(*tssItem)
			delete(tss, x.key)
			tssMetrics.tssItems.Dec()
			tssMetrics.tssValues.Sub(float64(x.len))
		}
		if len(tss) == tssCap {
			tssi = nil
		} else {
			// add timestamp store item
			tssi = &tssItem{key: clientID}
			tss[tssi.key] = tssi
			tssMetrics.tssItems.Inc()
			tssi.qval = rxt64
			heap.Push(&tssQ, tssi)
		}
		o, min, max = -1, -1, -1
	}

	resp.ReferenceTime = txt64
	resp.ReceiveTime = rxt64
	if req.ReceiveTime != req.TransmitTime && o != -1 {
		// interleaved mode: serve from timestamp store
		resp.OriginTime = req.ReceiveTime
		resp.TransmitTime = tssi.buf[o].txt
		tssMetrics.reqsServedInterleaved.Inc()
	} else {
		resp.OriginTime = req.TransmitTime
		resp.TransmitTime = txt64
	}

	if tssi != nil {
		if max != -1 && rxt64.After(tssi.buf[max].rxt) {
			// new maximum rx timestamp, fix queue accordingly
			tssi.qval = rxt64
			heap.Fix(&tssQ, tssi.qidx)
		}
		if o != -1 {
			// maintain interleaved mode timestamp values
			tssi.buf[o].rxt = rxt64
			tssi.buf[o].txt = txt64
		} else if tssi.len == cap(tssi.buf) {
			// replace minimum timestamp values
			tssi.buf[min].rxt = rxt64
			tssi.buf[min].txt = txt64
		} else {
			// add timestamp values
			tssi.buf[tssi.len].rxt = rxt64
			tssi.buf[tssi.len].txt = txt64
			tssi.len++
			tssMetrics.tssValues.Inc()
		}
	}
}

func updateTXTimestamp(clientID string, rxt time.Time, txt *time.Time) {
	tssMu.Lock()
	defer tssMu.Unlock()

	if !rxt.Before(*txt) {
		// ensure strict monotonicity of rx/tx timestamps
		*txt = rxt
		*txt = txt.Add(1)
		tssMetrics.txtIncrementsAfter.Inc()
	}

	tssi, ok := tss[clientID]
	if ok {
		rxt64 := ntp.Time64FromTime(rxt)
		txt64 := ntp.Time64FromTime(*txt)
		var i, x, max0, max1 int
		for i, x, max0, max1 = 0, -1, -1, -1; i != tssi.len; i++ {
			if tssi.buf[i].rxt == rxt64 {
				x = i
			}
			if max0 == -1 || !tssi.buf[i].rxt.Before(tssi.buf[max0].rxt) {
				max0, max1 = i, max0
			} else if max1 == -1 || !tssi.buf[i].rxt.Before(tssi.buf[max1].rxt) {
				max1 = i
			}
		}
		if x != -1 {
			if tssi.buf[x].txt != txt64 {
				tssi.buf[x].txt = txt64
			} else {
				// No updated tx timestamp available
				if tssi.len == 1 {
					// remove timestamp store item
					heap.Remove(&tssQ, tssi.qidx)
					delete(tss, tssi.key)
					tssMetrics.tssItems.Dec()
					tssMetrics.tssValues.Sub(float64(tssi.len))
				} else {
					// remove timestamp values
					if tssi.buf[max0].rxt == rxt64 {
						// new maximum rx timestamp, fix queue accordingly
						tssi.qval = tssi.buf[max1].rxt
						heap.Fix(&tssQ, tssi.qidx)
					}
					tssi.buf[x] = tssi.buf[tssi.len-1]
					tssi.len--
					tssMetrics.tssValues.Dec()
				}
			}
		}
	}
}
