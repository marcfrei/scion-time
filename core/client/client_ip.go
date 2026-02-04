package client

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"example.com/scion-time/base/metrics"

	"example.com/scion-time/core/measurements"
	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ntp"
	"example.com/scion-time/net/nts"
	"example.com/scion-time/net/ntske"
	"example.com/scion-time/net/udp"
)

type IPClient struct {
	Log             *slog.Logger
	DSCP            uint8
	InterleavedMode bool
	Auth            struct {
		Enabled      bool
		NTSKEFetcher ntske.Fetcher
	}
	Filter    measurements.Filter
	Histogram *hdrhistogram.Histogram
	prev      struct {
		reference   string
		interleaved bool
		cTxTime     ntp.Time64
		cRxTime     ntp.Time64
		sRxTime     ntp.Time64
	}
}

type ipClientMetrics struct {
	reqsSent                 prometheus.Counter
	reqsSentInterleaved      prometheus.Counter
	pktsReceived             prometheus.Counter
	pktsAuthenticated        prometheus.Counter
	respsAccepted            prometheus.Counter
	respsAcceptedInterleaved prometheus.Counter
}

func newIPClientMetrics() *ipClientMetrics {
	return &ipClientMetrics{
		reqsSent: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.IPClientReqsSentN,
			Help: metrics.IPClientReqsSentH,
		}),
		reqsSentInterleaved: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.IPClientReqsSentInterleavedN,
			Help: metrics.IPClientReqsSentInterleavedH,
		}),
		pktsReceived: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.IPClientPktsReceivedN,
			Help: metrics.IPClientPktsReceivedH,
		}),
		pktsAuthenticated: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.IPClientPktsAuthenticatedN,
			Help: metrics.IPClientPktsAuthenticatedH,
		}),
		respsAccepted: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.IPClientRespsAcceptedN,
			Help: metrics.IPClientRespsAcceptedH,
		}),
		respsAcceptedInterleaved: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.IPClientRespsAcceptedInterleavedN,
			Help: metrics.IPClientRespsAcceptedInterleavedH,
		}),
	}
}

func compareAddrs(x, y netip.Addr) int {
	return x.Unmap().Compare(y.Unmap())
}

func (c *IPClient) InInterleavedMode() bool {
	return c.InterleavedMode && c.prev.reference != "" && c.prev.interleaved
}

func (c *IPClient) InterleavedModeReference() string {
	if !c.InInterleavedMode() {
		return ""
	}
	return c.prev.reference
}

func (c *IPClient) ResetInterleavedMode() {
	c.prev.reference = ""
}

func (c *IPClient) measureClockOffsetIP(ctx context.Context, mtrcs *ipClientMetrics,
	localAddr, remoteAddr *net.UDPAddr) (
	timestamp time.Time, offset time.Duration, err error) {
	laddr, ok := netip.AddrFromSlice(localAddr.IP)
	if !ok {
		panic(errUnexpectedAddrType)
	}
	var lc net.ListenConfig
	pconn, err := lc.ListenPacket(ctx, "udp", netip.AddrPortFrom(laddr, 0).String())
	if err != nil {
		return time.Time{}, 0, err
	}
	conn := pconn.(*net.UDPConn)
	defer func() { _ = conn.Close() }()
	deadline, deadlineIsSet := ctx.Deadline()
	if deadlineIsSet {
		err = conn.SetDeadline(deadline)
		if err != nil {
			return time.Time{}, 0, err
		}
	}
	err = udp.EnableTimestamping(conn, localAddr.Zone, -1 /* index */)
	if err != nil {
		c.Log.LogAttrs(ctx, slog.LevelError, "failed to enable timestamping", slog.Any("error", err))
	}
	err = udp.SetDSCP(conn, c.DSCP)
	if err != nil {
		c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to set DSCP", slog.Any("error", err))
	}

	var ntskeData ntske.Data
	if c.Auth.Enabled {
		ntskeData, err = c.Auth.NTSKEFetcher.FetchData(ctx)
		if err != nil {
			c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to fetch key exchange data", slog.Any("error", err))
			return time.Time{}, 0, err
		}
		remoteAddr.IP = net.ParseIP(ntskeData.Server)
		remoteAddr.Port = int(ntskeData.Port)
	}
	ip4 := remoteAddr.IP.To4()
	if ip4 != nil {
		remoteAddr.IP = ip4
	}

	buf := make([]byte, ntp.PacketLen)

	reference := remoteAddr.String()
	cTxTime0 := timebase.Now()
	interleavedReq := false

	ntpreq := ntp.Packet{}
	ntpreq.SetVersion(ntp.VersionMax)
	ntpreq.SetMode(ntp.ModeClient)
	if c.InterleavedMode && reference == c.prev.reference &&
		cTxTime0.Sub(ntp.TimeFromTime64(c.prev.cTxTime, cTxTime0)) <= 3*time.Second {
		interleavedReq = true
		ntpreq.OriginTime = c.prev.sRxTime
		ntpreq.ReceiveTime = c.prev.cRxTime
		ntpreq.TransmitTime = c.prev.cTxTime
	} else {
		ntpreq.TransmitTime = ntp.Time64FromTime(cTxTime0)
	}
	ntp.EncodePacket(&buf, &ntpreq)

	var requestID []byte
	var ntsreq nts.Packet
	if c.Auth.Enabled {
		ntsreq, requestID = nts.NewRequestPacket(ntskeData)
		nts.EncodePacket(&buf, &ntsreq)
	}

	n, err := conn.WriteToUDPAddrPort(buf, remoteAddr.AddrPort())
	if err != nil {
		return time.Time{}, 0, err
	}
	if n != len(buf) {
		return time.Time{}, 0, errWrite
	}
	cTxTime1, id, err := udp.ReadTXTimestamp(conn, 0)
	if err != nil || id != 0 {
		cTxTime1 = timebase.Now()
		c.Log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp", slog.Any("error", err))
	}
	mtrcs.reqsSent.Inc()
	if interleavedReq {
		mtrcs.reqsSentInterleaved.Inc()
	}

	const maxNumRetries = 1
	numRetries := 0
	oob := make([]byte, udp.TimestampLen())
	for {
		buf = buf[:cap(buf)]
		oob = oob[:cap(oob)]
		n, oobn, flags, srcAddr, err := conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet", slog.Any("error", err))
				numRetries++
				continue
			}
			return time.Time{}, 0, err
		}
		if flags != 0 {
			err = errUnexpectedPacketFlags
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet", slog.Int("flags", flags))
				numRetries++
				continue
			}
			return time.Time{}, 0, err
		}
		oob = oob[:oobn]
		cRxTime, err := udp.TimestampFromOOBData(oob)
		if err != nil {
			cRxTime = timebase.Now()
			c.Log.LogAttrs(ctx, slog.LevelError, "failed to read packet rx timestamp", slog.Any("error", err))
		}
		buf = buf[:n]
		mtrcs.pktsReceived.Inc()

		if compareAddrs(srcAddr.Addr(), remoteAddr.AddrPort().Addr()) != 0 {
			err = errUnexpectedPacketSource
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "received packet from unexpected source")
				numRetries++
				continue
			}
			return time.Time{}, 0, err
		}

		var ntpresp ntp.Packet
		err = ntp.DecodePacket(&ntpresp, buf)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
				numRetries++
				continue
			}
			return time.Time{}, 0, err
		}

		authenticated := false
		var ntsresp nts.Packet
		if c.Auth.Enabled {
			err = nts.DecodePacket(&ntsresp, buf)
			if err != nil {
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode NTS packet", slog.Any("error", err))
					numRetries++
					continue
				}
				return time.Time{}, 0, err
			}

			err = nts.ProcessResponse(buf, ntskeData.S2cKey, &c.Auth.NTSKEFetcher, &ntsresp, requestID)
			if err != nil {
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to process NTS packet", slog.Any("error", err))
					numRetries++
					continue
				}
				return time.Time{}, 0, err
			}

			authenticated = true
			mtrcs.pktsAuthenticated.Inc()
		}

		interleavedResp := false
		if interleavedReq && ntpresp.OriginTime == ntpreq.ReceiveTime {
			interleavedResp = true
		} else if ntpresp.OriginTime != ntpreq.TransmitTime {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "received packet with unexpected type or structure")
				numRetries++
				continue
			}
			return time.Time{}, 0, err
		}

		err = ntp.ValidateResponseMetadata(&ntpresp)
		if err != nil {
			return time.Time{}, 0, err
		}

		c.Log.LogAttrs(ctx, slog.LevelDebug, "received response",
			slog.Time("at", cRxTime),
			slog.String("from", reference),
			slog.Bool("auth", authenticated),
			slog.Any("data", ntp.PacketLogValuer{Pkt: &ntpresp}),
		)

		sRxTime := ntp.TimeFromTime64(ntpresp.ReceiveTime, cTxTime0)
		sTxTime := ntp.TimeFromTime64(ntpresp.TransmitTime, cTxTime0)

		var t0, t1, t2, t3 time.Time
		if interleavedResp {
			t0 = ntp.TimeFromTime64(c.prev.cTxTime, cTxTime0)
			t1 = ntp.TimeFromTime64(c.prev.sRxTime, cTxTime0)
			t2 = sTxTime
			t3 = ntp.TimeFromTime64(c.prev.cRxTime, cTxTime0)
		} else {
			t0 = cTxTime1
			t1 = sRxTime
			t2 = sTxTime
			t3 = cRxTime
		}

		err = ntp.ValidateResponseTimestamps(t0, t1, t2, t3)
		if err != nil {
			return time.Time{}, 0, err
		}

		off := ntp.ClockOffset(t0, t1, t2, t3)
		rtd := ntp.RoundTripDelay(t0, t1, t2, t3)

		mtrcs.respsAccepted.Inc()
		if interleavedResp {
			mtrcs.respsAcceptedInterleaved.Inc()
		}
		c.Log.LogAttrs(ctx, slog.LevelDebug, "evaluated response",
			slog.Time("at", cRxTime),
			slog.String("from", reference),
			slog.Bool("interleaved", interleavedResp),
			slog.Duration("clock offset", off),
			slog.Duration("round trip delay", rtd),
		)

		if c.InterleavedMode {
			c.prev.reference = reference
			c.prev.interleaved = interleavedResp
			c.prev.cTxTime = ntp.Time64FromTime(cTxTime1)
			c.prev.cRxTime = ntp.Time64FromTime(cRxTime)
			c.prev.sRxTime = ntpresp.ReceiveTime
		}

		timestamp = cRxTime
		if c.Filter == nil {
			offset = off
		} else {
			offset = c.Filter.Do(t0, t1, t2, t3)
		}

		if c.Histogram != nil {
			err := c.Histogram.RecordValue(rtd.Microseconds())
			if err != nil {
				return time.Time{}, 0, err
			}
		}

		break
	}

	return timestamp, offset, nil
}
