package client

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"go.uber.org/zap"

	"example.com/scion-time/base/metrics"

	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ntp"
	"example.com/scion-time/net/nts"
	"example.com/scion-time/net/ntske"
	"example.com/scion-time/net/udp"
)

type IPClient struct {
	InterleavedMode bool
	Auth            struct {
		KeyExchangeNTS *ntske.KeyExchange
		Enabled        bool
	}
	prev struct {
		reference string
		cTxTime   ntp.Time64
		cRxTime   ntp.Time64
		sRxTime   ntp.Time64
	}
}

type ipClientMetrics struct {
	reqsSent                 prometheus.Counter
	reqsSentInterleaved      prometheus.Counter
	pktsReceived             prometheus.Counter
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
	if x.Is4In6() {
		x = netip.AddrFrom4(x.As4())
	}
	if y.Is4In6() {
		y = netip.AddrFrom4(y.As4())
	}
	return x.Compare(y)
}

func (c *IPClient) ResetInterleavedMode() {
	c.prev.reference = ""
}

func (c *IPClient) measureClockOffsetIP(ctx context.Context, log *zap.Logger, mtrcs *ipClientMetrics,
	localAddr, remoteAddr *net.UDPAddr) (
	offset time.Duration, weight float64, err error) {
	// set up connection
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: localAddr.IP})
	if err != nil {
		return offset, weight, err
	}
	defer conn.Close()
	deadline, deadlineIsSet := ctx.Deadline()
	if deadlineIsSet {
		err = conn.SetDeadline(deadline)
		if err != nil {
			return offset, weight, err
		}
	}
	err = udp.EnableTimestamping(conn, localAddr.Zone)
	if err != nil {
		log.Error("failed to enable timestamping", zap.Error(err))
	}

	if c.Auth.Enabled {
		remoteAddr.Port = int(c.Auth.KeyExchangeNTS.Meta.Port)
		remoteAddr.IP = net.ParseIP(c.Auth.KeyExchangeNTS.Meta.Server)
	}

	buf := make([]byte, ntp.PacketLen)

	reference := remoteAddr.String()
	cTxTime0 := timebase.Now()
	interleaved := false

	ntpreq := ntp.Packet{}
	ntpreq.SetVersion(ntp.VersionMax)
	ntpreq.SetMode(ntp.ModeClient)
	if c.InterleavedMode && reference == c.prev.reference &&
		cTxTime0.Sub(ntp.TimeFromTime64(c.prev.cTxTime)) <= time.Second {
		interleaved = true
		ntpreq.OriginTime = c.prev.sRxTime
		ntpreq.ReceiveTime = c.prev.cRxTime
		ntpreq.TransmitTime = c.prev.cTxTime
	} else {
		ntpreq.TransmitTime = ntp.Time64FromTime(cTxTime0)
	}

	ntp.EncodePacket(&buf, &ntpreq)

	// add NTS extension fields to packet
	var ntsrespfields nts.NTSResponseFields
	ntsreq := nts.NTSPacket{}

	if c.Auth.Enabled {
		ntsreq.NTPHeader = buf
		var uqext nts.UniqueIdentifier
		uqext.Generate()
		ntsreq.AddExt(uqext)

		var cookie nts.Cookie
		cookie.Cookie = c.Auth.KeyExchangeNTS.Meta.Cookie[0]
		ntsreq.AddExt(cookie)

		// add cookie extension fields here s.t. 8 cookies are available after respondse
		var cookiePlaceholderData []byte = make([]byte, len(cookie.Cookie))
		for i := len(c.Auth.KeyExchangeNTS.Meta.Cookie); i < 8; i++ {
			var cookiePlacholder nts.CookiePlaceholder
			cookiePlacholder.Cookie = cookiePlaceholderData
			ntsreq.AddExt(cookiePlacholder)
		}

		var auth nts.Authenticator
		auth.Key = c.Auth.KeyExchangeNTS.Meta.C2sKey
		ntsreq.AddExt(auth)

		ntsrespfields.S2cKey = c.Auth.KeyExchangeNTS.Meta.S2cKey
		ntsrespfields.UniqueId = uqext.ID
		nts.EncodePacket(&buf, &ntsreq)
	}

	n, err := conn.WriteToUDPAddrPort(buf, remoteAddr.AddrPort())
	if err != nil {
		return offset, weight, err
	}
	if n != len(buf) {
		return offset, weight, errWrite
	}
	cTxTime1, id, err := udp.ReadTXTimestamp(conn)
	if err != nil || id != 0 {
		cTxTime1 = timebase.Now()
		log.Error("failed to read packet tx timestamp", zap.Error(err))
	}
	mtrcs.reqsSent.Inc()
	if interleaved {
		mtrcs.reqsSentInterleaved.Inc()
	}

	numRetries := 0
	oob := make([]byte, udp.TimestampLen())
	for {
		buf = buf[:cap(buf)]
		oob = oob[:cap(oob)]
		n, oobn, flags, srcAddr, err := conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				log.Info("failed to read packet", zap.Error(err))
				numRetries++
				continue
			}
			return offset, weight, err
		}
		if flags != 0 {
			err = errUnexpectedPacketFlags
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				log.Info("failed to read packet", zap.Int("flags", flags))
				numRetries++
				continue
			}
			return offset, weight, err
		}
		oob = oob[:oobn]
		cRxTime, err := udp.TimestampFromOOBData(oob)
		if err != nil {
			cRxTime = timebase.Now()
			log.Error("failed to read packet rx timestamp", zap.Error(err))
		}
		buf = buf[:n]
		mtrcs.pktsReceived.Inc()

		if compareAddrs(srcAddr.Addr(), remoteAddr.AddrPort().Addr()) != 0 {
			err = errUnexpectedPacketSource
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				log.Info("received packet from unexpected source")
				numRetries++
				continue
			}
			return offset, weight, err
		}

		var ntpresp ntp.Packet
		err = ntp.DecodePacket(&ntpresp, buf)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				log.Info("failed to decode packet payload", zap.Error(err))
				numRetries++
				continue
			}
			return offset, weight, err
		}

		// remove first cookie as it has now been used and add all new received cookies to queue
		var ntsresp nts.NTSPacket
		if c.Auth.Enabled {
			ntsresp.NTPHeader = buf
			nts.DecodePacket(&ntsresp, buf, &ntsrespfields)
			c.Auth.KeyExchangeNTS.Meta.Cookie = c.Auth.KeyExchangeNTS.Meta.Cookie[1:]
			for _, cookie := range ntsrespfields.Cookies {
				c.Auth.KeyExchangeNTS.Meta.Cookie = append(c.Auth.KeyExchangeNTS.Meta.Cookie, cookie)
			}

		}

		interleaved = false
		if c.InterleavedMode && ntpresp.OriginTime == c.prev.cRxTime {
			interleaved = true
		} else if ntpresp.OriginTime != ntpreq.TransmitTime {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				log.Info("received packet with unexpected type or structure")
				numRetries++
				continue
			}
			return offset, weight, err
		}

		err = ntp.ValidateResponseMetadata(&ntpresp)
		if err != nil {
			return offset, weight, err
		}

		log.Debug("received response",
			zap.Time("at", cRxTime),
			zap.String("from", reference),
			zap.Object("data", ntp.PacketMarshaler{Pkt: &ntpresp}),
		)

		sRxTime := ntp.TimeFromTime64(ntpresp.ReceiveTime)
		sTxTime := ntp.TimeFromTime64(ntpresp.TransmitTime)

		var t0, t1, t2, t3 time.Time
		if interleaved {
			t0 = ntp.TimeFromTime64(c.prev.cTxTime)
			t1 = ntp.TimeFromTime64(c.prev.sRxTime)
			t2 = sTxTime
			t3 = ntp.TimeFromTime64(c.prev.cRxTime)
		} else {
			t0 = cTxTime1
			t1 = sRxTime
			t2 = sTxTime
			t3 = cRxTime
		}

		err = ntp.ValidateResponseTimestamps(t0, t1, t1, t3)
		if err != nil {
			return offset, weight, err
		}

		off := ntp.ClockOffset(t0, t1, t2, t3)
		rtd := ntp.RoundTripDelay(t0, t1, t2, t3)

		mtrcs.respsAccepted.Inc()
		if interleaved {
			mtrcs.respsAcceptedInterleaved.Inc()
		}
		log.Debug("evaluated response",
			zap.String("from", reference),
			zap.Bool("interleaved", interleaved),
			zap.Duration("clock offset", off),
			zap.Duration("round trip delay", rtd),
		)

		if c.InterleavedMode {
			c.prev.reference = reference
			c.prev.cTxTime = ntp.Time64FromTime(cTxTime1)
			c.prev.cRxTime = ntp.Time64FromTime(cRxTime)
			c.prev.sRxTime = ntpresp.ReceiveTime
		}

		// offset, weight = off, 1000.0

		offset, weight = filter(log, reference, t0, t1, t2, t3)

		break
	}

	return offset, weight, nil
}
