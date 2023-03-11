package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.uber.org/zap"

	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ntp"
	"example.com/scion-time/net/ntske"
	"example.com/scion-time/net/udp"
)

type IPClient struct {
	InterleavedMode bool
	IsAuthorized    bool
	auth            struct {
		keyExchangeNTS *ntske.KeyExchange
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

func keyExchange(server string, c *tls.Config, debug bool, log *zap.Logger) (*ntske.KeyExchange, error) {
	ke, err := ntske.Connect(server, c, debug)
	if err != nil {
		log.Error("Connection failure", zap.String("Server", server), zap.Error(err))
		return nil, err
	}

	err = ke.Exchange()
	if err != nil {
		log.Error("NTS-KE exchange error", zap.Error(err))
		return nil, err
	}

	if len(ke.Meta.Cookie) == 0 {
		log.Error("Received no cookies")
		return nil, errors.New("received no cookies")
	}

	if ke.Meta.Algo != ntske.AES_SIV_CMAC_256 {
		log.Error("unknown algorithm in NTS-KE")
		return nil, errors.New("unknown algorithm in NTS-KE")
	}

	err = ke.ExportKeys()
	if err != nil {
		log.Error("export key failure", zap.Error(err))
		return nil, err
	}

	return ke, nil
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

func (c *IPClient) measureClockOffsetIP(ctx context.Context, log *zap.Logger,
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

	if c.IsAuthorized {
		remoteAddr.Port = int(c.auth.keyExchangeNTS.Meta.Port)
		remoteAddr.IP = net.ParseIP(c.auth.keyExchangeNTS.Meta.Server)
	}

	buf := make([]byte, ntp.PacketLen)

	reference := remoteAddr.String()
	cTxTime0 := timebase.Now()

	ntpreq := ntp.Packet{}
	ntpreq.SetVersion(ntp.VersionMax)
	ntpreq.SetMode(ntp.ModeClient)
	if c.InterleavedMode && reference == c.prev.reference &&
		cTxTime0.Sub(ntp.TimeFromTime64(c.prev.cTxTime)) <= time.Second {
		ntpreq.OriginTime = c.prev.sRxTime
		ntpreq.ReceiveTime = c.prev.cRxTime
		ntpreq.TransmitTime = c.prev.cTxTime
	} else {
		ntpreq.TransmitTime = ntp.Time64FromTime(cTxTime0)
	}

	// add NTS extension fields to packet
	if c.IsAuthorized {
		var uqext ntp.UniqueIdentifier
		uqext.Generate()
		ntpreq.AddExt(uqext)

		var cookie ntp.Cookie
		cookie.Cookie = c.auth.keyExchangeNTS.Meta.Cookie[0]
		ntpreq.AddExt(cookie)

		// add cookie extension fields here until 8 cookies in total in keyexchange storage
		var cookiePlaceholderData []byte = make([]byte, len(cookie.Cookie))
		for i := len(c.auth.keyExchangeNTS.Meta.Cookie); i < 8; i++ {
			var cookiePlacholder ntp.CookiePlaceholder
			cookiePlacholder.Cookie = cookiePlaceholderData
			ntpreq.AddExt(cookiePlacholder)
		}

		var auth ntp.Authenticator
		auth.Key = c.auth.keyExchangeNTS.Meta.C2sKey
		ntpreq.AddExt(auth)
	}

	ntp.EncodePacket(&buf, &ntpreq)

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
		var key []byte
		var cookies [][]byte = make([][]byte, 0, 6)
		if c.IsAuthorized {
			key = c.auth.keyExchangeNTS.Meta.S2cKey
		}
		err = ntp.DecodePacket(&ntpresp, buf, &cookies, key)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				log.Info("failed to decode packet payload", zap.Error(err))
				numRetries++
				continue
			}
			return offset, weight, err
		}

		// remove first cookie as it has now been used and add all new received cookies to queue
		if c.IsAuthorized {
			c.auth.keyExchangeNTS.Meta.Cookie = c.auth.keyExchangeNTS.Meta.Cookie[1:]
			for _, cookie := range cookies {
				c.auth.keyExchangeNTS.Meta.Cookie = append(c.auth.keyExchangeNTS.Meta.Cookie, cookie)
			}

		}

		interleaved := false
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
