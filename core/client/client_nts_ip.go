package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"

	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ntp"
	"example.com/scion-time/net/udp"

	"gitlab.com/hacklunch/ntske"
)

type IPNtsClient struct {
	KeyExchange *ntske.KeyExchange
}

func tlsSetup(insecure bool) (*tls.Config, error) {
	// Enable experimental TLS 1.3
	//os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")

	c := &tls.Config{}

	if insecure {
		c.InsecureSkipVerify = true
	}

	return c, nil
}

func keyExchange(server string, c *tls.Config, debug bool) (*ntske.KeyExchange, error) {
	ke, err := ntske.Connect(server, c, debug)
	if err != nil {
		return nil, fmt.Errorf("connection failure to %v: %v", server, err)
	}

	err = ke.Exchange()
	if err != nil {
		return nil, fmt.Errorf("NTS-KE exchange error: %v", err)
	}

	if len(ke.Meta.Cookie) == 0 {
		return nil, fmt.Errorf("received no cookies")
	}

	if ke.Meta.Algo != ntske.AES_SIV_CMAC_256 {
		return nil, fmt.Errorf("unknown algorithm in NTS-KE")
	}

	err = ke.ExportKeys()
	if err != nil {
		return nil, fmt.Errorf("export key failure: %v", err)
	}

	return ke, nil
}

func (c *IPNtsClient) measureClockOffsetIP(ctx context.Context, log *zap.Logger,
	localAddr, remoteAddr *net.UDPAddr) (
	offset time.Duration, weight float64, err error) {
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

	buf := make([]byte, 228)

	reference := remoteAddr.String()
	cTxTime0 := timebase.Now()

	ntpreq := ntp.Packet{}
	ntpreq.SetVersion(ntp.VersionMax)
	ntpreq.SetMode(ntp.ModeClient)
	ntpreq.TransmitTime = ntp.Time64FromTime(cTxTime0)

	if false {
		ntpreq.LVM = 227
		ntpreq.TransmitTime.Seconds = 2155189238
		ntpreq.TransmitTime.Fraction = 349935905
		ntpreq.ReceiveTime.Seconds = 633437444
		ntpreq.ReceiveTime.Fraction = 3671234141
		ntpreq.ReferenceTime.Seconds = 633437444
		ntpreq.ReferenceTime.Fraction = 3671234141
		ntpreq.OriginTime.Seconds = 633437444
		ntpreq.OriginTime.Fraction = 3671234141
	}

	var uqext ntp.UniqueIdentifier

	// Generate and remember a unique identifier for our packet
	_, err = uqext.Generate()
	ntpreq.AddExt(uqext)

	var cookie ntp.Cookie

	cookie.Cookie = c.KeyExchange.Meta.Cookie[0]
	ntpreq.AddExt(cookie)

	var auth ntp.Authenticator

	auth.Key = c.KeyExchange.Meta.C2sKey
	ntpreq.AddExt(auth)

	ntp.EncodePacketNTS(&buf, &ntpreq)

	remoteAddr.Port = int(c.KeyExchange.Meta.Port)
	remoteAddr.IP = net.ParseIP(c.KeyExchange.Meta.Server)

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
		err = ntp.DecodePacketNTS(&ntpresp, buf, c.KeyExchange.Meta.S2cKey)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				log.Info("failed to decode packet payload", zap.Error(err))
				numRetries++
				continue
			}
			return offset, weight, err
		}

		if ntpresp.OriginTime != ntpreq.TransmitTime {
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

		t0 = cTxTime1
		t1 = sRxTime
		t2 = sTxTime
		t3 = cRxTime

		err = ntp.ValidateResponseTimestamps(t0, t1, t1, t3)
		if err != nil {
			return offset, weight, err
		}

		off := ntp.ClockOffset(t0, t1, t2, t3)
		rtd := ntp.RoundTripDelay(t0, t1, t2, t3)

		log.Debug("evaluated response",
			zap.String("from", reference),
			zap.Duration("clock offset", off),
			zap.Duration("round trip delay", rtd),
		)

		offset, weight = filter(log, reference, t0, t1, t2, t3)

		break
	}

	return offset, weight, nil
}
