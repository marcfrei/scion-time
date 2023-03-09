package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"go.uber.org/zap"

	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ntp"
	"example.com/scion-time/net/udp"

	"gitlab.com/hacklunch/ntske"
)

type IPNTSClient struct {
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

func (c *IPNTSClient) measureClockOffsetIP(ctx context.Context, log *zap.Logger,
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
	remoteAddr.Port = int(c.KeyExchange.Meta.Port)
	remoteAddr.IP = net.ParseIP(c.KeyExchange.Meta.Server)

	buf := make([]byte, 228)
	reference := remoteAddr.String()
	cTxTime0 := timebase.Now()

	ntpreq := createPacket(c, cTxTime0)
	ntp.EncodePacketNTS(&buf, &ntpreq)

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

	// receive validate and unpack packet
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
		var cookies [][]byte = make([][]byte, 0, 6)
		err = ntp.DecodePacketNTS(&ntpresp, buf, &cookies, c.KeyExchange.Meta.S2cKey)
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

		c.KeyExchange.Meta.Cookie = c.KeyExchange.Meta.Cookie[1:]
		for _, cookie := range cookies {
			c.KeyExchange.Meta.Cookie = append(c.KeyExchange.Meta.Cookie, cookie)
		}

		return calcOffset(ntpresp, cTxTime1, cRxTime, log, reference)
	}
}

func createPacket(c *IPNTSClient, cTxTime0 time.Time) ntp.Packet {
	ntpreq := ntp.Packet{}
	ntpreq.SetVersion(ntp.VersionMax)
	ntpreq.SetMode(ntp.ModeClient)
	ntpreq.TransmitTime = ntp.Time64FromTime(cTxTime0)

	var uqext ntp.UniqueIdentifier

	uqext.Generate()
	ntpreq.AddExt(uqext)

	var cookie ntp.Cookie

	cookie.Cookie = c.KeyExchange.Meta.Cookie[0]
	ntpreq.AddExt(cookie)

	var auth ntp.Authenticator

	auth.Key = c.KeyExchange.Meta.C2sKey
	ntpreq.AddExt(auth)
	return ntpreq
}

func calcOffset(ntpresp ntp.Packet, cTxTime1 time.Time, cRxTime time.Time, log *zap.Logger, reference string) (offset time.Duration, weight float64, err error) {

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

	return offset, weight, nil
}
