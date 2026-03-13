package client

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"

	"example.com/scion-time/core/timebase"
	"example.com/scion-time/net/csptp"
	"example.com/scion-time/net/ip"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

type CSPTPClientSCION struct {
	Log        *slog.Logger
	DSCP       uint8
	sequenceID uint16
}

type csptpReplySCION struct {
	msg csptp.Message
	tlv csptp.ResponseTLV
	rxt time.Time
	ok  bool
}

type csptpRepliesSCION struct {
	mu       sync.Mutex
	sync     csptpReplySCION
	followUp csptpReplySCION
}

func (c *CSPTPClientSCION) readCSPTPReplySCION(ctx context.Context,
	conn *net.UDPConn, localAddr, remoteAddr udp.UDPAddr, deadline time.Time, deadlineSet bool,
	sequenceID uint16, messageType uint8, replies *csptpRepliesSCION) error {
	buf := make([]byte, scion.MTU)
	oob := make([]byte, udp.TimestampLen())

	const maxNumRetries = 3
rxloop:
	for numRetries := 0; ; numRetries++ {
		buf = buf[:cap(buf)]
		oob = oob[:cap(oob)]
		n, oobn, flags, _, err := conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet", slog.Any("error", err))
				continue
			}
			return err
		}
		if flags != 0 {
			err = errUnexpectedPacketFlags
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet", slog.Int("flags", flags))
				continue
			}
			return err
		}
		oob = oob[:oobn]
		rxt, err := udp.TimestampFromOOBData(oob)
		if err != nil {
			rxt = timebase.Now()
			c.Log.LogAttrs(ctx, slog.LevelError, "failed to read packet rx timestamp", slog.Any("error", err))
		}
		buf = buf[:n]

		var (
			scionLayer slayers.SCION
			hbhLayer   slayers.HopByHopExtnSkipper
			e2eLayer   slayers.EndToEndExtn
			udpLayer   slayers.UDP
			scmpLayer  slayers.SCMP
		)
		parser := gopacket.NewDecodingLayerParser(
			slayers.LayerTypeSCION, &scionLayer, &hbhLayer, &e2eLayer, &udpLayer, &scmpLayer,
		)
		parser.IgnoreUnsupported = true
		decoded := make([]gopacket.LayerType, 4)
		err = parser.DecodeLayers(buf, &decoded)
		if err != nil {
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet", slog.Any("error", err))
				continue
			}
			return err
		}
		validType := len(decoded) >= 2 && (decoded[len(decoded)-1] == slayers.LayerTypeSCIONUDP ||
			decoded[len(decoded)-1] == slayers.LayerTypeSCMP)
		if !validType {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet", slog.String("cause", "unexpected type or structure"))
				continue
			}
			return err
		}
		if decoded[len(decoded)-1] == slayers.LayerTypeSCMP {
			err = errUnexpectedPacket
			c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to handle packet",
				slog.String("cause", "unexpected SCMP message type"),
				slog.Uint64("type", uint64(scmpLayer.TypeCode.Type())),
				slog.Uint64("code", uint64(scmpLayer.TypeCode.Code())))
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				continue
			}
			return err
		}
		if len(buf) < int(udpLayer.Length) {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "received packet with unexpected type or structure")
				continue
			}
			return err
		}
		validSrc := scionLayer.SrcIA == remoteAddr.IA &&
			ip.CompareIPs(scionLayer.RawSrcAddr, remoteAddr.Host.IP) == 0
		validDst := scionLayer.DstIA == localAddr.IA &&
			ip.CompareIPs(scionLayer.RawDstAddr, localAddr.Host.IP) == 0
		if !validSrc || !validDst {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				if !validSrc {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received packet from unexpected source")
				}
				if !validDst {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received packet to unexpected destination")
				}
				continue
			}
			return err
		}

		var respmsg csptp.Message
		err = csptp.DecodeMessage(&respmsg, udpLayer.Payload)
		if err != nil {
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
				continue
			}
			return err
		}

		if len(udpLayer.Payload) != int(respmsg.MessageLength) {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
				continue
			}
			return err
		}

		if respmsg.SequenceID != sequenceID || respmsg.MessageType() != messageType {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
				continue
			}
			return err
		}

		reply := csptpReplySCION{msg: respmsg, rxt: rxt, ok: true}

		switch messageType {
		case csptp.MessageTypeSync:
			if udpLayer.SrcPort != csptp.EventPortSCION {
				err = errUnexpectedPacketSource
				if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet: unexpected source")
					continue
				}
				return err
			}

			tlvbuf := udpLayer.Payload[csptp.MinMessageLength:]
			for len(tlvbuf) >= csptp.MinTLVLength {
				var tlvhdr csptp.TLVHeader
				err := csptp.DecodeTLVHeader(&tlvhdr, tlvbuf)
				if err != nil {
					if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
						c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
						continue rxloop
					}
					return err
				}
				if len(tlvbuf) < int(tlvhdr.Length) {
					err = errUnexpectedPacket
					if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
						c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
						continue rxloop
					}
					return err
				}
				tlvbuf = tlvbuf[tlvhdr.Length:]
			}
			if len(tlvbuf) != 0 {
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
					continue
				}
				return err
			}

			if respmsg.FlagField&csptp.FlagTwoStep != csptp.FlagTwoStep { // TODO: support one-step
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received one-step Sync message")
					continue
				}
				return err
			}

			replies.mu.Lock()
			replies.sync = reply
			replies.mu.Unlock()
			return nil
		case csptp.MessageTypeFollowUp:
			if udpLayer.SrcPort != csptp.GeneralPortSCION {
				err = errUnexpectedPacketSource
				if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet: unexpected source")
					continue
				}
				return err
			}

			var resptlvOk bool
			tlvbuf := udpLayer.Payload[csptp.MinMessageLength:]
			for len(tlvbuf) >= csptp.MinTLVLength {
				var tlvhdr csptp.TLVHeader
				err := csptp.DecodeTLVHeader(&tlvhdr, tlvbuf)
				if err != nil {
					if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
						c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
						continue rxloop
					}
					return err
				}
				if len(tlvbuf) < int(tlvhdr.Length) {
					err = errUnexpectedPacket
					if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
						c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
						continue rxloop
					}
					return err
				}
				if tlvhdr.Type == csptp.TLVTypeOrganizationExtension {
					var tlv csptp.ResponseTLV
					err := csptp.DecodeResponseTLV(&tlv, tlvbuf)
					if err != nil {
						if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
							c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
							continue rxloop
						}
						return err
					}
					if tlv.OrganizationID[0] != csptp.OrganizationIDMeinberg0 ||
						tlv.OrganizationID[1] != csptp.OrganizationIDMeinberg1 ||
						tlv.OrganizationID[2] != csptp.OrganizationIDMeinberg2 ||
						tlv.OrganizationSubType[0] != csptp.OrganizationSubTypeResponse0 ||
						tlv.OrganizationSubType[1] != csptp.OrganizationSubTypeResponse1 ||
						tlv.OrganizationSubType[2] != csptp.OrganizationSubTypeResponse2 {
						err = errUnexpectedPacket
						if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
							c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
							continue rxloop
						}
						return err
					}
					reply.tlv, resptlvOk = tlv, true
				}
				tlvbuf = tlvbuf[tlvhdr.Length:]
			}
			if len(tlvbuf) != 0 {
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
					continue
				}
				return err
			}
			if !resptlvOk {
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
					continue
				}
				return err
			}

			replies.mu.Lock()
			replies.followUp = reply
			replies.mu.Unlock()
			return nil
		default:
			panic("unexpected CSPTP message type")
		}
	}
}

func (c *CSPTPClientSCION) MeasureClockOffset(ctx context.Context, localAddr, remoteAddr udp.UDPAddr, path snet.Path) (
	timestamp time.Time, offset time.Duration, err error) {
	laddr, ok := netip.AddrFromSlice(localAddr.Host.IP)
	if !ok {
		panic(errUnexpectedAddrType)
	}
	deadline, deadlineSet := ctx.Deadline()
	var lc net.ListenConfig
	openConn := func(port uint16) (*net.UDPConn, error) {
		pconn, err := lc.ListenPacket(ctx, "udp", netip.AddrPortFrom(laddr, port).String())
		if err != nil {
			return nil, err
		}
		conn := pconn.(*net.UDPConn)
		if deadlineSet {
			err = conn.SetDeadline(deadline)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
		}
		err = udp.EnableTimestamping(conn, localAddr.Host.Zone, -1 /* index */)
		if err != nil {
			c.Log.LogAttrs(ctx, slog.LevelError, "failed to enable timestamping", slog.Any("error", err))
		}
		err = udp.SetDSCP(conn, c.DSCP)
		if err != nil {
			c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to set DSCP", slog.Any("error", err))
		}
		return conn, nil
	}
	econn, err := openConn(csptp.EventPortSCION)
	if err != nil {
		return time.Time{}, 0, err
	}
	defer func() { _ = econn.Close() }()
	gconn, err := openConn(csptp.GeneralPortSCION)
	if err != nil {
		return time.Time{}, 0, err
	}
	defer func() { _ = gconn.Close() }()

	ip4 := remoteAddr.Host.IP.To4()
	if ip4 != nil {
		remoteAddr.Host.IP = ip4
	}

	nextHop := path.UnderlayNextHop().AddrPort()
	nextHopAddr := nextHop.Addr()
	if nextHopAddr.Is4In6() {
		nextHop = netip.AddrPortFrom(
			netip.AddrFrom4(nextHopAddr.As4()),
			nextHop.Port())
	}

	var cTxTime0, cTxTime1 time.Time

	buf := make([]byte, scion.MTU)
	var n int

	reference := remoteAddr.IA.String() + "," + remoteAddr.Host.String()
	pathFingerprint := snet.Fingerprint(pathInterfaces(path)).String()

	var reqmsg csptp.Message
	var reqtlv csptp.RequestTLV

	reqmsg = csptp.Message{
		SdoIDMessageType: csptp.SdoIDMessageType(
			csptp.SdoID,
			csptp.MessageTypeSync,
		),
		PTPVersion:          csptp.PTPVersion,
		MessageLength:       csptp.MinMessageLength,
		DomainNumber:        csptp.DomainNumber,
		MinorSdoID:          csptp.MinorSdoID,
		FlagField:           csptp.FlagTwoStep | csptp.FlagUnicast,
		CorrectionField:     0,
		MessageTypeSpecific: 0,
		SourcePortIdentity: csptp.PortID{
			ClockID: 0,
			Port:    1,
		},
		SequenceID:         c.sequenceID,
		ControlField:       csptp.ControlSync,
		LogMessageInterval: 0,
		Timestamp:          csptp.Timestamp{},
	}

	buf = buf[:reqmsg.MessageLength]
	csptp.EncodeMessage(buf, &reqmsg)

	var scionLayer slayers.SCION
	scionLayer.TrafficClass = c.DSCP << 2
	scionLayer.SrcIA = localAddr.IA
	srcAddrIP, ok := netip.AddrFromSlice(localAddr.Host.IP)
	if !ok {
		panic(errUnexpectedAddrType)
	}
	err = scionLayer.SetSrcAddr(addr.HostIP(srcAddrIP.Unmap()))
	if err != nil {
		panic(err)
	}
	scionLayer.DstIA = remoteAddr.IA
	dstAddrIP, ok := netip.AddrFromSlice(remoteAddr.Host.IP)
	if !ok {
		panic(errUnexpectedAddrType)
	}
	err = scionLayer.SetDstAddr(addr.HostIP(dstAddrIP.Unmap()))
	if err != nil {
		panic(err)
	}
	err = path.Dataplane().SetPath(&scionLayer)
	if err != nil {
		panic(err)
	}
	scionLayer.NextHdr = slayers.L4UDP

	var udpLayer slayers.UDP
	udpLayer.SrcPort = csptp.EventPortSCION
	udpLayer.DstPort = csptp.EventPortSCION
	udpLayer.SetNetworkLayerForChecksum(&scionLayer)

	payload := gopacket.Payload(buf)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err = payload.SerializeTo(buffer, options)
	if err != nil {
		panic(err)
	}
	buffer.PushLayer(payload.LayerType())

	err = udpLayer.SerializeTo(buffer, options)
	if err != nil {
		panic(err)
	}
	buffer.PushLayer(udpLayer.LayerType())

	err = scionLayer.SerializeTo(buffer, options)
	if err != nil {
		panic(err)
	}
	buffer.PushLayer(scionLayer.LayerType())

	if remoteAddr.IA == localAddr.IA {
		nextHop = netip.AddrPortFrom(nextHop.Addr(), csptp.EventPortSCION)
	}
	n, err = econn.WriteToUDPAddrPort(buffer.Bytes(), nextHop)
	if err != nil {
		return time.Time{}, 0, err
	}
	if n != len(buffer.Bytes()) {
		return time.Time{}, 0, errWrite
	}
	cTxTime0, id, err := udp.ReadTXTimestamp(econn, 0)
	if err != nil || id != 0 {
		cTxTime0 = timebase.Now()
		c.Log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp", slog.Any("error", err))
	}

	buf = buf[:cap(buf)]

	reqmsg = csptp.Message{
		SdoIDMessageType: csptp.SdoIDMessageType(
			csptp.SdoID,
			csptp.MessageTypeFollowUp,
		),
		PTPVersion:          csptp.PTPVersion,
		MessageLength:       csptp.MinMessageLength,
		DomainNumber:        csptp.DomainNumber,
		MinorSdoID:          csptp.MinorSdoID,
		FlagField:           csptp.FlagUnicast,
		CorrectionField:     0,
		MessageTypeSpecific: 0,
		SourcePortIdentity: csptp.PortID{
			ClockID: 0,
			Port:    1,
		},
		SequenceID:         c.sequenceID,
		ControlField:       csptp.ControlFollowUp,
		LogMessageInterval: 0,
		Timestamp:          csptp.Timestamp{},
	}
	reqtlv = csptp.RequestTLV{
		Type:   csptp.TLVTypeOrganizationExtension,
		Length: 0,
		OrganizationID: [3]uint8{
			csptp.OrganizationIDMeinberg0,
			csptp.OrganizationIDMeinberg1,
			csptp.OrganizationIDMeinberg2},
		OrganizationSubType: [3]uint8{
			csptp.OrganizationSubTypeRequest0,
			csptp.OrganizationSubTypeRequest1,
			csptp.OrganizationSubTypeRequest2},
		FlagField: csptp.TLVFlagServerStateDS,
	}
	reqmsg.MessageLength += uint16(csptp.RequestTLVLength(&reqtlv))
	reqtlv.Length = uint16(csptp.RequestTLVLength(&reqtlv))

	buf = buf[:reqmsg.MessageLength]
	csptp.EncodeMessage(buf[:csptp.MinMessageLength], &reqmsg)
	csptp.EncodeRequestTLV(buf[csptp.MinMessageLength:], &reqtlv)

	scionLayer.TrafficClass = c.DSCP << 2
	scionLayer.SrcIA = localAddr.IA
	srcAddrIP, ok = netip.AddrFromSlice(localAddr.Host.IP)
	if !ok {
		panic(errUnexpectedAddrType)
	}
	err = scionLayer.SetSrcAddr(addr.HostIP(srcAddrIP.Unmap()))
	if err != nil {
		panic(err)
	}
	scionLayer.DstIA = remoteAddr.IA
	dstAddrIP, ok = netip.AddrFromSlice(remoteAddr.Host.IP)
	if !ok {
		panic(errUnexpectedAddrType)
	}
	err = scionLayer.SetDstAddr(addr.HostIP(dstAddrIP.Unmap()))
	if err != nil {
		panic(err)
	}
	err = path.Dataplane().SetPath(&scionLayer)
	if err != nil {
		panic(err)
	}
	scionLayer.NextHdr = slayers.L4UDP

	udpLayer.SrcPort = csptp.GeneralPortSCION
	udpLayer.DstPort = csptp.GeneralPortSCION
	udpLayer.SetNetworkLayerForChecksum(&scionLayer)

	payload = gopacket.Payload(buf)

	err = buffer.Clear()
	if err != nil {
		panic(err)
	}

	err = payload.SerializeTo(buffer, options)
	if err != nil {
		panic(err)
	}
	buffer.PushLayer(payload.LayerType())

	err = udpLayer.SerializeTo(buffer, options)
	if err != nil {
		panic(err)
	}
	buffer.PushLayer(udpLayer.LayerType())

	err = scionLayer.SerializeTo(buffer, options)
	if err != nil {
		panic(err)
	}
	buffer.PushLayer(scionLayer.LayerType())

	if remoteAddr.IA == localAddr.IA {
		nextHop = netip.AddrPortFrom(nextHop.Addr(), csptp.GeneralPortSCION)
	}
	n, err = gconn.WriteToUDPAddrPort(buffer.Bytes(), nextHop)
	if err != nil {
		return time.Time{}, 0, err
	}
	if n != len(buffer.Bytes()) {
		return time.Time{}, 0, errWrite
	}
	cTxTime1, id, err = udp.ReadTXTimestamp(gconn, 0)
	if err != nil || id != 0 {
		cTxTime1 = timebase.Now()
		c.Log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp", slog.Any("error", err))
	}
	_ = cTxTime1

	var replies csptpRepliesSCION
	rxerrch := make(chan error, 2)
	go func() {
		rxerrch <- c.readCSPTPReplySCION(
			ctx, econn, localAddr, remoteAddr, deadline, deadlineSet,
			c.sequenceID, csptp.MessageTypeSync, &replies)
	}()
	go func() {
		rxerrch <- c.readCSPTPReplySCION(
			ctx, gconn, localAddr, remoteAddr, deadline, deadlineSet,
			c.sequenceID, csptp.MessageTypeFollowUp, &replies)
	}()
	for range 2 {
		err = <-rxerrch
		if err != nil {
			return time.Time{}, 0, err
		}
	}

	replies.mu.Lock()
	syncReply := replies.sync
	followUpReply := replies.followUp
	replies.mu.Unlock()
	if !syncReply.ok || !followUpReply.ok {
		return time.Time{}, 0, errUnexpectedPacket
	}

	respmsg0 := syncReply.msg
	cRxTime0 := syncReply.rxt
	respmsg1 := followUpReply.msg
	resptlv := followUpReply.tlv
	cRxTime1 := followUpReply.rxt

	c.Log.LogAttrs(ctx, slog.LevelDebug, "received response",
		slog.Time("at", cRxTime1),
		slog.String("from", reference),
		slog.Any("respmsg0", &respmsg0),
		slog.Any("respmsg1", &respmsg1),
		slog.Any("resptlv", &resptlv),
	)

	t0 := cTxTime0
	t1 := csptp.TimeFromTimestamp(resptlv.RequestIngressTimestamp)
	t1Corr := csptp.DurationFromTimeInterval(resptlv.RequestCorrectionField)
	t2 := csptp.TimeFromTimestamp(respmsg1.Timestamp)
	t3 := cRxTime0
	t3Corr := csptp.DurationFromTimeInterval(respmsg0.CorrectionField) +
		csptp.DurationFromTimeInterval(respmsg1.CorrectionField)
	var utcCorr time.Duration
	if respmsg1.FlagField&csptp.FlagCurrentUTCOffsetValid == csptp.FlagCurrentUTCOffsetValid {
		utcCorr = time.Duration(int64(resptlv.UTCOffset) * time.Second.Nanoseconds())
	}

	c2sDelay := csptp.C2SDelay(t0, t1, t1Corr, utcCorr)
	s2cDelay := csptp.S2CDelay(t2, t3, t3Corr, utcCorr)
	clockOffset := csptp.ClockOffset(t0, t1, t2, t3, t1Corr, t3Corr)
	meanPathDelay := csptp.MeanPathDelay(t0, t1, t2, t3, t1Corr, t3Corr)

	c.Log.LogAttrs(ctx, slog.LevelDebug, "evaluated response",
		slog.Time("at", cRxTime1),
		slog.String("from", reference),
		slog.String("via", pathFingerprint),
		slog.Duration("C2S delay", c2sDelay),
		slog.Duration("S2C delay", s2cDelay),
		slog.Duration("clock offset", clockOffset),
		slog.Duration("mean path delay", meanPathDelay),
	)

	timestamp = cRxTime0
	offset = clockOffset

	c.sequenceID++
	return
}
