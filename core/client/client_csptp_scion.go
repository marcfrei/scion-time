package client

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
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

func (c *CSPTPClientSCION) MeasureClockOffset(ctx context.Context, localAddr, remoteAddr udp.UDPAddr, path snet.Path) (
	timestamp time.Time, offset time.Duration, err error) {
	laddr, ok := netip.AddrFromSlice(localAddr.Host.IP)
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
	err = udp.EnableTimestamping(conn, localAddr.Host.Zone)
	if err != nil {
		c.Log.LogAttrs(ctx, slog.LevelError, "failed to enable timestamping", slog.Any("error", err))
	}
	err = udp.SetDSCP(conn, c.DSCP)
	if err != nil {
		c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to set DSCP", slog.Any("error", err))
	}

	localPort := conn.LocalAddr().(*net.UDPAddr).Port

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

	var cTxTime0, cTxTime1, cRxTime0, cRxTime1 time.Time

	buf := make([]byte, scion.MTU)
	var n int

	reference := remoteAddr.IA.String() + "," + remoteAddr.Host.String()

	var msg csptp.Message
	var reqtlv csptp.RequestTLV

	msg = csptp.Message{
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

	buf = buf[:msg.MessageLength]
	csptp.EncodeMessage(buf, &msg)

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
	udpLayer.SrcPort = uint16(localPort)
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
	n, err = conn.WriteToUDPAddrPort(buffer.Bytes(), nextHop)
	if err != nil {
		return time.Time{}, 0, err
	}
	if n != len(buffer.Bytes()) {
		return time.Time{}, 0, errWrite
	}
	cTxTime0, id, err := udp.ReadTXTimestamp(conn, 0)
	if err != nil || id != 0 {
		cTxTime0 = timebase.Now()
		c.Log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp", slog.Any("error", err))
	}

	buf = buf[:cap(buf)]

	msg = csptp.Message{
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
	msg.MessageLength += uint16(csptp.EncodedRequestTLVLength(&reqtlv))
	reqtlv.Length = uint16(csptp.EncodedRequestTLVLength(&reqtlv))

	buf = buf[:msg.MessageLength]
	csptp.EncodeMessage(buf[:csptp.MinMessageLength], &msg)
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

	udpLayer.SrcPort = uint16(localPort)
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
	n, err = conn.WriteToUDPAddrPort(buffer.Bytes(), nextHop)
	if err != nil {
		return time.Time{}, 0, err
	}
	if n != len(buffer.Bytes()) {
		return time.Time{}, 0, errWrite
	}
	cTxTime1, id, err = udp.ReadTXTimestamp(conn, 0)
	if err != nil || id != 0 {
		cTxTime1 = timebase.Now()
		c.Log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp", slog.Any("error", err))
	}
	_ = cTxTime1

	oob := make([]byte, udp.TimestampLen())
	var oobn, flags int
	var lastHop netip.AddrPort

	var respmsg0, respmsg1 csptp.Message
	var resptlv csptp.ResponseTLV
	var respmsg0Ok, respmsg1Ok bool

	const maxNumRetries = 3
	for numRetries := 0; ; numRetries++ {
		buf = buf[:cap(buf)]
		oob = oob[:cap(oob)]
		n, oobn, flags, lastHop, err = conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet", slog.Any("error", err))
				continue
			}
			return time.Time{}, 0, err
		}
		if flags != 0 {
			err = errUnexpectedPacketFlags
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet", slog.Int("flags", flags))
				continue
			}
			return time.Time{}, 0, err
		}
		oob = oob[:oobn]
		rxt, err := udp.TimestampFromOOBData(oob)
		if err != nil {
			rxt = timebase.Now()
			c.Log.LogAttrs(ctx, slog.LevelError, "failed to read packet rx timestamp", slog.Any("error", err))
		}
		buf = buf[:n]

		var (
			hbhLayer  slayers.HopByHopExtnSkipper
			e2eLayer  slayers.EndToEndExtn
			scmpLayer slayers.SCMP
		)
		parser := gopacket.NewDecodingLayerParser(
			slayers.LayerTypeSCION, &scionLayer, &hbhLayer, &e2eLayer, &udpLayer, &scmpLayer,
		)
		parser.IgnoreUnsupported = true
		decoded := make([]gopacket.LayerType, 4)
		err = parser.DecodeLayers(buf, &decoded)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet", slog.Any("error", err))
				continue
			}
			return time.Time{}, 0, err
		}
		validType := len(decoded) >= 2 && (decoded[len(decoded)-1] == slayers.LayerTypeSCIONUDP ||
			decoded[len(decoded)-1] == slayers.LayerTypeSCMP)
		if !validType {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet", slog.String("cause", "unexpected type or structure"))
				continue
			}
			return time.Time{}, 0, err
		}
		if decoded[len(decoded)-1] == slayers.LayerTypeSCMP {
			err = errUnexpectedPacket
			c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to handle packet",
				slog.String("cause", "unexpected SCMP message type"),
				slog.Uint64("type", uint64(scmpLayer.TypeCode.Type())),
				slog.Uint64("code", uint64(scmpLayer.TypeCode.Code())))
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				continue
			}
			return time.Time{}, 0, err
		}
		if len(buf) < int(udpLayer.Length) {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "received packet with unexpected type or structure")
				continue
			}
			return time.Time{}, 0, err
		}
		validSrc := scionLayer.SrcIA == remoteAddr.IA &&
			ip.CompareIPs(scionLayer.RawSrcAddr, remoteAddr.Host.IP) == 0
		validDst := scionLayer.DstIA == localAddr.IA &&
			ip.CompareIPs(scionLayer.RawDstAddr, localAddr.Host.IP) == 0
		if !validSrc || !validDst {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				if !validSrc {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received packet from unexpected source")
				}
				if !validDst {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received packet to unexpected destination")
				}
				continue
			}
			return time.Time{}, 0, err
		}

		err = csptp.DecodeMessage(&msg, udpLayer.Payload[:csptp.MinMessageLength])
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
				continue
			}
			return time.Time{}, 0, err
		}

		if len(udpLayer.Payload) != int(msg.MessageLength) {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
				continue
			}
			return time.Time{}, 0, err
		}

		if msg.SequenceID != c.sequenceID {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
				continue
			}
			return time.Time{}, 0, err
		}

		if msg.MessageType() == csptp.MessageTypeSync {
			respmsg0Ok = false

			if udpLayer.SrcPort != csptp.EventPortSCION {
				err = errUnexpectedPacketSource
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet: unexpected source")
					continue
				}
				return time.Time{}, 0, err
			}

			if len(udpLayer.Payload)-csptp.MinMessageLength != 0 {
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
					continue
				}
				return time.Time{}, 0, err
			}

			if msg.FlagField&csptp.FlagTwoStep != csptp.FlagTwoStep { // TODO: support one-step
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received one-step Sync message")
					continue
				}
				return time.Time{}, 0, err
			}

			cRxTime0 = rxt
			respmsg0, respmsg0Ok = msg, true
		} else if msg.MessageType() == csptp.MessageTypeFollowUp {
			respmsg1Ok = false

			if udpLayer.SrcPort != csptp.GeneralPortSCION {
				err = errUnexpectedPacketSource
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet: unexpected source")
					continue
				}
				return time.Time{}, 0, err
			}

			err = csptp.DecodeResponseTLV(&resptlv, udpLayer.Payload[csptp.MinMessageLength:])
			if err != nil {
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
					continue
				}
				return time.Time{}, 0, err
			}
			if resptlv.Type != csptp.TLVTypeOrganizationExtension ||
				resptlv.OrganizationID[0] != csptp.OrganizationIDMeinberg0 ||
				resptlv.OrganizationID[1] != csptp.OrganizationIDMeinberg1 ||
				resptlv.OrganizationID[2] != csptp.OrganizationIDMeinberg2 ||
				resptlv.OrganizationSubType[0] != csptp.OrganizationSubTypeResponse0 ||
				resptlv.OrganizationSubType[1] != csptp.OrganizationSubTypeResponse1 ||
				resptlv.OrganizationSubType[2] != csptp.OrganizationSubTypeResponse2 {
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
					continue
				}
				return time.Time{}, 0, err
			}

			if len(udpLayer.Payload)-csptp.MinMessageLength != csptp.EncodedResponseTLVLength(&resptlv) {
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
					continue
				}
				return time.Time{}, 0, err
			}

			cRxTime1 = rxt
			respmsg1, respmsg1Ok = msg, true
		} else {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
				continue
			}
			return time.Time{}, 0, err
		}

		if respmsg0Ok && respmsg1Ok {
			break
		}
	}

	dscp := scionLayer.TrafficClass >> 2

	c.Log.LogAttrs(ctx, slog.LevelDebug, "received response",
		slog.Time("at", cRxTime1),
		slog.String("from", reference),
		slog.Any("via", lastHop),
		slog.Uint64("DSCP", uint64(dscp)),
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
		slog.String("via", path.Metadata().Fingerprint().String()),
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
