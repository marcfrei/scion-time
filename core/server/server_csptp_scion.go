package server

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/pkg/slayers"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/core/timebase"
	"example.com/scion-time/net/csptp"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

type csptpContextSCION struct {
	conn       *udpConn
	buf        []byte
	lastHop    netip.AddrPort
	scionLayer slayers.SCION
	udpLayer   slayers.UDP
	rxTime     time.Time
	sequenceID uint16
	correction int64
}

//lint:ignore U1000 work in progress
type csptpClientSCION struct {
	key   string
	ctxts [csptpContextCap]csptpContextSCION
	len   int
	qval  time.Time
	qidx  int
}

type csptpClientQueueSCION []*csptpClientSCION

var (
	csptpClntsSCION  = make(map[string]*csptpClientSCION)
	csptpClntsQSCION = make(csptpClientQueueSCION, 0, csptpClientCap)

	csptpMuSCION sync.Mutex

	csptpSyncClntSCION, csptpFollowUpClntSCION csptpClientSCION
)

func (q csptpClientQueueSCION) Len() int { return len(q) }

func (q csptpClientQueueSCION) Less(i, j int) bool {
	return q[i].qval.Before(q[j].qval)
}

func (q csptpClientQueueSCION) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].qidx = i
	q[j].qidx = j
}

func (q *csptpClientQueueSCION) Push(x any) {
	c := x.(*csptpClientSCION)
	c.qidx = len(*q)
	*q = append(*q, c)
}

func (q *csptpClientQueueSCION) Pop() any {
	n := len(*q)
	c := (*q)[n-1]
	(*q)[n-1] = nil
	*q = (*q)[0 : n-1]
	return c
}

func runCSPTPServerSCION(ctx context.Context, log *slog.Logger,
	conn *udpConn, localHostIface string, localHostPort int, dscp uint8) {
	err := udp.EnableTimestamping(conn.c, localHostIface)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError, "failed to enable timestamping", slog.Any("error", err))
	}
	err = udp.SetDSCP(conn.c, dscp)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelInfo, "failed to set DSCP", slog.Any("error", err))
	}

	var syncConn, followUpConn *udpConn

	buf := make([]byte, scion.MTU)
	oob := make([]byte, udp.TimestampLen())

	var (
		scionLayer slayers.SCION
		hbhLayer   slayers.HopByHopExtnSkipper
		e2eLayer   slayers.EndToEndExtn
		udpLayer   slayers.UDP
		scmpLayer  slayers.SCMP
	)
	scionLayer.RecyclePaths()
	udpLayer.SetNetworkLayerForChecksum(&scionLayer)
	scmpLayer.SetNetworkLayerForChecksum(&scionLayer)
	parser := gopacket.NewDecodingLayerParser(
		slayers.LayerTypeSCION, &scionLayer, &hbhLayer, &e2eLayer, &udpLayer, &scmpLayer,
	)
	parser.IgnoreUnsupported = true
	decoded := make([]gopacket.LayerType, 4)
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	for {
		buf = buf[:cap(buf)]
		oob = oob[:cap(oob)]
		n, oobn, flags, lastHop, err := conn.c.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			log.LogAttrs(ctx, slog.LevelError, "failed to read packet", slog.Any("error", err))
			continue
		}
		if flags != 0 {
			log.LogAttrs(ctx, slog.LevelError, "failed to read packet", slog.Int("flags", flags))
			continue
		}
		oob = oob[:oobn]
		rxt, err := udp.TimestampFromOOBData(oob)
		if err != nil {
			oob = oob[:0]
			rxt = timebase.Now()
			log.LogAttrs(ctx, slog.LevelError, "failed to read packet rx timestamp", slog.Any("error", err))
		}
		buf = buf[:n]

		err = parser.DecodeLayers(buf, &decoded)
		if err != nil {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet", slog.Any("error", err))
			continue
		}
		validType := len(decoded) >= 2 && (decoded[len(decoded)-1] == slayers.LayerTypeSCIONUDP ||
			decoded[len(decoded)-1] == slayers.LayerTypeSCMP)
		if !validType {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet", slog.String("cause", "unexpected type or structure"))
			continue
		}

		if decoded[len(decoded)-1] == slayers.LayerTypeSCMP {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to handle packet",
				slog.String("cause", "unexpected SCMP message type"),
				slog.Uint64("type", uint64(scmpLayer.TypeCode.Type())),
				slog.Uint64("code", uint64(scmpLayer.TypeCode.Code())))
			continue
		}

		if len(buf) < int(udpLayer.Length) {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet", slog.String("cause", "unexpected structure"))
			continue
		}

		srcAddr, ok := netip.AddrFromSlice(scionLayer.RawSrcAddr)
		if !ok {
			panic("unexpected IP address byte slice")
		}

		if int(udpLayer.DstPort) != localHostPort {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to handle packet",
				slog.String("cause", "unexpected L4 destination port"),
				slog.Int("l4_dst_port", int(udpLayer.DstPort)))
			continue
		}

		if len(udpLayer.Payload) < csptp.MinMessageLength {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload: unexpected structure")
			continue
		}

		var reqmsg csptp.Message
		err = csptp.DecodeMessage(&reqmsg, udpLayer.Payload[:csptp.MinMessageLength])
		if err != nil {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
			continue
		}

		if len(udpLayer.Payload) != int(reqmsg.MessageLength) {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to validate packet payload: unexpected message length")
			continue
		}

		clientID := scionLayer.SrcIA.String() + "," + srcAddr.String()

		if reqmsg.SdoIDMessageType == csptp.MessageTypeSync && localHostPort == csptp.EventPortSCION {
			if len(udpLayer.Payload)-csptp.MinMessageLength != 0 {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to validate packet payload: unexpected Sync message length")
				continue
			}

			if reqmsg.FlagField&csptp.FlagTwoStep != csptp.FlagTwoStep {
				log.LogAttrs(ctx, slog.LevelInfo, "received one-step Sync request")
				continue
			}

			log.LogAttrs(ctx, slog.LevelDebug, "received request",
				slog.Time("at", rxt),
				slog.String("from", clientID),
				slog.Any("reqmsg", &reqmsg),
			)

			syncConn, followUpConn = conn, nil
		} else if reqmsg.SdoIDMessageType == csptp.MessageTypeFollowUp && localHostPort == csptp.GeneralPortSCION {
			var reqtlv csptp.RequestTLV
			err = csptp.DecodeRequestTLV(&reqtlv, udpLayer.Payload[csptp.MinMessageLength:])
			if err != nil {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
				continue
			}
			if reqtlv.Type != csptp.TLVTypeOrganizationExtension ||
				reqtlv.OrganizationID[0] != csptp.OrganizationIDMeinberg0 ||
				reqtlv.OrganizationID[1] != csptp.OrganizationIDMeinberg1 ||
				reqtlv.OrganizationID[2] != csptp.OrganizationIDMeinberg2 ||
				reqtlv.OrganizationSubType[0] != csptp.OrganizationSubTypeRequest0 ||
				reqtlv.OrganizationSubType[1] != csptp.OrganizationSubTypeRequest1 ||
				reqtlv.OrganizationSubType[2] != csptp.OrganizationSubTypeRequest2 {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to validate packet payload: unexpected Follow Up message")
				continue
			}
			if len(udpLayer.Payload)-csptp.MinMessageLength != csptp.EncodedRequestTLVLength(&reqtlv) {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to validate packet payload: unexpected Follow Up message length")
				continue
			}

			log.LogAttrs(ctx, slog.LevelDebug, "received request",
				slog.Time("at", rxt),
				slog.String("from", clientID),
				slog.Any("reqmsg", &reqmsg),
				slog.Any("reqtlv", &reqtlv),
			)

			syncConn, followUpConn = nil, conn
		} else {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to validate packet payload: unexpected message")
			continue
		}

		var (
			syncCtx, followUpCtx csptpContextSCION
			sequenceComplete     bool
		)

		csptpMuSCION.Lock()
		// maintain CSPTP client data structure
		_ = len(csptpClntsSCION)
		_ = len(csptpClntsQSCION)
		var clnt *csptpClientSCION
		if syncConn != nil {
			clnt = &csptpSyncClntSCION
		} else if followUpConn != nil {
			clnt = &csptpFollowUpClntSCION
		}
		if clnt.key != clientID || clnt.ctxts[0].sequenceID <= reqmsg.SequenceID {
			clnt.key = clientID
			clnt.ctxts[0].conn = conn
			clnt.ctxts[0].buf = buf
			clnt.ctxts[0].lastHop = lastHop
			clnt.ctxts[0].scionLayer = scionLayer
			clnt.ctxts[0].udpLayer = udpLayer
			clnt.ctxts[0].rxTime = rxt
			clnt.ctxts[0].sequenceID = reqmsg.SequenceID
			clnt.ctxts[0].correction = reqmsg.CorrectionField
			clnt.len = 1
			buf = make([]byte, cap(buf))
		}
		if csptpSyncClntSCION.key == csptpFollowUpClntSCION.key &&
			csptpSyncClntSCION.ctxts[0].sequenceID == csptpFollowUpClntSCION.ctxts[0].sequenceID {

			sequenceComplete = true
			syncCtx = csptpSyncClntSCION.ctxts[0]
			followUpCtx = csptpFollowUpClntSCION.ctxts[0]

			csptpSyncClntSCION.key = ""
			csptpFollowUpClntSCION.key = ""
		}
		csptpMuSCION.Unlock()

		if sequenceComplete {
			var msg csptp.Message
			var resptlv csptp.ResponseTLV

			buf = buf[:cap(buf)]

			msg = csptp.Message{
				SdoIDMessageType:    csptp.MessageTypeSync,
				PTPVersion:          csptp.PTPVersion,
				MessageLength:       csptp.MinMessageLength,
				DomainNumber:        csptp.DomainNumber,
				MinorSdoID:          csptp.MinorSdoID,
				FlagField:           csptp.FlagTwoStep | csptp.FlagUnicast,
				CorrectionField:     0,
				MessageTypeSpecific: 0,
				SourcePortIdentity: csptp.PortID{
					ClockID: 1,
					Port:    1,
				},
				SequenceID:         syncCtx.sequenceID,
				ControlField:       csptp.ControlSync,
				LogMessageInterval: csptp.LogMessageInterval,
				Timestamp:          csptp.Timestamp{},
			}

			buf = buf[:msg.MessageLength]
			csptp.EncodeMessage(buf, &msg)

			syncCtx.scionLayer.TrafficClass = dscp << 2
			syncCtx.scionLayer.DstIA, syncCtx.scionLayer.SrcIA =
				syncCtx.scionLayer.SrcIA, syncCtx.scionLayer.DstIA
			syncCtx.scionLayer.DstAddrType, syncCtx.scionLayer.SrcAddrType =
				syncCtx.scionLayer.SrcAddrType, syncCtx.scionLayer.DstAddrType
			syncCtx.scionLayer.RawDstAddr, syncCtx.scionLayer.RawSrcAddr =
				syncCtx.scionLayer.RawSrcAddr, syncCtx.scionLayer.RawDstAddr
			syncCtx.scionLayer.Path, err = syncCtx.scionLayer.Path.Reverse()
			if err != nil {
				panic(err)
			}
			syncCtx.scionLayer.NextHdr = slayers.L4UDP

			syncCtx.udpLayer.DstPort, syncCtx.udpLayer.SrcPort =
				syncCtx.udpLayer.SrcPort, syncCtx.udpLayer.DstPort

			payload := gopacket.Payload(buf)

			err = buffer.Clear()
			if err != nil {
				panic(err)
			}

			err = payload.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(payload.LayerType())

			err = syncCtx.udpLayer.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(syncCtx.udpLayer.LayerType())

			err = syncCtx.scionLayer.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(syncCtx.scionLayer.LayerType())

			syncCtx.conn.mu.Lock()
			n, err = syncCtx.conn.c.WriteToUDPAddrPort(buffer.Bytes(), syncCtx.lastHop)
			if err != nil || n != len(buffer.Bytes()) {
				log.LogAttrs(ctx, slog.LevelError, "failed to write packet",
					slog.Any("error", err))
				syncCtx.conn.mu.Unlock()
				continue
			}
			txTime0, id, err := udp.ReadTXTimestamp(syncCtx.conn.c, syncCtx.conn.txid)
			if err != nil {
				txTime0 = timebase.Now()
				log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
					slog.Any("error", err))
			} else if id != syncCtx.conn.txid {
				txTime0 = timebase.Now()
				log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
					slog.Uint64("id", uint64(id)), slog.Uint64("expected", uint64(syncCtx.conn.txid)))
				syncCtx.conn.txid = id + 1
			} else {
				syncCtx.conn.txid++
			}
			syncCtx.conn.mu.Unlock()

			buf = buf[:cap(buf)]

			msg = csptp.Message{
				SdoIDMessageType:    csptp.MessageTypeFollowUp,
				PTPVersion:          csptp.PTPVersion,
				MessageLength:       csptp.MinMessageLength,
				DomainNumber:        csptp.DomainNumber,
				MinorSdoID:          csptp.MinorSdoID,
				FlagField:           csptp.FlagUnicast,
				CorrectionField:     0,
				MessageTypeSpecific: 0,
				SourcePortIdentity: csptp.PortID{
					ClockID: 1,
					Port:    1,
				},
				SequenceID:         followUpCtx.sequenceID,
				ControlField:       csptp.ControlFollowUp,
				LogMessageInterval: csptp.LogMessageInterval,
				Timestamp:          csptp.TimestampFromTime(txTime0),
			}
			resptlv = csptp.ResponseTLV{
				Type:   csptp.TLVTypeOrganizationExtension,
				Length: 0,
				OrganizationID: [3]uint8{
					csptp.OrganizationIDMeinberg0,
					csptp.OrganizationIDMeinberg1,
					csptp.OrganizationIDMeinberg2},
				OrganizationSubType: [3]uint8{
					csptp.OrganizationSubTypeResponse0,
					csptp.OrganizationSubTypeResponse1,
					csptp.OrganizationSubTypeResponse2},
				// FlagField:               csptp.TLVFlagServerStateDS,
				FlagField:               0,
				Error:                   0,
				RequestIngressTimestamp: csptp.TimestampFromTime(syncCtx.rxTime),
				RequestCorrectionField:  0,
				UTCOffset:               0,
				ServerStateDS: csptp.ServerStateDS{
					GMPriority1:     0, /* TODO */
					GMClockClass:    0, /* TODO */
					GMClockAccuracy: 0, /* TODO */
					GMClockVariance: 0, /* TODO */
					GMPriority2:     0, /* TODO */
					GMClockID:       0, /* TODO */
					StepsRemoved:    0, /* TODO */
					TimeSource:      0, /* TODO */
					Reserved:        0,
				},
			}
			msg.MessageLength += uint16(csptp.EncodedResponseTLVLength(&resptlv))
			resptlv.Length = uint16(csptp.EncodedResponseTLVLength(&resptlv))

			buf = buf[:msg.MessageLength]
			csptp.EncodeMessage(buf[:csptp.MinMessageLength], &msg)
			csptp.EncodeResponseTLV(buf[csptp.MinMessageLength:], &resptlv)

			followUpCtx.scionLayer.TrafficClass = dscp << 2
			followUpCtx.scionLayer.DstIA, followUpCtx.scionLayer.SrcIA =
				followUpCtx.scionLayer.SrcIA, followUpCtx.scionLayer.DstIA
			followUpCtx.scionLayer.DstAddrType, followUpCtx.scionLayer.SrcAddrType =
				followUpCtx.scionLayer.SrcAddrType, followUpCtx.scionLayer.DstAddrType
			followUpCtx.scionLayer.RawDstAddr, followUpCtx.scionLayer.RawSrcAddr =
				followUpCtx.scionLayer.RawSrcAddr, followUpCtx.scionLayer.RawDstAddr
			followUpCtx.scionLayer.Path, err = followUpCtx.scionLayer.Path.Reverse()
			if err != nil {
				panic(err)
			}
			followUpCtx.scionLayer.NextHdr = slayers.L4UDP

			followUpCtx.udpLayer.DstPort, followUpCtx.udpLayer.SrcPort =
				followUpCtx.udpLayer.SrcPort, followUpCtx.udpLayer.DstPort

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

			err = followUpCtx.udpLayer.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(followUpCtx.udpLayer.LayerType())

			err = followUpCtx.scionLayer.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(followUpCtx.scionLayer.LayerType())

			followUpCtx.conn.mu.Lock()
			n, err = followUpCtx.conn.c.WriteToUDPAddrPort(buffer.Bytes(), followUpCtx.lastHop)
			if err != nil || n != len(buffer.Bytes()) {
				log.LogAttrs(ctx, slog.LevelError, "failed to write packet",
					slog.Any("error", err))
				followUpCtx.conn.mu.Unlock()
				continue
			}
			txTime1, id, err := udp.ReadTXTimestamp(followUpCtx.conn.c, followUpCtx.conn.txid)
			if err != nil {
				txTime1 = timebase.Now()
				log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
					slog.Any("error", err))
			} else if id != followUpCtx.conn.txid {
				txTime1 = timebase.Now()
				log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
					slog.Uint64("id", uint64(id)), slog.Uint64("expected", uint64(followUpCtx.conn.txid)))
				followUpCtx.conn.txid = id + 1
			} else {
				followUpCtx.conn.txid++
			}
			_ = txTime1
			followUpCtx.conn.mu.Unlock()
		}
	}
}

func StartCSPTPServerSCION(ctx context.Context, log *slog.Logger,
	localHost *net.UDPAddr, dscp uint8) {
	log.LogAttrs(ctx, slog.LevelInfo, "CSPTP server listening via SCION",
		slog.Any("local host", localHost.IP),
	)

	if localHost.Port != 0 {
		logbase.FatalContext(ctx, log, "unexpected listener port",
			slog.Int("port", localHost.Port))
	}

	lc := net.ListenConfig{
		Control: udp.SetsockoptReuseAddrPort,
	}
	for _, localHostPort := range []int{csptp.EventPortSCION, csptp.GeneralPortSCION} {
		address := net.JoinHostPort(localHost.IP.String(), strconv.Itoa(localHostPort))
		for range scionServerNumGoroutine {
			conn, err := lc.ListenPacket(ctx, "udp", address)
			if err != nil {
				logbase.FatalContext(ctx, log, "failed to listen for packets", slog.Any("error", err))
			}
			go runCSPTPServerSCION(ctx, log, &udpConn{c: conn.(*net.UDPConn)}, localHost.Zone, localHostPort, dscp)
		}
	}
}
