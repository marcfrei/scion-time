package server

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/core/timebase"
	"example.com/scion-time/net/csptp"
	"example.com/scion-time/net/udp"
)

const (
	csptpContextCap = 8
	csptpClientCap  = 1 << 20
)

type udpConn struct {
	c    *net.UDPConn
	mu   sync.Mutex
	txid uint32
}

//lint:ignore U1000 work in progress
type csptpContext struct {
	conn       *udpConn
	srcPort    uint16
	rxTime     time.Time
	sequenceID uint16
	correction int64
}

//lint:ignore U1000 work in progress
type csptpClient struct {
	key   netip.Addr
	ctxts [csptpContextCap]csptpContext
	len   int
	qval  time.Time
	qidx  int
}

type csptpClientQueue []*csptpClient

var (
	csptpClients  = make(map[netip.Addr]*csptpClient)
	csptpClientsQ = make(csptpClientQueue, 0, csptpClientCap)

	csptpMu sync.Mutex

	csptpClientE, csptpClientG csptpClient
)

func (q csptpClientQueue) Len() int { return len(q) }

func (q csptpClientQueue) Less(i, j int) bool {
	return q[i].qval.Before(q[j].qval)
}

func (q csptpClientQueue) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].qidx = i
	q[j].qidx = j
}

func (q *csptpClientQueue) Push(x any) {
	c := x.(*csptpClient)
	c.qidx = len(*q)
	*q = append(*q, c)
}

func (q *csptpClientQueue) Pop() any {
	n := len(*q)
	c := (*q)[n-1]
	(*q)[n-1] = nil
	*q = (*q)[0 : n-1]
	return c
}

func runCSPTPServerIP(ctx context.Context, log *slog.Logger,
	conn *udpConn, localHostIface string, localHostPort int, dscp uint8) {
	err := udp.EnableTimestamping(conn.c, localHostIface)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError, "failed to enable timestamping", slog.Any("error", err))
	}
	err = udp.SetDSCP(conn.c, dscp)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelInfo, "failed to set DSCP", slog.Any("error", err))
	}

	var eConn, gConn *udpConn

	buf := make([]byte, csptp.MaxMessageLength)
	oob := make([]byte, udp.TimestampLen())
	for {
		buf = buf[:cap(buf)]
		oob = oob[:cap(oob)]
		n, oobn, flags, srcAddr, err := conn.c.ReadMsgUDPAddrPort(buf, oob)
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

		if len(buf) < csptp.MinMessageLength {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload: unexpected structure")
			continue
		}

		var reqmsg csptp.Message
		err = csptp.DecodeMessage(&reqmsg, buf[:csptp.MinMessageLength])
		if err != nil {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
			continue
		}

		if len(buf) != int(reqmsg.MessageLength) {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to validate packet payload: unexpected message length")
			continue
		}

		if reqmsg.SdoIDMessageType == csptp.MessageTypeSync && localHostPort == csptp.EventPortIP {
			if len(buf)-csptp.MinMessageLength != 0 {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to validate packet payload: unexpected Sync message length")
				continue
			}

			log.LogAttrs(ctx, slog.LevelDebug, "received request",
				slog.Time("at", rxt),
				slog.String("from", srcAddr.String()),
				slog.Any("reqmsg", &reqmsg),
			)

			eConn, gConn = conn, nil
		} else if reqmsg.SdoIDMessageType == csptp.MessageTypeFollowUp && localHostPort == csptp.GeneralPortIP {
			var reqtlv csptp.RequestTLV
			err = csptp.DecodeRequestTLV(&reqtlv, buf[csptp.MinMessageLength:])
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
			if len(buf)-csptp.MinMessageLength != csptp.EncodedRequestTLVLength(&reqtlv) {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to validate packet payload: unexpected Follow Up message length")
				continue
			}

			log.LogAttrs(ctx, slog.LevelDebug, "received request",
				slog.Time("at", rxt),
				slog.String("from", srcAddr.String()),
				slog.Any("reqmsg", &reqmsg),
				slog.Any("reqtlv", &reqtlv),
			)

			eConn, gConn = nil, conn
		} else {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to validate packet payload: unexpected message")
			continue
		}

		var (
			sequenceComplete bool
			sequenceID       uint16
			syncSrcPort      uint16
			followUpSrcPort  uint16
			rxTime           time.Time
		)

		csptpMu.Lock()
		// maintain CSPTP client data structure
		_ = len(csptpClients)
		_ = len(csptpClientsQ)
		var clnt *csptpClient
		if eConn != nil {
			clnt = &csptpClientE
		} else if gConn != nil {
			clnt = &csptpClientG
		}
		if clnt.key != srcAddr.Addr() || clnt.ctxts[0].sequenceID <= reqmsg.SequenceID {
			clnt.key = srcAddr.Addr()
			clnt.ctxts[0].conn = conn
			clnt.ctxts[0].srcPort = srcAddr.Port()
			clnt.ctxts[0].rxTime = rxt
			clnt.ctxts[0].sequenceID = reqmsg.SequenceID
			clnt.ctxts[0].correction = reqmsg.CorrectionField
			clnt.len = 1
		}
		if csptpClientE.key == csptpClientG.key &&
			csptpClientE.ctxts[0].sequenceID == csptpClientG.ctxts[0].sequenceID {

			sequenceComplete = true
			sequenceID = csptpClientE.ctxts[0].sequenceID

			eConn = csptpClientE.ctxts[0].conn
			syncSrcPort = csptpClientE.ctxts[0].srcPort
			gConn = csptpClientG.ctxts[0].conn
			followUpSrcPort = csptpClientG.ctxts[0].srcPort

			rxTime = csptpClientE.ctxts[0].rxTime

			csptpClientE.key = netip.Addr{}
			csptpClientG.key = netip.Addr{}
		}
		csptpMu.Unlock()

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
				SequenceID:         sequenceID,
				ControlField:       csptp.ControlSync,
				LogMessageInterval: csptp.LogMessageInterval,
				Timestamp:          csptp.Timestamp{},
			}

			buf = buf[:msg.MessageLength]
			csptp.EncodeMessage(buf, &msg)

			eConn.mu.Lock()
			n, err = eConn.c.WriteToUDPAddrPort(
				buf, netip.AddrPortFrom(srcAddr.Addr(), syncSrcPort))
			if err != nil || n != len(buf) {
				log.LogAttrs(ctx, slog.LevelError, "failed to write packet", slog.Any("error", err))
				eConn.mu.Unlock()
				continue
			}
			txTime0, id, err := udp.ReadTXTimestamp(eConn.c)
			if err != nil {
				txTime0 = timebase.Now()
				log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
					slog.Any("error", err))
			} else if id != eConn.txid {
				txTime0 = timebase.Now()
				log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
					slog.Uint64("id", uint64(id)), slog.Uint64("expected", uint64(eConn.txid)))
				eConn.txid = id + 1
			} else {
				eConn.txid++
			}
			_ = txTime0
			eConn.mu.Unlock()

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
				SequenceID:         sequenceID,
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
				RequestIngressTimestamp: csptp.TimestampFromTime(rxTime),
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

			gConn.mu.Lock()
			n, err = gConn.c.WriteToUDPAddrPort(
				buf, netip.AddrPortFrom(srcAddr.Addr(), followUpSrcPort))
			if err != nil || n != len(buf) {
				log.LogAttrs(ctx, slog.LevelError, "failed to write packet", slog.Any("error", err))
				gConn.mu.Unlock()
				continue
			}
			txTime1, id, err := udp.ReadTXTimestamp(gConn.c)
			if err != nil {
				txTime1 = timebase.Now()
				log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
					slog.Any("error", err))
			} else if id != gConn.txid {
				txTime1 = timebase.Now()
				log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
					slog.Uint64("id", uint64(id)), slog.Uint64("expected", uint64(gConn.txid)))
				gConn.txid = id + 1
			} else {
				gConn.txid++
			}
			_ = txTime1
			gConn.mu.Unlock()
		}
	}
}

func StartCSPTPServerIP(ctx context.Context, log *slog.Logger,
	localHost *net.UDPAddr, dscp uint8) {
	log.LogAttrs(ctx, slog.LevelInfo, "CSPTP server listening via IP",
		slog.Any("local host", localHost.IP),
	)

	if localHost.Port != 0 {
		logbase.FatalContext(ctx, log, "unexpected listener port",
			slog.Int("port", localHost.Port))
	}

	lc := net.ListenConfig{
		Control: udp.SetsockoptReuseAddrPort,
	}
	for _, localHostPort := range []int{csptp.EventPortIP, csptp.GeneralPortIP} {
		address := net.JoinHostPort(localHost.IP.String(), strconv.Itoa(localHostPort))
		for range ipServerNumGoroutine {
			conn, err := lc.ListenPacket(ctx, "udp", address)
			if err != nil {
				logbase.FatalContext(ctx, log, "failed to listen for packets", slog.Any("error", err))
			}
			go runCSPTPServerIP(ctx, log, &udpConn{c: conn.(*net.UDPConn)}, localHost.Zone, localHostPort, dscp)
		}
	}
}
