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

type csptpContextIP struct {
	conn       *udpConn
	srcPort    uint16
	rxTime     time.Time
	sequenceID uint16
	correction int64
}

//lint:ignore U1000 work in progress
type csptpClientIP struct {
	key   netip.Addr
	ctxts [csptpContextCap]csptpContextIP
	len   int
	qval  time.Time
	qidx  int
}

type csptpClientQueueIP []*csptpClientIP

var (
	csptpClntsIP  = make(map[netip.Addr]*csptpClientIP)
	csptpClntsQIP = make(csptpClientQueueIP, 0, csptpClientCap)

	csptpMuIP sync.Mutex

	csptpSyncClntIP, csptpFollowUpClntIP csptpClientIP
)

func (q csptpClientQueueIP) Len() int { return len(q) }

func (q csptpClientQueueIP) Less(i, j int) bool {
	return q[i].qval.Before(q[j].qval)
}

func (q csptpClientQueueIP) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].qidx = i
	q[j].qidx = j
}

func (q *csptpClientQueueIP) Push(x any) {
	c := x.(*csptpClientIP)
	c.qidx = len(*q)
	*q = append(*q, c)
}

func (q *csptpClientQueueIP) Pop() any {
	n := len(*q)
	c := (*q)[n-1]
	(*q)[n-1] = nil
	*q = (*q)[0 : n-1]
	return c
}

func runCSPTPServerIP(ctx context.Context, log *slog.Logger,
	conn *udpConn, localHostIface string, localHostPort int, dscp uint8) {
	err := udp.EnableTimestamping(conn.c, localHostIface, -1 /* index */)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError, "failed to enable timestamping", slog.Any("error", err))
	}
	err = udp.SetDSCP(conn.c, dscp)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelInfo, "failed to set DSCP", slog.Any("error", err))
	}

	var syncConn, followUpConn *udpConn

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

		if reqmsg.MessageType() == csptp.MessageTypeSync && localHostPort == csptp.EventPortIP {
			if len(buf)-csptp.MinMessageLength != 0 {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to validate packet payload: unexpected Sync message length")
				continue
			}

			if reqmsg.FlagField&csptp.FlagTwoStep != csptp.FlagTwoStep {
				log.LogAttrs(ctx, slog.LevelInfo, "received one-step Sync request")
				continue
			}

			log.LogAttrs(ctx, slog.LevelDebug, "received request",
				slog.Time("at", rxt),
				slog.String("from", srcAddr.String()),
				slog.Any("reqmsg", &reqmsg),
			)

			syncConn, followUpConn = conn, nil
		} else if reqmsg.MessageType() == csptp.MessageTypeFollowUp && localHostPort == csptp.GeneralPortIP {
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
			if len(buf)-csptp.MinMessageLength != csptp.RequestTLVLength(&reqtlv) {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to validate packet payload: unexpected Follow Up message length")
				continue
			}

			log.LogAttrs(ctx, slog.LevelDebug, "received request",
				slog.Time("at", rxt),
				slog.String("from", srcAddr.String()),
				slog.Any("reqmsg", &reqmsg),
				slog.Any("reqtlv", &reqtlv),
			)

			syncConn, followUpConn = nil, conn
		} else {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to validate packet payload: unexpected message")
			continue
		}

		var (
			syncCtx, followUpCtx csptpContextIP
			sequenceComplete     bool
		)

		csptpMuIP.Lock()
		// maintain CSPTP client data structure
		_ = len(csptpClntsIP)
		_ = len(csptpClntsQIP)
		var clnt *csptpClientIP
		if syncConn != nil {
			clnt = &csptpSyncClntIP
		} else if followUpConn != nil {
			clnt = &csptpFollowUpClntIP
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
		if csptpSyncClntIP.key == csptpFollowUpClntIP.key &&
			csptpSyncClntIP.ctxts[0].sequenceID == csptpFollowUpClntIP.ctxts[0].sequenceID {

			sequenceComplete = true
			syncCtx = csptpSyncClntIP.ctxts[0]
			followUpCtx = csptpFollowUpClntIP.ctxts[0]

			csptpSyncClntIP.key = netip.Addr{}
			csptpFollowUpClntIP.key = netip.Addr{}
		}
		csptpMuIP.Unlock()

		if sequenceComplete {
			var msg csptp.Message
			var resptlv csptp.ResponseTLV

			buf = buf[:cap(buf)]

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

			syncCtx.conn.mu.Lock()
			n, err = syncCtx.conn.c.WriteToUDPAddrPort(
				buf, netip.AddrPortFrom(srcAddr.Addr(), syncCtx.srcPort))
			if err != nil || n != len(buf) {
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
			msg.MessageLength += uint16(csptp.ResponseTLVLength(&resptlv))
			resptlv.Length = uint16(csptp.ResponseTLVLength(&resptlv))

			buf = buf[:msg.MessageLength]
			csptp.EncodeMessage(buf[:csptp.MinMessageLength], &msg)
			csptp.EncodeResponseTLV(buf[csptp.MinMessageLength:], &resptlv)

			followUpCtx.conn.mu.Lock()
			n, err = followUpCtx.conn.c.WriteToUDPAddrPort(
				buf, netip.AddrPortFrom(srcAddr.Addr(), followUpCtx.srcPort))
			if err != nil || n != len(buf) {
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
