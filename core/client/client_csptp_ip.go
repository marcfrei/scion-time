package client

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"example.com/scion-time/core/timebase"
	"example.com/scion-time/net/csptp"
	"example.com/scion-time/net/udp"
)

type CSPTPClientIP struct {
	Log           *slog.Logger
	DSCP          uint8
	FlashPTP      bool
	RequestStatus bool // IEEE P1588.1: request CSPTP_STATUS TLV
	sequenceID    uint16
	clockID       csptpLocalClockID
}

func readCSPTPReplyIP(ctx context.Context, log *slog.Logger,
	conn *net.UDPConn, remoteAddr netip.Addr, deadline time.Time, deadlineSet bool,
	sequenceID uint16, msgType uint8, flashPTP bool, replies *csptpReplies) error {
	buf := make([]byte, csptp.MaxMessageLength)
	oob := make([]byte, udp.TimestampLen())

	// Packets from other sources, with other sequence IDs, or of the other
	// message type are skipped without consuming a retry: the connection's
	// read deadline bounds the wait.
	const maxNumRetries = 3
	numRetries := 0
	for {
		buf = buf[:cap(buf)]
		oob = oob[:cap(oob)]
		n, oobn, flags, srcAddr, err := conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				numRetries++
				log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet", slog.Any("error", err))
				continue
			}
			return err
		}
		if flags != 0 {
			err = errUnexpectedPacketFlags
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				numRetries++
				log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet", slog.Int("flags", flags))
				continue
			}
			return err
		}

		srcPort := uint16(csptp.EventPortIP)
		if msgType == csptp.MessageTypeFollowUp {
			srcPort = csptp.GeneralPortIP
		}
		if srcAddr.Compare(netip.AddrPortFrom(remoteAddr, srcPort)) != 0 {
			log.LogAttrs(ctx, slog.LevelDebug, "skipped packet: unexpected source",
				slog.Any("from", srcAddr))
			continue
		}

		oob = oob[:oobn]
		rxt, err := udp.TimestampFromOOBData(oob)
		if err != nil {
			rxt = timebase.Now()
			log.LogAttrs(ctx, slog.LevelError, "failed to read packet rx timestamp", slog.Any("error", err))
		}
		buf = buf[:n]

		var reply csptpReply
		err = decodeCSPTPReply(&reply, buf, sequenceID, flashPTP)
		if err == errUnexpectedSequenceID {
			log.LogAttrs(ctx, slog.LevelDebug, "skipped packet: unexpected sequence ID",
				slog.Uint64("sequence_id", uint64(reply.msg.SequenceID)),
				slog.Uint64("expected", uint64(sequenceID)))
			continue
		}
		if err == nil && reply.msg.MessageType() != msgType {
			log.LogAttrs(ctx, slog.LevelDebug, "skipped packet: unexpected message type",
				slog.Uint64("message_type", uint64(reply.msg.MessageType())),
				slog.Uint64("expected", uint64(msgType)))
			continue
		}
		if err != nil {
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				numRetries++
				log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
				continue
			}
			return err
		}

		reply.rxt, reply.ok = rxt, true
		if msgType == csptp.MessageTypeSync {
			replies.sync = reply
		} else {
			replies.followUp = reply
		}
		return nil
	}
}

func (c *CSPTPClientIP) MeasureClockOffset(ctx context.Context, localAddr, remoteAddr netip.Addr) (
	timestamp time.Time, offset time.Duration, err error) {
	deadline, deadlineSet := ctx.Deadline()
	econn, err := openCSPTPConn(ctx, c.Log, c.DSCP,
		localAddr, localAddr.Zone(), csptp.EventPortIP, deadline, deadlineSet)
	if err != nil {
		return time.Time{}, 0, err
	}
	defer func() { _ = econn.Close() }()
	gport := uint16(0) // FlashPTP: Follow Up response to Follow Up request source port
	if !c.FlashPTP {
		gport = csptp.GeneralPortIP // IEEE P1588.1: Follow_Up response to general port
	}
	gconn, err := openCSPTPConn(ctx, c.Log, c.DSCP,
		localAddr, localAddr.Zone(), gport, deadline, deadlineSet)
	if err != nil {
		return time.Time{}, 0, err
	}
	defer func() { _ = gconn.Close() }()

	clockID := c.clockID.get(ctx, c.Log, localAddr)

	var cTxTime0, cTxTime1 time.Time

	buf := make([]byte, csptp.MaxMessageLength)
	var n int

	reference := remoteAddr.String()

	if c.FlashPTP {
		buf = flashPTPSyncRequest(buf, c.sequenceID, clockID)
	} else {
		var reqFlags uint32
		if c.RequestStatus {
			reqFlags |= csptp.TLVFlagStatus
		}
		buf = csptpSyncRequest(buf, c.sequenceID, clockID, reqFlags)
	}

	n, err = econn.WriteToUDPAddrPort(buf, netip.AddrPortFrom(remoteAddr, csptp.EventPortIP))
	if err != nil {
		return time.Time{}, 0, err
	}
	if n != len(buf) {
		return time.Time{}, 0, errWrite
	}
	cTxTime0, id, err := udp.ReadTXTimestamp(econn, 0)
	if err != nil || id != 0 {
		cTxTime0 = timebase.Now()
		c.Log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp", slog.Any("error", err))
	}

	if c.FlashPTP {
		buf = flashPTPFollowUpRequest(buf[:cap(buf)], c.sequenceID, clockID)

		n, err = gconn.WriteToUDPAddrPort(buf, netip.AddrPortFrom(remoteAddr, csptp.GeneralPortIP))
		if err != nil {
			return time.Time{}, 0, err
		}
		if n != len(buf) {
			return time.Time{}, 0, errWrite
		}
		cTxTime1, id, err = udp.ReadTXTimestamp(gconn, 0)
		if err != nil || id != 0 {
			cTxTime1 = timebase.Now()
			c.Log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp", slog.Any("error", err))
		}
		_ = cTxTime1
	}

	var replies csptpReplies
	for !replies.complete() {
		conn, msgType := econn, uint8(csptp.MessageTypeSync)
		if replies.sync.ok {
			// Follow Up response on general port connection
			conn, msgType = gconn, csptp.MessageTypeFollowUp
		}
		err = readCSPTPReplyIP(ctx, c.Log,
			conn, remoteAddr, deadline, deadlineSet,
			c.sequenceID, msgType, c.FlashPTP, &replies)
		if err != nil {
			return time.Time{}, 0, err
		}
	}

	cRxTime0 := replies.sync.rxt

	c.Log.LogAttrs(ctx, slog.LevelDebug, "received response",
		slog.Time("at", cRxTime0),
		slog.String("from", reference),
		slog.Any("respmsg0", &replies.sync.msg),
		slog.Any("respmsg1", &replies.followUp.msg),
		slog.Any("resptlv0", &replies.sync.resp),
		slog.Any("resptlv1", &replies.followUp.tlv),
		slog.Any("statustlv", &replies.sync.stat),
	)
	if !c.FlashPTP && c.RequestStatus && replies.sync.stat.Type != csptp.TLVTypeCSPTPStatus {
		c.Log.LogAttrs(ctx, slog.LevelInfo, "requested CSPTP_STATUS TLV not received",
			slog.String("from", reference))
	}

	t0 := cTxTime0
	t1, t1Corr, t2, t3Corr, utcCorr := csptpServerTimes(&replies, c.FlashPTP)
	t3 := cRxTime0

	c2sDelay := csptp.C2SDelay(t0, t1, t1Corr, utcCorr)
	s2cDelay := csptp.S2CDelay(t2, t3, t3Corr, utcCorr)
	clockOffset := csptp.ClockOffset(t0, t1, t2, t3, t1Corr, t3Corr)
	meanPathDelay := csptp.MeanPathDelay(t0, t1, t2, t3, t1Corr, t3Corr)

	c.Log.LogAttrs(ctx, slog.LevelDebug, "evaluated response",
		slog.Time("at", cRxTime0),
		slog.String("from", reference),
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
