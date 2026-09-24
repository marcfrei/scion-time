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
	Log        *slog.Logger
	DSCP       uint8
	FlashPTP   bool
	sequenceID uint16
}

func readCSPTPReplyIP(ctx context.Context, log *slog.Logger,
	conn *net.UDPConn, remoteAddr netip.Addr, deadline time.Time, deadlineSet bool,
	sequenceID uint16, flashPTP bool, replies *csptpReplies) error {
	buf := make([]byte, csptp.MaxMessageLength)
	oob := make([]byte, udp.TimestampLen())

	const maxNumRetries = 3
	for numRetries := 0; ; numRetries++ {
		buf = buf[:cap(buf)]
		oob = oob[:cap(oob)]
		n, oobn, flags, srcAddr, err := conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet", slog.Any("error", err))
				continue
			}
			return err
		}
		if flags != 0 {
			err = errUnexpectedPacketFlags
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet", slog.Int("flags", flags))
				continue
			}
			return err
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
		if err != nil {
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
				continue
			}
			return err
		}

		srcPort := uint16(csptp.EventPortIP)
		if reply.msg.MessageType() == csptp.MessageTypeFollowUp {
			srcPort = csptp.GeneralPortIP
		}
		if srcAddr.Compare(netip.AddrPortFrom(remoteAddr, srcPort)) != 0 {
			err = errUnexpectedPacketSource
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet: unexpected source")
				continue
			}
			return err
		}

		reply.rxt, reply.ok = rxt, true
		if reply.msg.MessageType() == csptp.MessageTypeSync {
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
		localAddr, localAddr.Zone(), 0, deadline, deadlineSet)
	if err != nil {
		return time.Time{}, 0, err
	}
	defer func() { _ = econn.Close() }()
	var gconn *net.UDPConn
	if c.FlashPTP {
		gconn, err = openCSPTPConn(ctx, c.Log, c.DSCP,
			localAddr, localAddr.Zone(), 0, deadline, deadlineSet)
		if err != nil {
			return time.Time{}, 0, err
		}
		defer func() { _ = gconn.Close() }()
	}

	var cTxTime0, cTxTime1 time.Time

	buf := make([]byte, csptp.MaxMessageLength)
	var n int

	reference := remoteAddr.String()

	if c.FlashPTP {
		buf = flashPTPSyncRequest(buf, c.sequenceID)
	} else {
		buf = csptpSyncRequest(buf, c.sequenceID)
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
		buf = flashPTPFollowUpRequest(buf[:cap(buf)], c.sequenceID)

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
		conn := econn
		if c.FlashPTP && replies.sync.ok {
			// FlashPTP: Follow Up response on general port connection
			conn = gconn
		}
		err = readCSPTPReplyIP(ctx, c.Log,
			conn, remoteAddr, deadline, deadlineSet,
			c.sequenceID, c.FlashPTP, &replies)
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
	)

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
