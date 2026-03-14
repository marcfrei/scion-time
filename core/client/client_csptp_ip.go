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
	sequenceID uint16
}

func readCSPTPReplyIP(ctx context.Context, log *slog.Logger,
	conn *net.UDPConn, remoteAddr netip.Addr, deadline time.Time, deadlineSet bool,
	messageType uint8, sequenceID uint16, replies *csptpReplies) error {
	buf := make([]byte, csptp.MaxMessageLength)
	oob := make([]byte, udp.TimestampLen())

	const maxNumRetries = 3
rxloop:
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

		var respmsg csptp.Message
		err = csptp.DecodeMessage(&respmsg, buf)
		if err != nil {
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
				continue
			}
			return err
		}

		if len(buf) != int(respmsg.MessageLength) {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
				continue
			}
			return err
		}

		if respmsg.SequenceID != sequenceID || respmsg.MessageType() != messageType {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
				log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
				continue
			}
			return err
		}

		reply := csptpReply{msg: respmsg, rxt: rxt, ok: true}

		switch messageType {
		case csptp.MessageTypeSync:
			if srcAddr.Compare(netip.AddrPortFrom(remoteAddr, csptp.EventPortIP)) != 0 {
				err = errUnexpectedPacketSource
				if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
					log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet: unexpected source")
					continue
				}
				return err
			}

			tlvbuf := buf[csptp.MinMessageLength:]
			for len(tlvbuf) >= csptp.MinTLVLength {
				var tlvhdr csptp.TLVHeader
				err := csptp.DecodeTLVHeader(&tlvhdr, tlvbuf)
				if err != nil {
					if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
						log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
						continue rxloop
					}
					return err
				}
				if len(tlvbuf) < int(tlvhdr.Length) {
					err = errUnexpectedPacket
					if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
						log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
						continue rxloop
					}
					return err
				}
				tlvbuf = tlvbuf[tlvhdr.Length:]
			}
			if len(tlvbuf) != 0 {
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
					log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
					continue
				}
				return err
			}

			if respmsg.FlagField&csptp.FlagTwoStep != csptp.FlagTwoStep { // TODO: support one-step
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
					log.LogAttrs(ctx, slog.LevelInfo, "received one-step Sync message")
					continue
				}
				return err
			}

			replies.mu.Lock()
			replies.sync = reply
			replies.mu.Unlock()
			return nil
		case csptp.MessageTypeFollowUp:
			if srcAddr.Compare(netip.AddrPortFrom(remoteAddr, csptp.GeneralPortIP)) != 0 {
				err = errUnexpectedPacketSource
				if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
					log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet: unexpected source")
					continue
				}
				return err
			}

			var resptlvOk bool
			tlvbuf := buf[csptp.MinMessageLength:]
			for len(tlvbuf) >= csptp.MinTLVLength {
				var tlvhdr csptp.TLVHeader
				err := csptp.DecodeTLVHeader(&tlvhdr, tlvbuf)
				if err != nil {
					if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
						log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
						continue rxloop
					}
					return err
				}
				if len(tlvbuf) < int(tlvhdr.Length) {
					err = errUnexpectedPacket
					if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
						log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
						continue rxloop
					}
					return err
				}
				if tlvhdr.Type == csptp.TLVTypeOrganizationExtension {
					var tlv csptp.ResponseTLV
					err := csptp.DecodeResponseTLV(&tlv, tlvbuf)
					if err != nil {
						if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
							log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
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
							log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
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
					log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
					continue
				}
				return err
			}
			if !resptlvOk {
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineSet && timebase.Now().Before(deadline) {
					log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
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

func (c *CSPTPClientIP) MeasureClockOffset(ctx context.Context, localAddr, remoteAddr netip.Addr) (
	timestamp time.Time, offset time.Duration, err error) {
	deadline, deadlineSet := ctx.Deadline()
	econn, err := openCSPTPConn(ctx, c.Log, c.DSCP,
		localAddr, localAddr.Zone(), 0, deadline, deadlineSet)
	if err != nil {
		return time.Time{}, 0, err
	}
	defer func() { _ = econn.Close() }()
	gconn, err := openCSPTPConn(ctx, c.Log, c.DSCP,
		localAddr, localAddr.Zone(), 0, deadline, deadlineSet)
	if err != nil {
		return time.Time{}, 0, err
	}
	defer func() { _ = gconn.Close() }()

	var cTxTime0, cTxTime1 time.Time

	buf := make([]byte, csptp.MaxMessageLength)
	var n int

	reference := remoteAddr.String()

	reqmsg := csptpSyncRequest(c.sequenceID)

	buf = buf[:reqmsg.MessageLength]
	csptp.EncodeMessage(buf, &reqmsg)

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

	buf = buf[:cap(buf)]

	reqmsg, reqtlv := csptpFollowUpRequest(c.sequenceID)

	buf = buf[:reqmsg.MessageLength]
	csptp.EncodeMessage(buf[:csptp.MinMessageLength], &reqmsg)
	csptp.EncodeRequestTLV(buf[csptp.MinMessageLength:], &reqtlv)

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

	var replies csptpReplies
	rxerrch := make(chan error, 2)
	go func() {
		rxerrch <- readCSPTPReplyIP(ctx, c.Log,
			econn, remoteAddr, deadline, deadlineSet,
			csptp.MessageTypeSync, c.sequenceID, &replies)
	}()
	go func() {
		rxerrch <- readCSPTPReplyIP(ctx, c.Log,
			gconn, remoteAddr, deadline, deadlineSet,
			csptp.MessageTypeFollowUp, c.sequenceID, &replies)
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
