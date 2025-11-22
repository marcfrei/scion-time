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

func (c *CSPTPClientIP) MeasureClockOffset(ctx context.Context, localAddr, remoteAddr netip.Addr) (
	timestamp time.Time, offset time.Duration, err error) {
	var lc net.ListenConfig
	pconn, err := lc.ListenPacket(ctx, "udp", netip.AddrPortFrom(localAddr, 0).String())
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
	err = udp.EnableTimestamping(conn, localAddr.Zone())
	if err != nil {
		c.Log.LogAttrs(ctx, slog.LevelError, "failed to enable timestamping", slog.Any("error", err))
	}
	err = udp.SetDSCP(conn, c.DSCP)
	if err != nil {
		c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to set DSCP", slog.Any("error", err))
	}

	var cTxTime0, cTxTime1, cRxTime0, cRxTime1 time.Time

	buf := make([]byte, csptp.MaxMessageLength)
	var n int

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

	n, err = conn.WriteToUDPAddrPort(buf, netip.AddrPortFrom(remoteAddr, csptp.EventPortIP))
	if err != nil {
		return time.Time{}, 0, err
	}
	if n != len(buf) {
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
	msg.MessageLength += uint16(csptp.RequestTLVLength(&reqtlv))
	reqtlv.Length = uint16(csptp.RequestTLVLength(&reqtlv))

	buf = buf[:msg.MessageLength]
	csptp.EncodeMessage(buf[:csptp.MinMessageLength], &msg)
	csptp.EncodeRequestTLV(buf[csptp.MinMessageLength:], &reqtlv)

	n, err = conn.WriteToUDPAddrPort(buf, netip.AddrPortFrom(remoteAddr, csptp.GeneralPortIP))
	if err != nil {
		return time.Time{}, 0, err
	}
	if n != len(buf) {
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
	var srcAddr netip.AddrPort

	var respmsg0, respmsg1 csptp.Message
	var resptlv csptp.ResponseTLV
	var respmsg0Ok, respmsg1Ok bool

	const maxNumRetries = 3
rxloop:
	for numRetries := 0; ; numRetries++ {
		buf = buf[:cap(buf)]
		oob = oob[:cap(oob)]
		n, oobn, flags, srcAddr, err = conn.ReadMsgUDPAddrPort(buf, oob)
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

		var msg csptp.Message
		err = csptp.DecodeMessage(&msg, buf)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
				continue
			}
			return time.Time{}, 0, err
		}

		if len(buf) != int(msg.MessageLength) {
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

			if srcAddr.Compare(netip.AddrPortFrom(remoteAddr, csptp.EventPortIP)) != 0 {
				err = errUnexpectedPacketSource
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet: unexpected source")
					continue
				}
				return time.Time{}, 0, err
			}

			tlvbuf := buf[csptp.MinMessageLength:]
			for len(tlvbuf) >= csptp.MinTLVLength {
				var tlvhdr csptp.TLVHeader
				err := csptp.DecodeTLVHeader(&tlvhdr, tlvbuf)
				if err != nil {
					if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
						c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
						continue rxloop
					}
					return time.Time{}, 0, err
				}
				if len(tlvbuf) < int(tlvhdr.Length) {
					err = errUnexpectedPacket
					if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
						c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
						continue rxloop
					}
					return time.Time{}, 0, err
				}
				tlvbuf = tlvbuf[tlvhdr.Length:]
			}
			if len(tlvbuf) != 0 {
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

			if srcAddr.Compare(netip.AddrPortFrom(remoteAddr, csptp.GeneralPortIP)) != 0 {
				err = errUnexpectedPacketSource
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet: unexpected source")
					continue
				}
				return time.Time{}, 0, err
			}

			var resptlvOk bool
			tlvbuf := buf[csptp.MinMessageLength:]
			for len(tlvbuf) >= csptp.MinTLVLength {
				var tlvhdr csptp.TLVHeader
				err := csptp.DecodeTLVHeader(&tlvhdr, tlvbuf)
				if err != nil {
					if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
						c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
						continue rxloop
					}
					return time.Time{}, 0, err
				}
				if len(tlvbuf) < int(tlvhdr.Length) {
					err = errUnexpectedPacket
					if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
						c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
						continue rxloop
					}
					return time.Time{}, 0, err
				}
				if tlvhdr.Type == csptp.TLVTypeOrganizationExtension {
					var tlv csptp.ResponseTLV
					err := csptp.DecodeResponseTLV(&tlv, tlvbuf)
					if err != nil {
						if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
							c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
							continue rxloop
						}
						return time.Time{}, 0, err
					}
					if tlv.Type != csptp.TLVTypeOrganizationExtension ||
						tlv.OrganizationID[0] != csptp.OrganizationIDMeinberg0 ||
						tlv.OrganizationID[1] != csptp.OrganizationIDMeinberg1 ||
						tlv.OrganizationID[2] != csptp.OrganizationIDMeinberg2 ||
						tlv.OrganizationSubType[0] != csptp.OrganizationSubTypeResponse0 ||
						tlv.OrganizationSubType[1] != csptp.OrganizationSubTypeResponse1 ||
						tlv.OrganizationSubType[2] != csptp.OrganizationSubTypeResponse2 {
						err = errUnexpectedPacket
						if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
							c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
							continue rxloop
						}
						return time.Time{}, 0, err
					}
					resptlv, resptlvOk = tlv, true
				}
				tlvbuf = tlvbuf[tlvhdr.Length:]
			}
			if len(tlvbuf) != 0 {
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received unexpected message")
					continue
				}
				return time.Time{}, 0, err
			}

			if !resptlvOk {
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

	c.Log.LogAttrs(ctx, slog.LevelDebug, "received response",
		slog.Time("at", cRxTime1),
		slog.String("from", remoteAddr.String()),
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
		slog.String("from", remoteAddr.String()),
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
