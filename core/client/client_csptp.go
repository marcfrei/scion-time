package client

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"example.com/scion-time/net/csptp"
	"example.com/scion-time/net/udp"
)

type csptpReply struct {
	msg  csptp.Message
	tlv  csptp.ResponseTLV      // FlashPTP: response TLV in Follow Up message
	resp csptp.CSPTPResponseTLV // IEEE P1588.1: CSPTP_RESPONSE TLV in Sync message
	rxt  time.Time
	ok   bool
}

type csptpReplies struct {
	sync     csptpReply
	followUp csptpReply
}

func (r *csptpReplies) complete() bool {
	return r.sync.ok &&
		(r.sync.msg.FlagField&csptp.FlagTwoStep != csptp.FlagTwoStep || r.followUp.ok)
}

func openCSPTPConn(ctx context.Context, log *slog.Logger, dscp uint8,
	localAddr netip.Addr, localZone string, localPort uint16, deadline time.Time, deadlineSet bool) (
	*net.UDPConn, error) {
	var lc net.ListenConfig
	pconn, err := lc.ListenPacket(ctx, "udp", netip.AddrPortFrom(localAddr, localPort).String())
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
	err = udp.EnableTimestamping(conn, localZone, -1 /* index */)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError, "failed to enable timestamping", slog.Any("error", err))
	}
	err = udp.SetDSCP(conn, dscp)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelInfo, "failed to set DSCP", slog.Any("error", err))
	}
	return conn, nil
}

func csptpSyncRequest(b []byte, sequenceID uint16) []byte {
	reqmsg := csptp.Message{
		SdoIDMessageType: csptp.SdoIDMessageType(
			csptp.CSPTPSdoID,
			csptp.MessageTypeSync,
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
			Port:    0,
		},
		SequenceID:         sequenceID,
		ControlField:       csptp.ControlField,
		LogMessageInterval: csptp.LogMessageInterval,
		Timestamp:          csptp.Timestamp{},
	}
	reqtlv := csptp.CSPTPRequestTLV{
		Type:         csptp.TLVTypeCSPTPRequest,
		Length:       csptp.CSPTPRequestTLVLength - csptp.MinTLVLength,
		RequestFlags: 0,
	}
	reqmsg.MessageLength += csptp.CSPTPRequestTLVLength

	b = b[:reqmsg.MessageLength]
	csptp.EncodeMessage(b[:csptp.MinMessageLength], &reqmsg)
	csptp.EncodeCSPTPRequestTLV(b[csptp.MinMessageLength:], &reqtlv)
	return b
}

func flashPTPSyncRequest(b []byte, sequenceID uint16) []byte {
	reqmsg := csptp.Message{
		SdoIDMessageType: csptp.SdoIDMessageType(
			csptp.SdoID, /* csptp.CSPTPSdoID */
			csptp.MessageTypeSync,
		),
		PTPVersion:          csptp.PTPVersion,
		MessageLength:       csptp.MinMessageLength,
		DomainNumber:        0, /* csptp.DomainNumber */
		MinorSdoID:          csptp.MinorSdoID,
		FlagField:           csptp.FlagTwoStep | csptp.FlagUnicast,
		CorrectionField:     0,
		MessageTypeSpecific: 0,
		SourcePortIdentity: csptp.PortID{
			ClockID: 0,
			Port:    1,
		},
		SequenceID:         sequenceID,
		ControlField:       csptp.ControlField,
		LogMessageInterval: 0, /* csptp.LogMessageInterval */
		Timestamp:          csptp.Timestamp{},
	}

	b = b[:reqmsg.MessageLength]
	csptp.EncodeMessage(b, &reqmsg)
	return b
}

func flashPTPFollowUpRequest(b []byte, sequenceID uint16) []byte {
	reqmsg := csptp.Message{
		SdoIDMessageType: csptp.SdoIDMessageType(
			csptp.SdoID, /* csptp.CSPTPSdoID */
			csptp.MessageTypeFollowUp,
		),
		PTPVersion:          csptp.PTPVersion,
		MessageLength:       csptp.MinMessageLength,
		DomainNumber:        0, /* csptp.DomainNumber */
		MinorSdoID:          csptp.MinorSdoID,
		FlagField:           csptp.FlagUnicast,
		CorrectionField:     0,
		MessageTypeSpecific: 0,
		SourcePortIdentity: csptp.PortID{
			ClockID: 0,
			Port:    1,
		},
		SequenceID:         sequenceID,
		ControlField:       csptp.ControlField,
		LogMessageInterval: 0, /* csptp.LogMessageInterval */
		Timestamp:          csptp.Timestamp{},
	}
	reqtlv := csptp.RequestTLV{
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

	b = b[:reqmsg.MessageLength]
	csptp.EncodeMessage(b[:csptp.MinMessageLength], &reqmsg)
	csptp.EncodeRequestTLV(b[csptp.MinMessageLength:], &reqtlv)
	return b
}

func decodeCSPTPReply(reply *csptpReply, b []byte, sequenceID uint16, flashPTP bool) error {
	err := csptp.DecodeMessage(&reply.msg, b)
	if err != nil {
		return err
	}
	if len(b) != int(reply.msg.MessageLength) || reply.msg.SequenceID != sequenceID {
		return errUnexpectedPacket
	}
	if !flashPTP && (reply.msg.MajorSdoID() != csptp.CSPTPSdoID ||
		reply.msg.DomainNumber != csptp.DomainNumber) {
		return errUnexpectedPacket
	}

	// FlashPTP: response TLV in Follow Up message
	// IEEE P1588.1: CSPTP_RESPONSE TLV in Sync message
	var tlvRequired bool
	switch reply.msg.MessageType() {
	case csptp.MessageTypeSync:
		if flashPTP && reply.msg.FlagField&csptp.FlagTwoStep != csptp.FlagTwoStep {
			return errUnexpectedPacket
		}
		tlvRequired = !flashPTP
	case csptp.MessageTypeFollowUp:
		tlvRequired = flashPTP
	default:
		return errUnexpectedPacket
	}

	var tlvFound bool
	tlvbuf := b[csptp.MinMessageLength:]
	for len(tlvbuf) >= csptp.MinTLVLength {
		var tlvhdr csptp.TLVHeader
		err = csptp.DecodeTLVHeader(&tlvhdr, tlvbuf)
		if err != nil {
			return err
		}
		// IEEE 1588: lengthField excludes tlvType and lengthField
		tlvlen := csptp.MinTLVLength + int(tlvhdr.Length)
		if flashPTP {
			// FlashPTP: lengthField includes tlvType and lengthField
			tlvlen = int(tlvhdr.Length)
		}
		if tlvlen < csptp.MinTLVLength || len(tlvbuf) < tlvlen {
			return errUnexpectedPacket
		}
		switch {
		case tlvRequired && flashPTP && tlvhdr.Type == csptp.TLVTypeOrganizationExtension:
			err = csptp.DecodeResponseTLV(&reply.tlv, tlvbuf[:tlvlen])
			if err != nil {
				return err
			}
			if reply.tlv.OrganizationID[0] != csptp.OrganizationIDMeinberg0 ||
				reply.tlv.OrganizationID[1] != csptp.OrganizationIDMeinberg1 ||
				reply.tlv.OrganizationID[2] != csptp.OrganizationIDMeinberg2 ||
				reply.tlv.OrganizationSubType[0] != csptp.OrganizationSubTypeResponse0 ||
				reply.tlv.OrganizationSubType[1] != csptp.OrganizationSubTypeResponse1 ||
				reply.tlv.OrganizationSubType[2] != csptp.OrganizationSubTypeResponse2 {
				return errUnexpectedPacket
			}
			tlvFound = true
		case tlvRequired && !flashPTP && tlvhdr.Type == csptp.TLVTypeCSPTPResponse:
			err = csptp.DecodeCSPTPResponseTLV(&reply.resp, tlvbuf[:tlvlen])
			if err != nil {
				return err
			}
			tlvFound = true
		}
		tlvbuf = tlvbuf[tlvlen:]
	}
	if len(tlvbuf) != 0 || tlvRequired && !tlvFound {
		return errUnexpectedPacket
	}

	return nil
}

func csptpServerTimes(replies *csptpReplies, flashPTP bool) (
	t1 time.Time, t1Corr time.Duration, t2 time.Time, t3Corr, utcCorr time.Duration) {
	respmsg0 := &replies.sync.msg
	respmsg1 := &replies.followUp.msg
	if respmsg0.FlagField&csptp.FlagTwoStep == csptp.FlagTwoStep {
		t2 = csptp.TimeFromTimestamp(respmsg1.Timestamp)
		t3Corr = csptp.DurationFromTimeInterval(respmsg0.CorrectionField) +
			csptp.DurationFromTimeInterval(respmsg1.CorrectionField)
	} else {
		t2 = csptp.TimeFromTimestamp(respmsg0.Timestamp)
		t3Corr = csptp.DurationFromTimeInterval(respmsg0.CorrectionField)
	}
	if flashPTP {
		resptlv := &replies.followUp.tlv
		t1 = csptp.TimeFromTimestamp(resptlv.RequestIngressTimestamp)
		t1Corr = csptp.DurationFromTimeInterval(resptlv.RequestCorrectionField)
		if respmsg1.FlagField&csptp.FlagCurrentUTCOffsetValid == csptp.FlagCurrentUTCOffsetValid {
			utcCorr = time.Duration(int64(resptlv.UTCOffset) * time.Second.Nanoseconds())
		}
	} else {
		resptlv := &replies.sync.resp
		t1 = csptp.TimeFromTimestamp(resptlv.ReqIngressTimestamp)
		t1Corr = csptp.DurationFromTimeInterval(resptlv.ReqCorrectionField)
	}
	return
}
