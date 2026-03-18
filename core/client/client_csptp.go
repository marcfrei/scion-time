package client

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"example.com/scion-time/net/csptp"
	"example.com/scion-time/net/udp"
)

type csptpReply struct {
	msg csptp.Message
	tlv csptp.ResponseTLV
	rxt time.Time
	ok  bool
}

type csptpReplies struct {
	mu       sync.Mutex
	sync     csptpReply
	followUp csptpReply
}

func openCSPTPConn(ctx context.Context, log *slog.Logger, dscp uint8,
	localAddr netip.Addr, localZone string, localPort uint16, deadline time.Time, deadlineSet bool) (
	*net.UDPConn, error) {
	listenAddr := net.UDPAddr{
		IP:   localAddr.AsSlice(),
		Port: int(localPort),
		Zone: localZone,
	}
	var lc net.ListenConfig
	pconn, err := lc.ListenPacket(ctx, "udp", listenAddr.String())
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

func csptpSyncRequest(sequenceID uint16) csptp.Message {
	return csptp.Message{
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
		SequenceID:         sequenceID,
		ControlField:       csptp.ControlSync,
		LogMessageInterval: 0,
		Timestamp:          csptp.Timestamp{},
	}
}

func csptpFollowUpRequest(sequenceID uint16) (csptp.Message, csptp.RequestTLV) {
	reqmsg := csptp.Message{
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
		SequenceID:         sequenceID,
		ControlField:       csptp.ControlFollowUp,
		LogMessageInterval: 0,
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
	return reqmsg, reqtlv
}
