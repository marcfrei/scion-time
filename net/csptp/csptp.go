package csptp

// See FlashPTP at https://github.com/meinberg-sync/flashptpd
// and IEEE 1588-2019, PTP version 2.1

import (
	"errors"
	"time"
)

const (
	EventPortIP      = 319   // Sync
	EventPortSCION   = 10319 // Sync
	GeneralPortIP    = 320   // Follow Up
	GeneralPortSCION = 10320 // Follow Up

	SdoID = 0

	MessageTypeSync     = 0
	MessageTypeFollowUp = 8

	PTPVersion = 0x12

	DomainNumber = 0

	MinorSdoID = 0

	FlagCurrentUTCOffsetValid = 1 << 2
	FlagPTPTimescale          = 1 << 3
	FlagTwoStep               = 1 << 9
	FlagUnicast               = 1 << 10

	ControlSync     = 0
	ControlFollowUp = 2
	ControlOther    = 5

	LogMessageInterval = 0x7f

	TLVTypeOrganizationExtension = 3

	OrganizationIDMeinberg0 = 0xec
	OrganizationIDMeinberg1 = 0x46
	OrganizationIDMeinberg2 = 0x70

	OrganizationSubTypeRequest0 = 0x52
	OrganizationSubTypeRequest1 = 0x65
	OrganizationSubTypeRequest2 = 0x71

	OrganizationSubTypeResponse0 = 0x52
	OrganizationSubTypeResponse1 = 0x65
	OrganizationSubTypeResponse2 = 0x73

	TLVFlagServerStateDS = 1 << 0

	ErrorTxTimestampInvalid = 1
)

type PortID struct {
	ClockID uint64
	Port    uint16
}

type Timestamp struct {
	Seconds     [6]uint8
	Nanoseconds uint32
}

type Message struct {
	SdoIDMessageType    uint8
	PTPVersion          uint8
	MessageLength       uint16
	DomainNumber        uint8
	MinorSdoID          uint8
	FlagField           uint16
	CorrectionField     int64
	MessageTypeSpecific uint32
	SourcePortIdentity  PortID
	SequenceID          uint16
	ControlField        uint8
	LogMessageInterval  int8
	Timestamp           Timestamp
}

type RequestTLV struct {
	Type                uint16
	Length              uint16
	OrganizationID      [3]uint8
	OrganizationSubType [3]uint8
	FlagField           uint32
}

type ServerStateDS struct {
	GMPriority1     uint8
	GMClockClass    uint8
	GMClockAccuracy uint8
	GMClockVariance uint16
	GMPriority2     uint8
	GMClockID       uint64
	StepsRemoved    uint16
	TimeSource      uint8
	Reserved        uint8
}

type ResponseTLV struct {
	Type                    uint16
	Length                  uint16
	OrganizationID          [3]uint8
	OrganizationSubType     [3]uint8
	FlagField               uint32
	Error                   uint16
	RequestIngressTimestamp Timestamp
	RequestCorrectionField  int64
	UTCOffset               int16
	ServerStateDS           ServerStateDS
}

//lint:ignore U1000 work in progress
func flagField(twoStep bool) uint16 {
	f := uint16(FlagUnicast)
	if twoStep {
		f |= FlagTwoStep
	}
	return f
}

func TimestampFromTime(t time.Time) Timestamp {
	s := t.Unix()
	if s < 0 {
		panic("invalid argument: t must not be before 1970-01-01T00:00:00Z")
	}
	if s > 1<<48-1 {
		panic("invalid argument: t must not be after 8921556-12-07T10:44:15.999999999Z")
	}
	return Timestamp{
		Seconds: [6]uint8{
			uint8(uint64(s) >> 40), uint8(uint64(s) >> 32), uint8(uint64(s) >> 24),
			uint8(uint64(s) >> 16), uint8(uint64(s) >> 8), uint8(uint64(s))},
		Nanoseconds: uint32(t.Nanosecond()),
	}
}

func TimeFromTimestamp(t Timestamp) time.Time {
	s := uint64(t.Seconds[0])<<40 | uint64(t.Seconds[1])<<32 | uint64(t.Seconds[2])<<24 |
		uint64(t.Seconds[3])<<16 | uint64(t.Seconds[4])<<8 | uint64(t.Seconds[5])
	return time.Unix(int64(s), int64(t.Nanoseconds)).UTC()
}

func DurationFromTimeInterval(i int64) time.Duration {
	return time.Duration(i >> 16)
}

const MinMessageLength = 44

func EncodeMessage(b []byte, msg *Message) {
	b[0] = byte(msg.SdoIDMessageType)
	b[1] = byte(msg.PTPVersion)
	b[2] = byte(msg.MessageLength >> 8)
	b[3] = byte(msg.MessageLength)
	b[4] = byte(msg.DomainNumber)
	b[5] = byte(msg.MinorSdoID)
	b[6] = byte(msg.FlagField >> 8)
	b[7] = byte(msg.FlagField)
	b[8] = byte(uint64(msg.CorrectionField) >> 56)
	b[9] = byte(uint64(msg.CorrectionField) >> 48)
	b[10] = byte(uint64(msg.CorrectionField) >> 40)
	b[11] = byte(uint64(msg.CorrectionField) >> 32)
	b[12] = byte(uint64(msg.CorrectionField) >> 24)
	b[13] = byte(uint64(msg.CorrectionField) >> 16)
	b[14] = byte(uint64(msg.CorrectionField) >> 8)
	b[15] = byte(uint64(msg.CorrectionField))
	b[16] = byte(msg.MessageTypeSpecific >> 24)
	b[17] = byte(msg.MessageTypeSpecific >> 16)
	b[18] = byte(msg.MessageTypeSpecific >> 8)
	b[19] = byte(msg.MessageTypeSpecific)
	b[20] = byte(msg.SourcePortIdentity.ClockID >> 56)
	b[21] = byte(msg.SourcePortIdentity.ClockID >> 48)
	b[22] = byte(msg.SourcePortIdentity.ClockID >> 40)
	b[23] = byte(msg.SourcePortIdentity.ClockID >> 32)
	b[24] = byte(msg.SourcePortIdentity.ClockID >> 24)
	b[25] = byte(msg.SourcePortIdentity.ClockID >> 16)
	b[26] = byte(msg.SourcePortIdentity.ClockID >> 8)
	b[27] = byte(msg.SourcePortIdentity.ClockID)
	b[28] = byte(msg.SourcePortIdentity.Port >> 8)
	b[29] = byte(msg.SourcePortIdentity.Port)
	b[30] = byte(msg.SequenceID >> 8)
	b[31] = byte(msg.SequenceID)
	b[32] = byte(msg.ControlField)
	b[33] = byte(msg.LogMessageInterval)
	b[34] = byte(msg.Timestamp.Seconds[0])
	b[35] = byte(msg.Timestamp.Seconds[1])
	b[36] = byte(msg.Timestamp.Seconds[2])
	b[37] = byte(msg.Timestamp.Seconds[3])
	b[38] = byte(msg.Timestamp.Seconds[4])
	b[39] = byte(msg.Timestamp.Seconds[5])
	b[40] = byte(msg.Timestamp.Nanoseconds >> 24)
	b[41] = byte(msg.Timestamp.Nanoseconds >> 16)
	b[42] = byte(msg.Timestamp.Nanoseconds >> 8)
	b[43] = byte(msg.Timestamp.Nanoseconds)
}

var (
	errUnexpectedMessageSize = errors.New("unexpected message size")
)

func DecodeMessage(msg *Message, b []byte) error {
	if len(b) < MinMessageLength {
		return errUnexpectedMessageSize
	}

	msg.SdoIDMessageType = b[0]
	msg.PTPVersion = b[1]
	msg.MessageLength = uint16(b[2])<<8 | uint16(b[3])
	msg.DomainNumber = b[4]
	msg.MinorSdoID = b[5]
	msg.FlagField = uint16(b[6])<<8 | uint16(b[7])
	msg.CorrectionField = int64(uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15]))
	msg.MessageTypeSpecific = uint32(b[16])<<24 | uint32(b[17])<<16 | uint32(b[18])<<8 | uint32(b[19])
	msg.SourcePortIdentity.ClockID = uint64(b[20])<<56 | uint64(b[21])<<48 | uint64(b[22])<<40 | uint64(b[23])<<32 |
		uint64(b[24])<<24 | uint64(b[25])<<16 | uint64(b[26])<<8 | uint64(b[27])
	msg.SourcePortIdentity.Port = uint16(b[28])<<8 | uint16(b[29])
	msg.SequenceID = uint16(b[30])<<8 | uint16(b[31])
	msg.ControlField = b[32]
	msg.LogMessageInterval = int8(b[33])
	msg.Timestamp.Seconds = [6]uint8{b[34], b[35], b[36], b[37], b[38], b[39]}
	msg.Timestamp.Nanoseconds = uint32(b[40])<<24 | uint32(b[41])<<16 | uint32(b[42])<<8 | uint32(b[43])

	return nil
}

func EncodedRequestTLVLength(tlv *RequestTLV) int {
	len := 14 + /* padding: */ 22
	if tlv.FlagField&TLVFlagServerStateDS == TLVFlagServerStateDS {
		len += 18
	}
	return len
}

func EncodeRequestTLV(b []byte, tlv *RequestTLV) {
	b[0] = byte(tlv.Type >> 8)
	b[1] = byte(tlv.Type)
	b[2] = byte(tlv.Length >> 8)
	b[3] = byte(tlv.Length)
	b[4] = byte(tlv.OrganizationID[0])
	b[5] = byte(tlv.OrganizationID[1])
	b[6] = byte(tlv.OrganizationID[2])
	b[7] = byte(tlv.OrganizationSubType[0])
	b[8] = byte(tlv.OrganizationSubType[1])
	b[9] = byte(tlv.OrganizationSubType[2])
	b[10] = byte(tlv.FlagField >> 24)
	b[11] = byte(tlv.FlagField >> 16)
	b[12] = byte(tlv.FlagField >> 8)
	b[13] = byte(tlv.FlagField)
	for i := 14; i != 36; i++ {
		b[i] = 0
	}
	if tlv.FlagField&TLVFlagServerStateDS == TLVFlagServerStateDS {
		for i := 36; i != 54; i++ {
			b[i] = 0
		}
	}
}

var (
	errUnexpectedRequestTLVSize = errors.New("unexpected request TLV size")
)

func DecodeRequestTLV(tlv *RequestTLV, b []byte) error {
	if len(b) < 14 {
		return errUnexpectedRequestTLVSize
	}
	tlv.Type = uint16(b[0])<<8 | uint16(b[1])
	tlv.Length = uint16(b[2])<<8 | uint16(b[3])
	tlv.OrganizationID = [3]uint8{b[4], b[5], b[6]}
	tlv.OrganizationSubType = [3]uint8{b[7], b[8], b[9]}
	tlv.FlagField = uint32(b[10])<<24 | uint32(b[11])<<16 | uint32(b[12])<<8 | uint32(b[13])
	if len(b) < EncodedRequestTLVLength(tlv) {
		return errUnexpectedRequestTLVSize
	}

	return nil
}

func EncodedResponseTLVLength(tlv *ResponseTLV) int {
	len := 36
	if tlv.FlagField&TLVFlagServerStateDS == TLVFlagServerStateDS {
		len += 18
	}
	return len
}

func EncodeResponseTLV(b []byte, tlv *ResponseTLV) {
	b[0] = byte(tlv.Type >> 8)
	b[1] = byte(tlv.Type)
	b[2] = byte(tlv.Length >> 8)
	b[3] = byte(tlv.Length)
	b[4] = byte(tlv.OrganizationID[0])
	b[5] = byte(tlv.OrganizationID[1])
	b[6] = byte(tlv.OrganizationID[2])
	b[7] = byte(tlv.OrganizationSubType[0])
	b[8] = byte(tlv.OrganizationSubType[1])
	b[9] = byte(tlv.OrganizationSubType[2])
	b[10] = byte(tlv.FlagField >> 24)
	b[11] = byte(tlv.FlagField >> 16)
	b[12] = byte(tlv.FlagField >> 8)
	b[13] = byte(tlv.FlagField)
	b[14] = byte(tlv.Error >> 8)
	b[15] = byte(tlv.Error)
	b[16] = byte(tlv.RequestIngressTimestamp.Seconds[0])
	b[17] = byte(tlv.RequestIngressTimestamp.Seconds[1])
	b[18] = byte(tlv.RequestIngressTimestamp.Seconds[2])
	b[19] = byte(tlv.RequestIngressTimestamp.Seconds[3])
	b[20] = byte(tlv.RequestIngressTimestamp.Seconds[4])
	b[21] = byte(tlv.RequestIngressTimestamp.Seconds[5])
	b[22] = byte(tlv.RequestIngressTimestamp.Nanoseconds >> 24)
	b[23] = byte(tlv.RequestIngressTimestamp.Nanoseconds >> 16)
	b[24] = byte(tlv.RequestIngressTimestamp.Nanoseconds >> 8)
	b[25] = byte(tlv.RequestIngressTimestamp.Nanoseconds)
	b[26] = byte(uint64(tlv.RequestCorrectionField) >> 56)
	b[27] = byte(uint64(tlv.RequestCorrectionField) >> 48)
	b[28] = byte(uint64(tlv.RequestCorrectionField) >> 40)
	b[29] = byte(uint64(tlv.RequestCorrectionField) >> 32)
	b[30] = byte(uint64(tlv.RequestCorrectionField) >> 24)
	b[31] = byte(uint64(tlv.RequestCorrectionField) >> 16)
	b[32] = byte(uint64(tlv.RequestCorrectionField) >> 8)
	b[33] = byte(uint64(tlv.RequestCorrectionField))
	b[34] = byte(tlv.UTCOffset >> 8)
	b[35] = byte(tlv.UTCOffset)
	if tlv.FlagField&TLVFlagServerStateDS == TLVFlagServerStateDS {
		b[36] = byte(tlv.ServerStateDS.GMPriority1)
		b[37] = byte(tlv.ServerStateDS.GMClockClass)
		b[38] = byte(tlv.ServerStateDS.GMClockAccuracy)
		b[39] = byte(tlv.ServerStateDS.GMClockVariance >> 8)
		b[40] = byte(tlv.ServerStateDS.GMClockVariance)
		b[41] = byte(tlv.ServerStateDS.GMPriority2)
		b[42] = byte(tlv.ServerStateDS.GMClockID >> 56)
		b[43] = byte(tlv.ServerStateDS.GMClockID >> 48)
		b[44] = byte(tlv.ServerStateDS.GMClockID >> 40)
		b[45] = byte(tlv.ServerStateDS.GMClockID >> 32)
		b[46] = byte(tlv.ServerStateDS.GMClockID >> 24)
		b[47] = byte(tlv.ServerStateDS.GMClockID >> 16)
		b[48] = byte(tlv.ServerStateDS.GMClockID >> 8)
		b[49] = byte(tlv.ServerStateDS.GMClockID)
		b[50] = byte(tlv.ServerStateDS.StepsRemoved >> 8)
		b[51] = byte(tlv.ServerStateDS.StepsRemoved)
		b[52] = byte(tlv.ServerStateDS.TimeSource)
		b[53] = byte(tlv.ServerStateDS.Reserved)
	}
}

var (
	errUnexpectedResponseTLVSize = errors.New("unexpected response TLV size")
)

func DecodeResponseTLV(tlv *ResponseTLV, b []byte) error {
	if len(b) < 14 {
		return errUnexpectedResponseTLVSize
	}
	tlv.Type = uint16(b[0])<<8 | uint16(b[1])
	tlv.Length = uint16(b[2])<<8 | uint16(b[3])
	tlv.OrganizationID = [3]uint8{b[4], b[5], b[6]}
	tlv.OrganizationSubType = [3]uint8{b[7], b[8], b[9]}
	tlv.FlagField = uint32(b[10])<<24 | uint32(b[11])<<16 | uint32(b[12])<<8 | uint32(b[13])
	if len(b) < EncodedResponseTLVLength(tlv) {
		return errUnexpectedResponseTLVSize
	}

	tlv.Error = uint16(b[14])<<8 | uint16(b[15])
	tlv.RequestIngressTimestamp.Seconds = [6]uint8{b[16], b[17], b[18], b[19], b[20], b[21]}
	tlv.RequestIngressTimestamp.Nanoseconds = uint32(b[22])<<24 | uint32(b[23])<<16 | uint32(b[24])<<8 | uint32(b[25])
	tlv.RequestCorrectionField = int64(uint64(b[26])<<56 | uint64(b[27])<<48 | uint64(b[28])<<40 | uint64(b[29])<<32 |
		uint64(b[30])<<24 | uint64(b[31])<<16 | uint64(b[32])<<8 | uint64(b[33]))
	tlv.UTCOffset = int16(uint16(b[34])<<8 | uint16(b[35]))
	if tlv.FlagField&TLVFlagServerStateDS == TLVFlagServerStateDS {
		tlv.ServerStateDS.GMPriority1 = b[36]
		tlv.ServerStateDS.GMClockClass = b[37]
		tlv.ServerStateDS.GMClockAccuracy = b[38]
		tlv.ServerStateDS.GMClockVariance = uint16(b[39])<<8 | uint16(b[40])
		tlv.ServerStateDS.GMPriority2 = b[41]
		tlv.ServerStateDS.GMClockID = uint64(b[42])<<56 | uint64(b[43])<<48 | uint64(b[44])<<40 | uint64(b[45])<<32 |
			uint64(b[46])<<24 | uint64(b[47])<<16 | uint64(b[48])<<8 | uint64(b[49])
		tlv.ServerStateDS.StepsRemoved = uint16(b[50])<<8 | uint16(b[51])
		tlv.ServerStateDS.TimeSource = b[52]
		tlv.ServerStateDS.Reserved = b[53]
	} else {
		tlv.ServerStateDS.GMPriority1 = 0
		tlv.ServerStateDS.GMClockClass = 0
		tlv.ServerStateDS.GMClockAccuracy = 0
		tlv.ServerStateDS.GMClockVariance = 0
		tlv.ServerStateDS.GMPriority2 = 0
		tlv.ServerStateDS.GMClockID = 0
		tlv.ServerStateDS.StepsRemoved = 0
		tlv.ServerStateDS.TimeSource = 0
		tlv.ServerStateDS.Reserved = 0
	}

	return nil
}
