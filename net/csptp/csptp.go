package csptp

// See FlashPTP at https://github.com/meinberg-sync/flashptpd
// and IEEE 1588-2019, PTP version 2.1

import (
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

	VersionMin     = 1
	VersionMax     = 0x12
	VersionDefault = 0x12

	DomainNumber = 0
)

type PortID struct {
	ClockID uint64
	Port    uint16
}

type Timestamp struct {
	Seconds     [6]uint8
	Nanoseconds uint32
}

type Packet struct {
	SdoIDMessageType    uint8
	Version             uint8
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

func DecodePacket(pkt *Packet, b []byte) error {
	return nil
}

func EncodePacket(b *[]byte, pkt *Packet) {}
