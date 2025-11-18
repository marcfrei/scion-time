package csptp_test

// Based on Claude AI interactions

import (
	"bytes"
	"math"
	"testing"
	"time"

	"example.com/scion-time/net/csptp"
)

func TestSdoIDMessageTypeRoundTrip(t *testing.T) {
	vs := []uint8{0, 1, math.MaxUint8 - 1, math.MaxUint8,
		csptp.MessageTypeSync, csptp.MessageTypeFollowUp}
	for _, v := range vs {
		msg0 := csptp.Message{SdoIDMessageType: v}
		b := make([]byte, csptp.MinMessageLength)
		csptp.EncodeMessage(b, &msg0)
		var msg1 csptp.Message
		err := csptp.DecodeMessage(&msg1, b)
		if err != nil {
			t.Fatal(err)
		}
		if msg0.SdoIDMessageType != v {
			t.Fail()
		}
		if msg1.SdoIDMessageType != msg0.SdoIDMessageType {
			t.Fail()
		}
	}
}

func TestPTPVersionRoundTrip(t *testing.T) {
	vs := []uint8{0, 1, math.MaxUint8 - 1, math.MaxUint8,
		csptp.PTPVersion}
	for _, v := range vs {
		msg0 := csptp.Message{PTPVersion: v}
		b := make([]byte, csptp.MinMessageLength)
		csptp.EncodeMessage(b, &msg0)
		var msg1 csptp.Message
		err := csptp.DecodeMessage(&msg1, b)
		if err != nil {
			t.Fatal(err)
		}
		if msg0.PTPVersion != v {
			t.Fail()
		}
		if msg1.PTPVersion != msg0.PTPVersion {
			t.Fail()
		}
	}
}

func TestMessageLengthRoundTrip(t *testing.T) {
	vs := []uint16{0, 1, math.MaxUint16 - 1, math.MaxUint16}
	for _, v := range vs {
		msg0 := csptp.Message{MessageLength: v}
		b := make([]byte, csptp.MinMessageLength)
		csptp.EncodeMessage(b, &msg0)
		var msg1 csptp.Message
		err := csptp.DecodeMessage(&msg1, b)
		if err != nil {
			t.Fatal(err)
		}
		if msg0.MessageLength != v {
			t.Fail()
		}
		if msg1.MessageLength != msg0.MessageLength {
			t.Fail()
		}
	}
}

func TestDomainNumberRoundTrip(t *testing.T) {
	vs := []uint8{0, 1, math.MaxUint8 - 1, math.MaxUint8}
	for _, v := range vs {
		msg0 := csptp.Message{DomainNumber: v}
		b := make([]byte, csptp.MinMessageLength)
		csptp.EncodeMessage(b, &msg0)
		var msg1 csptp.Message
		err := csptp.DecodeMessage(&msg1, b)
		if err != nil {
			t.Fatal(err)
		}
		if msg0.DomainNumber != v {
			t.Fail()
		}
		if msg1.DomainNumber != msg0.DomainNumber {
			t.Fail()
		}
	}
}

func TestMinorSdoIDRoundTrip(t *testing.T) {
	vs := []uint8{0, 1, math.MaxUint8 - 1, math.MaxUint8}
	for _, v := range vs {
		msg0 := csptp.Message{MinorSdoID: v}
		b := make([]byte, csptp.MinMessageLength)
		csptp.EncodeMessage(b, &msg0)
		var msg1 csptp.Message
		err := csptp.DecodeMessage(&msg1, b)
		if err != nil {
			t.Fatal(err)
		}
		if msg0.MinorSdoID != v {
			t.Fail()
		}
		if msg1.MinorSdoID != msg0.MinorSdoID {
			t.Fail()
		}
	}
}

func TestFlagFieldRoundTrip(t *testing.T) {
	vs := []uint16{0, 1, math.MaxUint16 - 1, math.MaxUint16,
		csptp.FlagTwoStep, csptp.FlagUnicast, csptp.FlagCurrentUTCOffsetValid, csptp.FlagPTPTimescale}
	for _, v := range vs {
		msg0 := csptp.Message{FlagField: v}
		b := make([]byte, csptp.MinMessageLength)
		csptp.EncodeMessage(b, &msg0)
		var msg1 csptp.Message
		err := csptp.DecodeMessage(&msg1, b)
		if err != nil {
			t.Fatal(err)
		}
		if msg0.FlagField != v {
			t.Fail()
		}
		if msg1.FlagField != msg0.FlagField {
			t.Fail()
		}
	}
}

func TestCorrectionFieldRoundTrip(t *testing.T) {
	vs := []int64{math.MinInt64, math.MinInt64 + 1, -1, 0, 1, math.MaxInt64 - 1, math.MaxInt64}
	for _, v := range vs {
		msg0 := csptp.Message{CorrectionField: v}
		b := make([]byte, csptp.MinMessageLength)
		csptp.EncodeMessage(b, &msg0)
		var msg1 csptp.Message
		err := csptp.DecodeMessage(&msg1, b)
		if err != nil {
			t.Fatal(err)
		}
		if msg0.CorrectionField != v {
			t.Fail()
		}
		if msg1.CorrectionField != msg0.CorrectionField {
			t.Fail()
		}
	}
}

func TestMessageTypeSpecificRoundTrip(t *testing.T) {
	vs := []uint32{0, 1, math.MaxUint32 - 1, math.MaxUint32}
	for _, v := range vs {
		msg0 := csptp.Message{MessageTypeSpecific: v}
		b := make([]byte, csptp.MinMessageLength)
		csptp.EncodeMessage(b, &msg0)
		var msg1 csptp.Message
		err := csptp.DecodeMessage(&msg1, b)
		if err != nil {
			t.Fatal(err)
		}
		if msg0.MessageTypeSpecific != v {
			t.Fail()
		}
		if msg1.MessageTypeSpecific != msg0.MessageTypeSpecific {
			t.Fail()
		}
	}
}

func TestSourcePortIdentityRoundTrip(t *testing.T) {
	vs := []csptp.PortID{
		{ClockID: 0, Port: 0},
		{ClockID: 0, Port: math.MaxUint16},
		{ClockID: 1, Port: 0},
		{ClockID: 1, Port: math.MaxUint16},
		{ClockID: math.MaxUint64 - 1, Port: 0},
		{ClockID: math.MaxUint64 - 1, Port: math.MaxUint16},
		{ClockID: math.MaxUint64, Port: 0},
		{ClockID: math.MaxUint64, Port: math.MaxUint16},
	}
	for _, v := range vs {
		msg0 := csptp.Message{SourcePortIdentity: v}
		b := make([]byte, csptp.MinMessageLength)
		csptp.EncodeMessage(b, &msg0)
		var msg1 csptp.Message
		err := csptp.DecodeMessage(&msg1, b)
		if err != nil {
			t.Fatal(err)
		}
		if msg0.SourcePortIdentity != v {
			t.Fail()
		}
		if msg1.SourcePortIdentity != msg0.SourcePortIdentity {
			t.Fail()
		}
	}
}

func TestSequenceIDRoundTrip(t *testing.T) {
	vs := []uint16{0, 1, math.MaxUint16 - 1, math.MaxUint16}
	for _, v := range vs {
		msg0 := csptp.Message{SequenceID: v}
		b := make([]byte, csptp.MinMessageLength)
		csptp.EncodeMessage(b, &msg0)
		var msg1 csptp.Message
		err := csptp.DecodeMessage(&msg1, b)
		if err != nil {
			t.Fatal(err)
		}
		if msg0.SequenceID != v {
			t.Fail()
		}
		if msg1.SequenceID != msg0.SequenceID {
			t.Fail()
		}
	}
}

func TestControlFieldRoundTrip(t *testing.T) {
	vs := []uint8{0, 1, math.MaxUint8 - 1, math.MaxUint8,
		csptp.ControlSync, csptp.ControlFollowUp, csptp.ControlOther}
	for _, v := range vs {
		msg0 := csptp.Message{ControlField: v}
		b := make([]byte, csptp.MinMessageLength)
		csptp.EncodeMessage(b, &msg0)
		var msg1 csptp.Message
		err := csptp.DecodeMessage(&msg1, b)
		if err != nil {
			t.Fatal(err)
		}
		if msg0.ControlField != v {
			t.Fail()
		}
		if msg1.ControlField != msg0.ControlField {
			t.Fail()
		}
	}
}

func TestLogMessageIntervalRoundTrip(t *testing.T) {
	vs := []int8{math.MinInt8, math.MinInt8 + 1, -1, 0, 1, math.MaxInt8 - 1, math.MaxInt8,
		csptp.LogMessageInterval}
	for _, v := range vs {
		msg0 := csptp.Message{LogMessageInterval: v}
		b := make([]byte, csptp.MinMessageLength)
		csptp.EncodeMessage(b, &msg0)
		var msg1 csptp.Message
		err := csptp.DecodeMessage(&msg1, b)
		if err != nil {
			t.Fatal(err)
		}
		if msg0.LogMessageInterval != v {
			t.Fail()
		}
		if msg1.LogMessageInterval != msg0.LogMessageInterval {
			t.Fail()
		}
	}
}

func TestTimestampRoundTrip(t *testing.T) {
	vs := []csptp.Timestamp{
		{
			Seconds:     [6]uint8{0, 0, 0, 0, 0, 0},
			Nanoseconds: 0,
		},
		{
			Seconds:     [6]uint8{0, 0, 0, 0, 0, 1},
			Nanoseconds: 1,
		},
		{
			Seconds:     [6]uint8{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE},
			Nanoseconds: math.MaxUint32 - 1,
		},
		{
			Seconds:     [6]uint8{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			Nanoseconds: math.MaxUint32,
		},
	}
	for _, v := range vs {
		msg0 := csptp.Message{Timestamp: v}
		b := make([]byte, csptp.MinMessageLength)
		csptp.EncodeMessage(b, &msg0)
		var msg1 csptp.Message
		err := csptp.DecodeMessage(&msg1, b)
		if err != nil {
			t.Fatal(err)
		}
		if msg0.Timestamp != v {
			t.Fail()
		}
		if msg1.Timestamp != msg0.Timestamp {
			t.Fail()
		}
	}
}

func TestCompleteMessageRoundTrip(t *testing.T) {
	msg0 := csptp.Message{
		SdoIDMessageType:    csptp.MessageTypeSync,
		PTPVersion:          csptp.PTPVersion,
		MessageLength:       csptp.MinMessageLength,
		DomainNumber:        csptp.DomainNumber,
		MinorSdoID:          0,
		FlagField:           csptp.FlagTwoStep | csptp.FlagUnicast,
		CorrectionField:     0x123456789ABCDEF,
		MessageTypeSpecific: 0xDEADBEEF,
		SourcePortIdentity: csptp.PortID{
			ClockID: 0xAAAABBBBCCCCDDDD,
			Port:    0xEEEE,
		},
		SequenceID:         0xFFFF,
		ControlField:       csptp.ControlSync,
		LogMessageInterval: csptp.LogMessageInterval,
		Timestamp: csptp.Timestamp{
			Seconds:     [6]uint8{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			Nanoseconds: 0x77777777,
		},
	}
	b := make([]byte, csptp.MinMessageLength)
	csptp.EncodeMessage(b, &msg0)
	var msg1 csptp.Message
	err := csptp.DecodeMessage(&msg1, b)
	if err != nil {
		t.Fatal(err)
	}
	if msg1 != msg0 {
		t.Fail()
	}
}

func TestRequestTLVTypeRoundTrip(t *testing.T) {
	vs := []uint16{0, 1, math.MaxUint16 - 1, math.MaxUint16,
		csptp.TLVTypeOrganizationExtension}
	for _, v := range vs {
		tlv0 := csptp.RequestTLV{Type: v}
		b := make([]byte, csptp.EncodedRequestTLVLength(&tlv0))
		csptp.EncodeRequestTLV(b, &tlv0)
		var tlv1 csptp.RequestTLV
		err := csptp.DecodeRequestTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.Type != v {
			t.Fail()
		}
		if tlv1.Type != tlv0.Type {
			t.Fail()
		}
	}
}

func TestRequestTLVLengthRoundTrip(t *testing.T) {
	vs := []uint16{0, 1, math.MaxUint16 - 1, math.MaxUint16}
	for _, v := range vs {
		tlv0 := csptp.RequestTLV{Length: v}
		b := make([]byte, csptp.EncodedRequestTLVLength(&tlv0))
		csptp.EncodeRequestTLV(b, &tlv0)
		var tlv1 csptp.RequestTLV
		err := csptp.DecodeRequestTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.Length != v {
			t.Fail()
		}
		if tlv1.Length != tlv0.Length {
			t.Fail()
		}
	}
}

func TestRequestTLVOrganizationIDRoundTrip(t *testing.T) {
	vs := [][3]uint8{
		{0, 0, 0},
		{1, 1, 1},
		{0xFF, 0xFF, 0xFE},
		{0xFF, 0xFF, 0xFF},
		{csptp.OrganizationIDMeinberg0, csptp.OrganizationIDMeinberg1, csptp.OrganizationIDMeinberg2},
	}
	for _, v := range vs {
		tlv0 := csptp.RequestTLV{OrganizationID: v}
		b := make([]byte, csptp.EncodedRequestTLVLength(&tlv0))
		csptp.EncodeRequestTLV(b, &tlv0)
		var tlv1 csptp.RequestTLV
		err := csptp.DecodeRequestTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.OrganizationID != v {
			t.Fail()
		}
		if tlv1.OrganizationID != tlv0.OrganizationID {
			t.Fail()
		}
	}
}

func TestRequestTLVOrganizationSubTypeRoundTrip(t *testing.T) {
	vs := [][3]uint8{
		{0, 0, 0},
		{1, 1, 1},
		{0xFF, 0xFF, 0xFE},
		{0xFF, 0xFF, 0xFF},
		{csptp.OrganizationSubTypeRequest0, csptp.OrganizationSubTypeRequest1, csptp.OrganizationSubTypeRequest2},
	}
	for _, v := range vs {
		tlv0 := csptp.RequestTLV{OrganizationSubType: v}
		b := make([]byte, csptp.EncodedRequestTLVLength(&tlv0))
		csptp.EncodeRequestTLV(b, &tlv0)
		var tlv1 csptp.RequestTLV
		err := csptp.DecodeRequestTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.OrganizationSubType != v {
			t.Fail()
		}
		if tlv1.OrganizationSubType != tlv0.OrganizationSubType {
			t.Fail()
		}
	}
}

func TestRequestTLVFlagFieldRoundTrip(t *testing.T) {
	vs := []uint32{0, 1, math.MaxUint32 - 1, math.MaxUint32,
		csptp.TLVFlagServerStateDS}
	for _, v := range vs {
		tlv0 := csptp.RequestTLV{FlagField: v}
		b := make([]byte, csptp.EncodedRequestTLVLength(&tlv0))
		csptp.EncodeRequestTLV(b, &tlv0)
		var tlv1 csptp.RequestTLV
		err := csptp.DecodeRequestTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.FlagField != v {
			t.Fail()
		}
		if tlv1.FlagField != tlv0.FlagField {
			t.Fail()
		}
	}
}

func TestRequestTLVFlagFieldServerStateDSRoundTrip(t *testing.T) {
	vs := []uint32{0, csptp.TLVFlagServerStateDS}
	for _, v := range vs {
		tlv0 := csptp.RequestTLV{FlagField: v}
		b := make([]byte, csptp.EncodedRequestTLVLength(&tlv0))
		csptp.EncodeRequestTLV(b, &tlv0)
		var tlv1 csptp.RequestTLV
		err := csptp.DecodeRequestTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.FlagField != v {
			t.Fail()
		}
		if tlv1.FlagField != tlv0.FlagField {
			t.Fail()
		}

		expectedLen := 36
		if v&csptp.TLVFlagServerStateDS == csptp.TLVFlagServerStateDS {
			expectedLen = 54
		}
		if len(b) != expectedLen {
			t.Fail()
		}
	}
}

func TestCompleteRequestTLVRoundTrip(t *testing.T) {
	tlv0 := csptp.RequestTLV{
		Type: csptp.TLVTypeOrganizationExtension,
		OrganizationID: [3]uint8{
			csptp.OrganizationIDMeinberg0,
			csptp.OrganizationIDMeinberg1,
			csptp.OrganizationIDMeinberg2,
		},
		OrganizationSubType: [3]uint8{
			csptp.OrganizationSubTypeRequest0,
			csptp.OrganizationSubTypeRequest1,
			csptp.OrganizationSubTypeRequest2,
		},
		FlagField: csptp.TLVFlagServerStateDS,
	}
	tlv0.Length = uint16(csptp.EncodedRequestTLVLength(&tlv0)) - 4

	b := make([]byte, csptp.EncodedRequestTLVLength(&tlv0))
	csptp.EncodeRequestTLV(b, &tlv0)
	var tlv1 csptp.RequestTLV
	err := csptp.DecodeRequestTLV(&tlv1, b)
	if err != nil {
		t.Fatal(err)
	}
	if tlv1 != tlv0 {
		t.Fail()
	}
}

func TestRequestTLVInvalidLength(t *testing.T) {
	var err error
	var tlv0, tlv1 csptp.RequestTLV
	var b []byte

	tlv0 = csptp.RequestTLV{}
	b = make([]byte, csptp.EncodedRequestTLVLength(&tlv0))
	csptp.EncodeRequestTLV(b, &tlv0)
	tlv1 = csptp.RequestTLV{}
	err = csptp.DecodeRequestTLV(&tlv1, b[:13])
	if err == nil {
		t.Error("Expected error for insufficient buffer length")
	}

	tlv0 = csptp.RequestTLV{}
	b = make([]byte, csptp.EncodedRequestTLVLength(&tlv0))
	csptp.EncodeRequestTLV(b, &tlv0)
	tlv1 = csptp.RequestTLV{}
	err = csptp.DecodeRequestTLV(&tlv1, b[:len(b)-1])
	if err == nil {
		t.Error("Expected error for insufficient buffer length")
	}

	tlv0 = csptp.RequestTLV{FlagField: csptp.TLVFlagServerStateDS}
	b = make([]byte, csptp.EncodedRequestTLVLength(&tlv0))
	csptp.EncodeRequestTLV(b, &tlv0)
	tlv1 = csptp.RequestTLV{}
	err = csptp.DecodeRequestTLV(&tlv1, b[:len(b)-1])
	if err == nil {
		t.Error("Expected error for insufficient buffer length with ServerStateDS flag set")
	}
}

func TestResponseTLVTypeRoundTrip(t *testing.T) {
	vs := []uint16{0, 1, math.MaxUint16 - 1, math.MaxUint16,
		csptp.TLVTypeOrganizationExtension}
	for _, v := range vs {
		tlv0 := csptp.ResponseTLV{Type: v}
		b := make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
		csptp.EncodeResponseTLV(b, &tlv0)
		var tlv1 csptp.ResponseTLV
		err := csptp.DecodeResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.Type != v {
			t.Fail()
		}
		if tlv1.Type != tlv0.Type {
			t.Fail()
		}
	}
}

func TestResponseTLVLengthRoundTrip(t *testing.T) {
	vs := []uint16{0, 1, math.MaxUint16 - 1, math.MaxUint16}
	for _, v := range vs {
		tlv0 := csptp.ResponseTLV{Length: v}
		b := make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
		csptp.EncodeResponseTLV(b, &tlv0)
		var tlv1 csptp.ResponseTLV
		err := csptp.DecodeResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.Length != v {
			t.Fail()
		}
		if tlv1.Length != tlv0.Length {
			t.Fail()
		}
	}
}

func TestResponseTLVOrganizationIDRoundTrip(t *testing.T) {
	vs := [][3]uint8{
		{0, 0, 0},
		{1, 1, 1},
		{0xFF, 0xFF, 0xFE},
		{0xFF, 0xFF, 0xFF},
		{csptp.OrganizationIDMeinberg0, csptp.OrganizationIDMeinberg1, csptp.OrganizationIDMeinberg2},
	}
	for _, v := range vs {
		tlv0 := csptp.ResponseTLV{OrganizationID: v}
		b := make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
		csptp.EncodeResponseTLV(b, &tlv0)
		var tlv1 csptp.ResponseTLV
		err := csptp.DecodeResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.OrganizationID != v {
			t.Fail()
		}
		if tlv1.OrganizationID != tlv0.OrganizationID {
			t.Fail()
		}
	}
}

func TestResponseTLVOrganizationSubTypeRoundTrip(t *testing.T) {
	vs := [][3]uint8{
		{0, 0, 0},
		{1, 1, 1},
		{0xFF, 0xFF, 0xFE},
		{0xFF, 0xFF, 0xFF},
		{csptp.OrganizationSubTypeResponse0, csptp.OrganizationSubTypeResponse1, csptp.OrganizationSubTypeResponse2},
	}
	for _, v := range vs {
		tlv0 := csptp.ResponseTLV{OrganizationSubType: v}
		b := make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
		csptp.EncodeResponseTLV(b, &tlv0)
		var tlv1 csptp.ResponseTLV
		err := csptp.DecodeResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.OrganizationSubType != v {
			t.Fail()
		}
		if tlv1.OrganizationSubType != tlv0.OrganizationSubType {
			t.Fail()
		}
	}
}

func TestResponseTLVFlagFieldRoundTrip(t *testing.T) {
	vs := []uint32{0, 1, math.MaxUint32 - 1, math.MaxUint32,
		csptp.TLVFlagServerStateDS}
	for _, v := range vs {
		tlv0 := csptp.ResponseTLV{FlagField: v}
		b := make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
		csptp.EncodeResponseTLV(b, &tlv0)
		var tlv1 csptp.ResponseTLV
		err := csptp.DecodeResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.FlagField != v {
			t.Fail()
		}
		if tlv1.FlagField != tlv0.FlagField {
			t.Fail()
		}
	}
}

func TestResponseTLVErrorRoundTrip(t *testing.T) {
	vs := []uint16{0, 1, math.MaxUint16 - 1, math.MaxUint16,
		csptp.ErrorTxTimestampInvalid}
	for _, v := range vs {
		tlv0 := csptp.ResponseTLV{Error: v}
		b := make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
		csptp.EncodeResponseTLV(b, &tlv0)
		var tlv1 csptp.ResponseTLV
		err := csptp.DecodeResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.Error != v {
			t.Fail()
		}
		if tlv1.Error != tlv0.Error {
			t.Fail()
		}
	}
}

func TestResponseTLVRequestIngressTimestampRoundTrip(t *testing.T) {
	vs := []csptp.Timestamp{
		{
			Seconds:     [6]uint8{0, 0, 0, 0, 0, 0},
			Nanoseconds: 0,
		},
		{
			Seconds:     [6]uint8{0, 0, 0, 0, 0, 1},
			Nanoseconds: 1,
		},
		{
			Seconds:     [6]uint8{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE},
			Nanoseconds: math.MaxUint32 - 1,
		},
		{
			Seconds:     [6]uint8{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			Nanoseconds: math.MaxUint32,
		},
	}
	for _, v := range vs {
		tlv0 := csptp.ResponseTLV{RequestIngressTimestamp: v}
		b := make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
		csptp.EncodeResponseTLV(b, &tlv0)
		var tlv1 csptp.ResponseTLV
		err := csptp.DecodeResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.RequestIngressTimestamp != v {
			t.Fail()
		}
		if tlv1.RequestIngressTimestamp != tlv0.RequestIngressTimestamp {
			t.Fail()
		}
	}
}

func TestResponseTLVRequestCorrectionFieldRoundTrip(t *testing.T) {
	vs := []int64{math.MinInt64, math.MinInt64 + 1, -1, 0, 1, math.MaxInt64 - 1, math.MaxInt64}
	for _, v := range vs {
		tlv0 := csptp.ResponseTLV{RequestCorrectionField: v}
		b := make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
		csptp.EncodeResponseTLV(b, &tlv0)
		var tlv1 csptp.ResponseTLV
		err := csptp.DecodeResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.RequestCorrectionField != v {
			t.Fail()
		}
		if tlv1.RequestCorrectionField != tlv0.RequestCorrectionField {
			t.Fail()
		}
	}
}

func TestResponseTLVUTCOffsetRoundTrip(t *testing.T) {
	vs := []int16{math.MinInt16, math.MinInt16 + 1, -1, 0, 1, math.MaxInt16 - 1, math.MaxInt16}
	for _, v := range vs {
		tlv0 := csptp.ResponseTLV{UTCOffset: v}
		b := make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
		csptp.EncodeResponseTLV(b, &tlv0)
		var tlv1 csptp.ResponseTLV
		err := csptp.DecodeResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.UTCOffset != v {
			t.Fail()
		}
		if tlv1.UTCOffset != tlv0.UTCOffset {
			t.Fail()
		}
	}
}

func TestResponseTLVServerStateDSRoundTrip(t *testing.T) {
	vs := []csptp.ServerStateDS{
		{},
		{
			GMPriority1:     1,
			GMClockClass:    1,
			GMClockAccuracy: 1,
			GMClockVariance: 1,
			GMPriority2:     1,
			GMClockID:       1,
			StepsRemoved:    1,
			TimeSource:      1,
		},
		{
			GMPriority1:     math.MaxUint8,
			GMClockClass:    math.MaxUint8,
			GMClockAccuracy: math.MaxUint8,
			GMClockVariance: math.MaxUint16,
			GMPriority2:     math.MaxUint8,
			GMClockID:       math.MaxUint64,
			StepsRemoved:    math.MaxUint16,
			TimeSource:      math.MaxUint8,
		},
	}
	for _, v := range vs {
		tlv0 := csptp.ResponseTLV{
			FlagField:     csptp.TLVFlagServerStateDS,
			ServerStateDS: v,
		}
		b := make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
		csptp.EncodeResponseTLV(b, &tlv0)
		var tlv1 csptp.ResponseTLV
		err := csptp.DecodeResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.ServerStateDS != v {
			t.Fail()
		}
		if tlv1.ServerStateDS != tlv0.ServerStateDS {
			t.Fail()
		}
	}
}

func TestResponseTLVFlagFieldServerStateDSRoundTrip(t *testing.T) {
	vs := []uint32{0, csptp.TLVFlagServerStateDS}
	for _, v := range vs {
		tlv0 := csptp.ResponseTLV{FlagField: v}
		b := make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
		csptp.EncodeResponseTLV(b, &tlv0)
		var tlv1 csptp.ResponseTLV
		err := csptp.DecodeResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.FlagField != v {
			t.Fail()
		}
		if tlv1.FlagField != tlv0.FlagField {
			t.Fail()
		}

		expectedLen := 36
		if v&csptp.TLVFlagServerStateDS == csptp.TLVFlagServerStateDS {
			expectedLen = 54
		}
		if len(b) != expectedLen {
			t.Fail()
		}
	}
}

func TestCompleteResponseTLVRoundTrip(t *testing.T) {
	tlv0 := csptp.ResponseTLV{
		Type: csptp.TLVTypeOrganizationExtension,
		OrganizationID: [3]uint8{
			csptp.OrganizationIDMeinberg0,
			csptp.OrganizationIDMeinberg1,
			csptp.OrganizationIDMeinberg2,
		},
		OrganizationSubType: [3]uint8{
			csptp.OrganizationSubTypeResponse0,
			csptp.OrganizationSubTypeResponse1,
			csptp.OrganizationSubTypeResponse2,
		},
		FlagField: csptp.TLVFlagServerStateDS,
		Error:     csptp.ErrorTxTimestampInvalid,
		RequestIngressTimestamp: csptp.Timestamp{
			Seconds:     [6]uint8{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			Nanoseconds: 0x77777777,
		},
		RequestCorrectionField: 0x123456789ABCDEF,
		UTCOffset:              37,
		ServerStateDS: csptp.ServerStateDS{
			GMPriority1:     1,
			GMClockClass:    2,
			GMClockAccuracy: 3,
			GMClockVariance: 4,
			GMPriority2:     5,
			GMClockID:       0xAAAABBBBCCCCDDDD,
			StepsRemoved:    6,
			TimeSource:      7,
		},
	}
	tlv0.Length = uint16(csptp.EncodedResponseTLVLength(&tlv0)) - 4

	b := make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
	csptp.EncodeResponseTLV(b, &tlv0)
	var tlv1 csptp.ResponseTLV
	err := csptp.DecodeResponseTLV(&tlv1, b)
	if err != nil {
		t.Fatal(err)
	}
	if tlv1 != tlv0 {
		t.Fail()
	}
}

func TestResponseTLVInvalidLength(t *testing.T) {
	var err error
	var tlv0, tlv1 csptp.ResponseTLV
	var b []byte

	tlv0 = csptp.ResponseTLV{}
	b = make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
	csptp.EncodeResponseTLV(b, &tlv0)
	tlv1 = csptp.ResponseTLV{}
	err = csptp.DecodeResponseTLV(&tlv1, b[:13])
	if err == nil {
		t.Error("Expected error for insufficient buffer length")
	}

	tlv0 = csptp.ResponseTLV{}
	b = make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
	csptp.EncodeResponseTLV(b, &tlv0)
	tlv1 = csptp.ResponseTLV{}
	err = csptp.DecodeResponseTLV(&tlv1, b[:len(b)-1])
	if err == nil {
		t.Error("Expected error for insufficient buffer length")
	}

	tlv0 = csptp.ResponseTLV{FlagField: csptp.TLVFlagServerStateDS}
	b = make([]byte, csptp.EncodedResponseTLVLength(&tlv0))
	csptp.EncodeResponseTLV(b, &tlv0)
	tlv1 = csptp.ResponseTLV{}
	err = csptp.DecodeResponseTLV(&tlv1, b[:len(b)-1])
	if err == nil {
		t.Error("Expected error for insufficient buffer length with ServerStateDS flag set")
	}
}

func TestSyncRequest0(t *testing.T) {
	msg0 := csptp.Message{
		SdoIDMessageType:    csptp.MessageTypeSync,
		PTPVersion:          csptp.PTPVersion,
		MessageLength:       csptp.MinMessageLength,
		DomainNumber:        csptp.DomainNumber,
		MinorSdoID:          csptp.MinorSdoID,
		FlagField:           csptp.FlagTwoStep | csptp.FlagUnicast,
		CorrectionField:     0,
		MessageTypeSpecific: 0,
		SourcePortIdentity: csptp.PortID{
			ClockID: 0x007665fffe746833,
			Port:    1,
		},
		SequenceID:         0,
		ControlField:       csptp.ControlSync,
		LogMessageInterval: 0,
		Timestamp:          csptp.Timestamp{},
	}
	b0 := []byte{
		0x00, 0x12, 0x00, 0x2c, 0x00, 0x00, 0x06, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x65, 0xff,
		0xfe, 0x74, 0x68, 0x33, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00}
	b1 := make([]byte, msg0.MessageLength)
	csptp.EncodeMessage(b1, &msg0)
	if !bytes.Equal(b1, b0) {
		t.Fail()
	}
	var msg1 csptp.Message
	err := csptp.DecodeMessage(&msg1, b1)
	if err != nil {
		t.Fail()
	}
	if msg1 != msg0 {
		t.Fail()
	}
}

func TestFollowUpRequest0(t *testing.T) {
	msg0 := csptp.Message{
		SdoIDMessageType:    csptp.MessageTypeFollowUp,
		PTPVersion:          csptp.PTPVersion,
		MessageLength:       csptp.MinMessageLength,
		DomainNumber:        csptp.DomainNumber,
		MinorSdoID:          csptp.MinorSdoID,
		FlagField:           csptp.FlagUnicast,
		CorrectionField:     0,
		MessageTypeSpecific: 0,
		SourcePortIdentity: csptp.PortID{
			ClockID: 0x007665fffe746833,
			Port:    1,
		},
		SequenceID:         0,
		ControlField:       csptp.ControlFollowUp,
		LogMessageInterval: 0,
		Timestamp:          csptp.Timestamp{},
	}
	tlv0 := csptp.RequestTLV{
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
	msg0.MessageLength += uint16(csptp.EncodedRequestTLVLength(&tlv0))
	tlv0.Length = uint16(csptp.EncodedRequestTLVLength(&tlv0))
	b0 := []byte{
		0x08, 0x12, 0x00, 0x62, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x65, 0xff,
		0xfe, 0x74, 0x68, 0x33, 0x00, 0x01, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x36,
		0xec, 0x46, 0x70, 0x52, 0x65, 0x71, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0}
	b1 := make([]byte, msg0.MessageLength)
	csptp.EncodeMessage(b1[:csptp.MinMessageLength], &msg0)
	csptp.EncodeRequestTLV(b1[csptp.MinMessageLength:], &tlv0)
	if !bytes.Equal(b1, b0) {
		t.Fail()
	}
	var msg1 csptp.Message
	err := csptp.DecodeMessage(&msg1, b1[:csptp.MinMessageLength])
	if err != nil {
		t.Fail()
	}
	if msg1 != msg0 {
		t.Fail()
	}
	var tlv1 csptp.RequestTLV
	err = csptp.DecodeRequestTLV(&tlv1, b1[csptp.MinMessageLength:])
	if err != nil {
		t.Fail()
	}
	if tlv1 != tlv0 {
		t.Fail()
	}
}

func TestSyncResponse0(t *testing.T) {
	msg0 := csptp.Message{
		SdoIDMessageType:    csptp.MessageTypeSync,
		PTPVersion:          csptp.PTPVersion,
		MessageLength:       csptp.MinMessageLength,
		DomainNumber:        csptp.DomainNumber,
		MinorSdoID:          csptp.MinorSdoID,
		FlagField:           csptp.FlagTwoStep | csptp.FlagUnicast,
		CorrectionField:     0,
		MessageTypeSpecific: 0,
		SourcePortIdentity: csptp.PortID{
			ClockID: 0x007665fffe746831,
			Port:    1,
		},
		SequenceID:         0,
		ControlField:       csptp.ControlSync,
		LogMessageInterval: csptp.LogMessageInterval,
		Timestamp:          csptp.Timestamp{},
	}
	b0 := []byte{
		0x00, 0x12, 0x00, 0x2c, 0x00, 0x00, 0x06, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x65, 0xff,
		0xfe, 0x74, 0x68, 0x31, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00}
	b1 := make([]byte, msg0.MessageLength)
	csptp.EncodeMessage(b1, &msg0)
	if !bytes.Equal(b1, b0) {
		t.Fail()
	}
	var msg1 csptp.Message
	err := csptp.DecodeMessage(&msg1, b1)
	if err != nil {
		t.Fail()
	}
	if msg1 != msg0 {
		t.Fail()
	}
}

func TestFollowUpResponse0(t *testing.T) {
	msg0 := csptp.Message{
		SdoIDMessageType:    csptp.MessageTypeFollowUp,
		PTPVersion:          csptp.PTPVersion,
		MessageLength:       csptp.MinMessageLength,
		DomainNumber:        csptp.DomainNumber,
		MinorSdoID:          csptp.MinorSdoID,
		FlagField:           csptp.FlagUnicast,
		CorrectionField:     0,
		MessageTypeSpecific: 0,
		SourcePortIdentity: csptp.PortID{
			ClockID: 0x007665fffe746831,
			Port:    1,
		},
		SequenceID:         0,
		ControlField:       csptp.ControlFollowUp,
		LogMessageInterval: csptp.LogMessageInterval,
		Timestamp:          csptp.TimestampFromTime(time.Unix(1737196455, 486627530).UTC()),
	}
	tlv0 := csptp.ResponseTLV{
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
		FlagField:               csptp.TLVFlagServerStateDS,
		Error:                   0,
		RequestIngressTimestamp: csptp.TimestampFromTime(time.Unix(1737196455, 482166607).UTC()),
		RequestCorrectionField:  0,
		UTCOffset:               0,
		ServerStateDS: csptp.ServerStateDS{
			GMPriority1:     128,
			GMClockClass:    248,
			GMClockAccuracy: 47,
			GMClockVariance: 65535,
			GMPriority2:     128,
			GMClockID:       33326197411964977,
			StepsRemoved:    0,
			TimeSource:      96,
			Reserved:        0,
		},
	}
	msg0.MessageLength += uint16(csptp.EncodedResponseTLVLength(&tlv0))
	tlv0.Length = uint16(csptp.EncodedResponseTLVLength(&tlv0))
	b0 := []byte{
		0x08, 0x12, 0x00, 0x62, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x65, 0xff,
		0xfe, 0x74, 0x68, 0x31, 0x00, 0x01, 0x00, 0x00,
		0x02, 0x7f, 0x00, 0x00, 0x67, 0x8b, 0x83, 0xa7,
		0x1d, 0x01, 0x58, 0xca, 0x00, 0x03, 0x00, 0x36,
		0xec, 0x46, 0x70, 0x52, 0x65, 0x73, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x67, 0x8b,
		0x83, 0xa7, 0x1c, 0xbd, 0x47, 0x4f, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x80, 0xf8, 0x2f, 0xff, 0xff, 0x80, 0x00, 0x76,
		0x65, 0xff, 0xfe, 0x74, 0x68, 0x31, 0x00, 0x00,
		0x60, 0x0}
	b1 := make([]byte, msg0.MessageLength)
	csptp.EncodeMessage(b1[:csptp.MinMessageLength], &msg0)
	csptp.EncodeResponseTLV(b1[csptp.MinMessageLength:], &tlv0)
	if !bytes.Equal(b1, b0) {
		t.Fail()
	}
	var msg1 csptp.Message
	err := csptp.DecodeMessage(&msg1, b1[:csptp.MinMessageLength])
	if err != nil {
		t.Fail()
	}
	if msg1 != msg0 {
		t.Fail()
	}
	var tlv1 csptp.ResponseTLV
	err = csptp.DecodeResponseTLV(&tlv1, b1[csptp.MinMessageLength:])
	if err != nil {
		t.Fail()
	}
	if tlv1 != tlv0 {
		t.Fail()
	}
}

func TestSyncRequest1(t *testing.T) {
	msg0 := csptp.Message{
		SdoIDMessageType:    csptp.MessageTypeSync,
		PTPVersion:          csptp.PTPVersion,
		MessageLength:       csptp.MinMessageLength,
		DomainNumber:        csptp.DomainNumber,
		MinorSdoID:          csptp.MinorSdoID,
		FlagField:           csptp.FlagTwoStep | csptp.FlagUnicast,
		CorrectionField:     0,
		MessageTypeSpecific: 0,
		SourcePortIdentity: csptp.PortID{
			ClockID: 0x007665fffe746833,
			Port:    1,
		},
		SequenceID:         1,
		ControlField:       csptp.ControlSync,
		LogMessageInterval: 0,
		Timestamp:          csptp.Timestamp{},
	}
	b0 := []byte{
		0x00, 0x12, 0x00, 0x2c, 0x00, 0x00, 0x06, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x65, 0xff,
		0xfe, 0x74, 0x68, 0x33, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x0}
	b1 := make([]byte, msg0.MessageLength)
	csptp.EncodeMessage(b1, &msg0)
	if !bytes.Equal(b1, b0) {
		t.Fail()
	}
	var msg1 csptp.Message
	err := csptp.DecodeMessage(&msg1, b1)
	if err != nil {
		t.Fail()
	}
	if msg1 != msg0 {
		t.Fail()
	}
}

func TestFollowUpRequest1(t *testing.T) {
	msg0 := csptp.Message{
		SdoIDMessageType:    csptp.MessageTypeFollowUp,
		PTPVersion:          csptp.PTPVersion,
		MessageLength:       csptp.MinMessageLength,
		DomainNumber:        csptp.DomainNumber,
		MinorSdoID:          csptp.MinorSdoID,
		FlagField:           csptp.FlagUnicast,
		CorrectionField:     0,
		MessageTypeSpecific: 0,
		SourcePortIdentity: csptp.PortID{
			ClockID: 0x007665fffe746833,
			Port:    1,
		},
		SequenceID:         1,
		ControlField:       csptp.ControlFollowUp,
		LogMessageInterval: 0,
		Timestamp:          csptp.Timestamp{},
	}
	tlv0 := csptp.RequestTLV{
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
		FlagField: 0,
	}
	msg0.MessageLength += uint16(csptp.EncodedRequestTLVLength(&tlv0))
	tlv0.Length = uint16(csptp.EncodedRequestTLVLength(&tlv0))
	b0 := []byte{
		0x08, 0x12, 0x00, 0x50, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x65, 0xff,
		0xfe, 0x74, 0x68, 0x33, 0x00, 0x01, 0x00, 0x01,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x24,
		0xec, 0x46, 0x70, 0x52, 0x65, 0x71, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	b1 := make([]byte, msg0.MessageLength)
	csptp.EncodeMessage(b1[:csptp.MinMessageLength], &msg0)
	csptp.EncodeRequestTLV(b1[csptp.MinMessageLength:], &tlv0)
	if !bytes.Equal(b1, b0) {
		t.Fail()
	}
	var msg1 csptp.Message
	err := csptp.DecodeMessage(&msg1, b1[:csptp.MinMessageLength])
	if err != nil {
		t.Fail()
	}
	if msg1 != msg0 {
		t.Fail()
	}
	var tlv1 csptp.RequestTLV
	err = csptp.DecodeRequestTLV(&tlv1, b1[csptp.MinMessageLength:])
	if err != nil {
		t.Fail()
	}
	if tlv1 != tlv0 {
		t.Fail()
	}
}

func TestSyncResponse1(t *testing.T) {
	msg0 := csptp.Message{
		SdoIDMessageType:    csptp.MessageTypeSync,
		PTPVersion:          csptp.PTPVersion,
		MessageLength:       csptp.MinMessageLength,
		DomainNumber:        csptp.DomainNumber,
		MinorSdoID:          csptp.MinorSdoID,
		FlagField:           csptp.FlagTwoStep | csptp.FlagUnicast,
		CorrectionField:     0,
		MessageTypeSpecific: 0,
		SourcePortIdentity: csptp.PortID{
			ClockID: 0x007665fffe746831,
			Port:    1,
		},
		SequenceID:         1,
		ControlField:       csptp.ControlSync,
		LogMessageInterval: csptp.LogMessageInterval,
		Timestamp:          csptp.Timestamp{},
	}
	b0 := []byte{
		0x00, 0x12, 0x00, 0x2c, 0x00, 0x00, 0x06, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x65, 0xff,
		0xfe, 0x74, 0x68, 0x31, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00}
	b1 := make([]byte, msg0.MessageLength)
	csptp.EncodeMessage(b1, &msg0)
	if !bytes.Equal(b1, b0) {
		t.Fail()
	}
	var msg1 csptp.Message
	err := csptp.DecodeMessage(&msg1, b1)
	if err != nil {
		t.Fail()
	}
	if msg1 != msg0 {
		t.Fail()
	}
}

func TestFollowUpResponse1(t *testing.T) {
	msg0 := csptp.Message{
		SdoIDMessageType:    csptp.MessageTypeFollowUp,
		PTPVersion:          csptp.PTPVersion,
		MessageLength:       csptp.MinMessageLength,
		DomainNumber:        csptp.DomainNumber,
		MinorSdoID:          csptp.MinorSdoID,
		FlagField:           csptp.FlagUnicast,
		CorrectionField:     0,
		MessageTypeSpecific: 0,
		SourcePortIdentity: csptp.PortID{
			ClockID: 0x007665fffe746831,
			Port:    1,
		},
		SequenceID:         1,
		ControlField:       csptp.ControlFollowUp,
		LogMessageInterval: csptp.LogMessageInterval,
		Timestamp:          csptp.TimestampFromTime(time.Unix(1737196456, 494391756).UTC()),
	}
	tlv0 := csptp.ResponseTLV{
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
		FlagField:               0,
		Error:                   0,
		RequestIngressTimestamp: csptp.TimestampFromTime(time.Unix(1737196456, 493401778).UTC()),
		RequestCorrectionField:  0,
		UTCOffset:               0,
		ServerStateDS: csptp.ServerStateDS{
			GMPriority1:     0,
			GMClockClass:    0,
			GMClockAccuracy: 0,
			GMClockVariance: 0,
			GMPriority2:     0,
			GMClockID:       0,
			StepsRemoved:    0,
			TimeSource:      0,
			Reserved:        0,
		},
	}
	msg0.MessageLength += uint16(csptp.EncodedResponseTLVLength(&tlv0))
	tlv0.Length = uint16(csptp.EncodedResponseTLVLength(&tlv0))
	b0 := []byte{
		0x08, 0x12, 0x00, 0x50, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x65, 0xff,
		0xfe, 0x74, 0x68, 0x31, 0x00, 0x01, 0x00, 0x01,
		0x02, 0x7f, 0x00, 0x00, 0x67, 0x8b, 0x83, 0xa8,
		0x1d, 0x77, 0xd1, 0xcc, 0x00, 0x03, 0x00, 0x24,
		0xec, 0x46, 0x70, 0x52, 0x65, 0x73, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x67, 0x8b,
		0x83, 0xa8, 0x1d, 0x68, 0xb6, 0xb2, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0}
	b1 := make([]byte, msg0.MessageLength)
	csptp.EncodeMessage(b1[:csptp.MinMessageLength], &msg0)
	csptp.EncodeResponseTLV(b1[csptp.MinMessageLength:], &tlv0)
	if !bytes.Equal(b1, b0) {
		t.Fail()
	}
	var msg1 csptp.Message
	err := csptp.DecodeMessage(&msg1, b1[:csptp.MinMessageLength])
	if err != nil {
		t.Fail()
	}
	if msg1 != msg0 {
		t.Fail()
	}
	var tlv1 csptp.ResponseTLV
	err = csptp.DecodeResponseTLV(&tlv1, b1[csptp.MinMessageLength:])
	if err != nil {
		t.Fail()
	}
	if tlv1 != tlv0 {
		t.Fail()
	}
}

func TestCSPTPRequestTLVTypeRoundTrip(t *testing.T) {
	vs := []uint16{0, 1, math.MaxUint16 - 1, math.MaxUint16,
		csptp.TLVTypeCSPTPRequest}
	for _, v := range vs {
		tlv0 := csptp.CSPTPRequestTLV{Type: v}
		b := make([]byte, csptp.EncodedCSPTPRequestTLVLength)
		csptp.EncodeCSPTPRequestTLV(b, &tlv0)
		var tlv1 csptp.CSPTPRequestTLV
		err := csptp.DecodeCSPTPRequestTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.Type != v {
			t.Fail()
		}
		if tlv1.Type != tlv0.Type {
			t.Fail()
		}
	}
}

func TestCSPTPRequestTLVLengthRoundTrip(t *testing.T) {
	vs := []uint16{0, 1, math.MaxUint16 - 1, math.MaxUint16}
	for _, v := range vs {
		tlv0 := csptp.CSPTPRequestTLV{Length: v}
		b := make([]byte, csptp.EncodedCSPTPRequestTLVLength)
		csptp.EncodeCSPTPRequestTLV(b, &tlv0)
		var tlv1 csptp.CSPTPRequestTLV
		err := csptp.DecodeCSPTPRequestTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.Length != v {
			t.Fail()
		}
		if tlv1.Length != tlv0.Length {
			t.Fail()
		}
	}
}

func TestCSPTPRequestTLVRequestFlagsRoundTrip(t *testing.T) {
	vs := []uint32{0, 1, math.MaxUint32 - 1, math.MaxUint32,
		csptp.TLVFlagStatus, csptp.TLVFlagAltTimescale,
		csptp.TLVFlagStatus | csptp.TLVFlagAltTimescale}
	for _, v := range vs {
		tlv0 := csptp.CSPTPRequestTLV{RequestFlags: v}
		b := make([]byte, csptp.EncodedCSPTPRequestTLVLength)
		csptp.EncodeCSPTPRequestTLV(b, &tlv0)
		var tlv1 csptp.CSPTPRequestTLV
		err := csptp.DecodeCSPTPRequestTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.RequestFlags != v {
			t.Fail()
		}
		if tlv1.RequestFlags != tlv0.RequestFlags {
			t.Fail()
		}
	}
}

func TestCompleteCSPTPRequestTLVRoundTrip(t *testing.T) {
	tlv0 := csptp.CSPTPRequestTLV{
		Type:         csptp.TLVTypeCSPTPRequest,
		RequestFlags: csptp.TLVFlagStatus | csptp.TLVFlagAltTimescale,
	}
	tlv0.Length = uint16(csptp.EncodedCSPTPRequestTLVLength) - 4

	b := make([]byte, csptp.EncodedCSPTPRequestTLVLength)
	csptp.EncodeCSPTPRequestTLV(b, &tlv0)
	var tlv1 csptp.CSPTPRequestTLV
	err := csptp.DecodeCSPTPRequestTLV(&tlv1, b)
	if err != nil {
		t.Fatal(err)
	}
	if tlv1 != tlv0 {
		t.Fail()
	}
}

func TestCSPTPRequestTLVInvalidLength(t *testing.T) {
	var err error
	var tlv0, tlv1 csptp.CSPTPRequestTLV

	tlv0 = csptp.CSPTPRequestTLV{}
	b := make([]byte, csptp.EncodedCSPTPRequestTLVLength)
	csptp.EncodeCSPTPRequestTLV(b, &tlv0)
	tlv1 = csptp.CSPTPRequestTLV{}
	err = csptp.DecodeCSPTPRequestTLV(&tlv1, b[:13])
	if err == nil {
		t.Error("Expected error for insufficient buffer length")
	}
}

func TestCSPTPResponseTLVTypeRoundTrip(t *testing.T) {
	vs := []uint16{0, 1, math.MaxUint16 - 1, math.MaxUint16,
		csptp.TLVTypeCSPTPResponse}
	for _, v := range vs {
		tlv0 := csptp.CSPTPResponseTLV{Type: v}
		b := make([]byte, csptp.EncodedCSPTPResponseTLVLength)
		csptp.EncodeCSPTPResponseTLV(b, &tlv0)
		var tlv1 csptp.CSPTPResponseTLV
		err := csptp.DecodeCSPTPResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.Type != v {
			t.Fail()
		}
		if tlv1.Type != tlv0.Type {
			t.Fail()
		}
	}
}

func TestCSPTPResponseTLVLengthRoundTrip(t *testing.T) {
	vs := []uint16{0, 1, math.MaxUint16 - 1, math.MaxUint16}
	for _, v := range vs {
		tlv0 := csptp.CSPTPResponseTLV{Length: v}
		b := make([]byte, csptp.EncodedCSPTPResponseTLVLength)
		csptp.EncodeCSPTPResponseTLV(b, &tlv0)
		var tlv1 csptp.CSPTPResponseTLV
		err := csptp.DecodeCSPTPResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.Length != v {
			t.Fail()
		}
		if tlv1.Length != tlv0.Length {
			t.Fail()
		}
	}
}

func TestCSPTPResponseTLVOrganizationIDRoundTrip(t *testing.T) {
	vs := [][3]uint8{
		{0, 0, 0},
		{1, 1, 1},
		{0xFF, 0xFF, 0xFE},
		{0xFF, 0xFF, 0xFF},
	}
	for _, v := range vs {
		tlv0 := csptp.CSPTPResponseTLV{OrganizationID: v}
		b := make([]byte, csptp.EncodedCSPTPResponseTLVLength)
		csptp.EncodeCSPTPResponseTLV(b, &tlv0)
		var tlv1 csptp.CSPTPResponseTLV
		err := csptp.DecodeCSPTPResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.OrganizationID != v {
			t.Fail()
		}
		if tlv1.OrganizationID != tlv0.OrganizationID {
			t.Fail()
		}
	}
}

func TestCSPTPResponseTLVOrganizationSubTypeRoundTrip(t *testing.T) {
	vs := [][3]uint8{
		{0, 0, 0},
		{1, 1, 1},
		{0xFF, 0xFF, 0xFE},
		{0xFF, 0xFF, 0xFF},
	}
	for _, v := range vs {
		tlv0 := csptp.CSPTPResponseTLV{OrganizationSubType: v}
		b := make([]byte, csptp.EncodedCSPTPResponseTLVLength)
		csptp.EncodeCSPTPResponseTLV(b, &tlv0)
		var tlv1 csptp.CSPTPResponseTLV
		err := csptp.DecodeCSPTPResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.OrganizationSubType != v {
			t.Fail()
		}
		if tlv1.OrganizationSubType != tlv0.OrganizationSubType {
			t.Fail()
		}
	}
}

func TestCSPTPResponseTLVReqIngressTimestampRoundTrip(t *testing.T) {
	vs := []csptp.Timestamp{
		{
			Seconds:     [6]uint8{0, 0, 0, 0, 0, 0},
			Nanoseconds: 0,
		},
		{
			Seconds:     [6]uint8{0, 0, 0, 0, 0, 1},
			Nanoseconds: 1,
		},
		{
			Seconds:     [6]uint8{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE},
			Nanoseconds: math.MaxUint32 - 1,
		},
		{
			Seconds:     [6]uint8{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			Nanoseconds: math.MaxUint32,
		},
	}
	for _, v := range vs {
		tlv0 := csptp.CSPTPResponseTLV{ReqIngressTimestamp: v}
		b := make([]byte, csptp.EncodedCSPTPResponseTLVLength)
		csptp.EncodeCSPTPResponseTLV(b, &tlv0)
		var tlv1 csptp.CSPTPResponseTLV
		err := csptp.DecodeCSPTPResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.ReqIngressTimestamp != v {
			t.Fail()
		}
		if tlv1.ReqIngressTimestamp != tlv0.ReqIngressTimestamp {
			t.Fail()
		}
	}
}

func TestCSPTPResponseTLVReqCorrectionFieldRoundTrip(t *testing.T) {
	vs := []int64{math.MinInt64, math.MinInt64 + 1, -1, 0, 1, math.MaxInt64 - 1, math.MaxInt64}
	for _, v := range vs {
		tlv0 := csptp.CSPTPResponseTLV{ReqCorrectionField: v}
		b := make([]byte, csptp.EncodedCSPTPResponseTLVLength)
		csptp.EncodeCSPTPResponseTLV(b, &tlv0)
		var tlv1 csptp.CSPTPResponseTLV
		err := csptp.DecodeCSPTPResponseTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.ReqCorrectionField != v {
			t.Fail()
		}
		if tlv1.ReqCorrectionField != tlv0.ReqCorrectionField {
			t.Fail()
		}
	}
}

func TestCompleteCSPTPResponseTLVRoundTrip(t *testing.T) {
	tlv0 := csptp.CSPTPResponseTLV{
		Type:                csptp.TLVTypeCSPTPResponse,
		OrganizationID:      [3]uint8{0xAA, 0xBB, 0xCC},
		OrganizationSubType: [3]uint8{0xDD, 0xEE, 0xFF},
		ReqIngressTimestamp: csptp.Timestamp{
			Seconds:     [6]uint8{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			Nanoseconds: 0x77777777,
		},
		ReqCorrectionField: 0x123456789ABCDEF,
	}
	tlv0.Length = uint16(csptp.EncodedCSPTPResponseTLVLength) - 4

	b := make([]byte, csptp.EncodedCSPTPResponseTLVLength)
	csptp.EncodeCSPTPResponseTLV(b, &tlv0)
	var tlv1 csptp.CSPTPResponseTLV
	err := csptp.DecodeCSPTPResponseTLV(&tlv1, b)
	if err != nil {
		t.Fatal(err)
	}
	if tlv1 != tlv0 {
		t.Fail()
	}
}

func TestCSPTPResponseTLVInvalidLength(t *testing.T) {
	var err error
	var tlv0, tlv1 csptp.CSPTPResponseTLV

	tlv0 = csptp.CSPTPResponseTLV{}
	b := make([]byte, csptp.EncodedCSPTPResponseTLVLength)
	csptp.EncodeCSPTPResponseTLV(b, &tlv0)
	tlv1 = csptp.CSPTPResponseTLV{}
	err = csptp.DecodeCSPTPResponseTLV(&tlv1, b[:27])
	if err == nil {
		t.Error("Expected error for insufficient buffer length")
	}
}

func TestCSPTPStatusTLVTypeRoundTrip(t *testing.T) {
	vs := []uint16{0, 1, math.MaxUint16 - 1, math.MaxUint16,
		csptp.TLVTypeCSPTPStatus}
	for _, v := range vs {
		tlv0 := csptp.CSPTPStatusTLV{
			Type: v,
			ParentAddress: csptp.PortAddress{
				NetworkProtocol: 1,
				AddressLength:   4,
				Address:         []byte{192, 168, 1, 1},
			},
		}
		b := make([]byte, csptp.EncodedCSPTPStatusTLVLength(&tlv0))
		csptp.EncodeCSPTPStatusTLV(b, &tlv0)
		var tlv1 csptp.CSPTPStatusTLV
		err := csptp.DecodeCSPTPStatusTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.Type != v {
			t.Fail()
		}
		if tlv1.Type != tlv0.Type {
			t.Fail()
		}
	}
}

func TestCSPTPStatusTLVLengthRoundTrip(t *testing.T) {
	vs := []uint16{0, 1, math.MaxUint16 - 1, math.MaxUint16}
	for _, v := range vs {
		tlv0 := csptp.CSPTPStatusTLV{
			Length: v,
			ParentAddress: csptp.PortAddress{
				NetworkProtocol: 1,
				AddressLength:   4,
				Address:         []byte{192, 168, 1, 1},
			},
		}
		b := make([]byte, csptp.EncodedCSPTPStatusTLVLength(&tlv0))
		csptp.EncodeCSPTPStatusTLV(b, &tlv0)
		var tlv1 csptp.CSPTPStatusTLV
		err := csptp.DecodeCSPTPStatusTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.Length != v {
			t.Fail()
		}
		if tlv1.Length != tlv0.Length {
			t.Fail()
		}
	}
}

func TestCSPTPStatusTLVOrganizationIDRoundTrip(t *testing.T) {
	vs := [][3]uint8{
		{0, 0, 0},
		{1, 1, 1},
		{0xFF, 0xFF, 0xFE},
		{0xFF, 0xFF, 0xFF},
	}
	for _, v := range vs {
		tlv0 := csptp.CSPTPStatusTLV{OrganizationID: v}
		b := make([]byte, csptp.EncodedCSPTPStatusTLVLength(&tlv0))
		csptp.EncodeCSPTPStatusTLV(b, &tlv0)
		var tlv1 csptp.CSPTPStatusTLV
		err := csptp.DecodeCSPTPStatusTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.OrganizationID != v {
			t.Fail()
		}
		if tlv1.OrganizationID != tlv0.OrganizationID {
			t.Fail()
		}
	}
}

func TestCSPTPStatusTLVOrganizationSubTypeRoundTrip(t *testing.T) {
	vs := [][3]uint8{
		{0, 0, 0},
		{1, 1, 1},
		{0xFF, 0xFF, 0xFE},
		{0xFF, 0xFF, 0xFF},
	}
	for _, v := range vs {
		tlv0 := csptp.CSPTPStatusTLV{OrganizationSubType: v}
		b := make([]byte, csptp.EncodedCSPTPStatusTLVLength(&tlv0))
		csptp.EncodeCSPTPStatusTLV(b, &tlv0)
		var tlv1 csptp.CSPTPStatusTLV
		err := csptp.DecodeCSPTPStatusTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.OrganizationSubType != v {
			t.Fail()
		}
		if tlv1.OrganizationSubType != tlv0.OrganizationSubType {
			t.Fail()
		}
	}
}

func TestCSPTPStatusTLVGrandmasterPriority1RoundTrip(t *testing.T) {
	vs := []uint8{0, 1, math.MaxUint8 - 1, math.MaxUint8}
	for _, v := range vs {
		tlv0 := csptp.CSPTPStatusTLV{
			GrandmasterPriority1: v,
			ParentAddress: csptp.PortAddress{
				NetworkProtocol: 1,
				AddressLength:   4,
				Address:         []byte{192, 168, 1, 1},
			},
		}
		b := make([]byte, csptp.EncodedCSPTPStatusTLVLength(&tlv0))
		csptp.EncodeCSPTPStatusTLV(b, &tlv0)
		var tlv1 csptp.CSPTPStatusTLV
		err := csptp.DecodeCSPTPStatusTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.GrandmasterPriority1 != v {
			t.Fail()
		}
		if tlv1.GrandmasterPriority1 != tlv0.GrandmasterPriority1 {
			t.Fail()
		}
	}
}

func TestCSPTPStatusTLVClockQualityRoundTrip(t *testing.T) {
	vs := []csptp.ClockQuality{
		{ClockClass: 0, ClockAccuracy: 0, OffsetScaledLogVariance: 0},
		{ClockClass: 1, ClockAccuracy: 1, OffsetScaledLogVariance: 1},
		{ClockClass: math.MaxUint8, ClockAccuracy: math.MaxUint8, OffsetScaledLogVariance: math.MaxUint16},
	}
	for _, v := range vs {
		tlv0 := csptp.CSPTPStatusTLV{
			GrandmasterClockQuality: v,
			ParentAddress: csptp.PortAddress{
				NetworkProtocol: 1,
				AddressLength:   4,
				Address:         []byte{192, 168, 1, 1},
			},
		}
		b := make([]byte, csptp.EncodedCSPTPStatusTLVLength(&tlv0))
		csptp.EncodeCSPTPStatusTLV(b, &tlv0)
		var tlv1 csptp.CSPTPStatusTLV
		err := csptp.DecodeCSPTPStatusTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.GrandmasterClockQuality != v {
			t.Fail()
		}
		if tlv1.GrandmasterClockQuality != tlv0.GrandmasterClockQuality {
			t.Fail()
		}
	}
}

func TestCSPTPStatusTLVParentAddressRoundTrip(t *testing.T) {
	vs := []csptp.PortAddress{
		{NetworkProtocol: 0, AddressLength: 0, Address: []byte{}},
		{NetworkProtocol: 1, AddressLength: 4, Address: []byte{192, 168, 1, 1}},
		{NetworkProtocol: 2, AddressLength: 16, Address: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		{NetworkProtocol: 3, AddressLength: 17, Address: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	}
	for _, v := range vs {
		tlv0 := csptp.CSPTPStatusTLV{
			ParentAddress: v,
		}
		b := make([]byte, csptp.EncodedCSPTPStatusTLVLength(&tlv0))
		csptp.EncodeCSPTPStatusTLV(b, &tlv0)
		var tlv1 csptp.CSPTPStatusTLV
		err := csptp.DecodeCSPTPStatusTLV(&tlv1, b)
		if err != nil {
			t.Fatal(err)
		}
		if tlv0.ParentAddress.NetworkProtocol != v.NetworkProtocol {
			t.Fail()
		}
		if tlv0.ParentAddress.AddressLength != v.AddressLength {
			t.Fail()
		}
		if !bytes.Equal(tlv0.ParentAddress.Address, v.Address) {
			t.Fail()
		}
		if tlv1.ParentAddress.NetworkProtocol != tlv0.ParentAddress.NetworkProtocol {
			t.Fail()
		}
		if tlv1.ParentAddress.AddressLength != tlv0.ParentAddress.AddressLength {
			t.Fail()
		}
		if !bytes.Equal(tlv1.ParentAddress.Address, tlv0.ParentAddress.Address) {
			t.Fail()
		}
	}
}

func TestCompleteCSPTPStatusTLVRoundTrip(t *testing.T) {
	tlv0 := csptp.CSPTPStatusTLV{
		Type:                 csptp.TLVTypeCSPTPStatus,
		GrandmasterPriority1: 128,
		GrandmasterClockQuality: csptp.ClockQuality{
			ClockClass:              248,
			ClockAccuracy:           47,
			OffsetScaledLogVariance: 65535,
		},
		GrandmasterPriority2: 128,
		StepsRemoved:         0,
		CurrentUTCOffset:     37,
		GrandmasterIdentity:  [8]uint8{0xA0, 0xA1, 0xB0, 0xB1, 0xC0, 0xC1, 0xD0, 0xD1},
		ParentAddress: csptp.PortAddress{
			NetworkProtocol: 1,
			AddressLength:   4,
			Address:         []byte{192, 168, 1, 1},
		},
	}
	tlv0.Length = uint16(csptp.EncodedCSPTPStatusTLVLength(&tlv0)) - 4

	b := make([]byte, csptp.EncodedCSPTPStatusTLVLength(&tlv0))
	csptp.EncodeCSPTPStatusTLV(b, &tlv0)
	var tlv1 csptp.CSPTPStatusTLV
	err := csptp.DecodeCSPTPStatusTLV(&tlv1, b)
	if err != nil {
		t.Fatal(err)
	}

	if tlv1.Type != tlv0.Type {
		t.Fail()
	}
	if tlv1.Length != tlv0.Length {
		t.Fail()
	}
	if tlv1.GrandmasterPriority1 != tlv0.GrandmasterPriority1 {
		t.Fail()
	}
	if tlv1.GrandmasterClockQuality != tlv0.GrandmasterClockQuality {
		t.Fail()
	}
	if tlv1.GrandmasterPriority2 != tlv0.GrandmasterPriority2 {
		t.Fail()
	}
	if tlv1.StepsRemoved != tlv0.StepsRemoved {
		t.Fail()
	}
	if tlv1.CurrentUTCOffset != tlv0.CurrentUTCOffset {
		t.Fail()
	}
	if tlv1.GrandmasterIdentity != tlv0.GrandmasterIdentity {
		t.Fail()
	}
	if tlv1.ParentAddress.NetworkProtocol != tlv0.ParentAddress.NetworkProtocol {
		t.Fail()
	}
	if tlv1.ParentAddress.AddressLength != tlv0.ParentAddress.AddressLength {
		t.Fail()
	}
	if !bytes.Equal(tlv1.ParentAddress.Address, tlv0.ParentAddress.Address) {
		t.Fail()
	}
}

func TestCSPTPStatusTLVInvalidLength(t *testing.T) {
	var err error
	var tlv0, tlv1 csptp.CSPTPStatusTLV

	tlv0 = csptp.CSPTPStatusTLV{
		ParentAddress: csptp.PortAddress{
			NetworkProtocol: 1,
			AddressLength:   4,
			Address:         []byte{192, 168, 1, 1},
		},
	}
	b := make([]byte, csptp.EncodedCSPTPStatusTLVLength(&tlv0))
	csptp.EncodeCSPTPStatusTLV(b, &tlv0)
	tlv1 = csptp.CSPTPStatusTLV{}
	err = csptp.DecodeCSPTPStatusTLV(&tlv1, b[:25])
	if err == nil {
		t.Error("Expected error for insufficient buffer length")
	}

	tlv0 = csptp.CSPTPStatusTLV{
		ParentAddress: csptp.PortAddress{
			NetworkProtocol: 1,
			AddressLength:   4,
			Address:         []byte{192, 168, 1, 1},
		},
	}
	b = make([]byte, csptp.EncodedCSPTPStatusTLVLength(&tlv0))
	csptp.EncodeCSPTPStatusTLV(b, &tlv0)
	tlv1 = csptp.CSPTPStatusTLV{}
	err = csptp.DecodeCSPTPStatusTLV(&tlv1, b[:len(b)-1])
	if err == nil {
		t.Error("Expected error for insufficient buffer length with parent address")
	}
}
