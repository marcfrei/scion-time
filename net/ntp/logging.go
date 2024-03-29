package ntp

import (
	"go.uber.org/zap/zapcore"
)

type Time32Marshaler struct {
	T Time32
}

func (m Time32Marshaler) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddUint16("Seconds", m.T.Seconds)
	enc.AddUint16("Fraction", m.T.Fraction)
	return nil
}

type Time64Marshaler struct {
	T Time64
}

func (m Time64Marshaler) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddUint32("Seconds", m.T.Seconds)
	enc.AddUint32("Fraction", m.T.Fraction)
	return nil
}

type PacketMarshaler struct {
	Pkt *Packet
}

func (m PacketMarshaler) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	var err error
	enc.AddUint8("LVM", m.Pkt.LVM)
	enc.AddUint8("Stratum", m.Pkt.Stratum)
	enc.AddInt8("Poll", m.Pkt.Poll)
	enc.AddInt8("Precision", m.Pkt.Precision)
	err = enc.AddObject("RootDelay", Time32Marshaler{T: m.Pkt.RootDelay})
	if err != nil {
		return err
	}
	err = enc.AddObject("RootDispersion", Time32Marshaler{T: m.Pkt.RootDispersion})
	if err != nil {
		return err
	}
	enc.AddUint32("ReferenceID", m.Pkt.ReferenceID)
	err = enc.AddObject("ReferenceTime", Time64Marshaler{T: m.Pkt.ReferenceTime})
	if err != nil {
		return err
	}
	err = enc.AddObject("OriginTime", Time64Marshaler{T: m.Pkt.OriginTime})
	if err != nil {
		return err
	}
	err = enc.AddObject("ReceiveTime", Time64Marshaler{T: m.Pkt.ReceiveTime})
	if err != nil {
		return err
	}
	err = enc.AddObject("TransmitTime", Time64Marshaler{T: m.Pkt.TransmitTime})
	if err != nil {
		return err
	}
	return nil
}
