package ntp

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"example.com/scion-time/go/core/timebase"
	"example.com/scion-time/go/net/ntp"
	"example.com/scion-time/go/net/udp"
)

const (
	ntpLogPrefix = "[driver/ntp]"

	timeout = 5 * time.Second
)

var errUnexpectedPacketFlags = fmt.Errorf("failed to read packet: unexpected flags")

func MeasureClockOffset(ctx context.Context, host string) (time.Duration, error) {
	now := timebase.Now()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = now.Add(timeout)
	}
	addr := net.JoinHostPort(host, "123")
	conn, err := net.DialTimeout("udp", addr, deadline.Sub(now))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	err = conn.SetDeadline(deadline)
	if err != nil {
		return 0, err
	}
	udpConn := conn.(*net.UDPConn)
	udp.EnableTimestamping(udpConn)

	pkt := ntp.Packet{}
	buf := make([]byte, ntp.PacketLen)
	oob := make([]byte, udp.TimestampLen())

	cTxTime := timebase.Now()

	pkt.SetVersion(ntp.VersionMax)
	pkt.SetMode(ntp.ModeClient)
	pkt.TransmitTime = ntp.Time64FromTime(cTxTime)
	ntp.EncodePacket(&buf, &pkt)

	_, err = udpConn.Write(buf)
	if err != nil {
		return 0, err
	}
	n, oobn, flags, srcAddr, err := udpConn.ReadMsgUDPAddrPort(buf, oob)
	if err != nil {
		log.Printf("%s Failed to read packet: %v", ntpLogPrefix, err)
		return 0, err
	}
	if flags != 0 {
		log.Printf("%s Failed to read packet, flags: %v", ntpLogPrefix, flags)
		return 0, errUnexpectedPacketFlags
	}

	oob = oob[:oobn]
	cRxTime, err := udp.TimestampFromOOBData(oob)
	if err != nil {
		log.Printf("%s %s, failed to read packet timestamp", ntpLogPrefix, host, err)
		cRxTime = timebase.Now()
	}
	buf = buf[:n]

	err = ntp.DecodePacket(&pkt, buf)
	if err != nil {
		log.Printf("%s %s, failed to decode packet payload: %v", ntpLogPrefix, host, err)
		return 0, err
	}

	log.Printf("%s %s, received packet at %v from srcAddr %v: %+v", ntpLogPrefix, host, cRxTime, srcAddr, pkt)

	sRxTime := ntp.TimeFromTime64(pkt.ReceiveTime)
	sTxTime := ntp.TimeFromTime64(pkt.TransmitTime)

	off := ntp.ClockOffset(cTxTime, sRxTime, sTxTime, cRxTime)
	rtd := ntp.RoundTripDelay(cTxTime, sRxTime, sTxTime, cRxTime)

	log.Printf("%s %s, clock offset: %fs (%fms), round trip delay: %fs (%fms)",
		ntpLogPrefix, host,
		float64(off.Nanoseconds())/float64(time.Second.Nanoseconds()),
		float64(off.Nanoseconds())/float64(time.Millisecond.Nanoseconds()),
		float64(rtd.Nanoseconds())/float64(time.Second.Nanoseconds()),
		float64(rtd.Nanoseconds())/float64(time.Millisecond.Nanoseconds()))

	return off, nil
}
