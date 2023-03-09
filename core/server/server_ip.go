package server

import (
	"context"
	"net"
	"time"

	"github.com/libp2p/go-reuseport"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"go.uber.org/zap"

	"example.com/scion-time/base/metrics"

	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ntp"
	"example.com/scion-time/net/udp"
)

const (
	ipServerNumGoroutine = 8
)

type ipServerMetrics struct {
	pktsReceived prometheus.Counter
	reqsAccepted prometheus.Counter
	reqsServed   prometheus.Counter
}

func newIPServerMetrics() *ipServerMetrics {
	return &ipServerMetrics{
		pktsReceived: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.IPServerPktsReceivedN,
			Help: metrics.IPServerPktsReceivedH,
		}),
		reqsAccepted: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.IPServerReqsAcceptedN,
			Help: metrics.IPServerReqsAcceptedH,
		}),
		reqsServed: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.IPServerReqsServedN,
			Help: metrics.IPServerReqsServedH,
		}),
	}
}

func runIPServer(log *zap.Logger, mtrcs *ipServerMetrics, conn *net.UDPConn, iface string) {
	defer conn.Close()
	err := udp.EnableTimestamping(conn, iface)
	if err != nil {
		log.Error("failed to enable timestamping", zap.Error(err))
	}

	var txId uint32
	buf := make([]byte, ntp.PacketLen)
	oob := make([]byte, udp.TimestampLen())
	for {
		buf = buf[:cap(buf)]
		oob = oob[:cap(oob)]
		n, oobn, flags, srcAddr, err := conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			log.Error("failed to read packet", zap.Error(err))
			continue
		}
		if flags != 0 {
			log.Error("failed to read packet", zap.Int("flags", flags))
			continue
		}
		oob = oob[:oobn]
		rxt, err := udp.TimestampFromOOBData(oob)
		if err != nil {
			oob = oob[:0]
			rxt = timebase.Now()
			log.Error("failed to read packet rx timestamp", zap.Error(err))
		}
		buf = buf[:n]
		mtrcs.pktsReceived.Inc()

		var ntpreq ntp.Packet
		err = ntp.DecodePacket(&ntpreq, buf, nil, nil)
		if err != nil {
			log.Info("failed to decode packet payload", zap.Error(err))
			continue
		}

		err = ntp.ValidateRequest(&ntpreq, srcAddr.Port())
		if err != nil {
			log.Info("failed to validate packet payload", zap.Error(err))
			continue
		}

		clientID := srcAddr.Addr().String()

		mtrcs.reqsAccepted.Inc()
		log.Debug("received request",
			zap.Time("at", rxt),
			zap.String("from", clientID),
			zap.Object("data", ntp.PacketMarshaler{Pkt: &ntpreq}),
		)

		var txt0 time.Time
		var ntpresp ntp.Packet
		handleRequest(clientID, &ntpreq, &rxt, &txt0, &ntpresp)

		ntp.EncodePacket(&buf, &ntpresp)

		n, err = conn.WriteToUDPAddrPort(buf, srcAddr)
		if err != nil || n != len(buf) {
			log.Error("failed to write packet", zap.Error(err))
			continue
		}
		txt1, id, err := udp.ReadTXTimestamp(conn)
		if err != nil {
			txt1 = txt0
			log.Error("failed to read packet tx timestamp", zap.Error(err))
		} else if id != txId {
			txt1 = txt0
			log.Error("failed to read packet tx timestamp", zap.Uint32("id", id), zap.Uint32("expected", txId))
			txId = id + 1
		} else {
			txId++
		}
		updateTXTimestamp(clientID, rxt, &txt1)

		mtrcs.reqsServed.Inc()
	}
}

func StartIPServer(ctx context.Context, log *zap.Logger,
	localHost *net.UDPAddr) {
	log.Info("server listening via IP",
		zap.Stringer("ip", localHost.IP),
		zap.Int("port", localHost.Port),
	)

	mtrcs := newIPServerMetrics()

	if ipServerNumGoroutine == 1 {
		conn, err := net.ListenUDP("udp", localHost)
		if err != nil {
			log.Fatal("failed to listen for packets", zap.Error(err))
		}
		go runIPServer(log, mtrcs, conn, localHost.Zone)
	} else {
		for i := ipServerNumGoroutine; i > 0; i-- {
			conn, err := reuseport.ListenPacket("udp", localHost.String())
			if err != nil {
				log.Fatal("failed to listen for packets", zap.Error(err))
			}
			go runIPServer(log, mtrcs, conn.(*net.UDPConn), localHost.Zone)
		}
	}
}
