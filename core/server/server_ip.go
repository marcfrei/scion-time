package server

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/base/metrics"

	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ntp"
	"example.com/scion-time/net/nts"
	"example.com/scion-time/net/ntske"
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

func runIPServer(ctx context.Context, log *slog.Logger, mtrcs *ipServerMetrics,
	conn *net.UDPConn, iface string, dscp uint8, provider *ntske.Provider) {
	defer func() { _ = conn.Close() }()
	err := udp.EnableTimestamping(conn, iface, -1 /* index */)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError, "failed to enable timestamping", slog.Any("error", err))
	}
	err = udp.SetDSCP(conn, dscp)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelInfo, "failed to set DSCP", slog.Any("error", err))
	}

	var txid uint32
	buf := make([]byte, 2048)
	oob := make([]byte, udp.TimestampLen())
	for {
		buf = buf[:cap(buf)]
		oob = oob[:cap(oob)]
		n, oobn, flags, srcAddr, err := conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			log.LogAttrs(ctx, slog.LevelError, "failed to read packet", slog.Any("error", err))
			continue
		}
		if flags != 0 {
			log.LogAttrs(ctx, slog.LevelError, "failed to read packet", slog.Int("flags", flags))
			continue
		}
		oob = oob[:oobn]
		rxt, err := udp.TimestampFromOOBData(oob)
		if err != nil {
			oob = oob[:0]
			rxt = timebase.Now()
			log.LogAttrs(ctx, slog.LevelError, "failed to read packet rx timestamp", slog.Any("error", err))
		}
		buf = buf[:n]
		mtrcs.pktsReceived.Inc()

		var ntpreq ntp.Packet
		err = ntp.DecodePacket(&ntpreq, buf)
		if err != nil {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
			continue
		}

		var authenticated bool
		var ntsreq nts.Packet
		var serverCookie ntske.ServerCookie
		if len(buf) > ntp.PacketLen {
			err = nts.DecodePacket(&ntsreq, buf)
			if err != nil {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to decode NTS packet", slog.Any("error", err))
				continue
			}

			cookie, err := ntsreq.FirstCookie()
			if err != nil {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to get cookie", slog.Any("error", err))
				continue
			}

			var encryptedCookie ntske.EncryptedServerCookie
			err = encryptedCookie.Decode(cookie)
			if err != nil {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to decode cookie", slog.Any("error", err))
				continue
			}

			key, ok := provider.Get(int(encryptedCookie.ID))
			if !ok {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to get key")
				continue
			}

			serverCookie, err = encryptedCookie.Decrypt(key.Value)
			if err != nil {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to decrypt cookie", slog.Any("error", err))
				continue
			}

			err = nts.ProcessRequest(buf, serverCookie.C2S, &ntsreq)
			if err != nil {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to process NTS packet", slog.Any("error", err))
				continue
			}
			authenticated = true
		}

		err = ntp.ValidateRequest(&ntpreq, srcAddr.Port())
		if err != nil {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to validate packet payload", slog.Any("error", err))
			continue
		}

		clientID := srcAddr.Addr().String()

		mtrcs.reqsAccepted.Inc()
		log.LogAttrs(ctx, slog.LevelDebug, "received request",
			slog.Time("at", rxt),
			slog.String("from", clientID),
			slog.Bool("ntsauth", authenticated),
			slog.Any("data", ntp.PacketLogValuer{Pkt: &ntpreq}),
		)

		var txt0 time.Time
		var ntpresp ntp.Packet
		handleRequest(clientID, &ntpreq, &rxt, &txt0, &ntpresp)

		ntp.EncodePacket(&buf, &ntpresp)

		if authenticated {
			var cookies [][]byte
			key := provider.Current()
			addedCookie := false
			for range len(ntsreq.Cookies) + len(ntsreq.CookiePlaceholders) {
				encryptedCookie, err := serverCookie.EncryptWithNonce(key.Value, key.ID)
				if err != nil {
					log.LogAttrs(ctx, slog.LevelInfo, "failed to encrypt cookie", slog.Any("error", err))
					continue
				}
				cookie := encryptedCookie.Encode()
				cookies = append(cookies, cookie)
				addedCookie = true
			}
			if !addedCookie {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to add at least one cookie")
				continue
			}

			ntsresp := nts.NewResponsePacket(cookies, serverCookie.S2C, ntsreq.UniqueID.ID)
			nts.EncodePacket(&buf, &ntsresp)
		}

		n, err = conn.WriteToUDPAddrPort(buf, srcAddr)
		if err != nil || n != len(buf) {
			log.LogAttrs(ctx, slog.LevelError, "failed to write packet", slog.Any("error", err))
			continue
		}
		txt1, id, err := udp.ReadTXTimestamp(conn, txid)
		if err != nil {
			txt1 = txt0
			log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
				slog.Any("error", err))
		} else if id != txid {
			txt1 = txt0
			log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
				slog.Uint64("id", uint64(id)), slog.Uint64("expected", uint64(txid)))
			txid = id + 1
		} else {
			txid++
		}
		updateTXTimestamp(clientID, rxt, &txt1)

		mtrcs.reqsServed.Inc()
	}
}

func StartIPServer(ctx context.Context, log *slog.Logger,
	localHost *net.UDPAddr, dscp uint8, provider *ntske.Provider) {
	log.LogAttrs(ctx, slog.LevelInfo, "server listening via IP",
		slog.Any("local host", localHost),
	)

	mtrcs := newIPServerMetrics()

	lc := net.ListenConfig{
		Control: udp.SetsockoptReuseAddrPort,
	}
	address := net.JoinHostPort(localHost.IP.String(), strconv.Itoa(localHost.Port))
	for range ipServerNumGoroutine {
		conn, err := lc.ListenPacket(ctx, "udp", address)
		if err != nil {
			logbase.FatalContext(ctx, log, "failed to listen for packets", slog.Any("error", err))
		}
		go runIPServer(ctx, log, mtrcs, conn.(*net.UDPConn), localHost.Zone, dscp, provider)
	}
}
