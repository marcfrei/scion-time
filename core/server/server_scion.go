package server

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/spao"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/base/metrics"

	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ntp"
	"example.com/scion-time/net/nts"
	"example.com/scion-time/net/ntske"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

const (
	scionServerNumGoroutine = 8
)

type scionServerMetrics struct {
	pktsReceived      prometheus.Counter
	pktsForwarded     prometheus.Counter
	pktsAuthenticated prometheus.Counter
	reqsAccepted      prometheus.Counter
	reqsServed        prometheus.Counter
}

func newSCIONServerMetrics() *scionServerMetrics {
	return &scionServerMetrics{
		pktsReceived: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.SCIONServerPktsReceivedN,
			Help: metrics.SCIONServerPktsReceivedH,
		}),
		pktsForwarded: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.SCIONServerPktsForwardedN,
			Help: metrics.SCIONServerPktsForwardedH,
		}),
		pktsAuthenticated: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.SCIONServerPktsAuthenticatedN,
			Help: metrics.SCIONServerPktsAuthenticatedH,
		}),
		reqsAccepted: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.SCIONServerReqsAcceptedN,
			Help: metrics.SCIONServerReqsAcceptedH,
		}),
		reqsServed: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.SCIONServerReqsServedN,
			Help: metrics.SCIONServerReqsServedH,
		}),
	}
}

func runSCIONServer(ctx context.Context, log *slog.Logger, mtrcs *scionServerMetrics,
	conn *net.UDPConn, localHostIface string, localHostPort int, dscp uint8,
	fetcher *scion.Fetcher, provider *ntske.Provider) {
	defer func() { _ = conn.Close() }()

	localConnPort := conn.LocalAddr().(*net.UDPAddr).Port

	err := udp.EnableTimestamping(conn, localHostIface, -1 /* index */)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError, "failed to enable timestamping", slog.Any("error", err))
	}
	err = udp.SetDSCP(conn, dscp)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelInfo, "failed to set DSCP", slog.Any("error", err))
	}

	var txid uint32
	buf := make([]byte, scion.MTU)
	oob := make([]byte, udp.TimestampLen())

	var (
		scionLayer slayers.SCION
		hbhLayer   slayers.HopByHopExtnSkipper
		e2eLayer   slayers.EndToEndExtn
		udpLayer   slayers.UDP
		scmpLayer  slayers.SCMP
	)
	scionLayer.RecyclePaths()
	udpLayer.SetNetworkLayerForChecksum(&scionLayer)
	scmpLayer.SetNetworkLayerForChecksum(&scionLayer)
	parser := gopacket.NewDecodingLayerParser(
		slayers.LayerTypeSCION, &scionLayer, &hbhLayer, &e2eLayer, &udpLayer, &scmpLayer,
	)
	parser.IgnoreUnsupported = true
	decoded := make([]gopacket.LayerType, 4)
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	var authBuf, authMAC, authMockKey []byte
	if fetcher != nil {
		authBuf = make([]byte, spao.MACBufferSize)
		authMAC = make([]byte, scion.PacketAuthMACLen)
		if scion.UseMockKeys() {
			authMockKey = new(drkey.Key)[:]
		}
	}
	tsOpt := &slayers.EndToEndOption{}

	for {
		buf = buf[:cap(buf)]
		oob = oob[:cap(oob)]
		n, oobn, flags, lastHop, err := conn.ReadMsgUDPAddrPort(buf, oob)
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

		err = parser.DecodeLayers(buf, &decoded)
		if err != nil {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet", slog.Any("error", err))
			continue
		}
		validType := len(decoded) >= 2 && (decoded[len(decoded)-1] == slayers.LayerTypeSCIONUDP ||
			decoded[len(decoded)-1] == slayers.LayerTypeSCMP)
		if !validType {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet", slog.String("cause", "unexpected type or structure"))
			continue
		}

		if decoded[len(decoded)-1] == slayers.LayerTypeSCMP {
			if scmpLayer.TypeCode.Type() == slayers.SCMPTypeEchoReply {
				var scmpEcho slayers.SCMPEcho
				err = scmpEcho.DecodeFromBytes(scmpLayer.Payload, gopacket.NilDecodeFeedback)
				if err != nil {
					log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet", slog.Any("error", err))
					continue
				}
				if localConnPort != scion.EndhostPort || scmpEcho.Identifier == scion.EndhostPort {
					log.LogAttrs(ctx, slog.LevelInfo, "failed to forward packet",
						slog.String("cause", "unexpected underlay or L4 destination port"),
						slog.Int("underlay_dst_port", localConnPort),
						slog.Int("l4_dst_port", int(scmpEcho.Identifier)))
					continue
				}
				dstAddr, ok := netip.AddrFromSlice(scionLayer.RawDstAddr)
				if !ok {
					panic("unexpected IP address byte slice")
				}
				dstAddrPort := netip.AddrPortFrom(dstAddr, scmpEcho.Identifier)
				err = buffer.Clear()
				if err != nil {
					panic(err)
				}
				payload := gopacket.Payload(scmpLayer.Payload)
				err = payload.SerializeTo(buffer, options)
				if err != nil {
					panic(err)
				}
				buffer.PushLayer(payload.LayerType())
				err = scmpLayer.SerializeTo(buffer, options)
				if err != nil {
					panic(err)
				}
				buffer.PushLayer(udpLayer.LayerType())
				if scionLayer.NextHdr == slayers.End2EndClass {
					err = e2eLayer.SerializeTo(buffer, options)
					if err != nil {
						panic(err)
					}
					buffer.PushLayer(e2eLayer.LayerType())
				}
				err = scionLayer.SerializeTo(buffer, options)
				if err != nil {
					panic(err)
				}
				buffer.PushLayer(scionLayer.LayerType())
				m, err := conn.WriteToUDPAddrPort(buffer.Bytes(), dstAddrPort)
				if err != nil || m != len(buffer.Bytes()) {
					log.LogAttrs(ctx, slog.LevelError, "failed to write packet", slog.Any("error", err))
					continue
				}
				_, id, err := udp.ReadTXTimestamp(conn, txid)
				if err != nil {
					log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
						slog.Any("error", err))
				} else if id != txid {
					log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
						slog.Uint64("id", uint64(id)), slog.Uint64("expected", uint64(txid)))
					txid = id + 1
				} else {
					txid++
				}
				mtrcs.pktsForwarded.Inc()
				continue
			}

			var payload gopacket.Payload
			switch scmpLayer.TypeCode.Type() {
			case slayers.SCMPTypeEchoRequest:
				payload = gopacket.Payload(scmpLayer.Payload)
				scmpLayer.TypeCode = slayers.CreateSCMPTypeCode(
					slayers.SCMPTypeEchoReply, 0 /* code */)
			case slayers.SCMPTypeTracerouteRequest:
				payload = gopacket.Payload(scmpLayer.Payload)
				scmpLayer.TypeCode = slayers.CreateSCMPTypeCode(
					slayers.SCMPTypeTracerouteReply, 0 /* code */)
			default:
				log.LogAttrs(ctx, slog.LevelInfo, "failed to handle packet",
					slog.String("cause", "unexpected SCMP message type"),
					slog.Uint64("type", uint64(scmpLayer.TypeCode.Type())),
					slog.Uint64("code", uint64(scmpLayer.TypeCode.Code())))
				continue
			}

			scionLayer.DstIA, scionLayer.SrcIA = scionLayer.SrcIA, scionLayer.DstIA
			scionLayer.DstAddrType, scionLayer.SrcAddrType = scionLayer.SrcAddrType, scionLayer.DstAddrType
			scionLayer.RawDstAddr, scionLayer.RawSrcAddr = scionLayer.RawSrcAddr, scionLayer.RawDstAddr
			scionLayer.Path, err = scionLayer.Path.Reverse()
			if err != nil {
				panic(err)
			}
			scionLayer.NextHdr = slayers.L4SCMP

			err = buffer.Clear()
			if err != nil {
				panic(err)
			}

			err = payload.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(payload.LayerType())

			err = scmpLayer.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(scmpLayer.LayerType())

			err = scionLayer.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(scionLayer.LayerType())

			m, err := conn.WriteToUDPAddrPort(buffer.Bytes(), lastHop)
			if err != nil || m != len(buffer.Bytes()) {
				log.LogAttrs(ctx, slog.LevelError, "failed to write packet", slog.Any("error", err))
				continue
			}
			_, id, err := udp.ReadTXTimestamp(conn, txid)
			if err != nil {
				log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
					slog.Any("error", err))
			} else if id != txid {
				log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
					slog.Uint64("id", uint64(id)), slog.Uint64("expected", uint64(txid)))
				txid = id + 1
			} else {
				txid++
			}

			continue
		}

		if len(buf) < int(udpLayer.Length) {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet", slog.String("cause", "unexpected structure"))
			continue
		}

		srcAddr, ok := netip.AddrFromSlice(scionLayer.RawSrcAddr)
		if !ok {
			panic("unexpected IP address byte slice")
		}
		dstAddr, ok := netip.AddrFromSlice(scionLayer.RawDstAddr)
		if !ok {
			panic("unexpected IP address byte slice")
		}

		if int(udpLayer.DstPort) != localHostPort {
			if localConnPort != scion.EndhostPort || udpLayer.DstPort == scion.EndhostPort {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to forward packet",
					slog.String("cause", "unexpected underlay or L4 destination port"),
					slog.Int("underlay_dst_port", localConnPort),
					slog.Int("l4_dst_port", int(udpLayer.DstPort)))
				continue
			}

			dstAddrPort := netip.AddrPortFrom(dstAddr, udpLayer.DstPort)
			payload := gopacket.Payload(udpLayer.Payload)

			err = buffer.Clear()
			if err != nil {
				panic(err)
			}

			err = payload.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(payload.LayerType())

			err = udpLayer.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(udpLayer.LayerType())

			if len(oob) != 0 {
				tsOpt.OptType = scion.OptTypeTimestamp
				tsOpt.OptData = oob
				tsOpt.OptAlign[0] = 0
				tsOpt.OptAlign[1] = 0
				tsOpt.OptDataLen = 0
				tsOpt.ActualLength = 0

				if scionLayer.NextHdr != slayers.End2EndClass {
					e2eLayer = slayers.EndToEndExtn{}
					e2eLayer.NextHdr = slayers.L4UDP
					scionLayer.NextHdr = slayers.End2EndClass
				}
				e2eLayer.Options = append(e2eLayer.Options, tsOpt)
			}

			if scionLayer.NextHdr == slayers.End2EndClass {
				err = e2eLayer.SerializeTo(buffer, options)
				if err != nil {
					panic(err)
				}
				buffer.PushLayer(e2eLayer.LayerType())
			}

			err = scionLayer.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(scionLayer.LayerType())

			m, err := conn.WriteToUDPAddrPort(buffer.Bytes(), dstAddrPort)
			if err != nil || m != len(buffer.Bytes()) {
				log.LogAttrs(ctx, slog.LevelError, "failed to write packet", slog.Any("error", err))
				continue
			}
			_, id, err := udp.ReadTXTimestamp(conn, txid)
			if err != nil {
				log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
					slog.Any("error", err))
			} else if id != txid {
				log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
					slog.Uint64("id", uint64(id)), slog.Uint64("expected", uint64(txid)))
				txid = id + 1
			} else {
				txid++
			}

			mtrcs.pktsForwarded.Inc()
		} else {
			if localHostPort == scion.EndhostPort {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to handle packet",
					slog.String("cause", "unexpected underlay or L4 destination port"),
					slog.Int("underlay_dst_port", localConnPort),
					slog.Int("l4_dst_port", int(udpLayer.DstPort)))
				continue
			}

			var (
				authOpt *slayers.EndToEndOption
				authKey []byte
			)
			authenticated := false

			if fetcher != nil && len(decoded) >= 3 &&
				decoded[len(decoded)-2] == slayers.LayerTypeEndToEndExtn {
				authOpt, err = e2eLayer.FindOption(slayers.OptTypeAuthenticator)
				if err == nil {
					spi, algo := scion.PacketAuthOptMetadata(authOpt)
					if spi == scion.PacketAuthSPIClient && algo == scion.PacketAuthAlgorithm {
						hostASKey, err := fetcher.FetchHostASKey(ctx, drkey.HostASMeta{
							ProtoId:  scion.DRKeyProtocolTS,
							Validity: rxt,
							SrcIA:    scionLayer.DstIA,
							DstIA:    scionLayer.SrcIA,
							SrcHost:  dstAddr.String(),
						})
						if err != nil {
							log.LogAttrs(ctx, slog.LevelError, "failed to fetch DRKey level 2: host-AS", slog.Any("error", err))
						} else {
							hostHostKey, err := scion.DeriveHostHostKey(hostASKey, srcAddr.String())
							if err != nil {
								panic(err)
							}
							authKey = hostHostKey.Key[:]
							if authMockKey != nil {
								authKey = authMockKey
							}
							_, err = spao.ComputeAuthCMAC(
								spao.MACInput{
									Key:        authKey,
									Header:     slayers.PacketAuthOption{EndToEndOption: authOpt},
									ScionLayer: &scionLayer,
									PldType:    slayers.L4UDP,
									Pld:        buf[len(buf)-int(udpLayer.Length):],
								},
								authBuf,
								authMAC,
							)
							if err != nil {
								panic(err)
							}
							authenticated = subtle.ConstantTimeCompare(scion.PacketAuthOptMAC(authOpt), authMAC) != 0
							if !authenticated {
								log.LogAttrs(ctx, slog.LevelInfo, "failed to authenticate packet")
								continue
							}
							mtrcs.pktsAuthenticated.Inc()
						}
					}
				}
			}

			var ntpreq ntp.Packet
			err = ntp.DecodePacket(&ntpreq, udpLayer.Payload)
			if err != nil {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
				continue
			}

			ntsAuthenticated := false
			var ntsreq nts.Packet
			var serverCookie ntske.ServerCookie
			if len(udpLayer.Payload) > ntp.PacketLen {
				err = nts.DecodePacket(&ntsreq, udpLayer.Payload)
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

				err = nts.ProcessRequest(udpLayer.Payload, serverCookie.C2S, &ntsreq)
				if err != nil {
					log.LogAttrs(ctx, slog.LevelInfo, "failed to process NTS packet", slog.Any("error", err))
					continue
				}
				ntsAuthenticated = true
			}

			err = ntp.ValidateRequest(&ntpreq, udpLayer.SrcPort)
			if err != nil {
				log.LogAttrs(ctx, slog.LevelInfo, "failed to validate packet payload", slog.Any("error", err))
				continue
			}

			clientID := scionLayer.SrcIA.String() + "," + srcAddr.String()

			mtrcs.reqsAccepted.Inc()
			log.LogAttrs(ctx, slog.LevelDebug, "received request",
				slog.Time("at", rxt),
				slog.String("from", clientID),
				slog.Bool("auth", authenticated),
				slog.Bool("ntsauth", ntsAuthenticated),
				slog.Any("data", ntp.PacketLogValuer{Pkt: &ntpreq}),
			)

			var txt0 time.Time
			var ntpresp ntp.Packet
			handleRequest(clientID, &ntpreq, &rxt, &txt0, &ntpresp)

			scionLayer.TrafficClass = dscp << 2
			scionLayer.DstIA, scionLayer.SrcIA = scionLayer.SrcIA, scionLayer.DstIA
			scionLayer.DstAddrType, scionLayer.SrcAddrType = scionLayer.SrcAddrType, scionLayer.DstAddrType
			scionLayer.RawDstAddr, scionLayer.RawSrcAddr = scionLayer.RawSrcAddr, scionLayer.RawDstAddr
			scionLayer.Path, err = scionLayer.Path.Reverse()
			if err != nil {
				panic(err)
			}
			scionLayer.NextHdr = slayers.L4UDP

			udpLayer.DstPort, udpLayer.SrcPort = udpLayer.SrcPort, udpLayer.DstPort
			ntp.EncodePacket(&udpLayer.Payload, &ntpresp)

			if ntsAuthenticated {
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
				nts.EncodePacket(&udpLayer.Payload, &ntsresp)
			}

			payload := gopacket.Payload(udpLayer.Payload)

			err = buffer.Clear()
			if err != nil {
				panic(err)
			}

			err = payload.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(payload.LayerType())

			err = udpLayer.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(udpLayer.LayerType())

			if authenticated {
				scion.PreparePacketAuthOpt(authOpt, scion.PacketAuthSPIServer, scion.PacketAuthAlgorithm)
				_, err = spao.ComputeAuthCMAC(
					spao.MACInput{
						Key:        authKey,
						Header:     slayers.PacketAuthOption{EndToEndOption: authOpt},
						ScionLayer: &scionLayer,
						PldType:    scionLayer.NextHdr,
						Pld:        buffer.Bytes(),
					},
					authBuf,
					scion.PacketAuthOptMAC(authOpt),
				)
				if err != nil {
					panic(err)
				}

				e2eExtn := slayers.EndToEndExtn{}
				e2eExtn.NextHdr = scionLayer.NextHdr
				e2eExtn.Options = []*slayers.EndToEndOption{authOpt}

				err = e2eExtn.SerializeTo(buffer, options)
				if err != nil {
					panic(err)
				}
				buffer.PushLayer(e2eExtn.LayerType())

				scionLayer.NextHdr = slayers.End2EndClass
			}

			err = scionLayer.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(scionLayer.LayerType())

			n, err = conn.WriteToUDPAddrPort(buffer.Bytes(), lastHop)
			if err != nil || n != len(buffer.Bytes()) {
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
}

func StartSCIONServer(ctx context.Context, log *slog.Logger,
	daemonAddr string, localHost *net.UDPAddr, dscp uint8, provider *ntske.Provider) {
	mtrcs := newSCIONServerMetrics()

	log.LogAttrs(ctx, slog.LevelInfo,
		"server listening via SCION",
		slog.Any("local host", localHost),
	)

	if localHost.Port == scion.EndhostPort {
		logbase.FatalContext(ctx, log, "invalid listener port",
			slog.Int("port", localHost.Port))
	}

	lc := net.ListenConfig{
		Control: udp.SetsockoptReuseAddrPort,
	}
	for _, localHostPort := range []int{localHost.Port, scion.EndhostPort} {
		address := net.JoinHostPort(localHost.IP.String(), strconv.Itoa(localHostPort))
		for range scionServerNumGoroutine {
			fetcher := scion.NewFetcher(scion.NewDaemonConnector(ctx, daemonAddr))
			conn, err := lc.ListenPacket(ctx, "udp", address)
			if err != nil {
				logbase.FatalContext(ctx, log, "failed to listen for packets", slog.Any("error", err))
			}
			go runSCIONServer(ctx, log, mtrcs, conn.(*net.UDPConn), localHost.Zone, localHost.Port, dscp, fetcher, provider)
		}
	}
}

func StartSCIONDispatcher(ctx context.Context, log *slog.Logger,
	localHost *net.UDPAddr) {
	mtrcs := newSCIONServerMetrics()

	log.LogAttrs(ctx, slog.LevelInfo,
		"dispatcher listening via SCION",
		slog.Any("local host", localHost),
	)

	if localHost.Port == scion.EndhostPort {
		logbase.FatalContext(ctx, log, "invalid listener port",
			slog.Int("port", localHost.Port))
	}

	localHost.Port = scion.EndhostPort

	lc := net.ListenConfig{}
	address := net.JoinHostPort(localHost.IP.String(), strconv.Itoa(localHost.Port))
	conn, err := lc.ListenPacket(ctx, "udp", address)
	if err != nil {
		logbase.FatalContext(ctx, log, "failed to listen for packets", slog.Any("error", err))
	}
	go runSCIONServer(ctx, log, mtrcs, conn.(*net.UDPConn), localHost.Zone, localHost.Port,
		0 /* DSCP */, nil /* DRKey fetcher */, nil /* NTSKE provider */)
}
