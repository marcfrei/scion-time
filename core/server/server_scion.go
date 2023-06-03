package server

import (
	"context"
	"crypto/subtle"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/google/gopacket"

	"github.com/libp2p/go-reuseport"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/spao"

	"go.uber.org/zap"

	"example.com/scion-time/base/metrics"

	"example.com/scion-time/core/config"
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

func runSCIONServer(ctx context.Context, log *zap.Logger, mtrcs *scionServerMetrics,
	conn *net.UDPConn, localHostIface string, localHostPort int,
	fetcher *scion.Fetcher, provider *ntske.Provider) {
	defer conn.Close()
	err := udp.EnableTimestamping(conn, localHostIface)
	if err != nil {
		log.Error("failed to enable timestamping", zap.Error(err))
	}
	err = udp.SetDSCP(conn, config.DSCP)
	if err != nil {
		log.Info("failed to set DSCP", zap.Error(err))
	}

	var txID uint32
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

		err = parser.DecodeLayers(buf, &decoded)
		if err != nil {
			log.Info("failed to decode packet", zap.Error(err))
			continue
		}
		validType := len(decoded) >= 2 &&
			decoded[len(decoded)-1] == slayers.LayerTypeSCIONUDP
		if !validType {
			log.Info("failed to decode packet", zap.String("cause", "unexpected type or structure"))
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
				log.Error("failed to write packet", zap.Error(err))
				continue
			}
			_, id, err := udp.ReadTXTimestamp(conn)
			if err != nil {
				log.Error("failed to read packet tx timestamp", zap.Error(err))
			} else if id != txID {
				log.Error("failed to read packet tx timestamp", zap.Uint32("id", id), zap.Uint32("expected", txID))
				txID = id + 1
			} else {
				txID++
			}

			mtrcs.pktsForwarded.Inc()
		} else if localHostPort != scion.EndhostPort {
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
							log.Error("failed to fetch DRKey level 2: host-AS", zap.Error(err))
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
								log.Info("failed to authenticate packet")
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
				log.Info("failed to decode packet payload", zap.Error(err))
				continue
			}

			ntsAuthenticated := false
			var ntsreq nts.Packet
			var serverCookie ntske.ServerCookie
			if len(udpLayer.Payload) > ntp.PacketLen {
				err = nts.DecodePacket(&ntsreq, udpLayer.Payload)
				if err != nil {
					log.Info("failed to decode NTS packet", zap.Error(err))
					continue
				}

				cookie, err := ntsreq.GetFirstCookie()
				if err != nil {
					log.Info("failed to get cookie", zap.Error(err))
					continue
				}

				var encryptedCookie ntske.EncryptedServerCookie
				err = encryptedCookie.Decode(cookie)
				if err != nil {
					log.Info("failed to decode cookie", zap.Error(err))
					continue
				}

				key, ok := provider.Get(int(encryptedCookie.ID))
				if !ok {
					log.Info("failed to get key", zap.Error(err))
					continue
				}

				serverCookie, err = encryptedCookie.Decrypt(key.Value)
				if err != nil {
					log.Info("failed to decrypt cookie", zap.Error(err))
					continue
				}

				err = nts.ProcessRequest(udpLayer.Payload, serverCookie.C2S, &ntsreq)
				if err != nil {
					log.Info("failed to process NTS packet", zap.Error(err))
					continue
				}
				ntsAuthenticated = true
			}

			err = ntp.ValidateRequest(&ntpreq, udpLayer.SrcPort)
			if err != nil {
				log.Info("failed to validate packet payload", zap.Error(err))
				continue
			}

			dscp := scionLayer.TrafficClass >> 2
			clientID := scionLayer.SrcIA.String() + "," + srcAddr.String()

			mtrcs.reqsAccepted.Inc()
			log.Debug("received request",
				zap.Time("at", rxt),
				zap.String("from", clientID),
				zap.Uint8("DSCP", dscp),
				zap.Bool("auth", authenticated),
				zap.Bool("ntsauth", ntsAuthenticated),
				zap.Object("data", ntp.PacketMarshaler{Pkt: &ntpreq}),
			)

			var txt0 time.Time
			var ntpresp ntp.Packet
			handleRequest(clientID, &ntpreq, &rxt, &txt0, &ntpresp)

			scionLayer.TrafficClass = config.DSCP << 2
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
				for i := 0; i < len(ntsreq.Cookies)+len(ntsreq.CookiePlaceholders); i++ {
					encryptedCookie, err := serverCookie.EncryptWithNonce(key.Value, key.ID)
					if err != nil {
						log.Info("failed to encrypt cookie", zap.Error(err))
						continue
					}
					cookie := encryptedCookie.Encode()
					cookies = append(cookies, cookie)
					addedCookie = true
				}
				if !addedCookie {
					log.Info("failed to add at least one cookie")
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
				log.Error("failed to write packet", zap.Error(err))
				continue
			}
			txt1, id, err := udp.ReadTXTimestamp(conn)
			if err != nil {
				txt1 = txt0
				log.Error("failed to read packet tx timestamp", zap.Error(err))
			} else if id != txID {
				txt1 = txt0
				log.Error("failed to read packet tx timestamp", zap.Uint32("id", id), zap.Uint32("expected", txID))
				txID = id + 1
			} else {
				txID++
			}
			updateTXTimestamp(clientID, rxt, &txt1)

			mtrcs.reqsServed.Inc()
		}
	}
}

func newDaemonConnector(ctx context.Context, log *zap.Logger, daemonAddr string) daemon.Connector {
	if daemonAddr == "" {
		return nil
	}
	s := &daemon.Service{
		Address: daemonAddr,
	}
	c, err := s.Connect(ctx)
	if err != nil {
		log.Fatal("failed to create demon connector", zap.Error(err))
	}
	return c
}

func StartSCIONServer(ctx context.Context, log *zap.Logger,
	daemonAddr string, localHost *net.UDPAddr, provider *ntske.Provider) {
	log.Info("server listening via SCION",
		zap.Stringer("ip", localHost.IP),
		zap.Int("port", localHost.Port),
	)

	if localHost.Port == scion.EndhostPort {
		log.Fatal("invalid listener port", zap.Int("port", scion.EndhostPort))
	}

	localHostPort := localHost.Port
	localHost.Port = scion.EndhostPort

	mtrcs := newSCIONServerMetrics()

	if scionServerNumGoroutine == 1 {
		fetcher := scion.NewFetcher(newDaemonConnector(ctx, log, daemonAddr))
		conn, err := net.ListenUDP("udp", localHost)
		if err != nil {
			log.Fatal("failed to listen for packets", zap.Error(err))
		}
		go runSCIONServer(ctx, log, mtrcs, conn, localHost.Zone, localHostPort, fetcher, provider)
	} else {
		for i := scionServerNumGoroutine; i > 0; i-- {
			fetcher := scion.NewFetcher(newDaemonConnector(ctx, log, daemonAddr))
			conn, err := reuseport.ListenPacket("udp",
				net.JoinHostPort(localHost.IP.String(), strconv.Itoa(localHost.Port)))
			if err != nil {
				log.Fatal("failed to listen for packets", zap.Error(err))
			}
			go runSCIONServer(ctx, log, mtrcs, conn.(*net.UDPConn), localHost.Zone, localHostPort, fetcher, provider)
		}
	}
}

func StartSCIONDispatcher(ctx context.Context, log *zap.Logger,
	localHost *net.UDPAddr) {
	log.Info("dispatcher listening via SCION",
		zap.Stringer("ip", localHost.IP),
		zap.Int("port", scion.EndhostPort),
	)

	if localHost.Port == scion.EndhostPort {
		log.Fatal("invalid listener port", zap.Int("port", scion.EndhostPort))
	}

	localHost.Port = scion.EndhostPort

	mtrcs := newSCIONServerMetrics()

	conn, err := net.ListenUDP("udp", localHost)
	if err != nil {
		log.Fatal("failed to listen for packets", zap.Error(err))
	}
	go runSCIONServer(ctx, log, mtrcs, conn, localHost.Zone, localHost.Port, nil /* DRKey fetcher */, nil /* NTSKE provider */)
}
