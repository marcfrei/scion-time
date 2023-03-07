package server

import (
	"context"
	"crypto/subtle"
	"net"
	"net/netip"
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

	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ntp"
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
	conn *net.UDPConn, localHostIface string, localHostPort int, f *scion.Fetcher) {
	defer conn.Close()
	err := udp.EnableTimestamping(conn, localHostIface)
	if err != nil {
		log.Error("failed to enable timestamping", zap.Error(err))
	}

	var txId uint32
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

	var authBuf, authMAC []byte
	if f != nil {
		authBuf = make([]byte, spao.MACBufferSize)
		authMAC = make([]byte, scion.PacketAuthMACLen)
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
			} else if id != txId {
				log.Error("failed to read packet tx timestamp", zap.Uint32("id", id), zap.Uint32("expected", txId))
				txId = id + 1
			} else {
				txId++
			}

			mtrcs.pktsForwarded.Inc()
		} else if localHostPort != scion.EndhostPort {
			var (
				authOpt *slayers.EndToEndOption
				authKey []byte
			)
			authenticated := false

			if f != nil && len(decoded) >= 3 &&
				decoded[len(decoded)-2] == slayers.LayerTypeEndToEndExtn {
				authOpt, err = e2eLayer.FindOption(slayers.OptTypeAuthenticator)
				if err == nil {
					if len(authOpt.OptData) != scion.PacketAuthOptDataLen {
						panic("unexpected authenticator option data")
					}
					authOptData := authOpt.OptData
					spi := uint32(authOptData[3]) |
						uint32(authOptData[2])<<8 |
						uint32(authOptData[1])<<16 |
						uint32(authOptData[0])<<24
					algo := uint8(authOptData[4])
					if spi == scion.PacketAuthSPIClient && algo == scion.PacketAuthAlgorithm {
						sv, err := f.FetchSecretValue(ctx, drkey.SecretValueMeta{
							Validity: rxt,
							ProtoId:  scion.DRKeyProtoIdTS,
						})
						if err == nil {
							key, err := scion.DeriveHostHostKey(sv, drkey.HostHostMeta{
								ProtoId:  scion.DRKeyProtoIdTS,
								Validity: rxt,
								SrcIA:    scionLayer.DstIA,
								DstIA:    scionLayer.SrcIA,
								SrcHost:  dstAddr.String(),
								DstHost:  srcAddr.String(),
							})
							if err == nil {
								authKey = key.Key[:]
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
								authenticated = subtle.ConstantTimeCompare(authOptData[scion.PacketAuthMetadataLen:], authMAC) != 0
								if !authenticated {
									log.Info("failed to authenticate packet")
									continue
								}
								mtrcs.pktsAuthenticated.Inc()
							}
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

			err = ntp.ValidateRequest(&ntpreq, udpLayer.SrcPort)
			if err != nil {
				log.Info("failed to validate packet payload", zap.Error(err))
				continue
			}

			clientID := scionLayer.SrcIA.String() + "," + srcAddr.String()

			mtrcs.reqsAccepted.Inc()
			log.Debug("received request",
				zap.Time("at", rxt),
				zap.String("from", clientID),
				zap.Bool("auth", authenticated),
				zap.Object("data", ntp.PacketMarshaler{Pkt: &ntpreq}),
			)

			var txt0 time.Time
			var ntpresp ntp.Packet
			handleRequest(clientID, &ntpreq, &rxt, &txt0, &ntpresp)

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
					authOpt.OptData[scion.PacketAuthMetadataLen:],
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
}

func newDaemonConnector(ctx context.Context, log *zap.Logger, daemonAddr string) daemon.Connector {
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
	daemonAddr string, localHost *net.UDPAddr) {
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
		f := scion.NewFetcher(newDaemonConnector(ctx, log, daemonAddr))
		conn, err := net.ListenUDP("udp", localHost)
		if err != nil {
			log.Fatal("failed to listen for packets", zap.Error(err))
		}
		go runSCIONServer(ctx, log, mtrcs, conn, localHost.Zone, localHostPort, f)
	} else {
		for i := scionServerNumGoroutine; i > 0; i-- {
			f := scion.NewFetcher(newDaemonConnector(ctx, log, daemonAddr))
			conn, err := reuseport.ListenPacket("udp", localHost.String())
			if err != nil {
				log.Fatal("failed to listen for packets", zap.Error(err))
			}
			go runSCIONServer(ctx, log, mtrcs, conn.(*net.UDPConn), localHost.Zone, localHostPort, f)
		}
	}
}

func StartSCIONDisptacher(ctx context.Context, log *zap.Logger,
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
	go runSCIONServer(ctx, log, mtrcs, conn, localHost.Zone, localHost.Port, nil /* DRKey fetcher */)
}