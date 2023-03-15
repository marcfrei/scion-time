package client

import (
	"context"
	"crypto/subtle"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/spao"

	"go.uber.org/zap"

	"example.com/scion-time/base/metrics"

	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ntp"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

type SCIONClient struct {
	InterleavedMode bool
	DRKeyFetcher    *scion.Fetcher
	auth            struct {
		opt *slayers.EndToEndOption
		buf []byte
		mac []byte
	}
	prev struct {
		reference string
		cTxTime   ntp.Time64
		cRxTime   ntp.Time64
		sRxTime   ntp.Time64
	}
}

type scionClientMetrics struct {
	reqsSent                 prometheus.Counter
	reqsSentInterleaved      prometheus.Counter
	pktsReceived             prometheus.Counter
	pktsAuthenticated        prometheus.Counter
	respsAccepted            prometheus.Counter
	respsAcceptedInterleaved prometheus.Counter
}

func newSCIONClientMetrics() *scionClientMetrics {
	return &scionClientMetrics{
		reqsSent: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.SCIONClientReqsSentN,
			Help: metrics.SCIONClientReqsSentH,
		}),
		reqsSentInterleaved: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.SCIONClientReqsSentInterleavedN,
			Help: metrics.SCIONClientReqsSentInterleavedH,
		}),
		pktsReceived: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.SCIONClientPktsReceivedN,
			Help: metrics.SCIONClientPktsReceivedH,
		}),
		pktsAuthenticated: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.SCIONClientPktsAuthenticatedN,
			Help: metrics.SCIONClientPktsAuthenticatedH,
		}),
		respsAccepted: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.SCIONClientRespsAcceptedN,
			Help: metrics.SCIONClientRespsAcceptedH,
		}),
		respsAcceptedInterleaved: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.SCIONClientRespsAcceptedInterleavedN,
			Help: metrics.SCIONClientRespsAcceptedInterleavedH,
		}),
	}
}

func compareIPs(x, y []byte) int {
	addrX, okX := netip.AddrFromSlice(x)
	addrY, okY := netip.AddrFromSlice(y)
	if !okX || !okY {
		panic("unexpected IP address byte slice")
	}
	if addrX.Is4In6() {
		addrX = netip.AddrFrom4(addrX.As4())
	}
	if addrY.Is4In6() {
		addrY = netip.AddrFrom4(addrY.As4())
	}
	return addrX.Compare(addrY)
}

func (c *SCIONClient) ResetInterleavedMode() {
	c.prev.reference = ""
}

func (c *SCIONClient) measureClockOffsetSCION(ctx context.Context, log *zap.Logger, mtrcs *scionClientMetrics,
	localAddr, remoteAddr udp.UDPAddr, path snet.Path) (
	offset time.Duration, weight float64, err error) {
	if c.DRKeyFetcher != nil && c.auth.opt == nil {
		c.auth.opt = &slayers.EndToEndOption{}
		c.auth.opt.OptData = make([]byte, scion.PacketAuthOptDataLen)
		c.auth.buf = make([]byte, spao.MACBufferSize)
		c.auth.mac = make([]byte, scion.PacketAuthMACLen)
	}
	var authKey []byte

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: localAddr.Host.IP})
	if err != nil {
		return offset, weight, err
	}
	defer conn.Close()
	deadline, deadlineIsSet := ctx.Deadline()
	if deadlineIsSet {
		err = conn.SetDeadline(deadline)
		if err != nil {
			return offset, weight, err
		}
	}
	err = udp.EnableTimestamping(conn, localAddr.Host.Zone)
	if err != nil {
		log.Error("failed to enable timestamping", zap.Error(err))
	}

	localPort := conn.LocalAddr().(*net.UDPAddr).Port

	nextHop := path.UnderlayNextHop().AddrPort()
	nextHopAddr := nextHop.Addr()
	if nextHopAddr.Is4In6() {
		nextHop = netip.AddrPortFrom(
			netip.AddrFrom4(nextHopAddr.As4()),
			nextHop.Port())
	}
	if nextHop == (netip.AddrPort{}) && remoteAddr.IA.Equal(localAddr.IA) {
		nextHop = netip.AddrPortFrom(
			netip.AddrFrom4(remoteAddr.Host.AddrPort().Addr().As4()),
			scion.EndhostPort)
	}

	srcAddr := &net.IPAddr{IP: localAddr.Host.IP}
	dstAddr := &net.IPAddr{IP: remoteAddr.Host.IP}

	buf := make([]byte, scion.MTU)

	reference := remoteAddr.IA.String() + "," + remoteAddr.Host.String()
	cTxTime0 := timebase.Now()
	interleaved := false

	ntpreq := ntp.Packet{}
	ntpreq.SetVersion(ntp.VersionMax)
	ntpreq.SetMode(ntp.ModeClient)
	if c.InterleavedMode && reference == c.prev.reference &&
		cTxTime0.Sub(ntp.TimeFromTime64(c.prev.cTxTime)) <= time.Second {
		interleaved = true
		ntpreq.OriginTime = c.prev.sRxTime
		ntpreq.ReceiveTime = c.prev.cRxTime
		ntpreq.TransmitTime = c.prev.cTxTime
	} else {
		ntpreq.TransmitTime = ntp.Time64FromTime(cTxTime0)
	}
	ntp.EncodePacket(&buf, &ntpreq)

	var scionLayer slayers.SCION
	scionLayer.SrcIA = localAddr.IA
	err = scionLayer.SetSrcAddr(srcAddr)
	if err != nil {
		panic(err)
	}
	scionLayer.DstIA = remoteAddr.IA
	err = scionLayer.SetDstAddr(dstAddr)
	if err != nil {
		panic(err)
	}
	err = path.Dataplane().SetPath(&scionLayer)
	if err != nil {
		panic(err)
	}
	scionLayer.NextHdr = slayers.L4UDP

	var udpLayer slayers.UDP
	udpLayer.SrcPort = uint16(localPort)
	udpLayer.DstPort = uint16(remoteAddr.Host.Port)
	udpLayer.SetNetworkLayerForChecksum(&scionLayer)

	payload := gopacket.Payload(buf)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
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

	if c.DRKeyFetcher != nil {
		hostHostKey, err := c.DRKeyFetcher.FetchHostHostKey(ctx, drkey.HostHostMeta{
			ProtoId:  scion.DRKeyProtoIdTS,
			Validity: cTxTime0,
			SrcIA:    remoteAddr.IA,
			DstIA:    localAddr.IA,
			SrcHost:  remoteAddr.Host.IP.String(),
			DstHost:  localAddr.Host.IP.String(),
		})
		if err != nil {
			log.Info("failed to fetch DRKey level 3: host-host key", zap.Error(err))
		} else {
			authKey = hostHostKey.Key[:]

			scion.PreparePacketAuthOpt(c.auth.opt, scion.PacketAuthSPIClient, scion.PacketAuthAlgorithm)
			_, err = spao.ComputeAuthCMAC(
				spao.MACInput{
					Key:        authKey,
					Header:     slayers.PacketAuthOption{EndToEndOption: c.auth.opt},
					ScionLayer: &scionLayer,
					PldType:    scionLayer.NextHdr,
					Pld:        buffer.Bytes(),
				},
				c.auth.buf,
				c.auth.opt.OptData[scion.PacketAuthMetadataLen:],
			)
			if err != nil {
				panic(err)
			}

			e2eExtn := slayers.EndToEndExtn{}
			e2eExtn.NextHdr = scionLayer.NextHdr
			e2eExtn.Options = []*slayers.EndToEndOption{c.auth.opt}

			err = e2eExtn.SerializeTo(buffer, options)
			if err != nil {
				panic(err)
			}
			buffer.PushLayer(e2eExtn.LayerType())

			scionLayer.NextHdr = slayers.End2EndClass
		}
	}

	err = scionLayer.SerializeTo(buffer, options)
	if err != nil {
		panic(err)
	}
	buffer.PushLayer(scionLayer.LayerType())

	n, err := conn.WriteToUDPAddrPort(buffer.Bytes(), nextHop)
	if err != nil {
		return offset, weight, err
	}
	if n != len(buffer.Bytes()) {
		return offset, weight, errWrite
	}
	cTxTime1, id, err := udp.ReadTXTimestamp(conn)
	if err != nil || id != 0 {
		cTxTime1 = timebase.Now()
		log.Error("failed to read packet tx timestamp", zap.Error(err))
	}
	mtrcs.reqsSent.Inc()
	if interleaved {
		mtrcs.reqsSentInterleaved.Inc()
	}

	numRetries := 0
	oob := make([]byte, udp.TimestampLen())
	for {
		buf = buf[:cap(buf)]
		oob = oob[:cap(oob)]
		n, oobn, flags, lastHop, err := conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				log.Info("failed to read packet", zap.Error(err))
				numRetries++
				continue
			}
			return offset, weight, err
		}
		if flags != 0 {
			err = errUnexpectedPacketFlags
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				log.Info("failed to read packet", zap.Int("flags", flags))
				numRetries++
				continue
			}
			return offset, weight, err
		}
		oob = oob[:oobn]
		cRxTime, err := udp.TimestampFromOOBData(oob)
		if err != nil {
			cRxTime = timebase.Now()
			log.Error("failed to read packet rx timestamp", zap.Error(err))
		}
		buf = buf[:n]
		mtrcs.pktsReceived.Inc()

		var (
			hbhLayer  slayers.HopByHopExtnSkipper
			e2eLayer  slayers.EndToEndExtn
			scmpLayer slayers.SCMP
		)
		parser := gopacket.NewDecodingLayerParser(
			slayers.LayerTypeSCION, &scionLayer, &hbhLayer, &e2eLayer, &udpLayer, &scmpLayer,
		)
		parser.IgnoreUnsupported = true
		decoded := make([]gopacket.LayerType, 4)
		err = parser.DecodeLayers(buf, &decoded)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				log.Info("failed to decode packet", zap.Error(err))
				numRetries++
				continue
			}
			return offset, weight, err
		}
		validType := len(decoded) >= 2 &&
			decoded[len(decoded)-1] == slayers.LayerTypeSCIONUDP
		if !validType {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				log.Info("failed to decode packet", zap.String("cause", "unexpected type or structure"))
				numRetries++
				continue
			}
			return offset, weight, err
		}
		validSrc := scionLayer.SrcIA.Equal(remoteAddr.IA) &&
			compareIPs(scionLayer.RawSrcAddr, remoteAddr.Host.IP) == 0
		validDst := scionLayer.DstIA.Equal(localAddr.IA) &&
			compareIPs(scionLayer.RawDstAddr, localAddr.Host.IP) == 0
		if !validSrc || !validDst {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				if !validSrc {
					log.Info("received packet from unexpected source")
				}
				if !validDst {
					log.Info("received packet to unexpected destination")
				}
				numRetries++
				continue
			}
			return offset, weight, err
		}

		authenticated := false
		if len(decoded) >= 3 &&
			decoded[len(decoded)-2] == slayers.LayerTypeEndToEndExtn {
			tsOpt, err := e2eLayer.FindOption(scion.OptTypeTimestamp)
			if err == nil {
				cRxTime0, err := udp.TimestampFromOOBData(tsOpt.OptData)
				if err == nil {
					cRxTime = cRxTime0
				}
			}
			if authKey != nil {
				authOpt, err := e2eLayer.FindOption(slayers.OptTypeAuthenticator)
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
					if spi == scion.PacketAuthSPIServer && algo == scion.PacketAuthAlgorithm {
						_, err = spao.ComputeAuthCMAC(
							spao.MACInput{
								Key:        authKey,
								Header:     slayers.PacketAuthOption{EndToEndOption: authOpt},
								ScionLayer: &scionLayer,
								PldType:    slayers.L4UDP,
								Pld:        buf[len(buf)-int(udpLayer.Length):],
							},
							c.auth.buf,
							c.auth.mac,
						)
						if err != nil {
							panic(err)
						}
						authenticated = subtle.ConstantTimeCompare(authOptData[scion.PacketAuthMetadataLen:], c.auth.mac) != 0
						if !authenticated {
							log.Info("failed to authenticate packet")
							continue
						}
						mtrcs.pktsAuthenticated.Inc()
					}
				}
			}
		}

		var ntpresp ntp.Packet
		err = ntp.DecodePacket(&ntpresp, udpLayer.Payload)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				log.Info("failed to decode packet payload", zap.Error(err))
				numRetries++
				continue
			}
			return offset, weight, err
		}

		interleaved = false
		if c.InterleavedMode && ntpresp.OriginTime == c.prev.cRxTime {
			interleaved = true
		} else if ntpresp.OriginTime != ntpreq.TransmitTime {
			err = errUnexpectedPacket
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				log.Info("received packet with unexpected type or structure")
				numRetries++
				continue
			}
			return offset, weight, err
		}

		err = ntp.ValidateResponseMetadata(&ntpresp)
		if err != nil {
			return offset, weight, err
		}

		log.Debug("received response",
			zap.Time("at", cRxTime),
			zap.String("from", reference),
			zap.Stringer("via", lastHop),
			zap.Bool("auth", authenticated),
			zap.Object("data", ntp.PacketMarshaler{Pkt: &ntpresp}),
		)

		sRxTime := ntp.TimeFromTime64(ntpresp.ReceiveTime)
		sTxTime := ntp.TimeFromTime64(ntpresp.TransmitTime)

		var t0, t1, t2, t3 time.Time
		if interleaved {
			t0 = ntp.TimeFromTime64(c.prev.cTxTime)
			t1 = ntp.TimeFromTime64(c.prev.sRxTime)
			t2 = sTxTime
			t3 = ntp.TimeFromTime64(c.prev.cRxTime)
		} else {
			t0 = cTxTime1
			t1 = sRxTime
			t2 = sTxTime
			t3 = cRxTime
		}

		err = ntp.ValidateResponseTimestamps(t0, t1, t1, t3)
		if err != nil {
			return offset, weight, err
		}

		off := ntp.ClockOffset(t0, t1, t2, t3)
		rtd := ntp.RoundTripDelay(t0, t1, t2, t3)

		mtrcs.respsAccepted.Inc()
		if interleaved {
			mtrcs.respsAcceptedInterleaved.Inc()
		}
		log.Debug("evaluated response",
			zap.String("from", reference),
			zap.Bool("interleaved", interleaved),
			zap.Duration("clock offset", off),
			zap.Duration("round trip delay", rtd),
		)

		if c.InterleavedMode {
			c.prev.reference = reference
			c.prev.cTxTime = ntp.Time64FromTime(cTxTime1)
			c.prev.cRxTime = ntp.Time64FromTime(cRxTime)
			c.prev.sRxTime = ntpresp.ReceiveTime
		}

		// offset, weight = off, 1000.0

		offset, weight = filter(log, reference, t0, t1, t2, t3)
		break
	}

	return offset, weight, nil
}
