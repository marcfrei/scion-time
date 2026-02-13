package client

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
	"github.com/gopacket/gopacket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/spao"

	spath "github.com/scionproto/scion/pkg/snet/path"

	"example.com/scion-time/base/metrics"

	"example.com/scion-time/core/measurements"
	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ip"
	"example.com/scion-time/net/ntp"
	"example.com/scion-time/net/nts"
	"example.com/scion-time/net/ntske"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

type SCIONClient struct {
	Log             *slog.Logger
	DSCP            uint8
	InterleavedMode bool
	Auth            struct {
		Enabled      bool
		NTSEnabled   bool
		DRKeyFetcher *scion.Fetcher
		opt          *slayers.EndToEndOption
		buf          []byte
		mac          []byte
		NTSKEFetcher ntske.Fetcher
	}
	Filter    measurements.Filter
	Histogram *hdrhistogram.Histogram
	prev      struct {
		reference   string
		path        string
		interleaved bool
		cTxTime     ntp.Time64
		cRxTime     ntp.Time64
		sRxTime     ntp.Time64
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

func (c *SCIONClient) InInterleavedMode() bool {
	return c.InterleavedMode && c.prev.reference != "" && c.prev.interleaved
}

func (c *SCIONClient) InterleavedModeReference() string {
	if !c.InInterleavedMode() {
		panic("undefined value, not in interleaved mode")
	}
	return c.prev.reference
}

func (c *SCIONClient) InterleavedModePath() string {
	if !c.InInterleavedMode() {
		panic("undefined value, not in interleaved mode")
	}
	return c.prev.path
}

func (c *SCIONClient) ResetInterleavedMode() {
	c.prev.reference = ""
}

func (c *SCIONClient) measureClockOffsetSCION(ctx context.Context, mtrcs *scionClientMetrics,
	localAddr, remoteAddr udp.UDPAddr, path snet.Path) (
	timestamp time.Time, offset time.Duration, err error) {
	if c.Auth.Enabled && c.Auth.opt == nil {
		c.Auth.opt = &slayers.EndToEndOption{}
		c.Auth.opt.OptData = make([]byte, scion.PacketAuthOptDataLen)
		c.Auth.buf = make([]byte, spao.MACBufferSize)
		c.Auth.mac = make([]byte, scion.PacketAuthMACLen)
	}

	laddr, ok := netip.AddrFromSlice(localAddr.Host.IP)
	if !ok {
		panic(errUnexpectedAddrType)
	}
	var lc net.ListenConfig
	pconn, err := lc.ListenPacket(ctx, "udp", netip.AddrPortFrom(laddr, 0).String())
	if err != nil {
		return time.Time{}, 0, err
	}
	conn := pconn.(*net.UDPConn)
	defer func() { _ = conn.Close() }()
	deadline, deadlineIsSet := ctx.Deadline()
	if deadlineIsSet {
		err = conn.SetDeadline(deadline)
		if err != nil {
			return time.Time{}, 0, err
		}
	}
	err = udp.EnableTimestamping(conn, localAddr.Host.Zone, -1 /* index */)
	if err != nil {
		c.Log.LogAttrs(ctx, slog.LevelError, "failed to enable timestamping", slog.Any("error", err))
	}
	err = udp.SetDSCP(conn, c.DSCP)
	if err != nil {
		c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to set DSCP", slog.Any("error", err))
	}

	localPort := conn.LocalAddr().(*net.UDPAddr).Port

	var ntskeData ntske.Data
	if c.Auth.NTSEnabled {
		ntskeData, err = c.Auth.NTSKEFetcher.FetchData(ctx)
		if err != nil {
			c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to fetch key exchange data", slog.Any("error", err))
			return time.Time{}, 0, err
		}
		remoteAddr.Host.IP = net.ParseIP(ntskeData.Server)
		remoteAddr.Host.Port = int(ntskeData.Port)
		if remoteAddr.IA == localAddr.IA {
			path = spath.Path{
				Src:           localAddr.IA,
				Dst:           remoteAddr.IA,
				DataplanePath: spath.Empty{},
				NextHop:       remoteAddr.Host,
			}
		}
	}
	ip4 := remoteAddr.Host.IP.To4()
	if ip4 != nil {
		remoteAddr.Host.IP = ip4
	}

	nextHop := path.UnderlayNextHop().AddrPort()
	nextHopAddr := nextHop.Addr()
	if nextHopAddr.Is4In6() {
		nextHop = netip.AddrPortFrom(
			netip.AddrFrom4(nextHopAddr.As4()),
			nextHop.Port())
	}

	reference := remoteAddr.IA.String() + "," + remoteAddr.Host.String()

	var txid uint32
	buf := make([]byte, scion.MTU)
	oob := make([]byte, udp.TimestampLen())
	for {
		cTxTime0 := timebase.Now()
		interleavedReq := false

		ntpreq := ntp.Packet{}
		ntpreq.SetVersion(ntp.VersionMax)
		ntpreq.SetMode(ntp.ModeClient)
		if c.InterleavedMode && reference == c.prev.reference &&
			cTxTime0.Sub(ntp.TimeFromTime64(c.prev.cTxTime, cTxTime0)) < 3*time.Second {
			interleavedReq = true
			ntpreq.OriginTime = c.prev.sRxTime
			ntpreq.ReceiveTime = c.prev.cRxTime
			ntpreq.TransmitTime = c.prev.cTxTime
		} else {
			ntpreq.TransmitTime = ntp.Time64FromTime(cTxTime0)
		}
		ntp.EncodePacket(&buf, &ntpreq)

		var requestID []byte
		var ntsreq nts.Packet
		if c.Auth.NTSEnabled {
			ntsreq, requestID = nts.NewRequestPacket(ntskeData)
			nts.EncodePacket(&buf, &ntsreq)
		}

		var scionLayer slayers.SCION
		scionLayer.TrafficClass = c.DSCP << 2
		scionLayer.SrcIA = localAddr.IA
		srcAddrIP, ok := netip.AddrFromSlice(localAddr.Host.IP)
		if !ok {
			panic(errUnexpectedAddrType)
		}
		err = scionLayer.SetSrcAddr(addr.HostIP(srcAddrIP.Unmap()))
		if err != nil {
			panic(err)
		}
		scionLayer.DstIA = remoteAddr.IA
		dstAddrIP, ok := netip.AddrFromSlice(remoteAddr.Host.IP)
		if !ok {
			panic(errUnexpectedAddrType)
		}
		err = scionLayer.SetDstAddr(addr.HostIP(dstAddrIP.Unmap()))
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

		var authKey []byte
		if c.Auth.Enabled {
			hostHostKey, err := c.Auth.DRKeyFetcher.FetchHostHostKey(ctx, drkey.HostHostMeta{
				ProtoId:  scion.DRKeyProtocolTS,
				Validity: cTxTime0,
				SrcIA:    remoteAddr.IA,
				DstIA:    localAddr.IA,
				SrcHost:  remoteAddr.Host.IP.String(),
				DstHost:  localAddr.Host.IP.String(),
			})
			if err != nil {
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to fetch DRKey level 3: host-host key", slog.Any("error", err))
			} else {
				authKey = hostHostKey.Key[:]

				scion.PreparePacketAuthOpt(c.Auth.opt, scion.PacketAuthSPIClient, scion.PacketAuthAlgorithm)
				_, err = spao.ComputeAuthCMAC(
					spao.MACInput{
						Key:        authKey,
						Header:     slayers.PacketAuthOption{EndToEndOption: c.Auth.opt},
						ScionLayer: &scionLayer,
						PldType:    scionLayer.NextHdr,
						Pld:        buffer.Bytes(),
					},
					c.Auth.buf,
					scion.PacketAuthOptMAC(c.Auth.opt),
				)
				if err != nil {
					panic(err)
				}

				e2eExtn := slayers.EndToEndExtn{}
				e2eExtn.NextHdr = scionLayer.NextHdr
				e2eExtn.Options = []*slayers.EndToEndOption{c.Auth.opt}

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
			return time.Time{}, 0, err
		}
		if n != len(buffer.Bytes()) {
			return time.Time{}, 0, errWrite
		}
		cTxTime1, id, err := udp.ReadTXTimestamp(conn, txid)
		if err != nil {
			cTxTime1 = cTxTime0
			c.Log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
				slog.Any("error", err))
		} else if id != txid {
			cTxTime1 = cTxTime0
			c.Log.LogAttrs(ctx, slog.LevelError, "failed to read packet tx timestamp",
				slog.Uint64("id", uint64(id)), slog.Uint64("expected", uint64(txid)))
			txid = id + 1
		} else {
			txid++
		}
		mtrcs.reqsSent.Inc()
		if interleavedReq {
			mtrcs.reqsSentInterleaved.Inc()
		}

		const maxNumRetries = 1
		numRetries := 0
		for {
			buf = buf[:cap(buf)]
			oob = oob[:cap(oob)]
			n, oobn, flags, lastHop, err := conn.ReadMsgUDPAddrPort(buf, oob)
			if err != nil {
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet", slog.Any("error", err))
					numRetries++
					continue
				}
				return time.Time{}, 0, err
			}
			if flags != 0 {
				err = errUnexpectedPacketFlags
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to read packet", slog.Int("flags", flags))
					numRetries++
					continue
				}
				return time.Time{}, 0, err
			}
			oob = oob[:oobn]
			cRxTime, err := udp.TimestampFromOOBData(oob)
			if err != nil {
				cRxTime = timebase.Now()
				c.Log.LogAttrs(ctx, slog.LevelError, "failed to read packet rx timestamp", slog.Any("error", err))
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
					c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet", slog.Any("error", err))
					numRetries++
					continue
				}
				return time.Time{}, 0, err
			}
			validType := len(decoded) >= 2 && (decoded[len(decoded)-1] == slayers.LayerTypeSCIONUDP ||
				decoded[len(decoded)-1] == slayers.LayerTypeSCMP)
			if !validType {
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet", slog.String("cause", "unexpected type or structure"))
					numRetries++
					continue
				}
				return time.Time{}, 0, err
			}
			if decoded[len(decoded)-1] == slayers.LayerTypeSCMP {
				err = errUnexpectedPacket
				c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to handle packet",
					slog.String("cause", "unexpected SCMP message type"),
					slog.Uint64("type", uint64(scmpLayer.TypeCode.Type())),
					slog.Uint64("code", uint64(scmpLayer.TypeCode.Code())))
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					numRetries++
					continue
				}
				return time.Time{}, 0, err
			}
			if len(buf) < int(udpLayer.Length) {
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received packet with unexpected type or structure")
					numRetries++
					continue
				}
				return time.Time{}, 0, err
			}
			validSrc := scionLayer.SrcIA == remoteAddr.IA &&
				ip.CompareIPs(scionLayer.RawSrcAddr, remoteAddr.Host.IP) == 0
			validDst := scionLayer.DstIA == localAddr.IA &&
				ip.CompareIPs(scionLayer.RawDstAddr, localAddr.Host.IP) == 0
			if !validSrc || !validDst {
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					if !validSrc {
						c.Log.LogAttrs(ctx, slog.LevelInfo, "received packet from unexpected source")
					}
					if !validDst {
						c.Log.LogAttrs(ctx, slog.LevelInfo, "received packet to unexpected destination")
					}
					numRetries++
					continue
				}
				return time.Time{}, 0, err
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
						spi, algo := scion.PacketAuthOptMetadata(authOpt)
						if spi == scion.PacketAuthSPIServer && algo == scion.PacketAuthAlgorithm {
							_, err = spao.ComputeAuthCMAC(
								spao.MACInput{
									Key:        authKey,
									Header:     slayers.PacketAuthOption{EndToEndOption: authOpt},
									ScionLayer: &scionLayer,
									PldType:    slayers.L4UDP,
									Pld:        buf[len(buf)-int(udpLayer.Length):],
								},
								c.Auth.buf,
								c.Auth.mac,
							)
							if err != nil {
								panic(err)
							}
							authenticated = subtle.ConstantTimeCompare(scion.PacketAuthOptMAC(authOpt), c.Auth.mac) != 0
							if !authenticated {
								err = errInvalidPacketAuthenticator
								if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
									c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to authenticate packet", slog.Any("error", err))
									numRetries++
									continue
								}
								return time.Time{}, 0, err
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
					c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode packet payload", slog.Any("error", err))
					numRetries++
					continue
				}
				return time.Time{}, 0, err
			}

			ntsAuthenticated := false
			var ntsresp nts.Packet
			if c.Auth.NTSEnabled {
				err = nts.DecodePacket(&ntsresp, udpLayer.Payload)
				if err != nil {
					if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
						c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to decode NTS packet", slog.Any("error", err))
						numRetries++
						continue
					}
					return time.Time{}, 0, err
				}

				err = nts.ProcessResponse(udpLayer.Payload, ntskeData.S2cKey, &c.Auth.NTSKEFetcher, &ntsresp, requestID)
				if err != nil {
					if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
						c.Log.LogAttrs(ctx, slog.LevelInfo, "failed to process NTS packet", slog.Any("error", err))
						numRetries++
						continue
					}
					return time.Time{}, 0, err
				}
				ntsAuthenticated = true
			}

			interleavedResp := false
			if interleavedReq && ntpresp.OriginTime == ntpreq.ReceiveTime {
				interleavedResp = true
			} else if ntpresp.OriginTime != ntpreq.TransmitTime {
				err = errUnexpectedPacket
				if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
					c.Log.LogAttrs(ctx, slog.LevelInfo, "received packet with unexpected type or structure")
					numRetries++
					continue
				}
				return time.Time{}, 0, err
			}

			err = ntp.ValidateResponseMetadata(&ntpresp)
			if err != nil {
				return time.Time{}, 0, err
			}

			dscp := scionLayer.TrafficClass >> 2

			c.Log.LogAttrs(ctx, slog.LevelDebug, "received response",
				slog.Time("at", cRxTime),
				slog.String("from", reference),
				slog.Any("via", lastHop),
				slog.Uint64("DSCP", uint64(dscp)),
				slog.Bool("auth", authenticated),
				slog.Bool("ntsauth", ntsAuthenticated),
				slog.Any("data", ntp.PacketLogValuer{Pkt: &ntpresp}),
			)

			sRxTime := ntp.TimeFromTime64(ntpresp.ReceiveTime, cTxTime0)
			sTxTime := ntp.TimeFromTime64(ntpresp.TransmitTime, cTxTime0)

			var t0, t1, t2, t3 time.Time
			if interleavedResp {
				t0 = ntp.TimeFromTime64(c.prev.cTxTime, cTxTime0)
				t1 = ntp.TimeFromTime64(c.prev.sRxTime, cTxTime0)
				t2 = sTxTime
				t3 = ntp.TimeFromTime64(c.prev.cRxTime, cTxTime0)
			} else {
				t0 = cTxTime1
				t1 = sRxTime
				t2 = sTxTime
				t3 = cRxTime
			}

			err = ntp.ValidateResponseTimestamps(t0, t1, t2, t3)
			if err != nil {
				return time.Time{}, 0, err
			}

			off := ntp.ClockOffset(t0, t1, t2, t3)
			rtd := ntp.RoundTripDelay(t0, t1, t2, t3)

			mtrcs.respsAccepted.Inc()
			if interleavedResp {
				mtrcs.respsAcceptedInterleaved.Inc()
			}
			c.Log.LogAttrs(ctx, slog.LevelDebug, "evaluated response",
				slog.Time("at", cRxTime),
				slog.String("from", reference),
				slog.String("via", path.Metadata().Fingerprint().String()),
				slog.Bool("interleaved", interleavedResp),
				slog.Duration("clock offset", off),
				slog.Duration("round trip delay", rtd),
			)

			if c.InterleavedMode {
				c.prev.reference = reference
				c.prev.path = path.Metadata().Fingerprint().String()
				c.prev.interleaved = interleavedResp
				c.prev.cTxTime = ntp.Time64FromTime(cTxTime1)
				c.prev.cRxTime = ntp.Time64FromTime(cRxTime)
				c.prev.sRxTime = ntpresp.ReceiveTime
			}

			if c.Histogram != nil {
				err := c.Histogram.RecordValue(rtd.Microseconds())
				if err != nil {
					return time.Time{}, 0, err
				}
			}

			if c.Filter != nil {
				off, ok = c.Filter.Do(t0, t1, t2, t3)
				if !ok {
					break
				}
			}

			return cRxTime, off, nil
		}
	}
}
