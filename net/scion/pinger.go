package scion

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"

	"example.com/scion-time/core/timebase"
	"example.com/scion-time/net/ip"
	"example.com/scion-time/net/udp"
)

var (
	errWrite            = errors.New("failed to write packet")
	errUnexpectedPacket = errors.New("unexpected packet")
)

func SendPing(ctx context.Context, localAddr, remoteAddr udp.UDPAddr, path snet.Path) (
	time.Duration, error) {
	laddr, ok := netip.AddrFromSlice(localAddr.Host.IP)
	if !ok {
		panic(errUnexpectedAddrType)
	}
	var lc net.ListenConfig
	pconn, err := lc.ListenPacket(ctx, "udp", netip.AddrPortFrom(laddr, 0).String())
	if err != nil {
		return 0, err
	}
	conn := pconn.(*net.UDPConn)
	defer func() { _ = conn.Close() }()
	deadline, deadlineIsSet := ctx.Deadline()
	if deadlineIsSet {
		err = conn.SetDeadline(deadline)
		if err != nil {
			return 0, err
		}
	}

	localPort := conn.LocalAddr().(*net.UDPAddr).Port

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

	var scionLayer slayers.SCION
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
	scionLayer.NextHdr = slayers.L4SCMP

	var scmpLayer slayers.SCMP
	scmpLayer.TypeCode = slayers.CreateSCMPTypeCode(
		slayers.SCMPTypeEchoRequest, 0 /* code */)
	scmpLayer.SetNetworkLayerForChecksum(&scionLayer)

	var scmpEchoLayer slayers.SCMPEcho
	scmpEchoLayer.Identifier = uint16(localPort)
	scmpEchoLayer.SeqNumber = 0

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err = scmpEchoLayer.SerializeTo(buffer, options)
	if err != nil {
		panic(err)
	}
	buffer.PushLayer(scmpEchoLayer.LayerType())

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

	txTime := timebase.Now()
	n, err := conn.WriteToUDPAddrPort(buffer.Bytes(), nextHop)
	if err != nil {
		return 0, err
	}
	if n != len(buffer.Bytes()) {
		return 0, errWrite
	}

	const maxNumRetries = 1
	numRetries := 0
	buf := make([]byte, MTU)
	for {
		buf = buf[:cap(buf)]
		n, _, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				numRetries++
				continue
			}
			return 0, err
		}
		buf = buf[:n]
		rxTime := timebase.Now()

		var (
			hbhLayer slayers.HopByHopExtnSkipper
			e2eLayer slayers.EndToEndExtn
		)
		parser := gopacket.NewDecodingLayerParser(
			slayers.LayerTypeSCION, &scionLayer, &hbhLayer, &e2eLayer, &scmpLayer,
		)
		parser.IgnoreUnsupported = true
		decoded := make([]gopacket.LayerType, 4)
		err = parser.DecodeLayers(buf, &decoded)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				numRetries++
				continue
			}
			return 0, err
		}

		validType := len(decoded) >= 2 && decoded[len(decoded)-1] == slayers.LayerTypeSCMP
		if !validType {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				numRetries++
				continue
			}
			return 0, errUnexpectedPacket
		}

		if scmpLayer.TypeCode.Type() != slayers.SCMPTypeEchoReply {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				numRetries++
				continue
			}
			return 0, errUnexpectedPacket
		}

		var scmpEcho slayers.SCMPEcho
		err = scmpEcho.DecodeFromBytes(scmpLayer.Payload, gopacket.NilDecodeFeedback)
		if err != nil {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				numRetries++
				continue
			}
			return 0, errUnexpectedPacket
		}

		if scmpEcho.Identifier != uint16(localPort) || scmpEcho.SeqNumber != 0 {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				numRetries++
				continue
			}
			return 0, errUnexpectedPacket
		}

		validSrc := scionLayer.SrcIA == remoteAddr.IA &&
			ip.CompareIPs(scionLayer.RawSrcAddr, remoteAddr.Host.IP) == 0
		if !validSrc {
			if numRetries != maxNumRetries && deadlineIsSet && timebase.Now().Before(deadline) {
				numRetries++
				continue
			}
			return 0, errUnexpectedPacket
		}

		rtt := rxTime.Sub(txTime)
		return rtt, nil
	}
}
