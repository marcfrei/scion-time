package scion

import (
	"bytes"

	"github.com/gopacket/gopacket"

	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"

	"example.com/scion-time/net/ip"
	"example.com/scion-time/net/udp"
)

func MatchUDP(localAddr, remoteAddr udp.UDPAddr, p snet.Path) udp.UDPMuxMatcher {
	localAddr = localAddr.Clone()
	remoteAddr = remoteAddr.Clone()
	pathType, reversedHopFields := reversedHopFields(p)

	var (
		scionLayer slayers.SCION
		hbhLayer   slayers.HopByHopExtnSkipper
		e2eLayer   slayers.EndToEndExtnSkipper
		udpLayer   slayers.UDP
		decoded    []gopacket.LayerType
	)
	scionLayer.RecyclePaths()
	parser := gopacket.NewDecodingLayerParser(
		slayers.LayerTypeSCION, &scionLayer, &hbhLayer, &e2eLayer, &udpLayer,
	)
	parser.IgnoreUnsupported = true

	return func(pkt udp.UDPMuxPacket) bool {
		if err := parser.DecodeLayers(pkt.Data, &decoded); err != nil ||
			len(decoded) < 2 || decoded[len(decoded)-1] != slayers.LayerTypeSCIONUDP {
			return false
		}
		if scionLayer.SrcIA != remoteAddr.IA ||
			ip.CompareIPs(scionLayer.RawSrcAddr, remoteAddr.Host.IP) != 0 ||
			scionLayer.DstIA != localAddr.IA ||
			ip.CompareIPs(scionLayer.RawDstAddr, localAddr.Host.IP) != 0 {
			return false
		}
		if udpLayer.SrcPort != uint16(remoteAddr.Host.Port) ||
			udpLayer.DstPort != uint16(localAddr.Host.Port) {
			return false
		}
		return matchHopFields(scionLayer.Path, pathType, reversedHopFields)
	}
}

func reversedHopFields(p snet.Path) (path.Type, []byte) {
	var scionLayer slayers.SCION
	if err := p.Dataplane().SetPath(&scionLayer); err != nil {
		panic(err)
	}
	pathType := scionLayer.Path.Type()
	if pathType == empty.PathType {
		return pathType, nil
	}
	if pathType != scion.PathType {
		panic("unsupported SCION path type: " + pathType.String())
	}
	raw, ok := scionLayer.Path.(*scion.Raw)
	if !ok {
		panic("unexpected SCION dataplane path representation")
	}
	hf, ok := hopFieldBytes(raw.Raw, raw.NumINF, raw.NumHops)
	if !ok {
		panic("invalid SCION dataplane path")
	}
	reversed := make([]byte, len(hf))
	for i := range raw.NumHops {
		src := hf[i*path.HopLen : (i+1)*path.HopLen]
		dst := reversed[(raw.NumHops-1-i)*path.HopLen : (raw.NumHops-i)*path.HopLen]
		copy(dst, src)
	}
	return pathType, reversed
}

func matchHopFields(p path.Path, pathType path.Type, hopFields []byte) bool {
	if p.Type() != pathType {
		return false
	}
	if pathType == empty.PathType {
		return true
	}
	if pathType != scion.PathType {
		return false
	}
	raw, ok := p.(*scion.Raw)
	if !ok {
		return false
	}
	hf, ok := hopFieldBytes(raw.Raw, raw.NumINF, raw.NumHops)
	if !ok {
		return false
	}
	return equalHopFields(hf, hopFields)
}

func hopFieldBytes(raw []byte, numINF, numHops int) ([]byte, bool) {
	start := scion.MetaLen + numINF*path.InfoLen
	end := start + numHops*path.HopLen
	if start < 0 || end < start || end > len(raw) {
		return nil, false
	}
	return raw[start:end], true
}

func equalHopFields(a, b []byte) bool {
	if len(a) != len(b) || len(a)%path.HopLen != 0 {
		return false
	}
	const routerAlertMask = 0x03
	for len(a) != 0 {
		if a[0]&^routerAlertMask != b[0]&^routerAlertMask ||
			!bytes.Equal(a[1:path.HopLen], b[1:path.HopLen]) {
			return false
		}
		a = a[path.HopLen:]
		b = b[path.HopLen:]
	}
	return true
}
