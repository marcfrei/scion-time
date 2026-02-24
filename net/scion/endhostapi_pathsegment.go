//go:build !ehapi_googleproto

package scion

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/VictoriaMetrics/easyproto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/extensions/digest"
	"github.com/scionproto/scion/pkg/segment/extensions/discovery"
	"github.com/scionproto/scion/pkg/segment/extensions/epic"
	"github.com/scionproto/scion/pkg/segment/extensions/staticinfo"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/slayers/path"
)

func decodePathSegment(raw []byte) (*segment.PathSegment, error) {
	var (
		infoRaw   []byte
		asEntries []segment.ASEntry
		fc        easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return nil, err
		}
		switch fc.FieldNum {
		case 1:
			v, ok := fc.Bytes()
			if !ok {
				return nil, fmt.Errorf("invalid PathSegment.segment_info field")
			}
			infoRaw = v
		case 2:
			v, ok := fc.MessageData()
			if !ok {
				return nil, fmt.Errorf("invalid PathSegment.as_entries field")
			}
			asEntry, err := decodeASEntry(v)
			if err != nil {
				return nil, fmt.Errorf("parsing AS entry: %w", err)
			}
			asEntries = append(asEntries, asEntry)
		}
	}

	info, err := decodeSegmentInfo(infoRaw)
	if err != nil {
		return nil, fmt.Errorf("parsing segment info: %w", err)
	}
	seg := &segment.PathSegment{
		Info:      info,
		ASEntries: asEntries,
	}
	if err := seg.Validate(segment.ValidateSegment); err != nil {
		return nil, err
	}
	return seg, nil
}

func decodeSegmentInfo(raw []byte) (segment.Info, error) {
	if len(raw) == 0 {
		return segment.Info{}, errors.New("empty segment info")
	}
	rawCopy := cloneBytes(raw)
	var (
		timestamp int64
		segmentID uint32
		fc        easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return segment.Info{}, err
		}
		switch fc.FieldNum {
		case 1:
			if v, ok := fc.Int64(); ok {
				timestamp = v
			}
		case 2:
			if v, ok := fc.Uint32(); ok {
				segmentID = v
			}
		}
	}
	if segmentID > math.MaxUint16 {
		return segment.Info{}, fmt.Errorf("segment ID overflows uint16: %d", segmentID)
	}
	return segment.Info{
		Raw:       rawCopy,
		Timestamp: time.Unix(timestamp, 0),
		SegmentID: uint16(segmentID),
	}, nil
}

type decodedASEntryBody struct {
	local       addr.IA
	next        addr.IA
	mtu         int
	hopEntry    segment.HopEntry
	peerEntries []segment.PeerEntry
	extensions  segment.Extensions
}

func decodeASEntry(raw []byte) (segment.ASEntry, error) {
	var (
		signedRaw   []byte
		unsignedRaw []byte
		fc          easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return segment.ASEntry{}, err
		}
		switch fc.FieldNum {
		case 1:
			v, ok := fc.MessageData()
			if !ok {
				return segment.ASEntry{}, fmt.Errorf("invalid ASEntry.signed field")
			}
			signedRaw = v
		case 2:
			v, ok := fc.MessageData()
			if !ok {
				return segment.ASEntry{}, fmt.Errorf("invalid ASEntry.unsigned field")
			}
			unsignedRaw = v
		}
	}

	signedMsg, signedBody, err := decodeSignedMessage(signedRaw)
	if err != nil {
		return segment.ASEntry{}, err
	}
	body, err := decodeASEntrySignedBody(signedBody)
	if err != nil {
		return segment.ASEntry{}, err
	}
	unsigned, err := decodeUnsignedExtensions(unsignedRaw)
	if err != nil {
		return segment.ASEntry{}, err
	}

	return segment.ASEntry{
		Signed:             signedMsg,
		Local:              body.local,
		Next:               body.next,
		HopEntry:           body.hopEntry,
		PeerEntries:        body.peerEntries,
		MTU:                body.mtu,
		Extensions:         body.extensions,
		UnsignedExtensions: unsigned,
	}, nil
}

func decodeSignedMessage(raw []byte) (*crypto.SignedMessage, []byte, error) {
	if len(raw) == 0 {
		return nil, nil, errors.New("missing signed message")
	}
	var (
		headerAndBody []byte
		signature     []byte
		fc            easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return nil, nil, err
		}
		switch fc.FieldNum {
		case 1:
			v, ok := fc.Bytes()
			if !ok {
				return nil, nil, fmt.Errorf("invalid SignedMessage.header_and_body field")
			}
			headerAndBody = v
		case 2:
			v, ok := fc.Bytes()
			if !ok {
				return nil, nil, fmt.Errorf("invalid SignedMessage.signature field")
			}
			signature = v
		}
	}
	if len(headerAndBody) == 0 {
		return nil, nil, errors.New("missing SignedMessage.header_and_body")
	}
	body, err := decodeHeaderAndBodyInternalBody(headerAndBody)
	if err != nil {
		return nil, nil, err
	}
	return &crypto.SignedMessage{
		HeaderAndBody: cloneBytes(headerAndBody),
		Signature:     cloneBytes(signature),
	}, body, nil
}

func decodeHeaderAndBodyInternalBody(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty HeaderAndBodyInternal message")
	}
	var (
		body []byte
		fc   easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return nil, err
		}
		if fc.FieldNum != 2 {
			continue
		}
		v, ok := fc.Bytes()
		if !ok {
			return nil, fmt.Errorf("invalid HeaderAndBodyInternal.body field")
		}
		body = v
	}
	return cloneBytes(body), nil
}

func decodeASEntrySignedBody(raw []byte) (decodedASEntryBody, error) {
	var (
		localRaw      uint64
		nextRaw       uint64
		mtuRaw        uint32
		hopEntryRaw   []byte
		peerEntries   []segment.PeerEntry
		extensionsRaw []byte
		fc            easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return decodedASEntryBody{}, err
		}
		switch fc.FieldNum {
		case 1:
			if v, ok := fc.Uint64(); ok {
				localRaw = v
			}
		case 2:
			if v, ok := fc.Uint64(); ok {
				nextRaw = v
			}
		case 3:
			v, ok := fc.MessageData()
			if !ok {
				return decodedASEntryBody{}, fmt.Errorf("invalid ASEntrySignedBody.hop_entry field")
			}
			hopEntryRaw = v
		case 4:
			v, ok := fc.MessageData()
			if !ok {
				return decodedASEntryBody{}, fmt.Errorf("invalid ASEntrySignedBody.peer_entries field")
			}
			peerEntry, err := decodePeerEntry(v)
			if err != nil {
				return decodedASEntryBody{}, fmt.Errorf("parsing peer entry: %w", err)
			}
			peerEntries = append(peerEntries, peerEntry)
		case 5:
			if v, ok := fc.Uint32(); ok {
				mtuRaw = v
			}
		case 6:
			v, ok := fc.MessageData()
			if !ok {
				return decodedASEntryBody{}, fmt.Errorf("invalid ASEntrySignedBody.extensions field")
			}
			extensionsRaw = v
		}
	}

	local := addr.IA(localRaw)
	if local.IsWildcard() {
		return decodedASEntryBody{}, fmt.Errorf("wildcard local ISD-AS: %s", local)
	}
	if mtuRaw > math.MaxInt32 {
		return decodedASEntryBody{}, fmt.Errorf("MTU too big: %d", mtuRaw)
	}

	hopEntry, err := decodeHopEntry(hopEntryRaw)
	if err != nil {
		return decodedASEntryBody{}, fmt.Errorf("parsing hop entry: %w", err)
	}

	extensions, err := decodePathSegmentExtensions(extensionsRaw)
	if err != nil {
		return decodedASEntryBody{}, err
	}

	return decodedASEntryBody{
		local:       local,
		next:        addr.IA(nextRaw),
		mtu:         int(mtuRaw),
		hopEntry:    hopEntry,
		peerEntries: peerEntries,
		extensions:  extensions,
	}, nil
}

func decodeHopEntry(raw []byte) (segment.HopEntry, error) {
	if len(raw) == 0 {
		return segment.HopEntry{}, errors.New("nil hop entry")
	}
	var (
		hopFieldRaw []byte
		ingressMTU  uint32
		fc          easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return segment.HopEntry{}, err
		}
		switch fc.FieldNum {
		case 1:
			v, ok := fc.MessageData()
			if !ok {
				return segment.HopEntry{}, fmt.Errorf("invalid HopEntry.hop_field field")
			}
			hopFieldRaw = v
		case 2:
			if v, ok := fc.Uint32(); ok {
				ingressMTU = v
			}
		}
	}
	if hopFieldRaw == nil {
		return segment.HopEntry{}, errors.New("hop field is nil")
	}
	if ingressMTU > math.MaxInt32 {
		return segment.HopEntry{}, fmt.Errorf("MTU too big: %d", ingressMTU)
	}
	hopField, err := decodeHopField(hopFieldRaw)
	if err != nil {
		return segment.HopEntry{}, err
	}
	return segment.HopEntry{
		HopField:   hopField,
		IngressMTU: int(ingressMTU),
	}, nil
}

func decodePeerEntry(raw []byte) (segment.PeerEntry, error) {
	var (
		peerISDAS     uint64
		peerInterface uint64
		peerMTU       uint32
		hopFieldRaw   []byte
		fc            easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return segment.PeerEntry{}, err
		}
		switch fc.FieldNum {
		case 1:
			if v, ok := fc.Uint64(); ok {
				peerISDAS = v
			}
		case 2:
			if v, ok := fc.Uint64(); ok {
				peerInterface = v
			}
		case 3:
			if v, ok := fc.Uint32(); ok {
				peerMTU = v
			}
		case 4:
			v, ok := fc.MessageData()
			if !ok {
				return segment.PeerEntry{}, fmt.Errorf("invalid PeerEntry.hop_field field")
			}
			hopFieldRaw = v
		}
	}
	if hopFieldRaw == nil {
		return segment.PeerEntry{}, errors.New("hop field is nil")
	}
	peer := addr.IA(peerISDAS)
	if peer.IsWildcard() {
		return segment.PeerEntry{}, fmt.Errorf("wildcard peer: %s", peer)
	}
	if peerInterface > math.MaxUint16 {
		return segment.PeerEntry{}, fmt.Errorf("peer interface exceeds 65535: %d", peerInterface)
	}
	if peerMTU > math.MaxInt32 {
		return segment.PeerEntry{}, fmt.Errorf("MTU too big: %d", peerMTU)
	}
	hopField, err := decodeHopField(hopFieldRaw)
	if err != nil {
		return segment.PeerEntry{}, err
	}
	return segment.PeerEntry{
		Peer:          peer,
		PeerInterface: uint16(peerInterface),
		PeerMTU:       int(peerMTU),
		HopField:      hopField,
	}, nil
}

func decodeHopField(raw []byte) (segment.HopField, error) {
	var (
		ingress uint64
		egress  uint64
		expTime uint32
		mac     []byte
		fc      easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return segment.HopField{}, err
		}
		switch fc.FieldNum {
		case 1:
			if v, ok := fc.Uint64(); ok {
				ingress = v
			}
		case 2:
			if v, ok := fc.Uint64(); ok {
				egress = v
			}
		case 3:
			if v, ok := fc.Uint32(); ok {
				expTime = v
			}
		case 4:
			v, ok := fc.Bytes()
			if !ok {
				return segment.HopField{}, fmt.Errorf("invalid HopField.mac field")
			}
			mac = v
		}
	}
	if ingress > math.MaxUint16 {
		return segment.HopField{}, fmt.Errorf("ingress exceeds 65535: %d", ingress)
	}
	if egress > math.MaxUint16 {
		return segment.HopField{}, fmt.Errorf("egress exceeds 65535: %d", egress)
	}
	if expTime > math.MaxUint8 {
		return segment.HopField{}, fmt.Errorf("exp_time exceeds 255: %d", expTime)
	}
	if len(mac) != path.MacLen {
		return segment.HopField{}, fmt.Errorf("MAC must be %d bytes, got %d", path.MacLen, len(mac))
	}
	hopMAC := [path.MacLen]byte{}
	copy(hopMAC[:], mac)
	return segment.HopField{
		ConsIngress: uint16(ingress),
		ConsEgress:  uint16(egress),
		ExpTime:     uint8(expTime),
		MAC:         hopMAC,
	}, nil
}

func decodePathSegmentExtensions(raw []byte) (segment.Extensions, error) {
	if len(raw) == 0 {
		return segment.Extensions{}, nil
	}
	var (
		ext          segment.Extensions
		staticRaw    []byte
		hiddenRaw    []byte
		discoveryRaw []byte
		digestRaw    []byte
		fc           easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return segment.Extensions{}, err
		}
		switch fc.FieldNum {
		case 1:
			v, ok := fc.MessageData()
			if !ok {
				return segment.Extensions{}, fmt.Errorf("invalid PathSegmentExtensions.static_info field")
			}
			staticRaw = v
		case 2:
			v, ok := fc.MessageData()
			if !ok {
				return segment.Extensions{}, fmt.Errorf("invalid PathSegmentExtensions.hidden_path field")
			}
			hiddenRaw = v
		case 3:
			v, ok := fc.MessageData()
			if !ok {
				return segment.Extensions{}, fmt.Errorf("invalid PathSegmentExtensions.discovery field")
			}
			discoveryRaw = v
		case 1000:
			v, ok := fc.MessageData()
			if !ok {
				return segment.Extensions{}, fmt.Errorf("invalid PathSegmentExtensions.digests field")
			}
			digestRaw = v
		}
	}
	if hiddenRaw != nil {
		hidden, err := decodeHiddenPathExtension(hiddenRaw)
		if err != nil {
			return segment.Extensions{}, err
		}
		ext.HiddenPath = hidden
	}
	if staticRaw != nil {
		staticInfo, err := decodeStaticInfoExtension(staticRaw)
		if err != nil {
			return segment.Extensions{}, err
		}
		ext.StaticInfo = staticInfo
	}
	if discoveryRaw != nil {
		discoveryInfo, err := decodeDiscoveryExtension(discoveryRaw)
		if err != nil {
			return segment.Extensions{}, err
		}
		ext.Discovery = discoveryInfo
	}
	if digestRaw != nil {
		digests, err := decodeDigestExtension(digestRaw)
		if err != nil {
			return segment.Extensions{}, err
		}
		ext.Digests = digests
	}
	return ext, nil
}

func decodeHiddenPathExtension(raw []byte) (segment.HiddenPathExtension, error) {
	var (
		isHidden bool
		fc       easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return segment.HiddenPathExtension{}, err
		}
		if fc.FieldNum != 1 {
			continue
		}
		if v, ok := fc.Bool(); ok {
			isHidden = v
		}
	}
	return segment.HiddenPathExtension{IsHidden: isHidden}, nil
}

func decodeStaticInfoExtension(raw []byte) (*staticinfo.Extension, error) {
	ext := &staticinfo.Extension{}
	var (
		latencyRaw   []byte
		bandwidthRaw []byte
		note         string
		fc           easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return nil, err
		}
		switch fc.FieldNum {
		case 1:
			v, ok := fc.MessageData()
			if !ok {
				return nil, fmt.Errorf("invalid StaticInfoExtension.latency field")
			}
			latencyRaw = v
		case 2:
			v, ok := fc.MessageData()
			if !ok {
				return nil, fmt.Errorf("invalid StaticInfoExtension.bandwidth field")
			}
			bandwidthRaw = v
		case 3:
			v, ok := fc.MessageData()
			if !ok {
				return nil, fmt.Errorf("invalid StaticInfoExtension.geo field")
			}
			ifID, coords, err := decodeStaticInfoGeoEntry(v)
			if err != nil {
				return nil, err
			}
			if ext.Geo == nil {
				ext.Geo = make(staticinfo.GeoInfo)
			}
			ext.Geo[ifID] = coords
		case 4:
			v, ok := fc.MessageData()
			if !ok {
				return nil, fmt.Errorf("invalid StaticInfoExtension.link_type field")
			}
			ifID, linkType, ok, err := decodeStaticInfoLinkTypeEntry(v)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			if ext.LinkType == nil {
				ext.LinkType = make(staticinfo.LinkTypeInfo)
			}
			ext.LinkType[ifID] = linkType
		case 5:
			v, ok := fc.MessageData()
			if !ok {
				return nil, fmt.Errorf("invalid StaticInfoExtension.internal_hops field")
			}
			ifID, hops, err := decodeStaticInfoInternalHopsEntry(v)
			if err != nil {
				return nil, err
			}
			if ext.InternalHops == nil {
				ext.InternalHops = make(staticinfo.InternalHopsInfo)
			}
			ext.InternalHops[ifID] = hops
		case 6:
			if v, ok := fc.String(); ok {
				note = v
			}
		}
	}
	if latencyRaw != nil {
		latency, err := decodeLatencyInfo(latencyRaw)
		if err != nil {
			return nil, err
		}
		ext.Latency = latency
	}
	if bandwidthRaw != nil {
		bandwidth, err := decodeBandwidthInfo(bandwidthRaw)
		if err != nil {
			return nil, err
		}
		ext.Bandwidth = bandwidth
	}
	ext.Note = note
	return ext, nil
}

func decodeLatencyInfo(raw []byte) (staticinfo.LatencyInfo, error) {
	var (
		intra map[iface.ID]time.Duration
		inter map[iface.ID]time.Duration
		fc    easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return staticinfo.LatencyInfo{}, err
		}
		switch fc.FieldNum {
		case 1:
			entryRaw, ok := fc.MessageData()
			if !ok {
				return staticinfo.LatencyInfo{}, fmt.Errorf("invalid LatencyInfo.intra map entry")
			}
			ifID, latencyUS, err := decodeUint64Uint32MapEntry(entryRaw)
			if err != nil {
				return staticinfo.LatencyInfo{}, err
			}
			if intra == nil {
				intra = make(map[iface.ID]time.Duration)
			}
			intra[iface.ID(ifID)] = time.Duration(latencyUS) * time.Microsecond
		case 2:
			entryRaw, ok := fc.MessageData()
			if !ok {
				return staticinfo.LatencyInfo{}, fmt.Errorf("invalid LatencyInfo.inter map entry")
			}
			ifID, latencyUS, err := decodeUint64Uint32MapEntry(entryRaw)
			if err != nil {
				return staticinfo.LatencyInfo{}, err
			}
			if inter == nil {
				inter = make(map[iface.ID]time.Duration)
			}
			inter[iface.ID(ifID)] = time.Duration(latencyUS) * time.Microsecond
		}
	}
	return staticinfo.LatencyInfo{
		Intra: intra,
		Inter: inter,
	}, nil
}

func decodeBandwidthInfo(raw []byte) (staticinfo.BandwidthInfo, error) {
	var (
		intra map[iface.ID]uint64
		inter map[iface.ID]uint64
		fc    easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return staticinfo.BandwidthInfo{}, err
		}
		switch fc.FieldNum {
		case 1:
			entryRaw, ok := fc.MessageData()
			if !ok {
				return staticinfo.BandwidthInfo{}, fmt.Errorf("invalid BandwidthInfo.intra map entry")
			}
			ifID, bandwidth, err := decodeUint64Uint64MapEntry(entryRaw)
			if err != nil {
				return staticinfo.BandwidthInfo{}, err
			}
			if intra == nil {
				intra = make(map[iface.ID]uint64)
			}
			intra[iface.ID(ifID)] = bandwidth
		case 2:
			entryRaw, ok := fc.MessageData()
			if !ok {
				return staticinfo.BandwidthInfo{}, fmt.Errorf("invalid BandwidthInfo.inter map entry")
			}
			ifID, bandwidth, err := decodeUint64Uint64MapEntry(entryRaw)
			if err != nil {
				return staticinfo.BandwidthInfo{}, err
			}
			if inter == nil {
				inter = make(map[iface.ID]uint64)
			}
			inter[iface.ID(ifID)] = bandwidth
		}
	}
	return staticinfo.BandwidthInfo{
		Intra: intra,
		Inter: inter,
	}, nil
}

func decodeStaticInfoGeoEntry(raw []byte) (iface.ID, staticinfo.GeoCoordinates, error) {
	var (
		key      uint64
		valueRaw []byte
		fc       easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return 0, staticinfo.GeoCoordinates{}, err
		}
		switch fc.FieldNum {
		case 1:
			if v, ok := fc.Uint64(); ok {
				key = v
			}
		case 2:
			v, ok := fc.MessageData()
			if !ok {
				return 0, staticinfo.GeoCoordinates{}, fmt.Errorf("invalid StaticInfoExtension.geo value")
			}
			valueRaw = v
		}
	}
	coords, err := decodeGeoCoordinates(valueRaw)
	if err != nil {
		return 0, staticinfo.GeoCoordinates{}, err
	}
	return iface.ID(key), coords, nil
}

func decodeGeoCoordinates(raw []byte) (staticinfo.GeoCoordinates, error) {
	var (
		coords staticinfo.GeoCoordinates
		fc     easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return staticinfo.GeoCoordinates{}, err
		}
		switch fc.FieldNum {
		case 1:
			if v, ok := fc.Float(); ok {
				coords.Latitude = v
			}
		case 2:
			if v, ok := fc.Float(); ok {
				coords.Longitude = v
			}
		case 3:
			if v, ok := fc.String(); ok {
				coords.Address = v
			}
		}
	}
	return coords, nil
}

func decodeStaticInfoLinkTypeEntry(raw []byte) (iface.ID, staticinfo.LinkType, bool, error) {
	var (
		key   uint64
		value int32
		fc    easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return 0, 0, false, err
		}
		switch fc.FieldNum {
		case 1:
			if v, ok := fc.Uint64(); ok {
				key = v
			}
		case 2:
			if v, ok := fc.Enum(); ok {
				value = v
			}
		}
	}
	switch value {
	case 1:
		return iface.ID(key), staticinfo.LinkTypeDirect, true, nil
	case 2:
		return iface.ID(key), staticinfo.LinkTypeMultihop, true, nil
	case 3:
		return iface.ID(key), staticinfo.LinkTypeOpennet, true, nil
	default:
		return 0, 0, false, nil
	}
}

func decodeStaticInfoInternalHopsEntry(raw []byte) (iface.ID, uint32, error) {
	key, value, err := decodeUint64Uint32MapEntry(raw)
	return iface.ID(key), value, err
}

func decodeUint64Uint32MapEntry(raw []byte) (uint64, uint32, error) {
	var (
		key   uint64
		value uint32
		fc    easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return 0, 0, err
		}
		switch fc.FieldNum {
		case 1:
			if v, ok := fc.Uint64(); ok {
				key = v
			}
		case 2:
			if v, ok := fc.Uint32(); ok {
				value = v
			}
		}
	}
	return key, value, nil
}

func decodeUint64Uint64MapEntry(raw []byte) (uint64, uint64, error) {
	var (
		key   uint64
		value uint64
		fc    easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return 0, 0, err
		}
		switch fc.FieldNum {
		case 1:
			if v, ok := fc.Uint64(); ok {
				key = v
			}
		case 2:
			if v, ok := fc.Uint64(); ok {
				value = v
			}
		}
	}
	return key, value, nil
}

func decodeDiscoveryExtension(raw []byte) (*discovery.Extension, error) {
	var (
		controlRaw   []string
		discoveryRaw []string
		fc           easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return nil, err
		}
		switch fc.FieldNum {
		case 2:
			if v, ok := fc.String(); ok {
				controlRaw = append(controlRaw, v)
			}
		case 3:
			if v, ok := fc.String(); ok {
				discoveryRaw = append(discoveryRaw, v)
			}
		}
	}

	var parseErrors []error
	controlAddrs := make([]netip.AddrPort, 0, len(controlRaw))
	for _, a := range controlRaw {
		ap, err := netip.ParseAddrPort(a)
		if err != nil {
			parseErrors = append(parseErrors, err)
			continue
		}
		controlAddrs = append(controlAddrs, ap)
	}
	discoveryAddrs := make([]netip.AddrPort, 0, len(discoveryRaw))
	for _, a := range discoveryRaw {
		ap, err := netip.ParseAddrPort(a)
		if err != nil {
			parseErrors = append(parseErrors, err)
			continue
		}
		discoveryAddrs = append(discoveryAddrs, ap)
	}

	if (len(controlRaw) > 0 && len(controlAddrs) == 0) || (len(discoveryRaw) > 0 && len(discoveryAddrs) == 0) {
		return nil, errors.Join(parseErrors...)
	}

	return &discovery.Extension{
		ControlServices:   controlAddrs,
		DiscoveryServices: discoveryAddrs,
	}, nil
}

func decodeDigestExtension(raw []byte) (*digest.Extension, error) {
	var (
		epicRaw []byte
		fc      easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return nil, err
		}
		if fc.FieldNum != 1000 {
			continue
		}
		v, ok := fc.MessageData()
		if !ok {
			return nil, fmt.Errorf("invalid DigestExtension.epic field")
		}
		epicRaw = v
	}
	if epicRaw == nil {
		return &digest.Extension{
			Epic: digest.Digest{},
		}, nil
	}

	var (
		digestRaw []byte
		epicFC    easyproto.FieldContext
	)
	for len(epicRaw) > 0 {
		var err error
		epicRaw, err = epicFC.NextField(epicRaw)
		if err != nil {
			return nil, err
		}
		if epicFC.FieldNum != 1 {
			continue
		}
		v, ok := epicFC.Bytes()
		if !ok {
			return nil, fmt.Errorf("invalid DigestExtension.Digest.digest field")
		}
		digestRaw = v
	}
	d := make([]byte, digest.DigestLength)
	copy(d, digestRaw)
	return &digest.Extension{
		Epic: digest.Digest{
			Digest: d,
		},
	}, nil
}

func decodeUnsignedExtensions(raw []byte) (segment.UnsignedExtensions, error) {
	if len(raw) == 0 {
		return segment.UnsignedExtensions{}, nil
	}
	var (
		epicRaw []byte
		fc      easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return segment.UnsignedExtensions{}, err
		}
		if fc.FieldNum != 1000 {
			continue
		}
		v, ok := fc.MessageData()
		if !ok {
			return segment.UnsignedExtensions{}, fmt.Errorf("invalid PathSegmentUnsignedExtensions.epic field")
		}
		epicRaw = v
	}
	if epicRaw == nil {
		return segment.UnsignedExtensions{}, nil
	}
	ext, err := decodeEPICDetachedExtension(epicRaw)
	if err != nil {
		return segment.UnsignedExtensions{}, err
	}
	return segment.UnsignedExtensions{EpicDetached: ext}, nil
}

func decodeEPICDetachedExtension(raw []byte) (*epic.Detached, error) {
	var (
		authHop   []byte
		authPeers [][]byte
		fc        easyproto.FieldContext
	)
	for len(raw) > 0 {
		var err error
		raw, err = fc.NextField(raw)
		if err != nil {
			return nil, err
		}
		switch fc.FieldNum {
		case 1:
			v, ok := fc.Bytes()
			if !ok {
				return nil, fmt.Errorf("invalid EPICDetachedExtension.auth_hop_entry field")
			}
			authHop = v
		case 2:
			v, ok := fc.Bytes()
			if !ok {
				return nil, fmt.Errorf("invalid EPICDetachedExtension.auth_peer_entries field")
			}
			authPeers = append(authPeers, v)
		}
	}
	hop := make([]byte, epic.AuthLen)
	copy(hop, authHop)
	peers := make([][]byte, 0, len(authPeers))
	for _, p := range authPeers {
		peer := make([]byte, epic.AuthLen)
		copy(peer, p)
		peers = append(peers, peer)
	}
	return &epic.Detached{
		AuthHopEntry:    hop,
		AuthPeerEntries: peers,
	}, nil
}

func cloneBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
