package scion

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	exppb "github.com/scionproto/scion/pkg/proto/control_plane/experimental"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/extensions/digest"
	"github.com/scionproto/scion/pkg/segment/extensions/epic"
	"github.com/scionproto/scion/pkg/segment/extensions/staticinfo"
)

func TestDecodePathSegmentEasyprotoParity(t *testing.T) {
	raw := mustEncodePathSegmentFixture(t, false)

	gotEasy, err := decodePathSegment(raw)
	if err != nil {
		t.Fatalf("decodePathSegment() error = %v", err)
	}
	gotPB, err := decodePathSegmentPBOracle(raw)
	if err != nil {
		t.Fatalf("decodePathSegmentPBOracle() error = %v", err)
	}

	assertPathSegmentsEquivalent(t, gotEasy, gotPB)
}

func decodePathSegmentPBOracle(raw []byte) (*segment.PathSegment, error) {
	var pb cppb.PathSegment
	if err := proto.Unmarshal(raw, &pb); err != nil {
		return nil, err
	}
	return segment.SegmentFromPB(&pb)
}

func TestDecodePathSegmentEasyprotoDiscoveryParseError(t *testing.T) {
	raw := mustEncodePathSegmentFixture(t, true)
	if _, err := decodePathSegment(raw); err == nil {
		t.Fatalf("decodePathSegment() unexpectedly succeeded")
	}
}

func mustEncodePathSegmentFixture(t *testing.T, invalidDiscovery bool) []byte {
	t.Helper()

	localIA := addr.MustParseIA("64-2:0:9")
	detachedPB := &exppb.EPICDetachedExtension{
		AuthHopEntry:    []byte{10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		AuthPeerEntries: [][]byte{{20, 21, 22, 23, 24, 25, 26, 27, 28, 29}},
	}
	detached := epic.DetachedFromPB(detachedPB)
	digestInput, err := detached.DigestInput()
	if err != nil {
		t.Fatalf("DigestInput() error = %v", err)
	}
	var digestValue digest.Digest
	digestValue.Set(digestInput)

	controlAddrs := []string{"192.0.2.1:30255"}
	if invalidDiscovery {
		controlAddrs = []string{"invalid"}
	}

	body := &cppb.ASEntrySignedBody{
		IsdAs: uint64(localIA),
		HopEntry: &cppb.HopEntry{
			HopField: &cppb.HopField{
				Ingress: 0,
				Egress:  0,
				ExpTime: 10,
				Mac:     []byte{1, 2, 3, 4, 5, 6},
			},
			IngressMtu: 1472,
		},
		Mtu: 1472,
		Extensions: &cppb.PathSegmentExtensions{
			StaticInfo: &cppb.StaticInfoExtension{
				Latency: &cppb.LatencyInfo{
					Intra: map[uint64]uint32{11: 1234},
				},
				Bandwidth: &cppb.BandwidthInfo{
					Inter: map[uint64]uint64{12: 500000},
				},
				Geo: map[uint64]*cppb.GeoCoordinates{
					11: {
						Latitude:  1.5,
						Longitude: 2.5,
						Address:   "geo",
					},
				},
				LinkType: map[uint64]cppb.LinkType{
					11: cppb.LinkType_LINK_TYPE_MULTI_HOP,
					12: cppb.LinkType_LINK_TYPE_UNSPECIFIED,
				},
				InternalHops: map[uint64]uint32{
					11: 2,
				},
				Note: "hello",
			},
			HiddenPath: &cppb.HiddenPathExtension{IsHidden: true},
			Discovery: &cppb.DiscoveryExtension{
				ControlServiceAddresses:   controlAddrs,
				DiscoveryServiceAddresses: []string{"192.0.2.2:30255"},
			},
			Digests: &cppb.DigestExtension{
				Epic: &cppb.DigestExtension_Digest{
					Digest: digestValue.Digest,
				},
			},
		},
	}
	bodyRaw, err := proto.Marshal(body)
	if err != nil {
		t.Fatalf("marshal ASEntrySignedBody: %v", err)
	}

	headerRaw, err := proto.Marshal(&cryptopb.Header{})
	if err != nil {
		t.Fatalf("marshal Header: %v", err)
	}
	headerAndBodyRaw, err := proto.Marshal(&cryptopb.HeaderAndBodyInternal{
		Header: headerRaw,
		Body:   bodyRaw,
	})
	if err != nil {
		t.Fatalf("marshal HeaderAndBodyInternal: %v", err)
	}

	segmentInfoRaw, err := proto.Marshal(&cppb.SegmentInformation{
		Timestamp: 1710000000,
		SegmentId: 7,
	})
	if err != nil {
		t.Fatalf("marshal SegmentInformation: %v", err)
	}

	psRaw, err := proto.Marshal(&cppb.PathSegment{
		SegmentInfo: segmentInfoRaw,
		AsEntries: []*cppb.ASEntry{
			{
				Signed: &cryptopb.SignedMessage{
					HeaderAndBody: headerAndBodyRaw,
					Signature:     []byte{1, 2, 3},
				},
				Unsigned: &cppb.PathSegmentUnsignedExtensions{
					Epic: detachedPB,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal PathSegment: %v", err)
	}
	return psRaw
}

func assertPathSegmentsEquivalent(t *testing.T, got, want *segment.PathSegment) {
	t.Helper()

	if got == nil || want == nil {
		t.Fatalf("nil segment comparison: got=%v want=%v", got, want)
	}
	if got.Info.SegmentID != want.Info.SegmentID {
		t.Fatalf("SegmentID = %d, want %d", got.Info.SegmentID, want.Info.SegmentID)
	}
	if !got.Info.Timestamp.Equal(want.Info.Timestamp) {
		t.Fatalf("Timestamp = %v, want %v", got.Info.Timestamp, want.Info.Timestamp)
	}
	if !bytes.Equal(got.Info.Raw, want.Info.Raw) {
		t.Fatalf("Info.Raw mismatch")
	}
	if len(got.ASEntries) != len(want.ASEntries) {
		t.Fatalf("ASEntry count = %d, want %d", len(got.ASEntries), len(want.ASEntries))
	}

	gotASE := got.ASEntries[0]
	wantASE := want.ASEntries[0]
	if gotASE.Local != wantASE.Local || gotASE.Next != wantASE.Next {
		t.Fatalf("IA mismatch: got local/next %s/%s want %s/%s",
			gotASE.Local, gotASE.Next, wantASE.Local, wantASE.Next)
	}
	if gotASE.MTU != wantASE.MTU {
		t.Fatalf("MTU = %d, want %d", gotASE.MTU, wantASE.MTU)
	}
	if (gotASE.Signed == nil) != (wantASE.Signed == nil) {
		t.Fatalf("Signed presence mismatch")
	}
	if gotASE.Signed != nil {
		if !bytes.Equal(gotASE.Signed.HeaderAndBody, wantASE.Signed.HeaderAndBody) {
			t.Fatalf("Signed.HeaderAndBody mismatch")
		}
		if !bytes.Equal(gotASE.Signed.Signature, wantASE.Signed.Signature) {
			t.Fatalf("Signed.Signature mismatch")
		}
	}
	gotHop := gotASE.HopEntry.HopField
	wantHop := wantASE.HopEntry.HopField
	if gotHop.ConsIngress != wantHop.ConsIngress || gotHop.ConsEgress != wantHop.ConsEgress ||
		gotHop.ExpTime != wantHop.ExpTime || gotHop.MAC != wantHop.MAC {
		t.Fatalf("hop field mismatch")
	}
	if gotASE.HopEntry.IngressMTU != wantASE.HopEntry.IngressMTU {
		t.Fatalf("HopEntry.IngressMTU = %d, want %d", gotASE.HopEntry.IngressMTU, wantASE.HopEntry.IngressMTU)
	}

	if gotASE.Extensions.HiddenPath.IsHidden != wantASE.Extensions.HiddenPath.IsHidden {
		t.Fatalf("HiddenPath.IsHidden mismatch")
	}
	assertStaticInfoEquivalent(t, gotASE.Extensions.StaticInfo, wantASE.Extensions.StaticInfo)
	if gotASE.Extensions.Discovery == nil || wantASE.Extensions.Discovery == nil {
		t.Fatalf("discovery extension missing")
	}
	if len(gotASE.Extensions.Discovery.ControlServices) != len(wantASE.Extensions.Discovery.ControlServices) {
		t.Fatalf("control service count mismatch")
	}
	if gotASE.Extensions.Discovery.ControlServices[0] != wantASE.Extensions.Discovery.ControlServices[0] {
		t.Fatalf("control service mismatch")
	}
	if len(gotASE.Extensions.Discovery.DiscoveryServices) != len(wantASE.Extensions.Discovery.DiscoveryServices) {
		t.Fatalf("discovery service count mismatch")
	}
	if gotASE.Extensions.Discovery.DiscoveryServices[0] != wantASE.Extensions.Discovery.DiscoveryServices[0] {
		t.Fatalf("discovery service mismatch")
	}
	if gotASE.Extensions.Digests == nil || wantASE.Extensions.Digests == nil {
		t.Fatalf("digest extension missing")
	}
	if !bytes.Equal(gotASE.Extensions.Digests.Epic.Digest, wantASE.Extensions.Digests.Epic.Digest) {
		t.Fatalf("digest mismatch")
	}

	if gotASE.UnsignedExtensions.EpicDetached == nil || wantASE.UnsignedExtensions.EpicDetached == nil {
		t.Fatalf("unsigned epic extension missing")
	}
	if !bytes.Equal(gotASE.UnsignedExtensions.EpicDetached.AuthHopEntry, wantASE.UnsignedExtensions.EpicDetached.AuthHopEntry) {
		t.Fatalf("unsigned epic hop auth mismatch")
	}
	if len(gotASE.UnsignedExtensions.EpicDetached.AuthPeerEntries) != len(wantASE.UnsignedExtensions.EpicDetached.AuthPeerEntries) {
		t.Fatalf("unsigned epic peer auth count mismatch")
	}
	if !bytes.Equal(gotASE.UnsignedExtensions.EpicDetached.AuthPeerEntries[0], wantASE.UnsignedExtensions.EpicDetached.AuthPeerEntries[0]) {
		t.Fatalf("unsigned epic peer auth mismatch")
	}
}

func assertStaticInfoEquivalent(t *testing.T, got, want *staticinfo.Extension) {
	t.Helper()
	if got == nil || want == nil {
		t.Fatalf("static info missing")
	}
	if got.Note != want.Note {
		t.Fatalf("static note = %q, want %q", got.Note, want.Note)
	}
	if got.Latency.Intra[11] != want.Latency.Intra[11] {
		t.Fatalf("latency intra mismatch")
	}
	if got.Bandwidth.Inter[12] != want.Bandwidth.Inter[12] {
		t.Fatalf("bandwidth inter mismatch")
	}
	if got.LinkType[11] != want.LinkType[11] {
		t.Fatalf("link type mismatch")
	}
	if got.InternalHops[11] != want.InternalHops[11] {
		t.Fatalf("internal hops mismatch")
	}
	if got.Geo[11] != want.Geo[11] {
		t.Fatalf("geo mismatch")
	}
}
