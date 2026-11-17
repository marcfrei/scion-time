package client

import (
	"slices"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

func testPath(hops ...uint64) snet.Path {
	src, dst := addr.MustParseIA("1-ff00:0:1"), addr.MustParseIA("1-ff00:0:9")
	var ifaces []snet.PathInterface
	for i, h := range hops {
		ia := src
		if i%2 == 1 {
			ia = dst
		}
		ifaces = append(ifaces, snet.PathInterface{IA: ia, ID: iface.ID(h)})
	}
	return path.Path{Src: src, Dst: dst, Meta: snet.PathMetadata{Interfaces: ifaces}}
}

func fingerprints(ps []snet.Path) []string {
	var fps []string
	for _, p := range ps {
		fps = append(fps, PathFingerprint(p))
	}
	return fps
}

func TestPreselectedPaths(t *testing.T) {
	ps := []snet.Path{testPath(1, 11), testPath(2, 12), testPath(3, 13), testPath(4, 14)}
	all := fingerprints(ps)
	got := fingerprints(PreselectedPaths(ps, []string{all[0], all[2], "unknown"}))
	if !slices.Equal(got, []string{all[0], all[2]}) {
		t.Fatalf("PreselectedPaths = %v", got)
	}
	if got := PreselectedPaths(ps, []string{"unknown"}); len(got) != 0 {
		t.Fatalf("PreselectedPaths without listed paths = %v", fingerprints(got))
	}
}
