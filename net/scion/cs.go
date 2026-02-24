package scion

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"google.golang.org/grpc/resolver"

	kgrpc "github.com/scionproto/scion/daemon/drkey/grpc"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/path/combinator"
	"github.com/scionproto/scion/private/segment/segfetcher"
	sgrpc "github.com/scionproto/scion/private/segment/segfetcher/grpc"
	"github.com/scionproto/scion/private/segment/segverifier"
	"github.com/scionproto/scion/private/segment/verifier"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/storage/db"
	"github.com/scionproto/scion/private/storage/trust/fspersister"
	"github.com/scionproto/scion/private/storage/trust/sqlite"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
	tgrpc "github.com/scionproto/scion/private/trust/grpc"
)

type segVerifier struct {
	trust.Verifier
}

func (v segVerifier) WithServer(server net.Addr) verifier.Verifier {
	v.BoundServer = server
	return v
}

func (v segVerifier) WithIA(ia addr.IA) verifier.Verifier {
	v.BoundIA = ia
	return v
}

func (v segVerifier) WithValidity(validity cppki.Validity) verifier.Verifier {
	v.BoundValidity = validity
	return v
}

type dstProvider struct{}

func (d *dstProvider) Dst(context.Context, segfetcher.Request) (net.Addr, error) {
	return &snet.SVCAddr{SVC: addr.SvcCS}, nil
}

type csControlPlane struct {
	topo         *topology.Loader
	trustDB      storage.TrustDB
	segVerifier  *segVerifier
	segRequester *segfetcher.DefaultRequester
	drkeyFetcher *kgrpc.Fetcher
}

func (cp *csControlPlane) LocalIA(ctx context.Context) (addr.IA, error) {
	return cp.topo.IA(), nil
}

func (cp *csControlPlane) FetchPaths(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	if dst.IsWildcard() {
		panic("wildcard destination is not supported")
	}

	src := cp.topo.IA()

	if dst == src {
		panic("local-AS destination is not supported")
	}

	srcCore := cp.topo.Core()

	requests := cp.createRequests(src, srcCore, dst)
	ups, cores, downs := cp.fetchSegments(ctx, requests)

	cpaths := combinator.Combine(src, dst, ups, cores, downs, false /* findAllIdentical */)
	spaths := cp.convertPaths(cpaths)

	return spaths, nil
}

func toWildcard(ia addr.IA) addr.IA {
	return addr.MustParseIA(fmt.Sprintf("%d-0", ia.ISD()))
}

func (cp *csControlPlane) createRequests(
	src addr.IA, srcCore bool, dst addr.IA) segfetcher.Requests {
	if srcCore {
		return segfetcher.Requests{
			{Src: src, Dst: dst, SegType: segment.TypeDown},
			{Src: src, Dst: dst, SegType: segment.TypeCore},
			{Src: src, Dst: toWildcard(dst), SegType: segment.TypeCore},
			{Src: toWildcard(dst), Dst: dst, SegType: segment.TypeDown},
		}
	} else {
		return segfetcher.Requests{
			{Src: src, Dst: toWildcard(src), SegType: segment.TypeUp},
			{Src: toWildcard(src), Dst: toWildcard(dst), SegType: segment.TypeCore},
			{Src: toWildcard(src), Dst: dst, SegType: segment.TypeCore},
			{Src: toWildcard(dst), Dst: dst, SegType: segment.TypeDown},
		}
	}
}

func (cp *csControlPlane) fetchSegments(ctx context.Context, requests segfetcher.Requests) (
	ups, cores, downs []*segment.PathSegment) {
	if len(requests) == 0 {
		return nil, nil, nil
	}

	replies := cp.segRequester.Request(ctx, requests)
	for reply := range replies {
		if reply.Err != nil {
			continue
		}
		for _, segMeta := range reply.Segments {
			seg := segMeta.Segment

			if cp.segVerifier != nil {
				if err := segverifier.VerifySegment(ctx, cp.segVerifier, reply.Peer, seg); err != nil {
					continue // Skip invalid segments
				}
			}

			switch segMeta.Type {
			case segment.TypeUp:
				ups = append(ups, seg)
			case segment.TypeCore:
				cores = append(cores, seg)
			case segment.TypeDown:
				downs = append(downs, seg)
			}
		}
	}
	return ups, cores, downs
}

func (cp *csControlPlane) convertPaths(cpaths []combinator.Path) []snet.Path {
	var paths []snet.Path
	for _, cpath := range cpaths {
		path, err := cp.convertPath(cpath)
		if err != nil {
			continue
		}
		paths = append(paths, path)
	}
	return paths
}

func (cp *csControlPlane) convertPath(cpath combinator.Path) (snet.Path, error) {
	if len(cpath.Metadata.Interfaces) == 0 {
		return nil, fmt.Errorf("path has no interfaces")
	}
	firstIF := cpath.Metadata.Interfaces[0]
	nextHop := cp.topo.UnderlayNextHop(uint16(firstIF.ID))
	if nextHop == nil {
		return nil, fmt.Errorf("unable to find next hop address, ifID = %v", firstIF.ID)
	}
	return path.Path{
		Src:           cpath.Metadata.Interfaces[0].IA,
		Dst:           cpath.Metadata.Interfaces[len(cpath.Metadata.Interfaces)-1].IA,
		DataplanePath: cpath.SCIONPath,
		NextHop:       nextHop,
		Meta:          cpath.Metadata,
	}, nil
}

func (cp *csControlPlane) FetchHostASKey(ctx context.Context, meta drkey.HostASMeta) (drkey.HostASKey, error) {
	return cp.drkeyFetcher.HostASKey(ctx, meta)
}

func (cp *csControlPlane) FetchHostHostKey(ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error) {
	return cp.drkeyFetcher.HostHostKey(ctx, meta)
}

func (cp *csControlPlane) Close() error {
	if cp.trustDB != nil {
		return cp.trustDB.Close()
	}
	return nil
}

var _ ControlPlane = (*csControlPlane)(nil)

func newCSControlPlane(topo *topology.Loader, trustDB storage.TrustDB) *csControlPlane {
	dialer := &grpc.TCPDialer{
		SvcResolver: func(dst addr.SVC) []resolver.Address {
			if base := dst.Base(); base != addr.SvcCS {
				panic("unexpected address type")
			}
			addrs := []resolver.Address{}
			for _, csaddr := range topo.ControlServiceAddresses() {
				addrs = append(addrs, resolver.Address{Addr: csaddr.String()})
			}
			return addrs
		},
	}

	var verifier *segVerifier
	if trustDB != nil {
		verifier = &segVerifier{
			Verifier: trust.Verifier{
				Engine: trust.FetchingProvider{
					DB: trustDB,
					Fetcher: tgrpc.Fetcher{
						IA:     topo.IA(),
						Dialer: dialer,
					},
					Recurser: trust.LocalOnlyRecurser{},
					Router: trust.LocalRouter{
						IA: topo.IA(),
					},
				},
			},
		}
	}

	return &csControlPlane{
		topo:        topo,
		trustDB:     trustDB,
		segVerifier: verifier,
		segRequester: &segfetcher.DefaultRequester{
			RPC:         &sgrpc.Requester{Dialer: dialer},
			DstProvider: &dstProvider{},
			MaxRetries:  4,
		},
		drkeyFetcher: &kgrpc.Fetcher{
			Dialer: dialer,
		},
	}
}

var trustDBSeq atomic.Uint64

type CSConnector struct {
	TopoFile    string
	CertsDir    string
	PersistTRCs bool
}

func (c CSConnector) Connect(ctx context.Context) (ControlPlane, error) {
	if c.TopoFile == "" {
		panic("invalid configuration: empty topology file")
	}

	topo, err := topology.NewLoader(topology.LoaderCfg{
		File: c.TopoFile,
	})
	if err != nil {
		return nil, err
	}

	var trustDB storage.TrustDB
	if c.CertsDir != "" {
		trustDB, err = sqlite.New(
			fmt.Sprintf(
				"in_memory_trust_db_%d_%d",
				os.Getpid(),
				trustDBSeq.Add(1),
			),
			&db.SqliteConfig{
				MaxOpenReadConns: 1,
				MaxIdleReadConns: 1,
				InMemory:         true,
			},
		)
		if err != nil {
			return nil, err
		}
		if c.PersistTRCs {
			trustDB = fspersister.WrapDB(trustDB, fspersister.Config{
				TRCDir: c.CertsDir,
			})
		}
		_, err = trust.LoadTRCs(ctx, c.CertsDir, trustDB)
		if err != nil {
			_ = trustDB.Close()
			return nil, err
		}
	}

	return newCSControlPlane(topo, trustDB), nil
}

var _ ControlPlaneConnector = (*CSConnector)(nil)
