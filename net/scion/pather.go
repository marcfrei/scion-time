package scion

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

const pathRefreshPeriod = 15 * time.Second

type Pather struct {
	log     *slog.Logger
	mu      sync.Mutex
	localIA addr.IA
	paths   map[addr.IA][]snet.Path
}

func (p *Pather) LocalIA() addr.IA {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.localIA
}

func (p *Pather) Paths(dst addr.IA) []snet.Path {
	p.mu.Lock()
	defer p.mu.Unlock()
	paths, ok := p.paths[dst]
	if !ok {
		return nil
	}
	return append(make([]snet.Path, 0, len(paths)), paths...)
}

func update(ctx context.Context, p *Pather, cp ControlPlane, dstIAs []addr.IA) {
	paths := map[addr.IA][]snet.Path{}
	for _, dstIA := range dstIAs {
		if dstIA.IsWildcard() {
			panic("unexpected destination IA: wildcard.")
		}
		ps, err := cp.FetchPaths(ctx, dstIA)
		if err != nil {
			p.log.LogAttrs(ctx, slog.LevelInfo,
				"failed to look up paths", slog.Any("to", dstIA), slog.Any("error", err))
		}
		paths[dstIA] = append(paths[dstIA], ps...)
	}

	p.mu.Lock()
	p.paths = paths
	p.mu.Unlock()
}

func StartPather(ctx context.Context, log *slog.Logger, cpc ControlPlaneConnector, dstIAs []addr.IA) (*Pather, error) {
	cp, err := cpc.Connect(ctx)
	if err != nil {
		return nil, err
	}
	localIA, err := cp.LocalIA(ctx)
	if err != nil {
		return nil, err
	}
	p := &Pather{
		log:     log,
		localIA: localIA,
	}
	update(ctx, p, cp, dstIAs)
	go func(ctx context.Context, p *Pather, cp ControlPlane, dstIAs []addr.IA) {
		ticker := time.NewTicker(pathRefreshPeriod)
		for range ticker.C {
			update(ctx, p, cp, dstIAs)
		}
	}(ctx, p, cp, dstIAs)
	return p, nil
}

func FetchPaths(ctx context.Context, cp ControlPlane, localIA, dstIA addr.IA, dstAddr *net.UDPAddr) ([]snet.Path, error) {
	if dstIA == localIA {
		return []snet.Path{path.Path{
			Src:           localIA,
			Dst:           dstIA,
			DataplanePath: path.Empty{},
			NextHop:       dstAddr,
		}}, nil
	}
	return cp.FetchPaths(ctx, dstIA)
}
