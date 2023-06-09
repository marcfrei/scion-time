package scion

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

const pathRefreshPeriod = 15 * time.Second

type Pather struct {
	log     *zap.Logger
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

func update(ctx context.Context, p *Pather, dc daemon.Connector, dstIAs []addr.IA) {
	localIA, err := dc.LocalIA(ctx)
	if err != nil {
		p.log.Info("failed to look up local IA", zap.Error(err))
		return
	}

	paths := map[addr.IA][]snet.Path{}
	for _, dstIA := range dstIAs {
		if dstIA.IsWildcard() {
			panic("unexpected destination IA: wildcard.")
		}
		ps, err := dc.Paths(ctx, dstIA, localIA, daemon.PathReqFlags{Refresh: true})
		if err != nil {
			p.log.Info("failed to look up paths", zap.Stringer("to", dstIA), zap.Error(err))
		}
		paths[dstIA] = append(paths[dstIA], ps...)
	}

	p.mu.Lock()
	p.localIA = localIA
	p.paths = paths
	p.mu.Unlock()
}

func StartPather(ctx context.Context, log *zap.Logger, daemonAddr string, dstIAs []addr.IA) *Pather {
	p := &Pather{log: log}
	dc := NewDaemonConnector(ctx, daemonAddr)
	update(ctx, p, dc, dstIAs)
	go func(ctx context.Context, p *Pather, dc daemon.Connector, dstIAs []addr.IA) {
		ticker := time.NewTicker(pathRefreshPeriod)
		for range ticker.C {
			update(ctx, p, dc, dstIAs)
		}
	}(ctx, p, dc, dstIAs)
	return p
}
