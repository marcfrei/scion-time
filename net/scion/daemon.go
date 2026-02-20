package scion

import (
	"context"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/snet"
)

type daemonControlPlane struct {
	dc      daemon.Connector
	mu      sync.Mutex
	localIA addr.IA
}

func (cp *daemonControlPlane) LocalIA(ctx context.Context) (addr.IA, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.localIA == 0 {
		lia, err := cp.dc.LocalIA(ctx)
		if err != nil {
			return 0, err
		}
		cp.localIA = lia
	}
	return cp.localIA, nil
}

func (cp *daemonControlPlane) FetchPaths(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	localIA, err := cp.LocalIA(ctx)
	if err != nil {
		return nil, err
	}
	return cp.dc.Paths(ctx, dst, localIA, daemon.PathReqFlags{Refresh: true})
}

func (cp *daemonControlPlane) FetchHostASKey(ctx context.Context, meta drkey.HostASMeta) (drkey.HostASKey, error) {
	return cp.dc.DRKeyGetHostASKey(ctx, meta)
}

func (cp *daemonControlPlane) FetchHostHostKey(ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error) {
	return cp.dc.DRKeyGetHostHostKey(ctx, meta)
}

func (cp *daemonControlPlane) Close() error {
	return cp.dc.Close()
}

type DaemonConnector struct {
	Address string
}

func (c DaemonConnector) Connect(ctx context.Context) (ControlPlane, error) {
	if c.Address == "" {
		panic("invalid configuration: empty address")
	}

	ds := &daemon.Service{
		Address: c.Address,
	}
	dc, err := ds.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &daemonControlPlane{dc: dc}, nil
}
