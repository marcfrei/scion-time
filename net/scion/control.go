package scion

import (
	"context"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/snet"
)

type ControlPlane interface {
	LocalIA(ctx context.Context) (addr.IA, error)
	FetchPaths(ctx context.Context, dst addr.IA) ([]snet.Path, error)
	FetchHostASKey(ctx context.Context, meta drkey.HostASMeta) (drkey.HostASKey, error)
	FetchHostHostKey(ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error)
	Close() error
}

type ControlPlaneConnector interface {
	Connect(ctx context.Context) (ControlPlane, error)
}
