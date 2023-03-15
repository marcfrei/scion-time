package scion

import (
	"context"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/drkey/generic"
)

func FetchHostASKey(ctx context.Context, dc daemon.Connector, meta drkey.HostASMeta) (
	drkey.HostASKey, error) {
	return dc.DRKeyGetHostASKey(ctx, meta)
}

func DeriveHostHostKey(hostASKey drkey.HostASKey, dstHost string) (
	drkey.HostHostKey, error) {
	deriver := generic.Deriver{
		Proto: hostASKey.ProtoId,
	}
	hostHostKey, err := deriver.DeriveHostHost(
		dstHost,
		hostASKey.Key,
	)
	if err != nil {
		return drkey.HostHostKey{}, err
	}
	return drkey.HostHostKey{
		ProtoId: hostASKey.ProtoId,
		Epoch:   hostASKey.Epoch,
		SrcIA:   hostASKey.SrcIA,
		DstIA:   hostASKey.DstIA,
		SrcHost: hostASKey.SrcHost,
		DstHost: dstHost,
		Key:     hostHostKey,
	}, nil
}

func FetchHostHostKey(ctx context.Context, dc daemon.Connector, meta drkey.HostHostMeta) (
	drkey.HostHostKey, error) {
	return dc.DRKeyGetHostHostKey(ctx, meta)
}
