package scion

import (
	"context"
	"os"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/drkey/generic"

	"example.com/scion-time/base/metrics"
)

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

type drkeyFetcherMetrics struct {
	keysInserted prometheus.Counter
	keysExpired  prometheus.Counter
	keysReplaced prometheus.Counter
}

func newDRKeyFetcherMetrics() *drkeyFetcherMetrics {
	return &drkeyFetcherMetrics{
		keysInserted: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.DRKeyCacheKeysInsertedN,
			Help: metrics.DRKeyCacheKeysInsertedH,
		}),
		keysExpired: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.DRKeyCacheKeysExpiredN,
			Help: metrics.DRKeyCacheKeysExpiredH,
		}),
		keysReplaced: promauto.NewCounter(prometheus.CounterOpts{
			Name: metrics.DRKeyCacheKeysReplacedN,
			Help: metrics.DRKeyCacheKeysReplacedH,
		}),
	}
}

var (
	drkeyFetcherMtrcs atomic.Pointer[drkeyFetcherMetrics]
	useMockKeys       bool
)

func init() {
	drkeyFetcherMtrcs.Store(newDRKeyFetcherMetrics())
	v := os.Getenv("USE_MOCK_KEYS")
	useMockKeys = v == "true" || v == "TRUE"
}

func UseMockKeys() bool {
	return useMockKeys
}

type DRKeyFetcher struct {
	cpc  ControlPlaneConnector
	cp   ControlPlane
	haks map[addr.IA]drkey.HostASKey
}

func (f *DRKeyFetcher) FetchHostASKey(ctx context.Context, meta drkey.HostASMeta) (
	drkey.HostASKey, error) {
	if f.cp == nil {
		cp, err := f.cpc.Connect(ctx)
		if err != nil {
			return drkey.HostASKey{}, err
		}
		f.cp = cp
	}
	var err error
	hak, ok := f.haks[meta.DstIA]
	expired := ok && !hak.Epoch.Contains(meta.Validity)
	if !ok || expired ||
		hak.ProtoId != meta.ProtoId ||
		hak.SrcIA != meta.SrcIA ||
		hak.DstIA != meta.DstIA ||
		hak.SrcHost != meta.SrcHost {
		if useMockKeys {
			now := time.Now().UTC()
			hak = drkey.HostASKey{
				ProtoId: meta.ProtoId,
				SrcIA:   meta.SrcIA,
				DstIA:   meta.DstIA,
				Epoch: drkey.Epoch{
					NotBefore: now.Add(-6 * time.Hour),
					NotAfter:  now.Add(6 * time.Hour),
				},
				SrcHost: meta.SrcHost,
			}
		} else {
			hak, err = f.cp.FetchHostASKey(ctx, meta)
		}
		if err == nil {
			f.haks[hak.DstIA] = hak
			mtrcs := drkeyFetcherMtrcs.Load()
			if !ok {
				mtrcs.keysInserted.Inc()
			} else {
				if expired {
					mtrcs.keysExpired.Inc()
				}
				mtrcs.keysReplaced.Inc()
			}
		}
	}
	return hak, err
}

func (f *DRKeyFetcher) FetchHostHostKey(ctx context.Context, meta drkey.HostHostMeta) (
	drkey.HostHostKey, error) {
	if f.cp == nil {
		cp, err := f.cpc.Connect(ctx)
		if err != nil {
			return drkey.HostHostKey{}, err
		}
		f.cp = cp
	}
	if useMockKeys {
		now := time.Now().UTC()
		return drkey.HostHostKey{
			ProtoId: meta.ProtoId,
			SrcIA:   meta.SrcIA,
			DstIA:   meta.DstIA,
			Epoch: drkey.Epoch{
				NotBefore: now.Add(-6 * time.Hour),
				NotAfter:  now.Add(6 * time.Hour),
			},
			SrcHost: meta.SrcHost,
			DstHost: meta.DstHost,
		}, nil
	}
	return f.cp.FetchHostHostKey(ctx, meta)
}

func NewDRKeyFetcher(cpc ControlPlaneConnector) *DRKeyFetcher {
	return &DRKeyFetcher{
		cpc:  cpc,
		haks: make(map[addr.IA]drkey.HostASKey),
	}
}
