package scion

import (
	"context"
	"os"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"example.com/scion-time/base/metrics"
)

type fetcherMetrics struct {
	keysInserted prometheus.Counter
	keysExpired  prometheus.Counter
	keysReplaced prometheus.Counter
}

func newFetcherMetrics() *fetcherMetrics {
	return &fetcherMetrics{
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
	fetcherMtrcs atomic.Pointer[fetcherMetrics]
	useMockKeys  bool
)

func init() {
	fetcherMtrcs.Store(newFetcherMetrics())
	v := os.Getenv("USE_MOCK_KEYS")
	useMockKeys = v == "true" || v == "TRUE"
}

func UseMockKeys() bool {
	return useMockKeys
}

type Fetcher struct {
	dc   daemon.Connector
	haks map[addr.IA]drkey.HostASKey
}

func (f *Fetcher) FetchHostASKey(ctx context.Context, meta drkey.HostASMeta) (
	drkey.HostASKey, error) {
	var err error
	hak, ok := f.haks[meta.DstIA]
	expired := ok && !hak.Epoch.Contains(meta.Validity)
	if !ok || expired ||
		hak.ProtoId != meta.ProtoId ||
		hak.SrcIA != meta.SrcIA ||
		hak.DstIA != meta.DstIA ||
		hak.SrcHost != meta.SrcHost {
		if useMockKeys {
			now := time.Now()
			hak = drkey.HostASKey{
				ProtoId: meta.ProtoId,
				SrcIA:   meta.SrcIA,
				DstIA:   meta.DstIA,
				Epoch: drkey.Epoch{
					Validity: cppki.Validity{
						NotBefore: now.Add(-6 * time.Hour),
						NotAfter:  now.Add(6 * time.Hour),
					},
				},
				SrcHost: meta.SrcHost,
			}
		} else {
			hak, err = FetchHostASKey(ctx, f.dc, meta)
		}
		if err == nil {
			f.haks[hak.DstIA] = hak
			mtrcs := fetcherMtrcs.Load()
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

func (f *Fetcher) FetchHostHostKey(ctx context.Context, meta drkey.HostHostMeta) (
	drkey.HostHostKey, error) {
	if useMockKeys {
		now := time.Now()
		return drkey.HostHostKey{
			ProtoId: meta.ProtoId,
			SrcIA:   meta.SrcIA,
			DstIA:   meta.DstIA,
			Epoch: drkey.Epoch{
				Validity: cppki.Validity{
					NotBefore: now.Add(-6 * time.Hour),
					NotAfter:  now.Add(6 * time.Hour),
				},
			},
			SrcHost: meta.SrcHost,
			DstHost: meta.DstHost,
		}, nil
	}
	return FetchHostHostKey(ctx, f.dc, meta)
}

func NewFetcher(c daemon.Connector) *Fetcher {
	return &Fetcher{
		dc:   c,
		haks: make(map[addr.IA]drkey.HostASKey),
	}
}
