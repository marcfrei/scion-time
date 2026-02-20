package benchmark

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"

	"github.com/scionproto/scion/pkg/snet"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/core/client"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

func RunSCIONBenchmark(
	cpc scion.ControlPlaneConnector, localAddr, remoteAddr *snet.UDPAddr,
	authModes []string, ntskeServer string,
	log *slog.Logger) {
	const numClientGoroutine = 10
	const numRequestPerClient = 10_000

	ctx := context.Background()

	var mu sync.Mutex
	sg := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numClientGoroutine)

	for range numClientGoroutine {
		go func() {
			hg := hdrhistogram.New(1, 50000, 5)

			cp, err := cpc.Connect(ctx)
			if err != nil {
				logbase.FatalContext(ctx, log, "failed to connect to control plane",
					slog.Any("error", err))
			}

			ps, err := scion.FetchPaths(ctx, cp, localAddr.IA, remoteAddr.IA, remoteAddr.Host)
			if err != nil {
				logbase.FatalContext(ctx, log, "failed to lookup paths",
					slog.Any("to", remoteAddr), slog.Any("error", err))
			}
			if len(ps) == 0 {
				logbase.FatalContext(ctx, log, "no paths available",
					slog.Any("to", remoteAddr))
			}
			log.LogAttrs(ctx, slog.LevelDebug,
				"available paths",
				slog.Any("to", remoteAddr),
				slog.Any("via", ps),
			)

			laddr := udp.UDPAddrFromSnet(localAddr)
			raddr := udp.UDPAddrFromSnet(remoteAddr)
			c := &client.SCIONClient{
				Log: log,
				// InterleavedMode: true,
				Histogram: hg,
			}

			if slices.Contains(authModes, "spao") {
				c.Auth.Enabled = true
				c.Auth.DRKeyFetcher = scion.NewDRKeyFetcher(cpc)
			}

			if slices.Contains(authModes, "nts") {
				ntskeHost, ntskePort, err := net.SplitHostPort(ntskeServer)
				if err != nil {
					logbase.FatalContext(ctx, log, "failed to split NTS-KE host and port",
						slog.Any("error", err))
				}
				c.Auth.NTSEnabled = true
				c.Auth.NTSKEFetcher.TLSConfig = tls.Config{
					InsecureSkipVerify: true,
					ServerName:         ntskeHost,
					MinVersion:         tls.VersionTLS13,
				}
				c.Auth.NTSKEFetcher.Port = ntskePort
				c.Auth.NTSKEFetcher.Log = log
				c.Auth.NTSKEFetcher.QUIC.Enabled = true
				c.Auth.NTSKEFetcher.QUIC.LocalAddr = laddr
				c.Auth.NTSKEFetcher.QUIC.RemoteAddr = raddr
				c.Auth.NTSKEFetcher.QUIC.ControlPlaneConnector = cpc
			}

			defer wg.Done()
			<-sg
			ntpcs := []*client.SCIONClient{c}
			for range numRequestPerClient {
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				_, _, err = client.MeasureClockOffsetSCION(ctx, log, ntpcs, laddr, raddr, ps)
				if err != nil {
					log.LogAttrs(ctx, slog.LevelInfo,
						"failed to measure clock offset",
						slog.Any("remote", raddr),
						slog.Any("error", err),
					)
				}
				cancel()
			}
			mu.Lock()
			defer mu.Unlock()
			_, _ = hg.PercentilesPrint(os.Stdout, 1, 1.0)
		}()
	}
	t0 := time.Now().UTC()
	close(sg)
	wg.Wait()
	log.LogAttrs(ctx, slog.LevelInfo, "time elapsed", slog.Duration("duration", time.Since(t0)))
}
