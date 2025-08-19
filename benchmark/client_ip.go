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

	"example.com/scion-time/base/logbase"

	"example.com/scion-time/core/client"
)

func RunIPBenchmark(localAddr, remoteAddr *net.UDPAddr, authModes []string, ntskeServer string, log *slog.Logger) {
	const numClientGoroutine = 100
	const numRequestPerClient = 10_000

	ctx := context.Background()
	dlog := slog.New(slog.DiscardHandler)

	var mu sync.Mutex
	sg := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numClientGoroutine)

	for range numClientGoroutine {
		go func() {
			var err error
			hg := hdrhistogram.New(1, 50000, 5)

			c := &client.IPClient{
				Log: dlog,
				// InterleavedMode: true,
				Histogram: hg,
			}

			if slices.Contains(authModes, "nts") {
				ntskeHost, ntskePort, err := net.SplitHostPort(ntskeServer)
				if err != nil {
					logbase.FatalContext(ctx, dlog, "failed to split NTS-KE host and port",
						slog.Any("error", err))
				}
				c.Auth.Enabled = true
				c.Auth.NTSKEFetcher.TLSConfig = tls.Config{
					InsecureSkipVerify: true,
					ServerName:         ntskeHost,
					MinVersion:         tls.VersionTLS13,
				}
				c.Auth.NTSKEFetcher.Port = ntskePort
				c.Auth.NTSKEFetcher.Log = dlog
			}

			defer wg.Done()
			<-sg
			for range numRequestPerClient + 5 {
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				_, _, err = client.MeasureClockOffsetIP(ctx, dlog, c, localAddr, remoteAddr)
				if err != nil {
					dlog.LogAttrs(ctx, slog.LevelInfo,
						"failed to measure clock offset",
						slog.Any("error", err),
					)
				}
				cancel()
			}
			if hg.TotalCount() < numRequestPerClient {
				mu.Lock()
				defer mu.Unlock()
				_, _ = hg.PercentilesPrint(os.Stdout, 1, 1.0)
			}
		}()
	}
	t0 := time.Now()
	close(sg)
	wg.Wait()
	log.LogAttrs(ctx, slog.LevelInfo, "time elapsed", slog.Duration("duration", time.Since(t0)))
}
