package benchmark

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"sync"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
	"go.uber.org/zap"

	"example.com/scion-time/core/client"
)

func RunIPBenchmark(localAddr, remoteAddr *net.UDPAddr, authModes []string, ntskeServer string, log *zap.Logger) {
	// const numClientGoroutine = 8
	// const numRequestPerClient = 10000
	const numClientGoroutine = 1
	const numRequestPerClient = 20_000
	var mu sync.Mutex
	sg := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numClientGoroutine)

	for i := numClientGoroutine; i > 0; i-- {
		go func() {
			var err error
			hg := hdrhistogram.New(1, 50000, 5)
			ctx := context.Background()

			c := &client.IPClient{
				InterleavedMode: true,
				Histo:           hg,
			}

			if contains(authModes, "nts") {
				ntskeHost, ntskePort, err := net.SplitHostPort(ntskeServer)
				if err != nil {
					log.Fatal("failed to split NTS-KE host and port", zap.Error(err))
				}
				c.Auth.Enabled = true
				c.Auth.NTSKEFetcher.TLSConfig = tls.Config{
					InsecureSkipVerify: true,
					ServerName:         ntskeHost,
					MinVersion:         tls.VersionTLS13,
				}
				c.Auth.NTSKEFetcher.Port = ntskePort
				c.Auth.NTSKEFetcher.Log = log
			}

			defer wg.Done()
			<-sg
			for j := numRequestPerClient; j > 0; j-- {
				_, err = client.MeasureClockOffsetIP(ctx, log, c, localAddr, remoteAddr)
				if err != nil {
					log.Info("failed to measure clock offset", zap.Error(err))
				}
			}
			mu.Lock()
			defer mu.Unlock()
			hg.PercentilesPrint(os.Stdout, 1, 1.0)
		}()
	}
	t0 := time.Now()
	close(sg)
	wg.Wait()
	log.Info(time.Since(t0).String())
}
