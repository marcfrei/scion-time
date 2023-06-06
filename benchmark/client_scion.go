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

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"

	"example.com/scion-time/core/client"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

func newDaemonConnector(ctx context.Context, log *zap.Logger, daemonAddr string) daemon.Connector {
	if daemonAddr == "" {
		return nil
	}
	s := &daemon.Service{
		Address: daemonAddr,
	}
	c, err := s.Connect(ctx)
	if err != nil {
		log.Fatal("failed to create demon connector", zap.Error(err))
	}
	return c
}

func RunSCIONBenchmark(daemonAddr string, localAddr, remoteAddr *snet.UDPAddr, authModes []string, ntskeServer string, log *zap.Logger) {
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

			dc := newDaemonConnector(ctx, log, daemonAddr)

			var ps []snet.Path
			if remoteAddr.IA.Equal(localAddr.IA) {
				ps = []snet.Path{path.Path{
					Src:           remoteAddr.IA,
					Dst:           remoteAddr.IA,
					DataplanePath: path.Empty{},
				}}
			} else {
				ps, err = dc.Paths(ctx, remoteAddr.IA, localAddr.IA, daemon.PathReqFlags{Refresh: true})
				if err != nil {
					log.Fatal("failed to lookup paths", zap.Stringer("to", remoteAddr.IA), zap.Error(err))
				}
				if len(ps) == 0 {
					log.Fatal("no paths available", zap.Stringer("to", remoteAddr.IA))
				}
			}
			log.Debug("available paths", zap.Stringer("to", remoteAddr.IA), zap.Array("via", scion.PathArrayMarshaler{Paths: ps}))

			laddr := udp.UDPAddrFromSnet(localAddr)
			raddr := udp.UDPAddrFromSnet(remoteAddr)
			c := &client.SCIONClient{
				InterleavedMode: true,
				Histo:           hg,
			}

			if contains(authModes, "spao") {
				c.Auth.Enabled = true
				c.Auth.DRKeyFetcher = scion.NewFetcher(dc)
			}

			if contains(authModes, "nts") {
				ntskeHost, ntskePort, err := net.SplitHostPort(ntskeServer)
				if err != nil {
					log.Fatal("failed to split NTS-KE host and port", zap.Error(err))
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
				c.Auth.NTSKEFetcher.QUIC.DaemonAddr = daemonAddr
				c.Auth.NTSKEFetcher.QUIC.LocalAddr = laddr
				c.Auth.NTSKEFetcher.QUIC.RemoteAddr = raddr
			}

			defer wg.Done()
			<-sg
			ntpcs := []*client.SCIONClient{c}
			for j := numRequestPerClient; j > 0; j-- {
				_, err = client.MeasureClockOffsetSCION(ctx, log, ntpcs, laddr, raddr, ps)
				if err != nil {
					log.Info("failed to measure clock offset",
						zap.Stringer("remoteIA", raddr.IA),
						zap.Stringer("remoteHost", raddr.Host),
						zap.Error(err),
					)
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
