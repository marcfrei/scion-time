package main

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"testing"

	"example.com/scion-time/core/client"
	"example.com/scion-time/core/timebase"
	"example.com/scion-time/driver/clock"
	"github.com/scionproto/scion/pkg/snet"
)

func TestTimeserviceNTSChrony(t *testing.T) {
	hasChrony := os.Getenv("HAS_CHRONY")
	if hasChrony == "" {
		t.Skip("set up and start chrony to run this integration test")
	}

	initLogger(true /* verbose */)
	remoteAddr := "0-0,127.0.0.1:4460"
	localAddr := "0-0,0.0.0.0:0"
	ntskeServer := "127.0.0.1:4460"

	remoteAddrSnet := snet.UDPAddr{}
	err := remoteAddrSnet.Set(remoteAddr)
	if err != nil {
		t.Fatalf("failed to parse remote address %v", err)
	}

	localAddrSnet := snet.UDPAddr{}
	err = localAddrSnet.Set(localAddr)
	if err != nil {
		t.Fatalf("failed to parse local address %v", err)
	}

	ctx := context.Background()

	lclk := &clock.SystemClock{Log: log}
	timebase.RegisterClock(lclk)

	laddr := localAddrSnet.Host
	raddr := remoteAddrSnet.Host
	c := &client.IPClient{
		InterleavedMode: true,
	}

	ntskeHost, ntskePort, err := net.SplitHostPort(ntskeServer)
	if err != nil {
		t.Fatalf("failed to split NTS-KE host and port %v", err)
	}

	c.Auth.Enabled = true
	c.Auth.NTSKEFetcher.TLSConfig = tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ntskeHost,
		MinVersion:         tls.VersionTLS13,
	}
	c.Auth.NTSKEFetcher.Port = ntskePort
	c.Auth.NTSKEFetcher.Log = log

	_, err = client.MeasureClockOffsetIP(ctx, log, c, laddr, raddr)
	if err != nil {
		t.Fatalf("failed to measure clock offset %v", err)
	}
}
