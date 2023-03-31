package main

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"

	"example.com/scion-time/core/client"
	"example.com/scion-time/core/timebase"
	"example.com/scion-time/driver/clock"
	"github.com/scionproto/scion/pkg/snet"
)

func TestTimeserviceNTSChrony(t *testing.T) {
	initLogger(true)
	remoteAddr := "0-0,127.0.0.1:4460"
	localAddr := "0-0,0.0.0.0:0"
	ntskeServer := "127.0.0.1:4460"

	remoteAddrSnet := snet.UDPAddr{}
	err := remoteAddrSnet.Set(remoteAddr)
	if err != nil {
		t.Fatalf("address parsing failed %v", err)
	}

	localAddrSnet := snet.UDPAddr{}
	err = localAddrSnet.Set(localAddr)
	if err != nil {
		t.Fatalf("address parsing failed %v", err)
	}
	ctx := context.Background()

	lclk := &clock.SystemClock{Log: log}
	timebase.RegisterClock(lclk)

	laddr := localAddrSnet.Host
	raddr := remoteAddrSnet.Host
	c := &client.IPClient{
		InterleavedMode: true,
	}

	ntskeServerName := strings.Split(ntskeServer, ":")[0]
	c.Auth.Enabled = true
	c.Auth.NTSKEFetcher.TLSConfig = tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ntskeServerName,
		MinVersion:         tls.VersionTLS13,
	}
	c.Auth.NTSKEFetcher.Port = strings.Split(ntskeServer, ":")[1]
	c.Auth.NTSKEFetcher.Log = log

	_, err = client.MeasureClockOffsetIP(ctx, log, c, laddr, raddr)
	if err != nil {
		t.Fatalf("request to chrony failed %v", err)
	}
}
