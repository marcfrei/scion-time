// Driver for quick experiments

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/core/client"
	"example.com/scion-time/core/server"
	"example.com/scion-time/core/timebase"
	"example.com/scion-time/driver/clocks"
	"example.com/scion-time/net/udp"
)

func runT() {
	var (
		laddr, raddr string
		dscp         uint
		periodic     bool
	)

	toolFlags := flag.NewFlagSet("tool", flag.ExitOnError)
	toolFlags.StringVar(&laddr, "local", "", "Local address")
	toolFlags.StringVar(&raddr, "remote", "", "Remote address")
	toolFlags.UintVar(&dscp, "dscp", 0, "Differentiated services codepoint, must be in range [0, 63]")
	toolFlags.BoolVar(&periodic, "periodic", false, "Perform periodic offset measurements")

	err := toolFlags.Parse(os.Args[2:])
	if err != nil || toolFlags.NArg() != 0 {
		panic("failed to parse arguments")
	}

	initLogger(logLevelVerbose)
	log := slog.Default()

	ctx := context.Background()

	lclk := clocks.NewSystemClock(log, clocks.UnknownDrift)
	timebase.RegisterClock(lclk)

	if raddr == "" {
		// Server mode
		var localAddr snet.UDPAddr
		if err := localAddr.Set(laddr); err != nil {
			panic("failed to parse local address")
		}
		if localAddr.IA.IsZero() {
			if ip4 := localAddr.Host.IP.To4(); ip4 != nil {
				localAddr.Host.IP = ip4
			}
			server.StartCSPTPServerIP(ctx, log, localAddr.Host, uint8(dscp))
		} else {
			server.StartCSPTPServerSCION(ctx, log, localAddr.Host, uint8(dscp))
		}
		select {}
	} else {
		// Client mode
		var localAddr snet.UDPAddr
		if err := localAddr.Set(laddr); err != nil {
			panic(fmt.Sprintf("failed to parse local address: %v", err))
		}
		var remoteAddr snet.UDPAddr
		if err = remoteAddr.Set(raddr); err != nil {
			panic(fmt.Sprintf("failed to parse remote address: %v", err))
		}
		if remoteAddr.IA.IsZero() {
			if ip4 := localAddr.Host.IP.To4(); ip4 != nil {
				localAddr.Host.IP = ip4
			}
			laddr, ok := netip.AddrFromSlice(localAddr.Host.IP)
			if !ok {
				panic("unexpected address type")
			}
			if ip4 := remoteAddr.Host.IP.To4(); ip4 != nil {
				remoteAddr.Host.IP = ip4
			}
			raddr, ok := netip.AddrFromSlice(remoteAddr.Host.IP)
			if !ok {
				panic("unexpected address type")
			}
			c := &client.CSPTPClientIP{
				Log:  log,
				DSCP: uint8(dscp),
			}
			for {
				ts, off, err := c.MeasureClockOffset(ctx, laddr, raddr)
				if err != nil {
					logbase.Fatal(slog.Default(), "failed to measure clock offset", slog.Any("remote", raddr), slog.Any("error", err))
				}
				if !periodic {
					break
				}
				fmt.Printf("%s,%+.9f\n", ts.UTC().Format(time.RFC3339), off.Seconds())
				lclk.Sleep(1 * time.Second)
			}
		} else {
			if remoteAddr.IA != localAddr.IA {
				panic("not yet implemented")
			}
			laddr := udp.UDPAddrFromSnet(&localAddr)
			raddr := udp.UDPAddrFromSnet(&remoteAddr)
			p := path.Path{
				Src:           localAddr.IA,
				Dst:           remoteAddr.IA,
				DataplanePath: path.Empty{},
				NextHop:       remoteAddr.Host,
			}
			c := &client.CSPTPClientSCION{
				Log:  log,
				DSCP: uint8(dscp),
			}
			for {
				ts, off, err := c.MeasureClockOffset(ctx, laddr, raddr, p)
				if err != nil {
					logbase.Fatal(slog.Default(), "failed to measure clock offset", slog.Any("remote", raddr), slog.Any("error", err))
				}
				if !periodic {
					break
				}
				fmt.Printf("%s,%+.9f\n", ts.UTC().Format(time.RFC3339), off.Seconds())
				lclk.Sleep(1 * time.Second)
			}
		}
	}
}
