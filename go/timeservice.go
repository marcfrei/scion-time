// SCION time service

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/config"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"example.com/scion-time/go/core"
	"example.com/scion-time/go/core/timebase"
	"example.com/scion-time/go/core/timemath"

	"example.com/scion-time/go/drkeyutil"

	"example.com/scion-time/go/net/scion"
	"example.com/scion-time/go/net/udp"

	mbgd "example.com/scion-time/go/driver/mbg"
	ntpd "example.com/scion-time/go/driver/ntp"

	"example.com/scion-time/go/benchmark"
)

const (
	dispatcherModeExternal = "external"
	dispatcherModeInternal = "internal"

	refClockImpact       = 1.25
	refClockCutoff       = 0
	refClockSyncTimeout  = 5 * time.Second
	refClockSyncInterval = 10 * time.Second
	netClockImpact       = 2.5
	netClockCutoff       = time.Microsecond
	netClockSyncTimeout  = 5 * time.Second
	netClockSyncInterval = 60 * time.Second
)

type svcConfig struct {
	MBGReferenceClocks []string `toml:"mbg_reference_clocks,omitempty"`
	NTPReferenceClocks []string `toml:"ntp_reference_clocks,omitempty"`
	SCIONPeers         []string `toml:"scion_peers,omitempty"`
}

type mbgReferenceClock struct {
	log *zap.Logger
	dev string
}

type ntpReferenceClockIP struct {
	log        *zap.Logger
	localAddr  *net.UDPAddr
	remoteAddr *net.UDPAddr
}

type ntpReferenceClockSCION struct {
	log        *zap.Logger
	localAddr  udp.UDPAddr
	remoteAddr udp.UDPAddr
	pather     *core.Pather
}

type localReferenceClock struct{}

var (
	log = newLogger()

	refClocks       []core.ReferenceClock
	refClockOffsets []time.Duration
	refClockClient  = core.ReferenceClockClient{Log: log}
	netClocks       []core.ReferenceClock
	netClockOffsets []time.Duration
	netClockClient  = core.ReferenceClockClient{Log: log}
)

func newLogger() *zap.Logger {
	c := zap.NewDevelopmentConfig()
	c.DisableStacktrace = true
	c.EncoderConfig.EncodeCaller = func(
		caller zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
		// See https://github.com/scionproto/scion/blob/master/pkg/log/log.go
		p := caller.TrimmedPath()
		if len(p) > 30 {
			p = "..." + p[len(p)-27:]
		}
		enc.AppendString(fmt.Sprintf("%30s", p))
	}
	l, err := c.Build()
	if err != nil {
		panic(err)
	}
	return l
}

func runMonitor(log *zap.Logger) {
	p := pprof.Lookup("threadcreate")
	for {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		log.Debug("runtime stats",
			zap.Uint64("TotalAlloc", m.TotalAlloc),
			zap.Uint64("Mallocs", m.Mallocs),
			zap.Uint64("Frees", m.Frees),
			zap.Int("Thread Count", p.Count()),
		)
		time.Sleep(15 * time.Second)
	}
}

func (c *mbgReferenceClock) MeasureClockOffset(ctx context.Context) (time.Duration, error) {
	return mbgd.MeasureClockOffset(ctx, c.log, c.dev)
}

func (c *ntpReferenceClockIP) MeasureClockOffset(ctx context.Context) (time.Duration, error) {
	offset, _, err := ntpd.MeasureClockOffsetIP(ctx, c.log, c.localAddr, c.remoteAddr)
	return offset, err
}

func (c *ntpReferenceClockSCION) MeasureClockOffset(ctx context.Context) (time.Duration, error) {
	paths := c.pather.Paths(c.remoteAddr.IA)
	offset, err := core.MeasureClockOffsetSCION(ctx, c.log, c.localAddr, c.remoteAddr, paths)
	return offset, err
}

func (c *localReferenceClock) MeasureClockOffset(ctx context.Context) (time.Duration, error) {
	return 0, nil
}

func newDaemonConnector(ctx context.Context, log *zap.Logger, daemonAddr string) daemon.Connector {
	s := &daemon.Service{
		Address: daemonAddr,
	}
	c, err := s.Connect(ctx)
	if err != nil {
		log.Fatal("failed to create demon connector", zap.Error(err))
	}
	return c
}

func loadConfig(ctx context.Context, log *zap.Logger,
	configFile, daemonAddr string, localAddr *snet.UDPAddr) {
	if configFile != "" {
		var cfg svcConfig
		err := config.LoadFile(configFile, &cfg)
		if err != nil {
			log.Fatal("failed to load configuration", zap.Error(err))
		}
		for _, s := range cfg.MBGReferenceClocks {
			refClocks = append(refClocks, &mbgReferenceClock{
				log: log,
				dev: s,
			})
		}
		var dstIAs []addr.IA
		for _, s := range cfg.NTPReferenceClocks {
			remoteAddr, err := snet.ParseUDPAddr(s)
			if err != nil {
				log.Fatal("failed to parse reference clock address",
					zap.String("address", s), zap.Error(err))
			}
			if !remoteAddr.IA.IsZero() {
				refClocks = append(refClocks, &ntpReferenceClockSCION{
					log:        log,
					localAddr:  udp.UDPAddrFromSnet(localAddr),
					remoteAddr: udp.UDPAddrFromSnet(remoteAddr),
				})
				dstIAs = append(dstIAs, remoteAddr.IA)
			} else {
				refClocks = append(refClocks, &ntpReferenceClockIP{
					log:        log,
					localAddr:  localAddr.Host,
					remoteAddr: remoteAddr.Host,
				})
			}
		}
		for _, s := range cfg.SCIONPeers {
			remoteAddr, err := snet.ParseUDPAddr(s)
			if err != nil {
				log.Fatal("failed to parse peer address", zap.String("address", s), zap.Error(err))
			}
			if remoteAddr.IA.IsZero() {
				log.Fatal("unexpected peer address", zap.String("address", s), zap.Error(err))
			}
			netClocks = append(netClocks, &ntpReferenceClockSCION{
				log:        log,
				localAddr:  udp.UDPAddrFromSnet(localAddr),
				remoteAddr: udp.UDPAddrFromSnet(remoteAddr),
			})
			dstIAs = append(dstIAs, remoteAddr.IA)
		}
		if len(netClocks) != 0 {
			netClocks = append(netClocks, &localReferenceClock{})
		}
		if daemonAddr != "" {
			pather := core.StartPather(log, newDaemonConnector(ctx, log, daemonAddr), dstIAs)
			for _, c := range refClocks {
				scionclk, ok := c.(*ntpReferenceClockSCION)
				if ok {
					scionclk.pather = pather
				}
			}
			for _, c := range netClocks {
				scionclk, ok := c.(*ntpReferenceClockSCION)
				if ok {
					scionclk.pather = pather
				}
			}
		}
		refClockOffsets = make([]time.Duration, len(refClocks))
		netClockOffsets = make([]time.Duration, len(netClocks))
	}
}

func measureOffsetToRefClocks(timeout time.Duration) time.Duration {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	refClockClient.MeasureClockOffsets(ctx, refClocks, refClockOffsets)
	return timemath.Median(refClockOffsets)
}

func syncToRefClocks(lclk timebase.LocalClock) {
	corr := measureOffsetToRefClocks(refClockSyncTimeout)
	if corr != 0 {
		lclk.Step(corr)
	}
}

func runLocalClockSync(log *zap.Logger, lclk timebase.LocalClock) {
	if refClockImpact <= 1.0 {
		panic("invalid reference clock impact factor")
	}
	if refClockSyncInterval <= 0 {
		panic("invalid reference clock sync interval")
	}
	if refClockSyncTimeout < 0 || refClockSyncTimeout > refClockSyncInterval/2 {
		panic("invalid reference clock sync timeout")
	}
	maxCorr := refClockImpact * float64(lclk.MaxDrift(refClockSyncInterval))
	if maxCorr <= 0 {
		panic("invalid reference clock max correction")
	}
	pll := core.NewPLL(log, lclk)
	for {
		corr := measureOffsetToRefClocks(refClockSyncTimeout)
		if timemath.Abs(corr) > refClockCutoff {
			if float64(timemath.Abs(corr)) > maxCorr {
				corr = time.Duration(float64(timemath.Sign(corr)) * maxCorr)
			}
			// lclk.Adjust(corr, refClockSyncInterval, 0)
			pll.Do(corr, 1000.0 /* weight */)
		}
		lclk.Sleep(refClockSyncInterval)
	}
}

func measureOffsetToNetClocks(timeout time.Duration) time.Duration {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	netClockClient.MeasureClockOffsets(ctx, netClocks, netClockOffsets)
	return timemath.FaultTolerantMidpoint(netClockOffsets)
}

func runGlobalClockSync(log *zap.Logger, lclk timebase.LocalClock) {
	if netClockImpact <= 1.0 {
		panic("invalid network clock impact factor")
	}
	if netClockImpact-1.0 <= refClockImpact {
		panic("invalid network clock impact factor")
	}
	if netClockSyncInterval < refClockSyncInterval {
		panic("invalid network clock sync interval")
	}
	if netClockSyncTimeout < 0 || netClockSyncTimeout > netClockSyncInterval/2 {
		panic("invalid network clock sync timeout")
	}
	maxCorr := netClockImpact * float64(lclk.MaxDrift(netClockSyncInterval))
	if maxCorr <= 0 {
		panic("invalid network clock max correction")
	}
	pll := core.NewPLL(log, lclk)
	for {
		corr := measureOffsetToNetClocks(netClockSyncTimeout)
		if timemath.Abs(corr) > netClockCutoff {
			if float64(timemath.Abs(corr)) > maxCorr {
				corr = time.Duration(float64(timemath.Sign(corr)) * maxCorr)
			}
			// lclk.Adjust(corr, netClockSyncInterval, 0)
			pll.Do(corr, 1000.0 /* weight */)
		}
		lclk.Sleep(netClockSyncInterval)
	}
}

func runServer(configFile, daemonAddr string, localAddr *snet.UDPAddr) {
	ctx := context.Background()

	loadConfig(ctx, log, configFile, daemonAddr, localAddr)

	lclk := &core.SystemClock{Log: log}
	timebase.RegisterClock(lclk)

	if len(refClocks) != 0 {
		syncToRefClocks(lclk)
		go runLocalClockSync(log, lclk)
	}

	if len(netClocks) != 0 {
		go runGlobalClockSync(log, lclk)
	}

	core.StartIPServer(log, snet.CopyUDPAddr(localAddr.Host))
	core.StartSCIONServer(ctx, log, snet.CopyUDPAddr(localAddr.Host), daemonAddr)

	select {}
}

func runRelay(configFile, daemonAddr string, localAddr *snet.UDPAddr) {
	ctx := context.Background()

	loadConfig(ctx, log, configFile, daemonAddr, localAddr)

	lclk := &core.SystemClock{Log: log}
	timebase.RegisterClock(lclk)

	if len(refClocks) != 0 {
		syncToRefClocks(lclk)
		go runLocalClockSync(log, lclk)
	}

	if len(netClocks) != 0 {
		log.Fatal("unexpected configuration", zap.Int("number of peers", len(netClocks)))
	}

	core.StartIPServer(log, snet.CopyUDPAddr(localAddr.Host))
	core.StartSCIONServer(ctx, log, snet.CopyUDPAddr(localAddr.Host), daemonAddr)

	select {}
}

func runClient(configFile, daemonAddr string, localAddr *snet.UDPAddr) {
	ctx := context.Background()

	loadConfig(ctx, log, configFile, daemonAddr, localAddr)

	lclk := &core.SystemClock{Log: log}
	timebase.RegisterClock(lclk)

	scionClocksAvailable := false
	for _, c := range refClocks {
		_, ok := c.(*ntpReferenceClockSCION)
		if ok {
			scionClocksAvailable = true
			break
		}
	}
	if scionClocksAvailable {
		core.StartSCIONDisptacher(ctx, log, snet.CopyUDPAddr(localAddr.Host))
	}

	if len(refClocks) != 0 {
		syncToRefClocks(lclk)
		go runLocalClockSync(log, lclk)
	}

	if len(netClocks) != 0 {
		log.Fatal("unexpected configuration", zap.Int("number of peers", len(netClocks)))
	}

	select {}
}

func runIPTool(localAddr, remoteAddr *snet.UDPAddr) {
	var err error
	ctx := context.Background()

	lclk := &core.SystemClock{Log: log}
	timebase.RegisterClock(lclk)

	c := &ntpd.IPClient{
		Log:             log,
		InterleavedMode: true,
	}
	for n := 2; n != 0; n-- {
		_, _, err = c.MeasureClockOffsetIP(ctx, localAddr.Host, remoteAddr.Host)
		if err != nil {
			log.Fatal("failed to measure clock offset", zap.Stringer("to", remoteAddr.Host), zap.Error(err))
		}
		lclk.Sleep(125 * time.Microsecond)
	}
}

func runSCIONTool(daemonAddr, dispatcherMode string, localAddr, remoteAddr *snet.UDPAddr) {
	var err error
	ctx := context.Background()

	lclk := &core.SystemClock{Log: log}
	timebase.RegisterClock(lclk)

	if dispatcherMode == dispatcherModeInternal {
		core.StartSCIONDisptacher(ctx, log, snet.CopyUDPAddr(localAddr.Host))
	}

	dc := newDaemonConnector(ctx, log, daemonAddr)
	ps, err := dc.Paths(ctx, remoteAddr.IA, localAddr.IA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		log.Fatal("failed to lookup paths", zap.Stringer("to", remoteAddr.IA), zap.Error(err))
	}
	if len(ps) == 0 {
		log.Fatal("no paths available", zap.Stringer("to", remoteAddr.IA))
	}
	log.Debug("available paths", zap.Stringer("to", remoteAddr.IA), zap.Any("via", ps))

	sp := ps[0]
	log.Debug("selected path", zap.Stringer("to", remoteAddr.IA), zap.Any("via", sp))

	laddr := udp.UDPAddrFromSnet(localAddr)
	raddr := udp.UDPAddrFromSnet(remoteAddr)
	c := &ntpd.SCIONClient{
		Log:             log,
		InterleavedMode: true,
		DRKeyFetcher:    drkeyutil.NewFetcher(dc),
	}
	for n := 2; n != 0; n-- {
		_, _, err = c.MeasureClockOffsetSCION(ctx, laddr, raddr, sp)
		if err != nil {
			log.Fatal("failed to measure clock offset",
				zap.Stringer("remote IA", raddr.IA),
				zap.Stringer("remote host", raddr.Host),
				zap.Error(err),
			)
		}
		lclk.Sleep(125 * time.Microsecond)
	}
}

func runIPBenchmark(localAddr, remoteAddr *snet.UDPAddr) {
	lclk := &core.SystemClock{Log: zap.NewNop()}
	timebase.RegisterClock(lclk)
	benchmark.RunIPBenchmark(localAddr.Host, remoteAddr.Host)
}

func runSCIONBenchmark(daemonAddr string, localAddr, remoteAddr *snet.UDPAddr) {
	lclk := &core.SystemClock{Log: zap.NewNop()}
	timebase.RegisterClock(lclk)
	benchmark.RunSCIONBenchmark(daemonAddr, localAddr, remoteAddr)
}

func runDRKeyDemo(daemonAddr string, serverMode bool, serverAddr, clientAddr *snet.UDPAddr) {
	ctx := context.Background()
	dc := newDaemonConnector(ctx, log, daemonAddr)

	meta := drkey.HostHostMeta{
		ProtoId:  scion.DRKeyProtoIdTS,
		Validity: time.Now(),
		SrcIA:    serverAddr.IA,
		DstIA:    clientAddr.IA,
		SrcHost:  serverAddr.Host.IP.String(),
		DstHost:  clientAddr.Host.IP.String(),
	}

	if serverMode {
		sv, err := drkeyutil.FetchSecretValue(ctx, dc, drkey.SecretValueMeta{
			Validity: meta.Validity,
			ProtoId:  meta.ProtoId,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error fetching secret value:", err)
			return
		}
		t0 := time.Now()
		serverKey, err := drkeyutil.DeriveHostHostKey(sv, meta)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error deriving key:", err)
			return
		}
		durationServer := time.Since(t0)

		fmt.Printf(
			"Server,\thost key = %s\tduration = %s\n",
			hex.EncodeToString(serverKey.Key[:]),
			durationServer,
		)
	} else {
		t0 := time.Now()
		clientKey, err := dc.DRKeyGetHostHostKey(ctx, meta)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error fetching key:", err)
			return
		}
		durationClient := time.Since(t0)

		fmt.Printf(
			"Client,\thost key = %s\tduration = %s\n",
			hex.EncodeToString(clientKey.Key[:]),
			durationClient,
		)
	}
}

func exitWithUsage() {
	fmt.Println("<usage>")
	os.Exit(1)
}

func main() {
	go runMonitor(log)

	var configFile string
	var daemonAddr string
	var localAddr snet.UDPAddr
	var remoteAddr snet.UDPAddr
	var dispatcherMode string
	var drkeyMode string
	var drkeyServerAddr snet.UDPAddr
	var drkeyClientAddr snet.UDPAddr

	serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
	relayFlags := flag.NewFlagSet("relay", flag.ExitOnError)
	clientFlags := flag.NewFlagSet("client", flag.ExitOnError)
	toolFlags := flag.NewFlagSet("tool", flag.ExitOnError)
	benchmarkFlags := flag.NewFlagSet("benchmark", flag.ExitOnError)
	drkeyFlags := flag.NewFlagSet("drkey", flag.ExitOnError)

	serverFlags.StringVar(&configFile, "config", "", "Config file")
	serverFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	serverFlags.Var(&localAddr, "local", "Local address")

	relayFlags.StringVar(&configFile, "config", "", "Config file")
	relayFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	relayFlags.Var(&localAddr, "local", "Local address")

	clientFlags.StringVar(&configFile, "config", "", "Config file")
	clientFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	clientFlags.Var(&localAddr, "local", "Local address")

	toolFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	toolFlags.StringVar(&dispatcherMode, "dispatcher", "", "Dispatcher mode")
	toolFlags.Var(&localAddr, "local", "Local address")
	toolFlags.Var(&remoteAddr, "remote", "Remote address")

	benchmarkFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	benchmarkFlags.Var(&localAddr, "local", "Local address")
	benchmarkFlags.Var(&remoteAddr, "remote", "Remote address")

	drkeyFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	drkeyFlags.StringVar(&drkeyMode, "mode", "", "Mode")
	drkeyFlags.Var(&drkeyServerAddr, "server", "Server address")
	drkeyFlags.Var(&drkeyClientAddr, "client", "Client address")

	if len(os.Args) < 2 {
		exitWithUsage()
	}

	switch os.Args[1] {
	case serverFlags.Name():
		err := serverFlags.Parse(os.Args[2:])
		if err != nil || serverFlags.NArg() != 0 {
			exitWithUsage()
		}
		runServer(configFile, daemonAddr, &localAddr)
	case relayFlags.Name():
		err := relayFlags.Parse(os.Args[2:])
		if err != nil || relayFlags.NArg() != 0 {
			exitWithUsage()
		}
		runRelay(configFile, daemonAddr, &localAddr)
	case clientFlags.Name():
		err := clientFlags.Parse(os.Args[2:])
		if err != nil || clientFlags.NArg() != 0 {
			exitWithUsage()
		}
		runClient(configFile, daemonAddr, &localAddr)
	case toolFlags.Name():
		err := toolFlags.Parse(os.Args[2:])
		if err != nil || toolFlags.NArg() != 0 {
			exitWithUsage()
		}
		if !remoteAddr.IA.IsZero() {
			if dispatcherMode == "" {
				dispatcherMode = dispatcherModeExternal
			} else if dispatcherMode != dispatcherModeExternal &&
				dispatcherMode != dispatcherModeInternal {
				exitWithUsage()
			}
			runSCIONTool(daemonAddr, dispatcherMode, &localAddr, &remoteAddr)
		} else {
			if daemonAddr != "" {
				exitWithUsage()
			}
			if dispatcherMode != "" {
				exitWithUsage()
			}
			runIPTool(&localAddr, &remoteAddr)
		}
	case benchmarkFlags.Name():
		err := benchmarkFlags.Parse(os.Args[2:])
		if err != nil || benchmarkFlags.NArg() != 0 {
			exitWithUsage()
		}
		if !remoteAddr.IA.IsZero() {
			runSCIONBenchmark(daemonAddr, &localAddr, &remoteAddr)
		} else {
			if daemonAddr != "" {
				exitWithUsage()
			}
			runIPBenchmark(&localAddr, &remoteAddr)
		}
	case drkeyFlags.Name():
		err := drkeyFlags.Parse(os.Args[2:])
		if err != nil || drkeyFlags.NArg() != 0 {
			exitWithUsage()
		}
		if drkeyMode != "server" && drkeyMode != "client" {
			exitWithUsage()
		}
		serverMode := drkeyMode == "server"
		runDRKeyDemo(daemonAddr, serverMode, &drkeyServerAddr, &drkeyClientAddr)
	case "x":
		runX()
	default:
		exitWithUsage()
	}
}
