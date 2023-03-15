// SCION time service

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pelletier/go-toml"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/snet"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"example.com/scion-time/benchmark"

	"example.com/scion-time/core/client"
	"example.com/scion-time/core/server"
	"example.com/scion-time/core/sync"
	"example.com/scion-time/core/timebase"

	"example.com/scion-time/driver/clock"
	"example.com/scion-time/driver/mbg"

	"example.com/scion-time/net/ntske"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

const (
	dispatcherModeExternal = "external"
	dispatcherModeInternal = "internal"
	authModeNTS            = "nts"

	scionRefClockNumClient = 5
)

type svcConfig struct {
	MBGReferenceClocks []string `toml:"mbg_reference_clocks,omitempty"`
	NTPReferenceClocks []string `toml:"ntp_reference_clocks,omitempty"`
	SCIONPeers         []string `toml:"scion_peers,omitempty"`
}

type mbgReferenceClock struct {
	dev string
}

type ntpReferenceClockIP struct {
	ntpc       *client.IPClient
	localAddr  *net.UDPAddr
	remoteAddr *net.UDPAddr
}

type ntpReferenceClockSCION struct {
	ntpcs      [scionRefClockNumClient]*client.SCIONClient
	localAddr  udp.UDPAddr
	remoteAddr udp.UDPAddr
	pather     *scion.Pather
}

var (
	log *zap.Logger
)

func initLogger(verbose bool) {
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
	if !verbose {
		c.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	var err error
	log, err = c.Build()
	if err != nil {
		panic(err)
	}
}

func runMonitor(log *zap.Logger) {
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe("127.0.0.1:8080", nil)
	log.Fatal("failed to serve metrics", zap.Error(err))
}

func (c *mbgReferenceClock) MeasureClockOffset(ctx context.Context, log *zap.Logger) (
	time.Duration, error) {
	return mbg.MeasureClockOffset(ctx, log, c.dev)
}

func newNTPRefernceClockIP(localAddr, remoteAddr *net.UDPAddr) *ntpReferenceClockIP {
	c := &ntpReferenceClockIP{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
	c.ntpc = &client.IPClient{
		InterleavedMode: true,
	}
	return c
}

func (c *ntpReferenceClockIP) MeasureClockOffset(ctx context.Context, log *zap.Logger) (
	time.Duration, error) {
	return client.MeasureClockOffsetIP(ctx, log, c.ntpc, c.localAddr, c.remoteAddr)
}

func newNTPRefernceClockSCION(localAddr, remoteAddr udp.UDPAddr) *ntpReferenceClockSCION {
	c := &ntpReferenceClockSCION{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
	for i := 0; i != len(c.ntpcs); i++ {
		c.ntpcs[i] = &client.SCIONClient{
			InterleavedMode: true,
		}
	}
	return c
}

func (c *ntpReferenceClockSCION) MeasureClockOffset(ctx context.Context, log *zap.Logger) (
	time.Duration, error) {
	paths := c.pather.Paths(c.remoteAddr.IA)
	return client.MeasureClockOffsetSCION(ctx, log, c.ntpcs[:], c.localAddr, c.remoteAddr, paths)
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
	configFile, daemonAddr string, localAddr *snet.UDPAddr) (
	refClocks, netClocks []client.ReferenceClock) {
	if configFile != "" {
		var cfg svcConfig
		raw, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatal("failed to load configuration", zap.Error(err))
		}
		err = toml.NewDecoder(bytes.NewReader(raw)).Strict(true).Decode(&cfg)
		if err != nil {
			log.Fatal("failed to decode configuration", zap.Error(err))
		}
		for _, s := range cfg.MBGReferenceClocks {
			refClocks = append(refClocks, &mbgReferenceClock{
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
				refClocks = append(refClocks, newNTPRefernceClockSCION(
					udp.UDPAddrFromSnet(localAddr),
					udp.UDPAddrFromSnet(remoteAddr),
				))
				dstIAs = append(dstIAs, remoteAddr.IA)
			} else {
				refClocks = append(refClocks, newNTPRefernceClockIP(
					localAddr.Host,
					remoteAddr.Host,
				))
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
			netClocks = append(netClocks, newNTPRefernceClockSCION(
				udp.UDPAddrFromSnet(localAddr),
				udp.UDPAddrFromSnet(remoteAddr),
			))
			dstIAs = append(dstIAs, remoteAddr.IA)
		}
		if daemonAddr != "" {
			ctx := context.Background()
			pather := scion.StartPather(ctx, log, daemonAddr, dstIAs)
			drkeyFetcher := scion.NewFetcher(newDaemonConnector(ctx, log, daemonAddr))
			for _, c := range refClocks {
				scionclk, ok := c.(*ntpReferenceClockSCION)
				if ok {
					scionclk.pather = pather
					for i := 0; i != len(scionclk.ntpcs); i++ {
						scionclk.ntpcs[i].DRKeyFetcher = drkeyFetcher
					}
				}
			}
			for _, c := range netClocks {
				scionclk, ok := c.(*ntpReferenceClockSCION)
				if ok {
					scionclk.pather = pather
					for i := 0; i != len(scionclk.ntpcs); i++ {
						scionclk.ntpcs[i].DRKeyFetcher = drkeyFetcher
					}
				}
			}
		}
	}
	return
}

func runServer(configFile, daemonAddr string, localAddr *snet.UDPAddr) {
	ctx := context.Background()

	refClocks, netClocks := loadConfig(ctx, log, configFile, daemonAddr, localAddr)
	sync.RegisterClocks(refClocks, netClocks)

	lclk := &clock.SystemClock{Log: log}
	timebase.RegisterClock(lclk)

	if len(refClocks) != 0 {
		sync.SyncToRefClocks(log, lclk)
		go sync.RunLocalClockSync(log, lclk)
	}

	if len(netClocks) != 0 {
		go sync.RunGlobalClockSync(log, lclk)
	}

	server.StartIPServer(ctx, log, snet.CopyUDPAddr(localAddr.Host))
	server.StartSCIONServer(ctx, log, daemonAddr, snet.CopyUDPAddr(localAddr.Host))

	runMonitor(log)
}

func runRelay(configFile, daemonAddr string, localAddr *snet.UDPAddr) {
	ctx := context.Background()

	refClocks, netClocks := loadConfig(ctx, log, configFile, daemonAddr, localAddr)
	sync.RegisterClocks(refClocks, netClocks)

	lclk := &clock.SystemClock{Log: log}
	timebase.RegisterClock(lclk)

	if len(refClocks) != 0 {
		sync.SyncToRefClocks(log, lclk)
		go sync.RunLocalClockSync(log, lclk)
	}

	if len(netClocks) != 0 {
		log.Fatal("unexpected configuration", zap.Int("number of peers", len(netClocks)))
	}

	server.StartIPServer(ctx, log, snet.CopyUDPAddr(localAddr.Host))
	server.StartSCIONServer(ctx, log, daemonAddr, snet.CopyUDPAddr(localAddr.Host))

	runMonitor(log)
}

func runClient(configFile, daemonAddr string, localAddr *snet.UDPAddr) {
	ctx := context.Background()

	refClocks, netClocks := loadConfig(ctx, log, configFile, daemonAddr, localAddr)
	sync.RegisterClocks(refClocks, netClocks)

	lclk := &clock.SystemClock{Log: log}
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
		server.StartSCIONDisptacher(ctx, log, snet.CopyUDPAddr(localAddr.Host))
	}

	if len(refClocks) != 0 {
		sync.SyncToRefClocks(log, lclk)
		go sync.RunLocalClockSync(log, lclk)
	}

	if len(netClocks) != 0 {
		log.Fatal("unexpected configuration", zap.Int("number of peers", len(netClocks)))
	}

	runMonitor(log)
}

func runIPTool(localAddr, remoteAddr *snet.UDPAddr, authMode string, NTSKEServerAddr string, skipTLSValidation bool) {
	var err error
	ctx := context.Background()

	lclk := &clock.SystemClock{Log: log}
	timebase.RegisterClock(lclk)

	laddr := localAddr.Host
	raddr := remoteAddr.Host
	c := &client.IPClient{
		InterleavedMode: true,
	}
	if authMode == authModeNTS {
		c.Auth.Enabled = true
		tlsconfig := &tls.Config{}
		// For testing do not verify tls certificate
		// CHANGE IN PRODUCTION VERSION
		tlsconfig.InsecureSkipVerify = skipTLSValidation
		tlsconfig.ServerName = NTSKEServerAddr

		ke, err := ntske.ExchangeKeys(tlsconfig, true, log)
		if err != nil {
			log.Error("NTS-KE exchange error: ", zap.Error(err))
		}
		c.Auth.KeyExchangeNTS = ke

	} else {
		c.Auth.Enabled = false
	}

	_, err = client.MeasureClockOffsetIP(ctx, log, c, laddr, raddr)
	if err != nil {
		log.Fatal("failed to measure clock offset", zap.Stringer("to", raddr), zap.Error(err))
	}
}

func runSCIONTool(daemonAddr, dispatcherMode string, localAddr, remoteAddr *snet.UDPAddr) {
	var err error
	ctx := context.Background()

	lclk := &clock.SystemClock{Log: log}
	timebase.RegisterClock(lclk)

	if dispatcherMode == dispatcherModeInternal {
		server.StartSCIONDisptacher(ctx, log, snet.CopyUDPAddr(localAddr.Host))
	}

	dc := newDaemonConnector(ctx, log, daemonAddr)
	ps, err := dc.Paths(ctx, remoteAddr.IA, localAddr.IA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		log.Fatal("failed to lookup paths", zap.Stringer("to", remoteAddr.IA), zap.Error(err))
	}
	if len(ps) == 0 {
		log.Fatal("no paths available", zap.Stringer("to", remoteAddr.IA))
	}
	log.Debug("available paths", zap.Stringer("to", remoteAddr.IA), zap.Array("via", scion.PathArrayMarshaler{Paths: ps}))

	laddr := udp.UDPAddrFromSnet(localAddr)
	raddr := udp.UDPAddrFromSnet(remoteAddr)
	cs := []*client.SCIONClient{{
		InterleavedMode: true,
		DRKeyFetcher:    scion.NewFetcher(dc),
	}}
	_, err = client.MeasureClockOffsetSCION(ctx, log, cs, laddr, raddr, ps)
	if err != nil {
		log.Fatal("failed to measure clock offset",
			zap.Stringer("remoteIA", raddr.IA),
			zap.Stringer("remoteHost", raddr.Host),
			zap.Error(err),
		)
	}
}

func runIPBenchmark(localAddr, remoteAddr *snet.UDPAddr) {
	lclk := &clock.SystemClock{Log: zap.NewNop()}
	timebase.RegisterClock(lclk)
	benchmark.RunIPBenchmark(localAddr.Host, remoteAddr.Host)
}

func runSCIONBenchmark(daemonAddr string, localAddr, remoteAddr *snet.UDPAddr) {
	lclk := &clock.SystemClock{Log: zap.NewNop()}
	timebase.RegisterClock(lclk)
	benchmark.RunSCIONBenchmark(daemonAddr, localAddr, remoteAddr)
}

func runDRKeyDemo(daemonAddr string, serverMode bool, serverAddr, clientAddr *snet.UDPAddr) {
	ctx := context.Background()
	dc := newDaemonConnector(ctx, log, daemonAddr)

	if serverMode {
		hostASMeta := drkey.HostASMeta{
			ProtoId:  123,
			Validity: time.Now(),
			SrcIA:    serverAddr.IA,
			DstIA:    clientAddr.IA,
			SrcHost:  serverAddr.Host.IP.String(),
		}
		hostASKey, err := scion.FetchHostASKey(ctx, dc, hostASMeta)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error fetching host-AS key:", err)
			return
		}
		t0 := time.Now()
		serverKey, err := scion.DeriveHostHostKey(hostASKey, clientAddr.Host.IP.String())
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error deriving host-host key:", err)
		}
		durationServer := time.Since(t0)
		fmt.Printf(
			"Server\thost key = %s\tduration = %s\n",
			hex.EncodeToString(serverKey.Key[:]),
			durationServer,
		)
	} else {
		hostHostMeta := drkey.HostHostMeta{
			ProtoId:  123,
			Validity: time.Now(),
			SrcIA:    serverAddr.IA,
			DstIA:    clientAddr.IA,
			SrcHost:  serverAddr.Host.IP.String(),
			DstHost:  clientAddr.Host.IP.String(),
		}
		t0 := time.Now()
		clientKey, err := scion.FetchHostHostKey(ctx, dc, hostHostMeta)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error fetching host-host key:", err)
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
	var (
		verbose           bool
		configFile        string
		daemonAddr        string
		localAddr         snet.UDPAddr
		remoteAddr        snet.UDPAddr
		dispatcherMode    string
		drkeyMode         string
		drkeyServerAddr   snet.UDPAddr
		drkeyClientAddr   snet.UDPAddr
		authMode          string
		ntskeServerAddr   string
		skipTLSValidation bool
	)

	serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
	relayFlags := flag.NewFlagSet("relay", flag.ExitOnError)
	clientFlags := flag.NewFlagSet("client", flag.ExitOnError)
	toolFlags := flag.NewFlagSet("tool", flag.ExitOnError)
	benchmarkFlags := flag.NewFlagSet("benchmark", flag.ExitOnError)
	drkeyFlags := flag.NewFlagSet("drkey", flag.ExitOnError)

	serverFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	serverFlags.StringVar(&configFile, "config", "", "Config file")
	serverFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	serverFlags.Var(&localAddr, "local", "Local address")

	relayFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	relayFlags.StringVar(&configFile, "config", "", "Config file")
	relayFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	relayFlags.Var(&localAddr, "local", "Local address")

	clientFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	clientFlags.StringVar(&configFile, "config", "", "Config file")
	clientFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	clientFlags.Var(&localAddr, "local", "Local address")

	toolFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	toolFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	toolFlags.StringVar(&dispatcherMode, "dispatcher", "", "Dispatcher mode")
	toolFlags.Var(&localAddr, "local", "Local address")
	toolFlags.Var(&remoteAddr, "remote", "Remote address")
	toolFlags.StringVar(&authMode, "auth", "", "Authentication mode")
	toolFlags.StringVar(&ntskeServerAddr, "ntskeServer", "", "NTSKE server address")
	toolFlags.BoolVar(&skipTLSValidation, "skipTLSValidation", false, "Skip TLS certificate validation")

	benchmarkFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	benchmarkFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	benchmarkFlags.Var(&localAddr, "local", "Local address")
	benchmarkFlags.Var(&remoteAddr, "remote", "Remote address")

	drkeyFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
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
		initLogger(verbose)
		runServer(configFile, daemonAddr, &localAddr)
	case relayFlags.Name():
		err := relayFlags.Parse(os.Args[2:])
		if err != nil || relayFlags.NArg() != 0 {
			exitWithUsage()
		}
		initLogger(verbose)
		runRelay(configFile, daemonAddr, &localAddr)
	case clientFlags.Name():
		err := clientFlags.Parse(os.Args[2:])
		if err != nil || clientFlags.NArg() != 0 {
			exitWithUsage()
		}
		initLogger(verbose)
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
			initLogger(verbose)
			runSCIONTool(daemonAddr, dispatcherMode, &localAddr, &remoteAddr)
		} else {
			if daemonAddr != "" {
				exitWithUsage()
			}
			if dispatcherMode != "" {
				exitWithUsage()
			}
			initLogger(verbose)
			runIPTool(&localAddr, &remoteAddr, authMode, ntskeServerAddr, skipTLSValidation)

		}
	case benchmarkFlags.Name():
		err := benchmarkFlags.Parse(os.Args[2:])
		if err != nil || benchmarkFlags.NArg() != 0 {
			exitWithUsage()
		}
		if !remoteAddr.IA.IsZero() {
			initLogger(verbose)
			runSCIONBenchmark(daemonAddr, &localAddr, &remoteAddr)
		} else {
			if daemonAddr != "" {
				exitWithUsage()
			}
			initLogger(verbose)
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
		initLogger(verbose)
		runDRKeyDemo(daemonAddr, serverMode, &drkeyServerAddr, &drkeyClientAddr)
	case "x":
		runX()
	default:
		exitWithUsage()
	}
}
