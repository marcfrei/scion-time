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
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"

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

	tlsCertReloadInterval = time.Minute * 10

	scionRefClockNumClient = 5
)

type svcConfig struct {
	LocalAddress            string   `toml:"local_address,omitempty"`
	DaemonAddress           string   `toml:"daemon_address,omitempty"`
	RemoteAddress           string   `toml:"remote_address,omitempty"`
	MBGReferenceClocks      []string `toml:"mbg_reference_clocks,omitempty"`
	NTPReferenceClocks      []string `toml:"ntp_reference_clocks,omitempty"`
	SCIONPeers              []string `toml:"scion_peers,omitempty"`
	NTSKECertFile           string   `toml:"ntske_cert_file,omitempty"`
	NTSKEKeyFile            string   `toml:"ntske_key_file,omitempty"`
	NTSKEServerName         string   `toml:"ntske_server_name,omitempty"`
	AuthMode                string   `toml:"auth_mode,omitempty"`
	NTSKEInsecureSkipVerify bool     `toml:"ntske_insecure_skip_verify,omitempty"`
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

type tlsCertCache struct {
	cert       *tls.Certificate
	reloadedAt time.Time
	certFile   string
	keyFile    string
}

func (c *tlsCertCache) loadCert(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	now := time.Now()
	if now.Before(c.reloadedAt) || !now.Before(c.reloadedAt.Add(tlsCertReloadInterval)) {
		cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
		if err != nil {
			return &tls.Certificate{}, err
		}
		c.cert = &cert
		c.reloadedAt = now
	}
	return c.cert, nil
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

func configureIPClientNTS(c *client.IPClient, ntskeServer string, ntskeInsecureSkipVerify bool) {
	ntskeHost, ntskePort, err := net.SplitHostPort(ntskeServer)
	if err != nil {
		log.Fatal("failed to split NTS-KE host and port", zap.Error(err))
	}
	c.Auth.Enabled = true
	c.Auth.NTSKEFetcher.TLSConfig = tls.Config{
		InsecureSkipVerify: ntskeInsecureSkipVerify,
		ServerName:         ntskeHost,
		MinVersion:         tls.VersionTLS13,
	}
	c.Auth.NTSKEFetcher.Port = ntskePort
	c.Auth.NTSKEFetcher.Log = log
}

func newNTPReferenceClockIP(localAddr, remoteAddr *net.UDPAddr, authMode, ntskeServer string, ntskeInsecureSkipVerify bool) *ntpReferenceClockIP {
	c := &ntpReferenceClockIP{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
	c.ntpc = &client.IPClient{
		InterleavedMode: true,
	}
	if authMode == authModeNTS {
		configureIPClientNTS(c.ntpc, ntskeServer, ntskeInsecureSkipVerify)
	}
	return c
}

func (c *ntpReferenceClockIP) MeasureClockOffset(ctx context.Context, log *zap.Logger) (
	time.Duration, error) {
	return client.MeasureClockOffsetIP(ctx, log, c.ntpc, c.localAddr, c.remoteAddr)
}

func configureSCIONClientNTS(c *client.SCIONClient, ntskeServer string, ntskeInsecureSkipVerify bool) {
	ntskeHost, ntskePort, err := net.SplitHostPort(ntskeServer)
	if err != nil {
		log.Fatal("failed to split NTS-KE host and port", zap.Error(err))
	}
	c.Auth.NTSEnabled = true
	c.Auth.NTSKEFetcher.TLSConfig = tls.Config{
		InsecureSkipVerify: ntskeInsecureSkipVerify,
		ServerName:         ntskeHost,
		MinVersion:         tls.VersionTLS13,
	}
	c.Auth.NTSKEFetcher.Port = ntskePort
	c.Auth.NTSKEFetcher.Log = log
}

func newNTPReferenceClockSCION(localAddr, remoteAddr udp.UDPAddr, authMode, ntskeServer string, ntskeInsecureSkipVerify bool) *ntpReferenceClockSCION {
	c := &ntpReferenceClockSCION{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
	for i := 0; i != len(c.ntpcs); i++ {
		c.ntpcs[i] = &client.SCIONClient{
			InterleavedMode: true,
		}
		if authMode == authModeNTS {
			configureSCIONClientNTS(c.ntpcs[i], ntskeServer, ntskeInsecureSkipVerify)
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

func loadConfig(log *zap.Logger, configFile string) svcConfig {
	raw, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatal("failed to load configuration", zap.Error(err))
	}
	var cfg svcConfig
	err = toml.NewDecoder(bytes.NewReader(raw)).DisallowUnknownFields().Decode(&cfg)
	if err != nil {
		log.Fatal("failed to decode configuration", zap.Error(err))
	}
	return cfg
}

func localAddress(log *zap.Logger, cfg svcConfig) *snet.UDPAddr {
	if cfg.LocalAddress == "" {
		log.Fatal("local_address not specified in config")
	}
	var localAddr snet.UDPAddr
	err := localAddr.Set(cfg.LocalAddress)
	if err != nil {
		log.Fatal("failed to parse local address")
	}
	return &localAddr
}

func remoteAddress(log *zap.Logger, cfg svcConfig) *snet.UDPAddr {
	if cfg.RemoteAddress == "" {
		log.Fatal("remote_address not specified in config")
	}
	var remoteAddr snet.UDPAddr
	err := remoteAddr.Set(cfg.RemoteAddress)
	if err != nil {
		log.Fatal("failed to parse remote address")
	}
	return &remoteAddr
}

func referenceClocks(ctx context.Context, log *zap.Logger, cfg svcConfig, localAddr *snet.UDPAddr) (
	refClocks, netClocks []client.ReferenceClock) {

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
		ntskeServer := strings.Split(s, ",")[1]
		if !remoteAddr.IA.IsZero() {
			refClocks = append(refClocks, newNTPReferenceClockSCION(
				udp.UDPAddrFromSnet(localAddr),
				udp.UDPAddrFromSnet(remoteAddr),
				cfg.AuthMode,
				ntskeServer,
				cfg.NTSKEInsecureSkipVerify,
			))
			dstIAs = append(dstIAs, remoteAddr.IA)
		} else {
			refClocks = append(refClocks, newNTPReferenceClockIP(
				localAddr.Host,
				remoteAddr.Host,
				cfg.AuthMode,
				ntskeServer,
				cfg.NTSKEInsecureSkipVerify,
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
		ntskeServer := strings.Split(s, ",")[1]
		netClocks = append(netClocks, newNTPReferenceClockSCION(
			udp.UDPAddrFromSnet(localAddr),
			udp.UDPAddrFromSnet(remoteAddr),
			cfg.AuthMode,
			ntskeServer,
			cfg.NTSKEInsecureSkipVerify,
		))
		dstIAs = append(dstIAs, remoteAddr.IA)
	}

	if cfg.DaemonAddress != "" {
		ctx := context.Background()
		pather := scion.StartPather(ctx, log, cfg.DaemonAddress, dstIAs)
		drkeyFetcher := scion.NewFetcher(newDaemonConnector(ctx, log, cfg.DaemonAddress))
		for _, c := range refClocks {
			scionclk, ok := c.(*ntpReferenceClockSCION)
			if ok {
				scionclk.pather = pather
				for i := 0; i != len(scionclk.ntpcs); i++ {
					scionclk.ntpcs[i].Auth.Enabled = true
					scionclk.ntpcs[i].Auth.DRKeyFetcher = drkeyFetcher
				}
			}
		}
		for _, c := range netClocks {
			scionclk, ok := c.(*ntpReferenceClockSCION)
			if ok {
				scionclk.pather = pather
				for i := 0; i != len(scionclk.ntpcs); i++ {
					scionclk.ntpcs[i].Auth.Enabled = true
					scionclk.ntpcs[i].Auth.DRKeyFetcher = drkeyFetcher
				}
			}
		}
	}

	return
}

func tlsConfig(log *zap.Logger, cfg svcConfig) *tls.Config {
	if cfg.NTSKEServerName == "" || cfg.NTSKECertFile == "" || cfg.NTSKEKeyFile == "" {
		log.Fatal("missing parameters in configuration for NTSKE server")
	}
	certCache := tlsCertCache{
		certFile: cfg.NTSKECertFile,
		keyFile:  cfg.NTSKEKeyFile,
	}
	return &tls.Config{
		ServerName:     cfg.NTSKEServerName,
		NextProtos:     []string{"ntske/1"},
		GetCertificate: certCache.loadCert,
		MinVersion:     tls.VersionTLS13,
	}
}

func runServer(configFile string) {
	ctx := context.Background()

	cfg := loadConfig(log, configFile)
	localAddr := localAddress(log, cfg)
	daemonAddr := cfg.DaemonAddress
	refClocks, netClocks := referenceClocks(ctx, log, cfg, localAddr)
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

	tlsConfig := tlsConfig(log, cfg)
	provider := ntske.NewProvider()

	server.StartNTSKEServer(ctx, log, snet.CopyUDPAddr(localAddr.Host), tlsConfig, provider)
	server.StartIPServer(ctx, log, snet.CopyUDPAddr(localAddr.Host), provider)
	server.StartSCIONServer(ctx, log, daemonAddr, snet.CopyUDPAddr(localAddr.Host), provider)

	runMonitor(log)
}

func runRelay(configFile string) {
	ctx := context.Background()

	cfg := loadConfig(log, configFile)
	localAddr := localAddress(log, cfg)
	daemonAddr := cfg.DaemonAddress
	refClocks, netClocks := referenceClocks(ctx, log, cfg, localAddr)
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

	tlsConfig := tlsConfig(log, cfg)
	provider := ntske.NewProvider()

	server.StartNTSKEServer(ctx, log, snet.CopyUDPAddr(localAddr.Host), tlsConfig, provider)
	server.StartIPServer(ctx, log, snet.CopyUDPAddr(localAddr.Host), provider)
	server.StartSCIONServer(ctx, log, daemonAddr, snet.CopyUDPAddr(localAddr.Host), provider)

	runMonitor(log)
}

func runClient(configFile string) {
	ctx := context.Background()

	cfg := loadConfig(log, configFile)
	localAddr := localAddress(log, cfg)
	refClocks, netClocks := referenceClocks(ctx, log, cfg, localAddr)
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
		server.StartSCIONDispatcher(ctx, log, snet.CopyUDPAddr(localAddr.Host))
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

func runIPTool(localAddr, remoteAddr *snet.UDPAddr, authMode,
	ntskeServer string, ntskeInsecureSkipVerify bool) {
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
		configureIPClientNTS(c, ntskeServer, ntskeInsecureSkipVerify)
	}

	_, err = client.MeasureClockOffsetIP(ctx, log, c, laddr, raddr)
	if err != nil {
		log.Fatal("failed to measure clock offset", zap.Stringer("to", raddr), zap.Error(err))
	}
}

func runSCIONTool(daemonAddr, dispatcherMode string, localAddr, remoteAddr *snet.UDPAddr,
	authMode, ntskeServer string, ntskeInsecureSkipVerify bool) {
	var err error
	ctx := context.Background()

	lclk := &clock.SystemClock{Log: log}
	timebase.RegisterClock(lclk)

	if dispatcherMode == dispatcherModeInternal {
		server.StartSCIONDispatcher(ctx, log, snet.CopyUDPAddr(localAddr.Host))
	}

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
	}
	c.Auth.Enabled = true
	c.Auth.DRKeyFetcher = scion.NewFetcher(dc)

	if authMode == authModeNTS {
		configureSCIONClientNTS(c, ntskeServer, ntskeInsecureSkipVerify)
	}

	_, err = client.MeasureClockOffsetSCION(ctx, log, []*client.SCIONClient{c}, laddr, raddr, ps)
	if err != nil {
		log.Fatal("failed to measure clock offset",
			zap.Stringer("remoteIA", raddr.IA),
			zap.Stringer("remoteHost", raddr.Host),
			zap.Error(err),
		)
	}
}

func runBenchmark(configFile string) {
	cfg := loadConfig(log, configFile)
	localAddr := localAddress(log, cfg)
	daemonAddr := cfg.DaemonAddress
	remoteAddr := remoteAddress(log, cfg)

	if !remoteAddr.IA.IsZero() {
		runSCIONBenchmark(daemonAddr, localAddr, remoteAddr)
	} else {
		if daemonAddr != "" {
			exitWithUsage()
		}
		runIPBenchmark(localAddr, remoteAddr)
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
		verbose                 bool
		configFile              string
		daemonAddr              string
		localAddr               snet.UDPAddr
		remoteAddrStr           string
		dispatcherMode          string
		drkeyMode               string
		drkeyServerAddr         snet.UDPAddr
		drkeyClientAddr         snet.UDPAddr
		authMode                string
		ntskeInsecureSkipVerify bool
	)

	serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
	relayFlags := flag.NewFlagSet("relay", flag.ExitOnError)
	clientFlags := flag.NewFlagSet("client", flag.ExitOnError)
	toolFlags := flag.NewFlagSet("tool", flag.ExitOnError)
	benchmarkFlags := flag.NewFlagSet("benchmark", flag.ExitOnError)
	drkeyFlags := flag.NewFlagSet("drkey", flag.ExitOnError)

	serverFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	serverFlags.StringVar(&configFile, "config", "", "Config file")

	relayFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	relayFlags.StringVar(&configFile, "config", "", "Config file")

	clientFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	clientFlags.StringVar(&configFile, "config", "", "Config file")

	toolFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	toolFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	toolFlags.StringVar(&dispatcherMode, "dispatcher", "", "Dispatcher mode")
	toolFlags.Var(&localAddr, "local", "Local address")
	toolFlags.StringVar(&remoteAddrStr, "remote", "", "Remote address")
	toolFlags.StringVar(&authMode, "auth", "", "Authentication mode")
	toolFlags.BoolVar(&ntskeInsecureSkipVerify, "ntske-insecure-skip-verify", false, "Skip NTSKE verification")

	benchmarkFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	benchmarkFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")

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
		if configFile == "" {
			exitWithUsage()
		}
		initLogger(verbose)
		runServer(configFile)
	case relayFlags.Name():
		err := relayFlags.Parse(os.Args[2:])
		if err != nil || relayFlags.NArg() != 0 {
			exitWithUsage()
		}
		if configFile == "" {
			exitWithUsage()
		}
		initLogger(verbose)
		runRelay(configFile)
	case clientFlags.Name():
		err := clientFlags.Parse(os.Args[2:])
		if err != nil || clientFlags.NArg() != 0 {
			exitWithUsage()
		}
		if configFile == "" {
			exitWithUsage()
		}
		initLogger(verbose)
		runClient(configFile)
	case toolFlags.Name():
		err := toolFlags.Parse(os.Args[2:])
		if err != nil || toolFlags.NArg() != 0 {
			exitWithUsage()
		}
		var remoteAddr snet.UDPAddr
		err = remoteAddr.Set(remoteAddrStr)
		if err != nil {
			exitWithUsage()
		}
		if !remoteAddr.IA.IsZero() {
			if dispatcherMode == "" {
				dispatcherMode = dispatcherModeExternal
			} else if dispatcherMode != dispatcherModeExternal &&
				dispatcherMode != dispatcherModeInternal {
				exitWithUsage()
			}
			if authMode != "" && authMode != authModeNTS {
				exitWithUsage()
			}
			ntskeServer := strings.Split(remoteAddrStr, ",")[1]
			initLogger(verbose)
			runSCIONTool(daemonAddr, dispatcherMode, &localAddr, &remoteAddr, authMode, ntskeServer, ntskeInsecureSkipVerify)
		} else {
			if daemonAddr != "" {
				exitWithUsage()
			}
			if dispatcherMode != "" {
				exitWithUsage()
			}
			if authMode != "" && authMode != authModeNTS {
				exitWithUsage()
			}
			ntskeServer := strings.Split(remoteAddrStr, ",")[1]
			initLogger(verbose)
			runIPTool(&localAddr, &remoteAddr, authMode, ntskeServer, ntskeInsecureSkipVerify)
		}
	case benchmarkFlags.Name():
		err := benchmarkFlags.Parse(os.Args[2:])
		if err != nil || benchmarkFlags.NArg() != 0 {
			exitWithUsage()
		}
		if configFile == "" {
			exitWithUsage()
		}
		initLogger(verbose)
		runBenchmark(configFile)
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
