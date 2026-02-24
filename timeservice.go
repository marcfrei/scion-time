// SCION time service

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/base/timemath"

	"example.com/scion-time/benchmark"

	"example.com/scion-time/core/client"
	"example.com/scion-time/core/server"
	"example.com/scion-time/core/sync"
	"example.com/scion-time/core/sync/adjustments"
	"example.com/scion-time/core/timebase"

	"example.com/scion-time/driver/clocks"
	"example.com/scion-time/driver/mbg"
	"example.com/scion-time/driver/phc"
	"example.com/scion-time/driver/shm"

	"example.com/scion-time/net/ntp"
	"example.com/scion-time/net/ntske"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"

	"example.com/scion-time/service"
)

const (
	logLevelQuiet = iota
	logLevelDefault
	logLevelVerbose

	dispatcherModeExternal = "external"
	dispatcherModeInternal = "internal"
	authModeNTS            = "nts"
	authModeSPAO           = "spao"
	clockAlgoNtimed        = "ntimed"
	clockAlgoPI            = "pi"

	tlsCertReloadInterval = time.Minute * 10

	scionRefClockNumClient = 7
)

type svcConfig struct {
	LocalAddr               string   `toml:"local_address,omitempty"`
	LocalMetricsAddr        string   `toml:"local_metrics_address,omitempty"`
	SCIONDaemonAddr         string   `toml:"scion_daemon_address,omitempty"`
	SCIONEndhostAPIAddr     string   `toml:"scion_endhost_api_address,omitempty"`
	SCIONTopoFile           string   `toml:"scion_topo_file,omitempty"`
	SCIONCertsDir           string   `toml:"scion_certs_dir,omitempty"`
	SCIONPersistTRCs        bool     `toml:"scion_persist_trcs,omitempty"`
	SCIONDispatcherMode     string   `toml:"scion_dispatcher_mode,omitempty"`
	RemoteAddr              string   `toml:"remote_address,omitempty"`
	MBGReferenceClocks      []string `toml:"mbg_reference_clocks,omitempty"`
	PHCReferenceClocks      []string `toml:"phc_reference_clocks,omitempty"`
	SHMReferenceClocks      []string `toml:"shm_reference_clocks,omitempty"`
	NTPReferenceClocks      []string `toml:"ntp_reference_clocks,omitempty"`
	SCIONPeers              []string `toml:"scion_peer_clocks,omitempty"`
	NTSKECertFile           string   `toml:"ntske_cert_file,omitempty"`
	NTSKEKeyFile            string   `toml:"ntske_key_file,omitempty"`
	NTSKEServerName         string   `toml:"ntske_server_name,omitempty"`
	AuthModes               []string `toml:"auth_modes,omitempty"`
	NTSKEInsecureSkipVerify bool     `toml:"ntske_insecure_skip_verify,omitempty"`
	DSCP                    uint8    `toml:"dscp,omitempty"` // must be in range [0, 63]
	FilterSize              int      `toml:"filter_size,omitempty"`
	FilterPick              int      `toml:"filter_pick,omitempty"`
	PIControllerKP          float64  `toml:"pi_controller_kp,omitempty"`
	PIControllerKI          float64  `toml:"pi_controller_ki,omitempty"`
	ClockDrift              float64  `toml:"clock_drift,omitempty"`
	ReferenceClockImpact    float64  `toml:"reference_clock_impact,omitempty"`
	PeerClockImpact         float64  `toml:"peer_clock_impact,omitempty"`
	PeerClockCutoff         float64  `toml:"peer_clock_cutoff,omitempty"`
	SyncTimeout             float64  `toml:"sync_timeout,omitempty"`
	SyncInterval            float64  `toml:"sync_interval,omitempty"`
	PHCSync                 string   `toml:"phc_sync,omitempty"`
}

type ntpReferenceClockIP struct {
	log        *slog.Logger
	ntpc       *client.IPClient
	localAddr  *net.UDPAddr
	remoteAddr *net.UDPAddr
}

type ntpReferenceClockSCION struct {
	log        *slog.Logger
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

func initLogger(logLevel int) {
	var h slog.Handler
	if logLevel == logLevelQuiet {
		h = slog.DiscardHandler
	} else {
		var (
			addSource   bool
			level       slog.Leveler
			replaceAttr func(groups []string, a slog.Attr) slog.Attr
		)
		if logLevel == logLevelVerbose {
			_, f, _, ok := runtime.Caller(0)
			var basepath string
			if ok {
				basepath = filepath.Dir(f)
			}
			addSource = true
			level = slog.LevelDebug
			replaceAttr = func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.SourceKey {
					source := a.Value.Any().(*slog.Source)
					if basepath == "" {
						source.File = filepath.Base(source.File)
					} else {
						relpath, err := filepath.Rel(basepath, source.File)
						if err != nil {
							source.File = filepath.Base(source.File)
						} else {
							source.File = relpath
						}
					}
				}
				return a
			}
		}
		h = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource:   addSource,
			Level:       level,
			ReplaceAttr: replaceAttr,
		})
	}
	slog.SetDefault(slog.New(h))
}

func showInfo() {
	bi, ok := debug.ReadBuildInfo()
	if ok {
		fmt.Print(bi.String())
	}
}

func runMonitor(cfg svcConfig) {
	if cfg.LocalMetricsAddr != "" {
		http.Handle("/metrics", promhttp.Handler())
		err := http.ListenAndServe(cfg.LocalMetricsAddr, nil)
		logbase.Fatal(slog.Default(), "failed to serve metrics", slog.Any("error", err))
	} else {
		select {}
	}
}

func ntskeServerFromRemoteAddr(remoteAddr string) string {
	split := strings.Split(remoteAddr, ",")
	if len(split) < 2 {
		panic("remote address has wrong format")
	}
	return split[1]
}

func (c *tlsCertCache) loadCert(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	now := time.Now().UTC()
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

func configureIPClientNTS(c *client.IPClient, ntskeServer string, ntskeInsecureSkipVerify bool, log *slog.Logger) {
	ntskeHost, ntskePort, err := net.SplitHostPort(ntskeServer)
	if err != nil {
		logbase.Fatal(slog.Default(), "failed to split NTS-KE host and port", slog.Any("error", err))
	}
	c.Auth.Enabled = true
	c.Auth.NTSKEFetcher.TLSConfig = tls.Config{
		NextProtos:         []string{"ntske/1"},
		InsecureSkipVerify: ntskeInsecureSkipVerify,
		ServerName:         ntskeHost,
		MinVersion:         tls.VersionTLS13,
	}
	c.Auth.NTSKEFetcher.Port = ntskePort
	c.Auth.NTSKEFetcher.Log = log
}

func newNTPReferenceClockIP(log *slog.Logger, localAddr, remoteAddr *net.UDPAddr, dscp uint8,
	filterSize, filterPick int, authModes []string, ntskeServer string, ntskeInsecureSkipVerify bool) *ntpReferenceClockIP {
	c := &ntpReferenceClockIP{
		log:        log,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
	c.ntpc = &client.IPClient{
		Log:             log,
		DSCP:            dscp,
		InterleavedMode: true,
	}
	c.ntpc.Filter = client.NewNtimedFilter(log, filterSize, filterPick)
	if slices.Contains(authModes, authModeNTS) {
		configureIPClientNTS(c.ntpc, ntskeServer, ntskeInsecureSkipVerify, log)
	}
	return c
}

func (c *ntpReferenceClockIP) MeasureClockOffset(ctx context.Context) (
	time.Time, time.Duration, error) {
	return client.MeasureClockOffsetIP(ctx, c.log, c.ntpc, c.localAddr, c.remoteAddr)
}

func configureSCIONClientNTS(c *client.SCIONClient, ntskeServer string, ntskeInsecureSkipVerify bool,
	cpc scion.ControlPlaneConnector, localAddr, remoteAddr udp.UDPAddr, log *slog.Logger) {
	ntskeHost, ntskePort, err := net.SplitHostPort(ntskeServer)
	if err != nil {
		logbase.Fatal(slog.Default(), "failed to split NTS-KE host and port", slog.Any("error", err))
	}
	c.Auth.NTSEnabled = true
	c.Auth.NTSKEFetcher.TLSConfig = tls.Config{
		NextProtos:         []string{"ntske/1"},
		InsecureSkipVerify: ntskeInsecureSkipVerify,
		ServerName:         ntskeHost,
		MinVersion:         tls.VersionTLS13,
	}
	c.Auth.NTSKEFetcher.Port = ntskePort
	c.Auth.NTSKEFetcher.Log = log
	c.Auth.NTSKEFetcher.QUIC.Enabled = true
	c.Auth.NTSKEFetcher.QUIC.LocalAddr = localAddr
	c.Auth.NTSKEFetcher.QUIC.RemoteAddr = remoteAddr
	c.Auth.NTSKEFetcher.QUIC.ControlPlaneConnector = cpc
}

func newNTPReferenceClockSCION(log *slog.Logger, cpc scion.ControlPlaneConnector, localAddr, remoteAddr udp.UDPAddr, dscp uint8,
	filterSize, filterPick int, authModes []string, ntskeServer string, ntskeInsecureSkipVerify bool) *ntpReferenceClockSCION {
	c := &ntpReferenceClockSCION{
		log:        log,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
	for i := range len(c.ntpcs) {
		c.ntpcs[i] = &client.SCIONClient{
			Log:             log,
			DSCP:            dscp,
			InterleavedMode: true,
		}
		c.ntpcs[i].Filter = client.NewNtimedFilter(log, filterSize, filterPick)
		if slices.Contains(authModes, authModeNTS) {
			configureSCIONClientNTS(c.ntpcs[i], ntskeServer, ntskeInsecureSkipVerify, cpc, localAddr, remoteAddr, log)
		}
	}
	return c
}

func (c *ntpReferenceClockSCION) MeasureClockOffset(ctx context.Context) (
	time.Time, time.Duration, error) {
	var ps []snet.Path
	if c.remoteAddr.IA == c.localAddr.IA {
		ps = []snet.Path{path.Path{
			Src:           c.localAddr.IA,
			Dst:           c.remoteAddr.IA,
			DataplanePath: path.Empty{},
			NextHop:       c.remoteAddr.Host,
		}}
	} else {
		ps = c.pather.Paths(c.remoteAddr.IA)
	}
	return client.MeasureClockOffsetSCION(ctx, c.log, c.ntpcs[:], c.localAddr, c.remoteAddr, ps)
}

func loadConfig(configFile string) svcConfig {
	raw, err := os.ReadFile(configFile)
	if err != nil {
		logbase.Fatal(slog.Default(), "failed to load configuration", slog.Any("error", err))
	}
	var cfg svcConfig
	err = toml.NewDecoder(bytes.NewReader(raw)).DisallowUnknownFields().Decode(&cfg)
	if err != nil {
		logbase.Fatal(slog.Default(), "failed to decode configuration", slog.Any("error", err))
	}
	return cfg
}

func localAddress(cfg svcConfig) *snet.UDPAddr {
	if cfg.LocalAddr == "" {
		logbase.Fatal(slog.Default(), "local_address not specified in config")
	}
	var localAddr snet.UDPAddr
	err := localAddr.Set(cfg.LocalAddr)
	if err != nil {
		logbase.Fatal(slog.Default(), "failed to parse local address")
	}
	return &localAddr
}

func remoteAddress(cfg svcConfig) *snet.UDPAddr {
	if cfg.RemoteAddr == "" {
		logbase.Fatal(slog.Default(), "remote_address not specified in config")
	}
	var remoteAddr snet.UDPAddr
	err := remoteAddr.Set(cfg.RemoteAddr)
	if err != nil {
		logbase.Fatal(slog.Default(), "failed to parse remote address")
	}
	return &remoteAddr
}

func dispatcherMode(cfg svcConfig) string {
	dispatcherMode := cfg.SCIONDispatcherMode
	if dispatcherMode == "" {
		dispatcherMode = dispatcherModeExternal
	} else if dispatcherMode != dispatcherModeExternal &&
		dispatcherMode != dispatcherModeInternal {
		logbase.Fatal(slog.Default(), "invalid dispatcher mode value specified in config")
	}
	return dispatcherMode
}

func dscp(cfg svcConfig) uint8 {
	if cfg.DSCP > 63 {
		logbase.Fatal(slog.Default(), "invalid differentiated services codepoint value specified in config")
	}
	return cfg.DSCP
}

func filterConfig(cfg svcConfig) (size, pick int) {
	size, pick = cfg.FilterSize, cfg.FilterPick
	if size == 0 {
		size = 1
	}
	if pick == 0 {
		pick = 1
	}
	if size < 1 || pick < 1 || pick > size {
		logbase.Fatal(slog.Default(), "invalid filter configuration specified in config")
	}
	return
}

func clockDrift(cfg svcConfig) time.Duration {
	if cfg.ClockDrift < 0 {
		logbase.Fatal(slog.Default(), "invalid clock drift value specified in config")
	}
	return timemath.Duration(cfg.ClockDrift)
}

func piControllerConfig(cfg svcConfig) (kp, ki float64) {
	kp, ki = cfg.PIControllerKP, cfg.PIControllerKI
	if kp == 0 {
		kp = adjustments.PIControllerDefaultPRatio
	}
	if ki == 0 {
		ki = adjustments.PIControllerDefaultIRatio
	}
	if kp < adjustments.PIControllerMinPRatio || kp > adjustments.PIControllerMaxPRatio ||
		ki < adjustments.PIControllerMinIRatio || ki > adjustments.PIControllerMaxIRatio {
		logbase.Fatal(slog.Default(), "invalid PI controller configuration specified in config")
	}
	return
}

func syncConfig(cfg svcConfig) sync.Config {
	const (
		defaultReferenceClockImpact = 1.25
		defaultPeerClockImpact      = 2.5
		defaultPeerClockCutoff      = 50 * time.Microsecond
		defaultSyncTimeout          = 500 * time.Millisecond
		defaultSyncInterval         = 1000 * time.Millisecond
	)

	syncCfg := sync.Config{
		ReferenceClockImpact: cfg.ReferenceClockImpact,
		PeerClockImpact:      cfg.PeerClockImpact,
		PeerClockCutoff:      timemath.Duration(cfg.PeerClockCutoff),
		SyncTimeout:          timemath.Duration(cfg.SyncTimeout),
		SyncInterval:         timemath.Duration(cfg.SyncInterval),
	}

	if syncCfg.ReferenceClockImpact == 0 {
		syncCfg.ReferenceClockImpact = defaultReferenceClockImpact
	}
	if syncCfg.PeerClockImpact == 0 {
		syncCfg.PeerClockImpact = defaultPeerClockImpact
	}
	if syncCfg.PeerClockCutoff == 0 {
		syncCfg.PeerClockCutoff = defaultPeerClockCutoff
	}
	if syncCfg.SyncTimeout == 0 {
		syncCfg.SyncTimeout = defaultSyncTimeout
	}
	if syncCfg.SyncInterval == 0 {
		syncCfg.SyncInterval = defaultSyncInterval
	}

	return syncCfg
}

func tlsConfig(cfg svcConfig) *tls.Config {
	if cfg.NTSKEServerName == "" || cfg.NTSKECertFile == "" || cfg.NTSKEKeyFile == "" {
		logbase.Fatal(slog.Default(), "missing parameters in configuration for NTSKE server")
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

func controlPlaneConnector(daemonAddr, apiAddr, topoFile, certsDir string, persistTRCs bool) scion.ControlPlaneConnector {
	if daemonAddr != "" {
		return scion.DaemonConnector{Address: daemonAddr}
	}
	if apiAddr != "" {
		return scion.EndhostAPIConnector{Address: apiAddr}
	}
	return scion.CSConnector{
		TopoFile:    topoFile,
		CertsDir:    certsDir,
		PersistTRCs: persistTRCs,
	}
}

func controlPlaneConnectorFromConfig(cfg svcConfig) scion.ControlPlaneConnector {
	if cfg.SCIONDaemonAddr != "" {
		if cfg.SCIONEndhostAPIAddr != "" {
			logbase.Fatal(slog.Default(), "unexpected endhost API specification in config")
		}
		if cfg.SCIONTopoFile != "" {
			logbase.Fatal(slog.Default(), "unexpected topology file specification in config")
		}
		if cfg.SCIONCertsDir != "" {
			logbase.Fatal(slog.Default(), "unexpected certificates directory specification in config")
		}
		if cfg.SCIONPersistTRCs {
			logbase.Fatal(slog.Default(), "unexpected TRC persistence specification in config")
		}
	} else if cfg.SCIONEndhostAPIAddr != "" {
		if cfg.SCIONTopoFile != "" {
			logbase.Fatal(slog.Default(), "unexpected topology file specification in config")
		}
		if cfg.SCIONCertsDir != "" {
			logbase.Fatal(slog.Default(), "unexpected certificates directory specification in config")
		}
		if cfg.SCIONPersistTRCs {
			logbase.Fatal(slog.Default(), "unexpected TRC persistence specification in config")
		}
	} else if cfg.SCIONTopoFile == "" {
		logbase.Fatal(slog.Default(), "missing topology file specification in config")
	}
	return controlPlaneConnector(
		cfg.SCIONDaemonAddr, cfg.SCIONEndhostAPIAddr, cfg.SCIONTopoFile, cfg.SCIONCertsDir, cfg.SCIONPersistTRCs)
}

func createClocks(cfg svcConfig, localAddr *snet.UDPAddr, log *slog.Logger) (
	refClocks, peerClocks []client.ReferenceClock) {
	dscp := dscp(cfg)
	filterSize, filterPick := filterConfig(cfg)

	for _, s := range cfg.MBGReferenceClocks {
		refClocks = append(refClocks, mbg.NewReferenceClock(log, s))
	}

	for _, c := range cfg.PHCReferenceClocks {
		t := strings.Split(c, ",")
		if len(t) > 2 {
			logbase.Fatal(slog.Default(), "unexpected PHC reference clock specification",
				slog.String("config", c))
		}
		var o int
		if len(t) > 1 {
			var err error
			o, err = strconv.Atoi(t[1])
			if err != nil {
				logbase.Fatal(slog.Default(), "unexpected PHC reference clock offset",
					slog.String("config", c), slog.Any("error", err))
			}
		}
		refClocks = append(refClocks, phc.NewReferenceClock(log, t[0], time.Duration(o)*time.Second))
	}

	for _, s := range cfg.SHMReferenceClocks {
		t := strings.Split(s, ":")
		if len(t) > 2 || t[0] != shm.ReferenceClockType {
			logbase.Fatal(slog.Default(), "unexpected SHM reference clock id", slog.String("id", s))
		}
		var u int
		if len(t) > 1 {
			var err error
			u, err = strconv.Atoi(t[1])
			if err != nil {
				logbase.Fatal(slog.Default(), "unexpected SHM reference clock id",
					slog.String("id", s), slog.Any("error", err))
			}
		}
		refClocks = append(refClocks, shm.NewReferenceClock(log, u))
	}

	var dstIAs []addr.IA
	for _, s := range cfg.NTPReferenceClocks {
		remoteAddr, err := snet.ParseUDPAddr(s)
		if err != nil {
			logbase.Fatal(slog.Default(), "failed to parse reference clock address",
				slog.String("address", s), slog.Any("error", err))
		}
		ntskeServer := ntskeServerFromRemoteAddr(s)
		if !remoteAddr.IA.IsZero() {
			refClocks = append(refClocks, newNTPReferenceClockSCION(log,
				controlPlaneConnectorFromConfig(cfg),
				udp.UDPAddrFromSnet(localAddr), udp.UDPAddrFromSnet(remoteAddr),
				dscp, filterSize, filterPick,
				cfg.AuthModes, ntskeServer, cfg.NTSKEInsecureSkipVerify,
			))
			dstIAs = append(dstIAs, remoteAddr.IA)
		} else {
			refClocks = append(refClocks, newNTPReferenceClockIP(log,
				localAddr.Host, remoteAddr.Host,
				dscp, filterSize, filterPick,
				cfg.AuthModes, ntskeServer, cfg.NTSKEInsecureSkipVerify,
			))
		}
	}

	for _, s := range cfg.SCIONPeers {
		remoteAddr, err := snet.ParseUDPAddr(s)
		if err != nil {
			logbase.Fatal(slog.Default(), "failed to parse peer address", slog.String("address", s), slog.Any("error", err))
		}
		if remoteAddr.IA.IsZero() {
			logbase.Fatal(slog.Default(), "unexpected peer address", slog.String("address", s), slog.Any("error", err))
		}
		ntskeServer := ntskeServerFromRemoteAddr(s)
		peerClocks = append(peerClocks, newNTPReferenceClockSCION(log,
			controlPlaneConnectorFromConfig(cfg),
			udp.UDPAddrFromSnet(localAddr), udp.UDPAddrFromSnet(remoteAddr),
			dscp, filterSize, filterPick,
			cfg.AuthModes, ntskeServer, cfg.NTSKEInsecureSkipVerify,
		))
		dstIAs = append(dstIAs, remoteAddr.IA)
	}

	if cfg.SCIONDaemonAddr != "" || cfg.SCIONTopoFile != "" {
		ctx := context.Background()
		pather, err := scion.StartPather(ctx, log,
			controlPlaneConnectorFromConfig(cfg), dstIAs)
		if err != nil {
			logbase.Fatal(slog.Default(), "failed to start path discovery",
				slog.Any("error", err))
		}
		for _, c := range refClocks {
			scionclk, ok := c.(*ntpReferenceClockSCION)
			if ok {
				scionclk.pather = pather
				if slices.Contains(cfg.AuthModes, authModeSPAO) {
					for i := range len(scionclk.ntpcs) {
						scionclk.ntpcs[i].Auth.Enabled = true
						scionclk.ntpcs[i].Auth.DRKeyFetcher = scion.NewDRKeyFetcher(
							controlPlaneConnectorFromConfig(cfg))
					}
				}
			}
		}
		for _, c := range peerClocks {
			scionclk, ok := c.(*ntpReferenceClockSCION)
			if ok {
				scionclk.pather = pather
				if slices.Contains(cfg.AuthModes, authModeSPAO) {
					for i := range len(scionclk.ntpcs) {
						scionclk.ntpcs[i].Auth.Enabled = true
						scionclk.ntpcs[i].Auth.DRKeyFetcher = scion.NewDRKeyFetcher(
							controlPlaneConnectorFromConfig(cfg))
					}
				}
			}
		}
	}

	return
}

func runServer(configFile string) {
	ctx := context.Background()
	log := slog.Default()

	cfg := loadConfig(configFile)
	localAddr := localAddress(cfg)

	localAddr.Host.Port = 0
	refClocks, peerClocks := createClocks(cfg, localAddr, log)

	lclk := clocks.NewSystemClock(log, clockDrift(cfg))
	timebase.RegisterClock(lclk)

	dscp := dscp(cfg)
	tlsConfig := tlsConfig(cfg)
	provider := ntske.NewProvider()

	localAddr.Host.Port = ntp.ServerPortIP
	server.StartNTSKEServerIP(ctx, log, slices.Clone(localAddr.Host.IP), localAddr.Host.Port, tlsConfig, provider)
	server.StartIPServer(ctx, log, snet.CopyUDPAddr(localAddr.Host), dscp, provider)

	localAddr.Host.Port = ntp.ServerPortSCION
	server.StartNTSKEServerSCION(ctx, log, udp.UDPAddrFromSnet(localAddr), tlsConfig, provider)
	cpc := controlPlaneConnectorFromConfig(cfg)
	server.StartSCIONServer(ctx, log, cpc, snet.CopyUDPAddr(localAddr.Host), dscp, provider)

	syncCfg := syncConfig(cfg)
	kp, ki := piControllerConfig(cfg)

	adj := &adjustments.PIController{
		KP:            kp,
		KI:            ki,
		StepThreshold: adjustments.PIControllerDefaultStepThreshold,
	}

	go sync.Run(log, syncCfg, lclk, adj, refClocks, peerClocks)

	service.StartPHCSync(log, cfg.PHCSync)

	runMonitor(cfg)
}

func runClient(configFile string) {
	ctx := context.Background()
	log := slog.Default()

	cfg := loadConfig(configFile)
	localAddr := localAddress(cfg)

	localAddr.Host.Port = 0
	refClocks, peerClocks := createClocks(cfg, localAddr, log)

	if len(peerClocks) != 0 {
		logbase.Fatal(slog.Default(), "unexpected configuration", slog.Int("number of peers", len(peerClocks)))
	}

	lclk := clocks.NewSystemClock(log, clockDrift(cfg))
	timebase.RegisterClock(lclk)

	scionClocksAvailable := false
	for _, c := range refClocks {
		_, ok := c.(*ntpReferenceClockSCION)
		if ok {
			scionClocksAvailable = true
			break
		}
	}
	dispatcherMode := dispatcherMode(cfg)
	if scionClocksAvailable && dispatcherMode == dispatcherModeInternal {
		server.StartSCIONDispatcher(ctx, log, snet.CopyUDPAddr(localAddr.Host))
	}

	syncCfg := syncConfig(cfg)
	kp, ki := piControllerConfig(cfg)

	adj := &adjustments.PIController{
		KP:            kp,
		KI:            ki,
		StepThreshold: adjustments.PIControllerDefaultStepThreshold,
	}

	go sync.Run(log, syncCfg, lclk, adj, refClocks, peerClocks)

	service.StartPHCSync(log, cfg.PHCSync)

	runMonitor(cfg)
}

func runToolIP(localAddr, remoteAddr *snet.UDPAddr, dscp uint8,
	authModes []string, ntskeServer string, ntskeInsecureSkipVerify, periodic bool) {
	log := slog.Default()

	lclk := clocks.NewSystemClock(log, clocks.UnknownDrift)
	timebase.RegisterClock(lclk)

	laddr := localAddr.Host
	raddr := remoteAddr.Host
	c := &client.IPClient{
		Log:  log,
		DSCP: dscp,
		// InterleavedMode: true,
	}
	if slices.Contains(authModes, authModeNTS) {
		configureIPClientNTS(c, ntskeServer, ntskeInsecureSkipVerify, log)
	}

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		ts, off, err := client.MeasureClockOffsetIP(ctx, log, c, laddr, raddr)
		if err != nil {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to measure clock offset",
				slog.Any("remote", raddr), slog.Any("error", err))
		}
		cancel()
		if !periodic {
			break
		}
		if err == nil {
			fmt.Printf("%s,%+.9f,%t\n", ts.UTC().Format(time.RFC3339), off.Seconds(), c.InInterleavedMode())
		}
		lclk.Sleep(8 * time.Second)
	}
}

func runToolSCION(daemonAddr, apiAddr, topoFile, certsDir, dispatcherMode string,
	localAddr, remoteAddr *snet.UDPAddr, dscp uint8,
	authModes []string, ntskeServer string, ntskeInsecureSkipVerify bool, periodic bool) {
	ctx := context.Background()
	log := slog.Default()

	lclk := clocks.NewSystemClock(log, clocks.UnknownDrift)
	timebase.RegisterClock(lclk)

	if dispatcherMode == dispatcherModeInternal {
		server.StartSCIONDispatcher(ctx, log, snet.CopyUDPAddr(localAddr.Host))
	}

	cpc := controlPlaneConnector(daemonAddr, apiAddr, topoFile, certsDir, false /* persistTRCs */)
	cp, err := cpc.Connect(ctx)
	if err != nil {
		logbase.Fatal(slog.Default(), "failed to connect to control plane", slog.Any("error", err))
	}

	ps, err := scion.FetchPaths(ctx, cp, localAddr.IA, remoteAddr.IA, remoteAddr.Host)
	if err != nil {
		logbase.Fatal(slog.Default(), "failed to lookup paths", slog.Any("remote", remoteAddr), slog.Any("error", err))
	}
	if len(ps) == 0 {
		logbase.Fatal(slog.Default(), "no paths available", slog.Any("remote", remoteAddr))
	}
	log.LogAttrs(ctx, slog.LevelDebug,
		"available paths",
		slog.Any("remote", remoteAddr),
		slog.Any("via", ps),
	)

	laddr := udp.UDPAddrFromSnet(localAddr)
	raddr := udp.UDPAddrFromSnet(remoteAddr)
	c := &client.SCIONClient{
		Log:             log,
		DSCP:            dscp,
		InterleavedMode: true,
	}
	if slices.Contains(authModes, authModeSPAO) {
		c.Auth.Enabled = true
		c.Auth.DRKeyFetcher = scion.NewDRKeyFetcher(cpc)
	}
	if slices.Contains(authModes, authModeNTS) {
		configureSCIONClientNTS(c, ntskeServer, ntskeInsecureSkipVerify, cpc, laddr, raddr, log)
	}

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		ts, off, err := client.MeasureClockOffsetSCION(ctx, log, []*client.SCIONClient{c}, laddr, raddr, ps)
		if err != nil {
			log.LogAttrs(ctx, slog.LevelInfo, "failed to measure clock offset",
				slog.Any("remote", raddr), slog.Any("error", err))
		}
		cancel()
		if !periodic {
			break
		}
		if err == nil {
			fmt.Printf("%s,%+.9f,%t\n", ts.UTC().Format(time.RFC3339), off.Seconds(), c.InInterleavedMode())
		}
		lclk.Sleep(1 * time.Second)
	}
}

func runPing(daemonAddr, apiAddr, topoFile, certsDir, dispatcherMode string,
	localAddr, remoteAddr *snet.UDPAddr) {
	ctx := context.Background()
	log := slog.Default()

	lclk := clocks.NewSystemClock(log, clocks.UnknownDrift)
	timebase.RegisterClock(lclk)

	if remoteAddr.IA.IsZero() {
		logbase.Fatal(slog.Default(), "ping subcommand only supports SCION addresses")
	}

	if dispatcherMode == dispatcherModeInternal {
		server.StartSCIONDispatcher(ctx, log, snet.CopyUDPAddr(localAddr.Host))
	}

	cpc := controlPlaneConnector(daemonAddr, apiAddr, topoFile, certsDir, false /* persistTRCs */)
	cp, err := cpc.Connect(ctx)
	if err != nil {
		logbase.Fatal(slog.Default(), "failed to connect to control plane", slog.Any("error", err))
	}

	ps, err := scion.FetchPaths(ctx, cp, localAddr.IA, remoteAddr.IA, remoteAddr.Host)
	if err != nil {
		logbase.Fatal(slog.Default(), "failed to lookup paths", slog.Any("remote", remoteAddr), slog.Any("error", err))
	}
	if len(ps) == 0 {
		logbase.Fatal(slog.Default(), "no paths available", slog.Any("remote", remoteAddr))
	}

	laddr := udp.UDPAddrFromSnet(localAddr)
	raddr := udp.UDPAddrFromSnet(remoteAddr)

	for _, p := range ps {
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		rtt, err := scion.SendPing(ctx, laddr, raddr, ps[0])
		if err != nil {
			logbase.Fatal(slog.Default(), "failed to send ping",
				slog.Any("remote", remoteAddr),
				slog.Any("via", p.Metadata().Fingerprint().String()),
				slog.Any("error", err))
		}
		fmt.Printf("rtt=%v, via %v\n", rtt, p)
	}
}

func runShowPaths(daemonAddr, apiAddr, topoFile, certsDir string, remoteIA addr.IA) {
	ctx := context.Background()

	cpc := controlPlaneConnector(daemonAddr, apiAddr, topoFile, certsDir, false /* persistTRCs */)
	cp, err := cpc.Connect(ctx)
	if err != nil {
		logbase.Fatal(slog.Default(), "failed to connect to control plane", slog.Any("error", err))
	}

	localIA, err := cp.LocalIA(ctx)
	if err != nil {
		logbase.Fatal(slog.Default(), "failed to lookup local IA", slog.Any("error", err))
	}
	if remoteIA == localIA {
		return
	}

	ps, err := cp.FetchPaths(ctx, remoteIA)
	if err != nil {
		logbase.Fatal(slog.Default(), "failed to lookup paths", slog.Any("remote", remoteIA), slog.Any("error", err))
	}

	for _, p := range ps {
		fmt.Printf("%v\n", p)
	}
}

func runBenchmark(configFile string) {
	cfg := loadConfig(configFile)
	log := slog.Default()

	localAddr := localAddress(cfg)
	remoteAddr := remoteAddress(cfg)

	localAddr.Host.Port = 0
	ntskeServer := ntskeServerFromRemoteAddr(cfg.RemoteAddr)

	if !remoteAddr.IA.IsZero() {
		cpc := controlPlaneConnectorFromConfig(cfg)
		runBenchmarkSCION(cpc, localAddr, remoteAddr, cfg.AuthModes, ntskeServer, log)
	} else {
		runBenchmarkIP(localAddr, remoteAddr, cfg.AuthModes, ntskeServer, log)
	}
}

func runBenchmarkIP(localAddr, remoteAddr *snet.UDPAddr, authModes []string, ntskeServer string, log *slog.Logger) {
	lclk := clocks.NewSystemClock(
		slog.New(slog.DiscardHandler),
		clocks.UnknownDrift,
	)
	timebase.RegisterClock(lclk)
	benchmark.RunIPBenchmark(localAddr.Host, remoteAddr.Host, authModes, ntskeServer, log)
}

func runBenchmarkSCION(cpc scion.ControlPlaneConnector, localAddr, remoteAddr *snet.UDPAddr, authModes []string, ntskeServer string, log *slog.Logger) {
	lclk := clocks.NewSystemClock(
		slog.New(slog.DiscardHandler),
		clocks.UnknownDrift,
	)
	timebase.RegisterClock(lclk)
	benchmark.RunSCIONBenchmark(cpc, localAddr, remoteAddr, authModes, ntskeServer, log)
}

func runDRKeyDemo(daemonAddr, apiAddr, topoFile, certsDir string,
	serverMode bool, serverAddr, clientAddr *snet.UDPAddr) {
	ctx := context.Background()
	cpc := controlPlaneConnector(daemonAddr, apiAddr, topoFile, certsDir, false /* persistTRCs */)
	cp, err := cpc.Connect(ctx)
	if err != nil {
		logbase.Fatal(slog.Default(), "failed to connect to control plane", slog.Any("error", err))
		return
	}

	if serverMode {
		hostASMeta := drkey.HostASMeta{
			ProtoId:  123,
			Validity: time.Now().UTC(),
			SrcIA:    serverAddr.IA,
			DstIA:    clientAddr.IA,
			SrcHost:  serverAddr.Host.IP.String(),
		}
		hostASKey, err := cp.FetchHostASKey(ctx, hostASMeta)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error fetching host-AS key:", err)
			return
		}
		t0 := time.Now().UTC()
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
			Validity: time.Now().UTC(),
			SrcIA:    serverAddr.IA,
			DstIA:    clientAddr.IA,
			SrcHost:  serverAddr.Host.IP.String(),
			DstHost:  clientAddr.Host.IP.String(),
		}
		t0 := time.Now().UTC()
		clientKey, err := cp.FetchHostHostKey(ctx, hostHostMeta)
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
		quiet                   bool
		verbose                 bool
		configFile              string
		daemonAddr              string
		apiAddr                 string
		topoFile                string
		certsDir                string
		localAddr               snet.UDPAddr
		remoteAddrStr           string
		remoteIA                addr.IA
		dispatcherMode          string
		drkeyMode               string
		drkeyServerAddr         snet.UDPAddr
		drkeyClientAddr         snet.UDPAddr
		dscp                    uint
		authModesStr            string
		ntskeInsecureSkipVerify bool
		periodic                bool
	)

	infoFlags := flag.NewFlagSet("info", flag.ExitOnError)
	serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
	clientFlags := flag.NewFlagSet("client", flag.ExitOnError)
	toolFlags := flag.NewFlagSet("tool", flag.ExitOnError)
	pingFlags := flag.NewFlagSet("ping", flag.ExitOnError)
	showPathsFlags := flag.NewFlagSet("showpaths", flag.ExitOnError)
	benchmarkFlags := flag.NewFlagSet("benchmark", flag.ExitOnError)
	drkeyFlags := flag.NewFlagSet("drkey", flag.ExitOnError)

	serverFlags.BoolVar(&quiet, "quiet", false, "Disable logging")
	serverFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	serverFlags.StringVar(&configFile, "config", "", "Config file")

	clientFlags.BoolVar(&quiet, "quiet", false, "Disable logging")
	clientFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	clientFlags.StringVar(&configFile, "config", "", "Config file")

	toolFlags.BoolVar(&quiet, "quiet", false, "Disable logging")
	toolFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	toolFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	toolFlags.StringVar(&apiAddr, "api", "", "Endhost API base URL")
	toolFlags.StringVar(&topoFile, "topo", "", "Topology file")
	toolFlags.StringVar(&certsDir, "certs", "", "Certificates directory")
	toolFlags.StringVar(&dispatcherMode, "dispatcher", "", "Dispatcher mode")
	toolFlags.Var(&localAddr, "local", "Local address")
	toolFlags.StringVar(&remoteAddrStr, "remote", "", "Remote address")
	toolFlags.UintVar(&dscp, "dscp", 0, "Differentiated services codepoint, must be in range [0, 63]")
	toolFlags.StringVar(&authModesStr, "auth", "", "Authentication modes")
	toolFlags.BoolVar(&ntskeInsecureSkipVerify, "ntske-insecure-skip-verify", false, "Skip NTSKE verification")
	toolFlags.BoolVar(&periodic, "periodic", false, "Perform periodic offset measurements")

	pingFlags.BoolVar(&quiet, "quiet", false, "Disable logging")
	pingFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	pingFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	pingFlags.StringVar(&apiAddr, "api", "", "Endhost API base URL")
	pingFlags.StringVar(&topoFile, "topo", "", "Topology file")
	pingFlags.StringVar(&certsDir, "certs", "", "Certificates directory")
	pingFlags.StringVar(&dispatcherMode, "dispatcher", "", "Dispatcher mode")
	pingFlags.Var(&localAddr, "local", "Local address")
	pingFlags.StringVar(&remoteAddrStr, "remote", "", "Remote address")

	showPathsFlags.BoolVar(&quiet, "quiet", false, "Disable logging")
	showPathsFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	showPathsFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	showPathsFlags.StringVar(&apiAddr, "api", "", "Endhost API base URL")
	showPathsFlags.StringVar(&topoFile, "topo", "", "Topology file")
	showPathsFlags.StringVar(&certsDir, "certs", "", "Certificates directory")
	showPathsFlags.Var(&remoteIA, "remote", "Remote ISD-AS")

	benchmarkFlags.BoolVar(&quiet, "quiet", false, "Disable logging")
	benchmarkFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	benchmarkFlags.StringVar(&configFile, "config", "", "Config file")

	drkeyFlags.BoolVar(&quiet, "quiet", false, "Disable logging")
	drkeyFlags.BoolVar(&verbose, "verbose", false, "Verbose logging")
	drkeyFlags.StringVar(&daemonAddr, "daemon", "", "Daemon address")
	drkeyFlags.StringVar(&apiAddr, "api", "", "Endhost API base URL")
	drkeyFlags.StringVar(&topoFile, "topo", "", "Topology file")
	drkeyFlags.StringVar(&certsDir, "certs", "", "Certificates directory")
	drkeyFlags.StringVar(&drkeyMode, "mode", "", "Mode")
	drkeyFlags.Var(&drkeyServerAddr, "server", "Server address")
	drkeyFlags.Var(&drkeyClientAddr, "client", "Client address")

	logLevel := func() int {
		if quiet && verbose {
			exitWithUsage()
		}
		if quiet {
			return logLevelQuiet
		}
		if verbose {
			return logLevelVerbose
		}
		return logLevelDefault
	}

	if len(os.Args) < 2 {
		exitWithUsage()
	}

	switch os.Args[1] {
	case infoFlags.Name():
		err := infoFlags.Parse(os.Args[2:])
		if err != nil || infoFlags.NArg() != 0 {
			exitWithUsage()
		}
		showInfo()
	case serverFlags.Name():
		err := serverFlags.Parse(os.Args[2:])
		if err != nil || serverFlags.NArg() != 0 {
			exitWithUsage()
		}
		if configFile == "" {
			exitWithUsage()
		}
		initLogger(logLevel())
		runServer(configFile)
	case clientFlags.Name():
		err := clientFlags.Parse(os.Args[2:])
		if err != nil || clientFlags.NArg() != 0 {
			exitWithUsage()
		}
		if configFile == "" {
			exitWithUsage()
		}
		initLogger(logLevel())
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
		if dscp > 63 {
			exitWithUsage()
		}
		authModes := strings.Split(authModesStr, ",")
		for i := range authModes {
			authModes[i] = strings.TrimSpace(authModes[i])
		}
		if !remoteAddr.IA.IsZero() {
			if daemonAddr != "" {
				if apiAddr != "" || topoFile != "" || certsDir != "" {
					exitWithUsage()
				}
			} else if apiAddr != "" {
				if topoFile != "" || certsDir != "" {
					exitWithUsage()
				}
			} else {
				if topoFile == "" {
					exitWithUsage()
				}
			}
			if dispatcherMode == "" {
				dispatcherMode = dispatcherModeExternal
			} else if dispatcherMode != dispatcherModeExternal &&
				dispatcherMode != dispatcherModeInternal {
				exitWithUsage()
			}
			ntskeServer := ntskeServerFromRemoteAddr(remoteAddrStr)
			initLogger(logLevel())
			runToolSCION(daemonAddr, apiAddr, topoFile, certsDir, dispatcherMode,
				&localAddr, &remoteAddr, uint8(dscp),
				authModes, ntskeServer, ntskeInsecureSkipVerify, periodic)
		} else {
			if daemonAddr != "" || apiAddr != "" || topoFile != "" || certsDir != "" {
				exitWithUsage()
			}
			if dispatcherMode != "" {
				exitWithUsage()
			}
			ntskeServer := ntskeServerFromRemoteAddr(remoteAddrStr)
			initLogger(logLevel())
			runToolIP(&localAddr, &remoteAddr, uint8(dscp),
				authModes, ntskeServer, ntskeInsecureSkipVerify, periodic)
		}
	case pingFlags.Name():
		err := pingFlags.Parse(os.Args[2:])
		if err != nil || pingFlags.NArg() != 0 {
			exitWithUsage()
		}
		if daemonAddr != "" {
			if apiAddr != "" || topoFile != "" || certsDir != "" {
				exitWithUsage()
			}
		} else if apiAddr != "" {
			if topoFile != "" || certsDir != "" {
				exitWithUsage()
			}
		} else {
			if topoFile == "" {
				exitWithUsage()
			}
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
		}
		initLogger(logLevel())
		runPing(daemonAddr, apiAddr, topoFile, certsDir, dispatcherMode,
			&localAddr, &remoteAddr)
	case showPathsFlags.Name():
		err := showPathsFlags.Parse(os.Args[2:])
		if err != nil || showPathsFlags.NArg() != 0 {
			exitWithUsage()
		}
		if daemonAddr != "" {
			if apiAddr != "" || topoFile != "" || certsDir != "" {
				exitWithUsage()
			}
		} else if apiAddr != "" {
			if topoFile != "" || certsDir != "" {
				exitWithUsage()
			}
		} else {
			if topoFile == "" {
				exitWithUsage()
			}
		}
		if remoteIA.IsZero() {
			exitWithUsage()
		}
		initLogger(logLevel())
		runShowPaths(daemonAddr, apiAddr, topoFile, certsDir, remoteIA)
	case benchmarkFlags.Name():
		err := benchmarkFlags.Parse(os.Args[2:])
		if err != nil || benchmarkFlags.NArg() != 0 {
			exitWithUsage()
		}
		if configFile == "" {
			exitWithUsage()
		}
		initLogger(logLevel())
		runBenchmark(configFile)
	case drkeyFlags.Name():
		err := drkeyFlags.Parse(os.Args[2:])
		if err != nil || drkeyFlags.NArg() != 0 {
			exitWithUsage()
		}
		if daemonAddr != "" {
			if apiAddr != "" || topoFile != "" || certsDir != "" {
				exitWithUsage()
			}
		} else if apiAddr != "" {
			if topoFile != "" || certsDir != "" {
				exitWithUsage()
			}
		} else {
			if topoFile == "" {
				exitWithUsage()
			}
		}
		if drkeyMode != "server" && drkeyMode != "client" {
			exitWithUsage()
		}
		serverMode := drkeyMode == "server"
		initLogger(logLevel())
		runDRKeyDemo(daemonAddr, apiAddr, topoFile, certsDir,
			serverMode, &drkeyServerAddr, &drkeyClientAddr)
	case "t":
		runT()
	default:
		exitWithUsage()
	}
}
