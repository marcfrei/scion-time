package ntske

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"

	"example.com/scion-time/net/ntp"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

var errNoPath = errors.New("failed to dial QUIC connection: no path")

func dialQUIC(log *slog.Logger, localAddr, remoteAddr udp.UDPAddr, cpc scion.ControlPlaneConnector, config *tls.Config) (*scion.QUICConnection, Data, error) {
	config.NextProtos = []string{alpn}
	ctx := context.Background()

	cp, err := cpc.Connect(ctx)
	if err != nil {
		return nil, Data{}, err
	}
	defer func() { _ = cp.Close() }()

	ps, err := scion.FetchPaths(ctx, cp, localAddr.IA, remoteAddr.IA, remoteAddr.Host)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError,
			"failed to lookup paths",
			slog.Any("remote", remoteAddr),
			slog.Any("error", err),
		)
		return nil, Data{}, err
	}
	if len(ps) == 0 {
		log.LogAttrs(ctx, slog.LevelError,
			"no paths available",
			slog.Any("remote", remoteAddr),
		)
		return nil, Data{}, errNoPath
	}

	log.LogAttrs(ctx, slog.LevelDebug, "available paths", slog.Any("remote", remoteAddr), slog.Any("via", ps))
	sp := ps[0]
	log.LogAttrs(ctx, slog.LevelDebug, "selected path", slog.Any("remote", remoteAddr), slog.Any("via", sp))

	conn, err := scion.DialQUIC(ctx, localAddr, remoteAddr, sp,
		"" /* host*/, config, nil /* quicCfg */)
	if err != nil {
		return nil, Data{}, err
	}

	var data Data
	data.Server, _, err = net.SplitHostPort(remoteAddr.Host.String())
	if err != nil {
		_ = conn.Close()
		return nil, Data{}, err
	}
	data.Port = ntp.ServerPortSCION

	return conn, data, nil
}

func exchangeDataQUIC(ctx context.Context, log *slog.Logger, conn *scion.QUICConnection, data *Data) error {
	stream, err := conn.OpenStream()
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()

	var msg ExchangeMsg

	var nextproto NextProto
	nextproto.NextProto = NTPv4
	msg.AddRecord(nextproto)

	var algo Algorithm
	algo.Algo = []uint16{AES_SIV_CMAC_256}
	msg.AddRecord(algo)

	var end End
	msg.AddRecord(end)

	buf, err := msg.Pack()
	if err != nil {
		return err
	}

	_, err = stream.Write(buf.Bytes())
	if err != nil {
		return err
	}

	reader := bufio.NewReader(stream)
	err = ReadData(ctx, log, reader, data)
	if err != nil {
		return err
	}

	return nil
}
