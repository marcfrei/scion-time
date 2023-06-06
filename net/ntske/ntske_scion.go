package ntske

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/scionproto/scion/pkg/daemon"

	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

func AcceptQUICConn(ctx context.Context, l quic.Listener) (quic.Connection, error) {
	return l.Accept(ctx)
}

func dialQUIC(log *zap.Logger, localAddr, remoteAddr udp.UDPAddr, daemonAddr string, config *tls.Config) (*scion.QUICConnection, Data, error) {
	config.NextProtos = []string{alpn}
	ctx := context.Background()

	dc := scion.NewDaemonConnector(ctx, log, daemonAddr)
	ps, err := dc.Paths(ctx, remoteAddr.IA, localAddr.IA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		log.Info("failed to lookup paths", zap.Stringer("to", remoteAddr.IA), zap.Error(err))
		return nil, Data{}, err
	}
	if len(ps) == 0 {
		log.Info("no paths available", zap.Stringer("to", remoteAddr.IA))
		return nil, Data{}, err
	}
	log.Debug("available paths", zap.Stringer("to", remoteAddr.IA), zap.Array("via", scion.PathArrayMarshaler{Paths: ps}))
	sp := ps[0]
	log.Debug("selected path", zap.Stringer("to", remoteAddr.IA), zap.Object("via", scion.PathMarshaler{Path: sp}))

	conn, err := scion.DialQUIC(ctx, localAddr, remoteAddr, sp,
		"" /* host*/, config, nil /* quicCfg */)
	if err != nil {
		_ = conn.Close()
		return nil, Data{}, err
	}

	var data Data
	data.Server, _, err = net.SplitHostPort(remoteAddr.Host.String())
	if err != nil {
		_ = conn.Close()
		return nil, Data{}, err
	}
	data.Port = DEFAULT_NTP_PORT

	return conn, data, nil
}

func exchangeDataQUIC(log *zap.Logger, conn *scion.QUICConnection, data *Data) error {
	stream, err := conn.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()

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
	err = ReadData(log, reader, data)
	if err != nil {
		return err
	}

	return nil
}
