package ntske

import (
	"bufio"
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/scionproto/scion/pkg/daemon"

	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

func newDaemonConnector(log *zap.Logger, ctx context.Context, daemonAddr string) daemon.Connector {
	s := &daemon.Service{
		Address: daemonAddr,
	}
	c, err := s.Connect(ctx)
	if err != nil {
		log.Fatal("failed to create demon connector", zap.Error(err))
	}
	return c
}

func NewQUICListener(ctx context.Context, listener quic.Listener) (quic.Connection, error) {
	conn, err := listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func ConnectQUIC(log *zap.Logger, localAddr, remoteAddr udp.UDPAddr, daemonAddr string, config *tls.Config) (*scion.QUICConnection, Data, error) {
	config.NextProtos = []string{alpn}
	ctx := context.Background()

	dc := newDaemonConnector(log, ctx, daemonAddr)
	ps, err := dc.Paths(ctx, remoteAddr.IA, localAddr.IA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		log.Fatal("failed to lookup paths", zap.Stringer("to", remoteAddr.IA), zap.Error(err))
	}
	if len(ps) == 0 {
		log.Fatal("no paths available", zap.Stringer("to", remoteAddr.IA))
	}
	log.Debug("available paths", zap.Stringer("to", remoteAddr.IA), zap.Array("via", scion.PathArrayMarshaler{Paths: ps}))
	sp := ps[0]
	log.Debug("selected path", zap.Stringer("to", remoteAddr.IA), zap.Object("via", scion.PathMarshaler{Path: sp}))

	conn, err := scion.DialQUIC(ctx, localAddr, remoteAddr, sp,
		"" /* host*/, config, nil /* quicCfg */)
	if err != nil {
		return nil, Data{}, err
	}

	//state := conn.ConnectionState().TLS.ConnectionState
	//if state.NegotiatedProtocol != alpn {
	//	return nil, Data{}, fmt.Errorf("server not speaking ntske/1")
	//}

	return conn, Data{}, nil
}

func ExchangeQUIC(log *zap.Logger, conn *scion.QUICConnection, data *Data) error {
	stream, err := conn.OpenStream()
	if err != nil {
		return err
	}
	defer quic.SendStream(stream).Close()

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
	quic.SendStream(stream).Close()
	reader := bufio.NewReader(stream)

	// Wait for response
	err = Read(log, reader, data)
	if err != nil {
		return err
	}
	return nil
}
