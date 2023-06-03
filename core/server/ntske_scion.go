package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"example.com/scion-time/net/ntske"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

func handleSCIONKeyExchange(log *zap.Logger, conn quic.Connection, localPort int, provider *ntske.Provider) error {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return err
	}
	defer quic.SendStream(stream).Close()

	reader := bufio.NewReader(stream)
	var data ntske.Data
	err = ntske.Read(log, reader, &data)
	if err != nil {
		return errors.New("failed to read key exchange")
	}

	err = ntske.ExportKeys(conn.ConnectionState().TLS.ConnectionState, &data)
	if err != nil {
		return errors.New("failed to export keys")
	}

	localIP := conn.LocalAddr().(udp.UDPAddr).Host.IP

	msg, err := createMessage(log, localIP, localPort, &data, provider)
	if err != nil {
		log.Info("failed to create packet", zap.Error(err))
		return err
	}

	buf, err := msg.Pack()
	if err != nil {
		return errors.New("failed to build packet")
	}

	_, err = stream.Write(buf.Bytes())
	if err != nil {
		return err
	}

	quic.SendStream(stream).Close()

	return nil
}

func runSCIONNTSKEServer(ctx context.Context, log *zap.Logger, listener quic.Listener, localPort int, provider *ntske.Provider) {
	defer listener.Close()
	for {
		conn, err := ntske.NewQUICListener(context.Background(), listener)
		if err != nil {
			log.Info("failed to accept connection", zap.Error(err))
			continue
		}

		go func() {
			err := handleSCIONKeyExchange(log, conn, localPort, provider)
			var errApplication *quic.ApplicationError
			if err != nil && !(errors.As(err, &errApplication) && errApplication.ErrorCode == 0) {
				log.Info("failed to handle connection",
					zap.Stringer("remote", conn.RemoteAddr()),
					zap.Error(err),
				)
			}
		}()
	}
}

func StartSCIONNTSKEServer(ctx context.Context, log *zap.Logger, localIP net.IP, localPort int, config *tls.Config, provider *ntske.Provider, localAddr udp.UDPAddr) {
	//ntskeAddr := net.JoinHostPort(localIP.String(), strconv.Itoa(defaultNtskePort))
	log.Info("server listening via SCION",
		zap.Stringer("ip", localIP),
		zap.Int("port", defaultNtskePort),
	)

	localAddr.Host.Port = defaultNtskePort

	listener, err := scion.ListenQUIC(ctx, localAddr, config, nil /* quicCfg */)
	if err != nil {
		log.Fatal("failed to start listening", zap.Error(err))
	}

	go runSCIONNTSKEServer(ctx, log, listener, localPort, provider)
}
