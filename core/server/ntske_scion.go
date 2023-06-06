package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"example.com/scion-time/net/ntske"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

func writeNTSKEErrorMsgQUIC(log *zap.Logger, stream quic.Stream, code int) {
	var msg ntske.ExchangeMsg
	msg.AddRecord(ntske.Error{
		Code: uint16(code),
	})

	buf, err := msg.Pack()
	if err != nil {
		log.Info("failed to build packet", zap.Error(err))
		return
	}

	n, err := stream.Write(buf.Bytes())
	if err != nil || n != buf.Len() {
		log.Info("failed to write error message", zap.Error(err))
		return
	}
}

func handleKeyExchangeQUIC(log *zap.Logger, conn quic.Connection, localPort int, provider *ntske.Provider) error {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return err
	}
	defer stream.Close()

	var data ntske.Data
	reader := bufio.NewReader(stream)
	err = ntske.ReadData(log, reader, &data)
	if err != nil {
		log.Info("failed to read key exchange", zap.Error(err))
		writeNTSKEErrorMsgQUIC(log, stream, ntske.ErrorCodeBadRequest)
		return err
	}

	err = ntske.ExportKeys(conn.ConnectionState().TLS.ConnectionState, &data)
	if err != nil {
		log.Info("failed to export keys", zap.Error(err))
		writeNTSKEErrorMsgQUIC(log, stream, ntske.ErrorCodeInternalServer)
		return err
	}

	localIP := conn.LocalAddr().(udp.UDPAddr).Host.IP

	msg, err := newNTSKEMsg(log, localIP, localPort, &data, provider)
	if err != nil {
		log.Info("failed to create packet", zap.Error(err))
		writeNTSKEErrorMsgQUIC(log, stream, ntske.ErrorCodeInternalServer)
		return err
	}

	buf, err := msg.Pack()
	if err != nil {
		log.Info("failed to build packet", zap.Error(err))
		writeNTSKEErrorMsgQUIC(log, stream, ntske.ErrorCodeInternalServer)
		return err
	}

	_, err = stream.Write(buf.Bytes())
	if err != nil {
		log.Info("failed to write response", zap.Error(err))
		return err
	}

	return nil
}

func runNTSKEServerQUIC(ctx context.Context, log *zap.Logger, listener quic.Listener, localPort int, provider *ntske.Provider) {
	defer listener.Close()
	for {
		conn, err := ntske.AcceptQUICConn(context.Background(), listener)
		if err != nil {
			log.Info("failed to accept connection", zap.Error(err))
			continue
		}

		go func() {
			err := handleKeyExchangeQUIC(log, conn, localPort, provider)
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

func StartNTSKEServerSCION(ctx context.Context, log *zap.Logger, localAddr udp.UDPAddr, config *tls.Config, provider *ntske.Provider) {
	log.Info("server listening via SCION",
		zap.Stringer("ip", localAddr.Host.IP),
		zap.Int("port", defaultNTSKEPort),
	)

	localPort := localAddr.Host.Port
	localAddr.Host.Port = defaultNTSKEPort

	listener, err := scion.ListenQUIC(ctx, localAddr, config, nil /* quicCfg */)
	if err != nil {
		log.Fatal("failed to create QUIC listener")
	}

	go runNTSKEServerQUIC(ctx, log, listener, localPort, provider)
}
