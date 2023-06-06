package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strconv"

	"go.uber.org/zap"

	"example.com/scion-time/net/ntske"
)

func writeNTSKEErrorMsgTLS(log *zap.Logger, conn *tls.Conn, code int) {
	var msg ntske.ExchangeMsg
	msg.AddRecord(ntske.Error{
		Code: uint16(code),
	})

	buf, err := msg.Pack()
	if err != nil {
		log.Info("failed to build packet", zap.Error(err))
		return
	}

	n, err := conn.Write(buf.Bytes())
	if err != nil || n != buf.Len() {
		log.Info("failed to write error message", zap.Error(err))
		return
	}
}

func handleKeyExchangeTLS(log *zap.Logger, conn *tls.Conn, localPort int, provider *ntske.Provider) {
	defer conn.Close()

	var err error
	var data ntske.Data
	reader := bufio.NewReader(conn)
	err = ntske.ReadData(log, reader, &data)
	if err != nil {
		log.Info("failed to read key exchange", zap.Error(err))
		writeNTSKEErrorMsgTLS(log, conn, ntske.ErrorCodeBadRequest)
		return
	}

	err = ntske.ExportKeys(conn.ConnectionState(), &data)
	if err != nil {
		log.Info("failed to export keys", zap.Error(err))
		writeNTSKEErrorMsgTLS(log, conn, ntske.ErrorCodeInternalServer)
		return
	}

	localIP := conn.LocalAddr().(*net.TCPAddr).IP

	msg, err := newNTSKEMsg(log, localIP, localPort, &data, provider)
	if err != nil {
		log.Info("failed to create packet", zap.Error(err))
		writeNTSKEErrorMsgTLS(log, conn, ntske.ErrorCodeInternalServer)
		return
	}

	buf, err := msg.Pack()
	if err != nil {
		log.Info("failed to build packet", zap.Error(err))
		writeNTSKEErrorMsgTLS(log, conn, ntske.ErrorCodeInternalServer)
		return
	}

	n, err := conn.Write(buf.Bytes())
	if err != nil || n != buf.Len() {
		log.Info("failed to write response", zap.Error(err))
		return
	}
}

func runNTSKEServerTLS(log *zap.Logger, listener net.Listener, localPort int, provider *ntske.Provider) {
	defer listener.Close()
	for {
		conn, err := ntske.AcceptTLSConn(listener)
		if err != nil {
			log.Info("failed to accept client", zap.Error(err))
			continue
		}
		go handleKeyExchangeTLS(log, conn, localPort, provider)
	}
}

func StartNTSKEServerIP(ctx context.Context, log *zap.Logger, localIP net.IP, localPort int, config *tls.Config, provider *ntske.Provider) {
	ntskeAddr := net.JoinHostPort(localIP.String(), strconv.Itoa(defaultNTSKEPort))
	log.Info("server listening via IP",
		zap.Stringer("ip", localIP),
		zap.Int("port", defaultNTSKEPort),
	)

	listener, err := tls.Listen("tcp", ntskeAddr, config)
	if err != nil {
		log.Fatal("failed to create TLS listener")
	}

	go runNTSKEServerTLS(log, listener, localPort, provider)
}
