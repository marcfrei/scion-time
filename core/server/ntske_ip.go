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

func sendNtskeTcpErrorMessage(log *zap.Logger, conn *tls.Conn, code int) {
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

func handleTCPKeyExchange(log *zap.Logger, conn *tls.Conn, localPort int, provider *ntske.Provider) {
	defer conn.Close()

	var err error
	var data ntske.Data
	reader := bufio.NewReader(conn)
	err = ntske.Read(log, reader, &data)
	if err != nil {
		log.Info("failed to read key exchange", zap.Error(err))
		sendNtskeTcpErrorMessage(log, conn, 1)
		return
	}

	err = ntske.ExportKeys(conn.ConnectionState(), &data)
	if err != nil {
		log.Info("failed to export keys", zap.Error(err))
		sendNtskeTcpErrorMessage(log, conn, 2)
		return
	}

	localIP := conn.LocalAddr().(*net.TCPAddr).IP

	msg, err := newNtskeMessage(log, localIP, localPort, &data, provider)
	if err != nil {
		log.Info("failed to create packet", zap.Error(err))
		sendNtskeTcpErrorMessage(log, conn, 2)
		return
	}

	buf, err := msg.Pack()
	if err != nil {
		log.Info("failed to build packet", zap.Error(err))
		sendNtskeTcpErrorMessage(log, conn, 2)
		return
	}

	n, err := conn.Write(buf.Bytes())
	if err != nil || n != buf.Len() {
		log.Info("failed to write response", zap.Error(err))
		return
	}
}

func runNTSKEServer(log *zap.Logger, listener net.Listener, localPort int, provider *ntske.Provider) {
	defer listener.Close()
	for {
		conn, err := ntske.NewTCPListener(listener)
		if err != nil {
			log.Info("failed to accept client", zap.Error(err))
			continue
		}
		go handleTCPKeyExchange(log, conn, localPort, provider)
	}
}

func StartNTSKEServer(ctx context.Context, log *zap.Logger, localIP net.IP, localPort int, config *tls.Config, provider *ntske.Provider) {
	ntskeAddr := net.JoinHostPort(localIP.String(), strconv.Itoa(defaultNtskePort))
	log.Info("server listening via IP",
		zap.Stringer("ip", localIP),
		zap.Int("port", defaultNtskePort),
	)

	listener, err := tls.Listen("tcp", ntskeAddr, config)
	if err != nil {
		log.Error("failed to create TLS listener")
	}

	go runNTSKEServer(log, listener, localPort, provider)
}
