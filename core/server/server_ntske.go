package server

import (
	"context"
	"crypto/tls"
	"net"

	"go.uber.org/zap"

	"example.com/scion-time/net/nts"
	"example.com/scion-time/net/ntske"
)

const (
	cookiesecret string = "12345678901234567890123456789012"
	cookiekeyid  int    = 17
)

func runNTSKEServer(log *zap.Logger, listener net.Listener) {
	log.Info("server NTSKE listening via IP")

	for {
		ke, err := ntske.NewListener(listener)
		if err != nil {
			log.Error("server: accept", zap.Error(err))
			break
		}

		err = ke.Read()
		if err != nil {
			log.Error("Read Key Exchange", zap.Error(err))
			return
		}

		err = ke.ExportKeys()
		if err != nil {
			log.Error("Key Exchange export", zap.Error(err))
			return
		}

		var msg ntske.ExchangeMsg

		var nextproto ntske.NextProto
		nextproto.NextProto = ntske.NTPv4
		msg.AddRecord(nextproto)

		var algo ntske.Algorithm
		algo.Algo = []uint16{ntske.AES_SIV_CMAC_256}
		msg.AddRecord(algo)

		var server ntske.Server
		server.Addr = []byte("127.0.0.1")
		msg.AddRecord(server)

		var port ntske.Port
		port.Port = 1234
		msg.AddRecord(port)

		for i := 0; i < 8; i++ {
			var plaincookie nts.PlainCookie
			plaincookie.Algo = ntske.AES_SIV_CMAC_256
			plaincookie.C2S = ke.Meta.C2sKey
			plaincookie.S2C = ke.Meta.S2cKey
			ecookie, err := plaincookie.Encrypt([]byte(cookiesecret), cookiekeyid)
			if err != nil {
				log.Error("Couldn't encrypt cookie", zap.Error(err))
				continue
			}

			b, err := ecookie.Encode()
			if err != nil {
				log.Error("Couldn't encode cookie", zap.Error(err))
				continue
			}

			var cookie ntske.Cookie
			cookie.Cookie = b

			msg.AddRecord(cookie)
		}

		var end ntske.End
		msg.AddRecord(end)

		buf, err := msg.Pack()
		if err != nil {
			return
		}

		_, err = ke.Conn.Write(buf.Bytes())

		if err != nil {
			log.Error("failed sending response", zap.Error(err))
		}
	}
}

func StartNTSKEServer(ctx context.Context, log *zap.Logger,
	localHost *net.UDPAddr) {
	certs, err := tls.LoadX509KeyPair("./core/server/tls.crt", "./core/server/tls.key")
	if err != nil {
		log.Error("TLS Key load", zap.Error(err))
		return
	}

	config := &tls.Config{
		ServerName:   "localhost",
		NextProtos:   []string{"ntske/1"},
		Certificates: []tls.Certificate{certs},
		MinVersion:   tls.VersionTLS13,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:4600", config)
	go runNTSKEServer(log, listener)
}
