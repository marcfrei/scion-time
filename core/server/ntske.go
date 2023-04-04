package server

import (
	"context"
	"crypto/tls"
	"net"

	"go.uber.org/zap"

	"example.com/scion-time/net/ntske"
)

func runNTSKEServer(log *zap.Logger, listener net.Listener, timeServerIP string, timeServerPort int, provider *Provider) {
	log.Info("server NTSKE listening via IP")

	for {
		ke, err := ntske.NewListener(listener)
		if err != nil {
			log.Info("failed to connect to client", zap.Error(err))
			break
		}

		err = ke.Read()
		if err != nil {
			log.Info("failed to read key exchange", zap.Error(err))
			return
		}

		err = ke.ExportKeys()
		if err != nil {
			log.Info("failed to export keys", zap.Error(err))
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
		server.Addr = []byte(timeServerIP)
		msg.AddRecord(server)

		var port ntske.Port
		port.Port = uint16(timeServerPort)
		msg.AddRecord(port)

		for i := 0; i < 8; i++ {
			var plaincookie ntske.PlainCookie
			plaincookie.Algo = ntske.AES_SIV_CMAC_256
			plaincookie.C2S = ke.Meta.C2sKey
			plaincookie.S2C = ke.Meta.S2cKey
			key, err := provider.GetNewest()
			if err != nil {
				log.Info("failed to get key", zap.Error(err))
				continue
			}
			ecookie, err := plaincookie.Encrypt(key.Value, key.Id)
			if err != nil {
				log.Info("failed to encrypt cookie", zap.Error(err))
				continue
			}

			b := ecookie.Encode()
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

func StartNTSKEServer(ctx context.Context, log *zap.Logger, localHost *net.UDPAddr, ntskeAddr string, provider *Provider) {
	certs, err := tls.LoadX509KeyPair("./testnet/gen/tls.crt", "./testnet/gen/tls.key")
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

	listener, err := tls.Listen("tcp", ntskeAddr, config)
	go runNTSKEServer(log, listener, localHost.IP.String(), localHost.Port, provider)
}
