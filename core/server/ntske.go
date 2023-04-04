package server

import (
	"context"
	"crypto/tls"
	"net"

	"go.uber.org/zap"

	"example.com/scion-time/net/ntske"
)

func runNTSKEServer(log *zap.Logger, listener net.Listener, localHost *net.UDPAddr, provider *Provider) {
	for {
		ke, err := ntske.NewListener(listener)
		if err != nil {
			log.Info("failed to accept client", zap.Error(err))
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
		msg.AddRecord(ntske.NextProto{
			NextProto: ntske.NTPv4,
		})
		msg.AddRecord(ntske.Algorithm{
			Algo: []uint16{ntske.AES_SIV_CMAC_256},
		})
		msg.AddRecord(ntske.Server{
			Addr: []byte(localHost.IP.String()),
		})
		msg.AddRecord(ntske.Port{
			Port: uint16(localHost.Port),
		})

		for i := 0; i < 8; i++ {
			var plaintextCookie ntske.PlainCookie
			plaintextCookie.Algo = ntske.AES_SIV_CMAC_256
			plaintextCookie.C2S = ke.Meta.C2sKey
			plaintextCookie.S2C = ke.Meta.S2cKey
			key, err := provider.GetNewest()
			if err != nil {
				log.Info("failed to get key", zap.Error(err))
				continue
			}
			encryptedCookie, err := plaintextCookie.Encrypt(key.Value, key.Id)
			if err != nil {
				log.Info("failed to encrypt cookie", zap.Error(err))
				continue
			}

			b := encryptedCookie.Encode()
			var cookie ntske.Cookie
			cookie.Cookie = b

			msg.AddRecord(cookie)
		}

		var end ntske.End
		msg.AddRecord(end)

		buf, err := msg.Pack()
		if err != nil {
			log.Info("failed to build packet", zap.Error(err))
			continue
		}

		n, err := ke.Conn.Write(buf.Bytes())
		if err != nil || n != buf.Len() {
			log.Info("failed to write response", zap.Error(err))
			continue
		}
	}
}

func StartNTSKEServer(ctx context.Context, log *zap.Logger, localHost *net.UDPAddr, ntskeAddr string, config *tls.Config, provider *Provider) {
	log.Info("NTSKE server listening via IP", zap.String("ip", ntskeAddr))

	listener, err := tls.Listen("tcp", ntskeAddr, config)
	if err != nil {
		log.Error("failed to create TLS listener")
	}

	go runNTSKEServer(log, listener, localHost, provider)
}
