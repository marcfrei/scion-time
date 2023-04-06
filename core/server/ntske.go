package server

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"

	"go.uber.org/zap"

	"example.com/scion-time/net/ntske"
)

const defaultNtskePort int = 4460

func runNTSKEServer(log *zap.Logger, listener net.Listener, localHost *net.UDPAddr, provider *ntske.Provider) {
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

		var plaintextCookie ntske.PlainCookie
		plaintextCookie.Algo = ntske.AES_SIV_CMAC_256
		plaintextCookie.C2S = ke.Meta.C2sKey
		plaintextCookie.S2C = ke.Meta.S2cKey
		key := provider.Current()
		for i := 0; i < 8; i++ {
			encryptedCookie, err := plaintextCookie.Encrypt(key.Value, key.Id)
			if err != nil {
				log.Info("failed to encrypt cookie", zap.Error(err))
				continue
			}

			b := encryptedCookie.Encode()
			msg.AddRecord(ntske.Cookie{
				Cookie: b,
			})
		}

		msg.AddRecord(ntske.End{})

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

func StartNTSKEServer(ctx context.Context, log *zap.Logger, localHost *net.UDPAddr, config *tls.Config, provider *ntske.Provider) {
	ntskeAddr := net.JoinHostPort(localHost.IP.String(), strconv.Itoa(defaultNtskePort))
	log.Info("server listening via IP",
		zap.Stringer("ip", localHost.IP),
		zap.Int("port", defaultNtskePort),
	)

	listener, err := tls.Listen("tcp", ntskeAddr, config)
	if err != nil {
		log.Error("failed to create TLS listener")
	}

	go runNTSKEServer(log, listener, localHost, provider)
}
