package ntske

import (
	"crypto/tls"
	"errors"
	"log"
	"net"

	"go.uber.org/zap"

	"github.com/quic-go/quic-go"

	"example.com/scion-time/net/udp"
)

var (
	errNoCookies   = errors.New("unexpected NTS-KE meta data: no cookies")
	errUnknownAEAD = errors.New("unexpected NTS-KE meta data: unknown algorithm")
)

type Fetcher struct {
	Log       *zap.Logger
	TLSConfig tls.Config
	Port      string
	SCIONQuic struct {
		Enabled    bool
		RemoteAddr udp.UDPAddr
		LocalAddr  udp.UDPAddr
		DaemonAddr string
	}
	data Data
}

func (f *Fetcher) exchangeKeys() error {
	if f.SCIONQuic.Enabled {
		conn, _, err := ConnectQUIC(f.Log, f.SCIONQuic.LocalAddr, f.SCIONQuic.RemoteAddr, f.SCIONQuic.DaemonAddr, &f.TLSConfig)
		if err != nil {
			return err
		}
		defer func() {
			err := conn.CloseWithError(quic.ApplicationErrorCode(0), "" /* error string */)
			if err != nil {
				log.Fatal("failed to close connection", zap.Error(err))
			}
		}()

		err = ExchangeQUIC(f.Log, conn, &f.data)
		if err != nil {
			return err
		}

		err = ExportKeys(conn.ConnectionState().TLS.ConnectionState, &f.data)
		if err != nil {
			return err
		}

	} else {

		var err error
		var conn *tls.Conn
		serverAddr := net.JoinHostPort(f.TLSConfig.ServerName, f.Port)
		conn, f.data, err = ConnectTCP(serverAddr, &f.TLSConfig)
		if err != nil {
			return err
		}

		err = ExchangeTCP(f.Log, conn, &f.data)
		if err != nil {
			return err
		}

		if len(f.data.Cookie) == 0 {
			return errNoCookies
		}
		if f.data.Algo != AES_SIV_CMAC_256 {
			return errUnknownAEAD
		}

		err = ExportKeys(conn.ConnectionState(), &f.data)
		if err != nil {
			return err
		}
	}

	logData(f.Log, f.data)
	return nil
}

func (f *Fetcher) FetchData() (Data, error) {
	if len(f.data.Cookie) == 0 {
		err := f.exchangeKeys()
		if err != nil {
			return Data{}, err
		}
	}
	data := f.data
	f.data.Cookie = f.data.Cookie[1:]
	return data, nil
}

func (f *Fetcher) StoreCookie(cookie []byte) {
	f.data.Cookie = append(f.data.Cookie, cookie)
}
