package ntske

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"example.com/scion-time/net/udp"
)

var (
	errNoCookies   = errors.New("unexpected NTS-KE meta data: no cookies")
	errUnknownAlgo = errors.New("unexpected NTS-KE meta data: unknown algorithm")
)

type Fetcher struct {
	Log       *zap.Logger
	TLSConfig tls.Config
	Port      string
	QUIC      struct {
		Enabled    bool
		DaemonAddr string
		LocalAddr  udp.UDPAddr
		RemoteAddr udp.UDPAddr
	}
	data Data
}

func (f *Fetcher) exchangeKeys() error {
	if f.QUIC.Enabled {
		conn, _, err := dialQUIC(f.Log, f.QUIC.LocalAddr, f.QUIC.RemoteAddr, f.QUIC.DaemonAddr, &f.TLSConfig)
		if err != nil {
			return err
		}
		defer func() {
			err := conn.CloseWithError(quic.ApplicationErrorCode(0), "" /* error string */)
			if err != nil {
				f.Log.Info("failed to close connection", zap.Error(err))
			}
		}()

		err = exchangeDataQUIC(f.Log, conn, &f.data)
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
		conn, f.data, err = dialTLS(serverAddr, &f.TLSConfig)
		if err != nil {
			return err
		}

		err = exchangeDataTLS(f.Log, conn, &f.data)
		if err != nil {
			return err
		}

		err = ExportKeys(conn.ConnectionState(), &f.data)
		if err != nil {
			return err
		}
	}

	if len(f.data.Cookie) == 0 {
		return errNoCookies
	}
	if f.data.Algo != AES_SIV_CMAC_256 {
		return errUnknownAlgo
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
