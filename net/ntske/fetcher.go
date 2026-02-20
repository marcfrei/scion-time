package ntske

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"

	"github.com/quic-go/quic-go"

	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

var (
	errNoCookies   = errors.New("unexpected NTS-KE meta data: no cookies")
	errUnknownAlgo = errors.New("unexpected NTS-KE meta data: unknown algorithm")
)

// Fetcher is a client side NTS Cookie fetcher. It can be used for both TCP/TLS and SCION QUIC connections.
type Fetcher struct {
	Log       *slog.Logger
	TLSConfig tls.Config
	Port      string
	QUIC      struct {
		Enabled               bool
		LocalAddr             udp.UDPAddr
		RemoteAddr            udp.UDPAddr
		ControlPlaneConnector scion.ControlPlaneConnector
	}
	data Data
}

func logData(ctx context.Context, log *slog.Logger, data Data) {
	log.LogAttrs(ctx, slog.LevelDebug,
		"NTS-KE data",
		slog.String("c2s", hex.EncodeToString(data.C2sKey)),
		slog.String("s2c", hex.EncodeToString(data.S2cKey)),
		slog.String("server", data.Server),
		slog.Uint64("port", uint64(data.Port)),
		slog.Uint64("algo", uint64(data.Algo)),
		slog.Any("cookies", data.Cookie),
	)
}

func (f *Fetcher) exchangeKeys(ctx context.Context) error {
	if f.QUIC.Enabled {
		conn, _, err := dialQUIC(f.Log, f.QUIC.LocalAddr, f.QUIC.RemoteAddr, f.QUIC.ControlPlaneConnector,
			&f.TLSConfig)
		if err != nil {
			return err
		}
		defer func() {
			err := conn.CloseWithError(quic.ApplicationErrorCode(0), "" /* error string */)
			if err != nil {
				f.Log.LogAttrs(ctx, slog.LevelInfo, "failed to close connection", slog.Any("error", err))
			}
		}()

		err = exchangeDataQUIC(ctx, f.Log, conn, &f.data)
		if err != nil {
			return err
		}

		err = ExportKeys(conn.ConnectionState().TLS, &f.data)
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

		err = exchangeDataTLS(ctx, f.Log, conn, &f.data)
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

	logData(ctx, f.Log, f.data)
	return nil
}

// FetchData returns either cached data or requests new Data by performing a NTS key exchange.
func (f *Fetcher) FetchData(ctx context.Context) (Data, error) {
	if len(f.data.Cookie) == 0 {
		err := f.exchangeKeys(ctx)
		if err != nil {
			return Data{}, err
		}
	}
	data := f.data
	f.data.Cookie = f.data.Cookie[1:]
	return data, nil
}

// StoreCookie stores a cookie byte slice and appends it to the cached data.
func (f *Fetcher) StoreCookie(cookie []byte) {
	f.data.Cookie = append(f.data.Cookie, cookie)
}
