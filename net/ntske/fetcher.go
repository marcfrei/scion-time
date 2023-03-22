package ntske

import (
	"crypto/tls"
	"errors"

	"go.uber.org/zap"
)

type Fetcher struct {
	TLSConfig tls.Config
	Log       *zap.Logger
	data      Data
}

func (f *Fetcher) exchangeKeys() {
	ke, err := exchangeKeys(&f.TLSConfig, false)
	if err != nil {
		f.Log.Error("failed to exchange NTS keys", zap.Error(err))
	}
	logNTSKEMetadata(f.Log, ke.Meta)
	f.data = ke.Meta
}

func (f *Fetcher) FetchC2sKey() (key, cookie []byte) {
	if f.NumCookies() < 1 || f.data.C2sKey == nil {
		f.exchangeKeys()
	}

	cookie = f.data.Cookie[0]
	f.data.Cookie = f.data.Cookie[1:]

	return f.data.C2sKey, cookie
}

func (f *Fetcher) FetchS2cKey() []byte {
	if f.data.S2cKey == nil {
		f.exchangeKeys()
	}

	return f.data.S2cKey
}

func (f *Fetcher) StoreCookie(cookie []byte) {
	f.data.Cookie = append(f.data.Cookie, cookie)
}

func (f *Fetcher) FetchServer() string {
	if f.data.Server == "" {
		f.exchangeKeys()
	}

	return f.data.Server
}

func (f *Fetcher) FetchPort() int {
	if f.data.Port == 0 {
		f.exchangeKeys()
	}

	return int(f.data.Port)
}

func (f *Fetcher) NumCookies() int {
	return len(f.data.Cookie)
}

func exchangeKeys(c *tls.Config, debug bool) (*KeyExchange, error) {
	ke, err := Connect(c.ServerName, c, debug)
	if err != nil {
		return nil, err
	}

	err = ke.Exchange()
	if err != nil {
		return nil, err
	}

	if len(ke.Meta.Cookie) == 0 {
		return nil, errors.New("unexpected NTS-KE meta data: no cookies")
	}

	if ke.Meta.Algo != AES_SIV_CMAC_256 {
		return nil, errors.New("unexpected NTS-KE meta data: unknown algorithm")
	}

	err = ke.ExportKeys()
	if err != nil {
		return nil, err
	}

	return ke, nil
}
