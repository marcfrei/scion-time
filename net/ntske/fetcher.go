package ntske

import (
	"crypto/tls"

	"go.uber.org/zap"
)

type Fetcher struct {
	TLSConfig tls.Config
	Log       *zap.Logger
	data      Data
}

func (f *Fetcher) exchangeKeys() {
	ke, err := ExchangeKeys(&f.TLSConfig, false, f.Log)
	if err != nil {
		f.Log.Error("failed to exchange NTS keys", zap.Error(err))
	}
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

func (f *Fetcher) GetS2cKey() []byte {
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
