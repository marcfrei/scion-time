package ntske

import (
	"crypto/tls"

	"go.uber.org/zap"
)

type Fetcher struct {
	TLSConfig tls.Config
	data      Data
	Log       *zap.Logger
}

func (f *Fetcher) exchangeKeys() {
	ke, err := ExchangeKeys(&f.TLSConfig, true, f.Log)
	if err != nil {
		f.Log.Error("NTS-KE exchange error: ", zap.Error(err))
	}
	f.data = ke.Meta
}

func (f *Fetcher) GetCookieC2sKey() ([]byte, []byte) {
	if f.GetNumberOfCookies() < 1 || f.data.C2sKey == nil {
		f.exchangeKeys()
	}

	cookie := f.data.Cookie[0]
	f.data.Cookie = f.data.Cookie[1:]

	return cookie, f.data.C2sKey
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

func (f *Fetcher) GetServerIP() string {
	if f.data.Server == "" {
		f.exchangeKeys()
	}

	return f.data.Server
}

func (f *Fetcher) GetServerPort() int {
	if f.data.Port == 0 {
		f.exchangeKeys()
	}

	return int(f.data.Port)
}

func (f *Fetcher) GetNumberOfCookies() int {
	return len(f.data.Cookie)
}
