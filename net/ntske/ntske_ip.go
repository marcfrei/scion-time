package ntske

import (
	"bufio"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

func AcceptTLSConn(l net.Listener) (*tls.Conn, error) {
	conn, err := l.Accept()
	if err != nil {
		return nil, err
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		panic("invalid listener type: TLS listener expected")
	}

	return tlsConn, nil
}

func dialTLS(hostport string, config *tls.Config) (*tls.Conn, Data, error) {
	config.NextProtos = []string{alpn}

	_, _, err := net.SplitHostPort(hostport)
	if err != nil {
		if !strings.Contains(err.Error(), "missing port in address") {
			return nil, Data{}, err
		}
		hostport = net.JoinHostPort(hostport, strconv.Itoa(DEFAULT_NTSKE_PORT))
	}

	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: time.Second * 5,
	}, "tcp", hostport, config)
	if err != nil {
		_ = conn.Close()
		return nil, Data{}, err
	}

	var data Data
	data.Server, _, err = net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		_ = conn.Close()
		return nil, Data{}, err
	}
	data.Port = DEFAULT_NTP_PORT

	state := conn.ConnectionState()
	if state.NegotiatedProtocol != alpn {
		_ = conn.Close()
		return nil, Data{}, errServerNoNTSKE
	}

	return conn, data, nil
}

func exchangeDataTLS(log *zap.Logger, conn *tls.Conn, data *Data) error {
	var msg ExchangeMsg

	var nextproto NextProto
	nextproto.NextProto = NTPv4
	msg.AddRecord(nextproto)

	var algo Algorithm
	algo.Algo = []uint16{AES_SIV_CMAC_256}
	msg.AddRecord(algo)

	var end End
	msg.AddRecord(end)

	buf, err := msg.Pack()
	if err != nil {
		return err
	}

	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return err
	}

	reader := bufio.NewReader(conn)
	err = ReadData(log, reader, data)
	if err != nil {
		return err
	}

	return nil
}
