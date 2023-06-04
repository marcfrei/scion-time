package ntske

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

func NewTCPListener(listener net.Listener) (*tls.Conn, error) {
	conn, err := listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("Couldn't answer`")
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("could not convert to tls connection")
	}

	//state := tlsConn.ConnectionState()
	//if state.NegotiatedProtocol != alpn {
	//	fmt.Println(state.NegotiatedProtocol)
	//	return nil, fmt.Errorf("client not speaking ntske/1")
	//}

	return tlsConn, nil
}

func ConnectTCP(hostport string, config *tls.Config) (*tls.Conn, Data, error) {
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
		return nil, Data{}, err
	}

	var data Data
	data.Server, _, err = net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, Data{}, fmt.Errorf("unexpected remoteaddr issue: %s", err)
	}
	data.Port = DEFAULT_NTP_PORT

	state := conn.ConnectionState()
	if state.NegotiatedProtocol != alpn {
		return nil, Data{}, fmt.Errorf("server not speaking ntske/1")
	}

	return conn, data, nil
}

func ExchangeTCP(log *zap.Logger, conn *tls.Conn, data *Data) error {
	reader := bufio.NewReader(conn)

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

	err = Read(log, reader, data)
	if err != nil {
		return err
	}

	return nil
}
