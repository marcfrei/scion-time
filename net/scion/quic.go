package scion

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/quic-go/quic-go"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"

	"example.com/scion-time/net/udp"
)

var (
	errInvalidListenerPort = errors.New("invalid listener port")
	errPacketWriting       = errors.New("failed to write packet")
	errPathAvailability    = errors.New("no path available")
	errPathReversal        = errors.New("failed to reverse path")
	errUnexpectedAddrType  = errors.New("unexpected address type")
	errUnexpectedPathType  = errors.New("unexpected path type")
)

type baseConn struct {
	raw       *net.UDPConn
	localAddr udp.UDPAddr
	readMu    sync.Mutex
	readBuf   []byte
}

func (c *baseConn) readPkt(b []byte) (int, udp.UDPAddr, snet.DataplanePath, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readBuf == nil {
		c.readBuf = make([]byte, MTU)
	}
	buf := c.readBuf

	var (
		scionLayer slayers.SCION
		hbhLayer   slayers.HopByHopExtnSkipper
		e2eLayer   slayers.EndToEndExtnSkipper
		udpLayer   slayers.UDP
	)
	scionLayer.RecyclePaths()
	udpLayer.SetNetworkLayerForChecksum(&scionLayer)
	parser := gopacket.NewDecodingLayerParser(
		slayers.LayerTypeSCION, &scionLayer, &hbhLayer, &e2eLayer, &udpLayer,
	)
	parser.IgnoreUnsupported = true
	decoded := make([]gopacket.LayerType, 4)

	for {
		buf = buf[:cap(buf)]
		n, lastHop, err := c.raw.ReadFrom(buf)
		if err != nil {
			return 0, udp.UDPAddr{}, nil, nil, err
		}
		buf = buf[:n]

		err = parser.DecodeLayers(buf, &decoded)
		if err != nil {
			continue // ignore non-SCION packet
		}
		validType := len(decoded) >= 2 &&
			decoded[len(decoded)-1] == slayers.LayerTypeSCIONUDP
		if !validType {
			continue // ignore non-UDP payload
		}
		srcAddr, err := scionLayer.SrcAddr()
		if err != nil {
			continue // ignore unexpected address type
		}
		remoteAddr := udp.UDPAddr{
			IA: scionLayer.SrcIA,
			Host: &net.UDPAddr{
				IP:   srcAddr.IP().AsSlice(),
				Port: int(udpLayer.SrcPort),
			},
		}
		rpath := snet.RawPath{
			PathType: scionLayer.Path.Type(),
		}
		if l := scionLayer.Path.Len(); l != 0 {
			rpath.Raw = make([]byte, l)
			if err := scionLayer.Path.SerializeTo(rpath.Raw); err != nil {
				panic(err)
			}
		}
		n = copy(b, gopacket.Payload(udpLayer.Payload))

		return n, remoteAddr, rpath, lastHop, nil
	}
}

func (c *baseConn) writePkt(remoteAddr udp.UDPAddr, path snet.DataplanePath, nextHop net.Addr, b []byte) (int, error) {
	var err error

	var scionLayer slayers.SCION
	scionLayer.SrcIA = c.localAddr.IA
	srcAddrIP, ok := netip.AddrFromSlice(c.localAddr.Host.IP)
	if !ok {
		panic(errUnexpectedAddrType)
	}
	err = scionLayer.SetSrcAddr(addr.HostIP(srcAddrIP.Unmap()))
	if err != nil {
		panic(err)
	}
	scionLayer.DstIA = remoteAddr.IA
	dstAddrIP, ok := netip.AddrFromSlice(remoteAddr.Host.IP)
	if !ok {
		panic(errUnexpectedAddrType)
	}
	err = scionLayer.SetDstAddr(addr.HostIP(dstAddrIP.Unmap()))
	if err != nil {
		panic(err)
	}
	err = path.SetPath(&scionLayer)
	if err != nil {
		panic(err)
	}
	scionLayer.NextHdr = slayers.L4UDP

	var udpLayer slayers.UDP
	udpLayer.SrcPort = uint16(c.localAddr.Host.Port)
	udpLayer.DstPort = uint16(remoteAddr.Host.Port)
	udpLayer.SetNetworkLayerForChecksum(&scionLayer)

	payload := gopacket.Payload(b)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err = payload.SerializeTo(buffer, options)
	if err != nil {
		panic(err)
	}
	buffer.PushLayer(payload.LayerType())

	err = udpLayer.SerializeTo(buffer, options)
	if err != nil {
		panic(err)
	}
	buffer.PushLayer(udpLayer.LayerType())

	err = scionLayer.SerializeTo(buffer, options)
	if err != nil {
		panic(err)
	}
	buffer.PushLayer(scionLayer.LayerType())

	n, err := c.raw.WriteTo(buffer.Bytes(), nextHop)
	if err != nil {
		return 0, err
	}
	if n != len(buffer.Bytes()) {
		return 0, errPacketWriting
	}

	return len(b), nil
}

func (c *baseConn) Close() error {
	return c.raw.Close()
}

func (c *baseConn) SetDeadline(t time.Time) error {
	return c.raw.SetDeadline(t)
}

func (c *baseConn) SetReadDeadline(t time.Time) error {
	return c.raw.SetReadDeadline(t)
}

func (c *baseConn) SetWriteDeadline(t time.Time) error {
	return c.raw.SetWriteDeadline(t)
}

func (c *baseConn) SetReadBuffer(bytes int) error {
	return c.raw.SetReadBuffer(bytes)
}

func (c *baseConn) SyscallConn() (syscall.RawConn, error) {
	return c.raw.SyscallConn()
}

var _ net.Addr = (*udpAddrPath)(nil)

type udpAddrPath struct {
	addr    udp.UDPAddr
	path    snet.DataplanePath
	nextHop net.Addr
}

func (ap udpAddrPath) Network() string {
	return ap.addr.Network()
}

func (ap udpAddrPath) String() string {
	return ap.addr.String()
}

type serverConn struct {
	baseConn
}

func (c *serverConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *serverConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, remoteAddr, path, lastHop, err := c.readPkt(b)
	if err != nil {
		return 0, nil, err
	}
	rpath, ok := path.(snet.RawPath)
	if !ok {
		return 0, nil, errUnexpectedPathType
	}
	replyPather := snet.DefaultReplyPather{}
	replyPath, err := replyPather.ReplyPath(rpath)
	if err != nil {
		return 0, nil, errPathReversal
	}
	remoteAddrPath := udpAddrPath{
		addr:    remoteAddr,
		path:    replyPath,
		nextHop: lastHop,
	}
	return n, remoteAddrPath, err
}

func (c *serverConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	remoteAddrPath, ok := addr.(udpAddrPath)
	if !ok {
		return 0, errUnexpectedAddrType
	}
	return c.writePkt(remoteAddrPath.addr, remoteAddrPath.path, remoteAddrPath.nextHop, b)
}

func (c *serverConn) Close() error {
	return c.baseConn.Close()
}

func listenUDP(ctx context.Context, localAddr udp.UDPAddr) (net.PacketConn, error) {
	if localAddr.Host.Port == EndhostPort {
		return nil, errInvalidListenerPort
	}
	raw, err := net.ListenUDP("udp", localAddr.Host)
	if err != nil {
		return nil, err
	}
	localAddr.Host.Port = raw.LocalAddr().(*net.UDPAddr).Port
	conn := &serverConn{
		baseConn: baseConn{
			raw:       raw,
			localAddr: localAddr,
		},
	}
	return conn, nil
}

type QUICListener struct {
	*quic.Listener
	conn net.PacketConn
}

func (l *QUICListener) Close() error {
	err := l.Listener.Close()
	_ = l.conn.Close()
	return err
}

func ListenQUIC(ctx context.Context, localAddr udp.UDPAddr,
	tlsCfg *tls.Config, quicCfg *quic.Config) (*QUICListener, error) {
	conn, err := listenUDP(ctx, localAddr)
	if err != nil {
		return nil, err
	}
	if quicCfg == nil {
		quicCfg = &quic.Config{}
	}
	qlistener, err := quic.Listen(conn, tlsCfg, quicCfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &QUICListener{qlistener, conn}, nil
}

type clientConn struct {
	baseConn
	remoteAddr string
	path       snet.DataplanePath
	nextHop    net.Addr
}

func (c *clientConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *clientConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, remoteAddr, _, _, err := c.readPkt(b)
		if err != nil {
			return 0, nil, err
		}
		if remoteAddr.String() != c.remoteAddr {
			continue // ignore packet from unexpected source
		}
		return n, remoteAddr, err
	}
}

func (c *clientConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	remoteAddr, ok := addr.(udp.UDPAddr)
	if !ok {
		return 0, errUnexpectedAddrType
	}
	if remoteAddr.String() != c.remoteAddr {
		return 0, errPathAvailability
	}
	return c.writePkt(remoteAddr, c.path, c.nextHop, b)
}

func (c *clientConn) Close() error {
	return c.baseConn.Close()
}

func dialUDP(ctx context.Context, localAddr, remoteAddr udp.UDPAddr, path snet.Path) (net.PacketConn, error) {
	raw, err := net.ListenUDP("udp", &net.UDPAddr{IP: localAddr.Host.IP})
	if err != nil {
		return nil, err
	}
	localAddr.Host.Port = raw.LocalAddr().(*net.UDPAddr).Port
	nextHop := path.UnderlayNextHop()
	return &clientConn{
		baseConn: baseConn{
			raw:       raw,
			localAddr: localAddr,
		},
		remoteAddr: remoteAddr.String(),
		path:       path.Dataplane(),
		nextHop:    nextHop,
	}, nil
}

type QUICConnection struct {
	*quic.Conn
	net.PacketConn
}

func (c *QUICConnection) CloseWithError(code quic.ApplicationErrorCode, desc string) error {
	err := c.Conn.CloseWithError(code, desc)
	_ = c.PacketConn.Close()
	return err
}

func DialQUIC(ctx context.Context, localAddr, remoteAddr udp.UDPAddr, path snet.Path,
	host string, tlsCfg *tls.Config, quicCfg *quic.Config) (*QUICConnection, error) {
	conn, err := dialUDP(ctx, localAddr, remoteAddr, path)
	if err != nil {
		return nil, err
	}
	qconn, err := quic.Dial(ctx, conn, remoteAddr, tlsCfg, quicCfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &QUICConnection{qconn, conn}, nil
}
