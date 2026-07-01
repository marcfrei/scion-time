package udp

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"syscall"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"

	"golang.org/x/sys/unix"
)

const (
	HdrLen = 8
)

var (
	errTimestampNotFound = errors.New("failed to read timestamp from out of band data")
	errUnexpectedData    = errors.New("failed to read out of band data")
)

func seqLess(x, y uint32) bool {
	return int32(x-y) < 0
}

var _ net.Addr = (*UDPAddr)(nil)

type UDPAddr struct {
	IA   addr.IA
	Host *net.UDPAddr
}

func (a UDPAddr) Clone() UDPAddr {
	host := *a.Host
	host.IP = slices.Clone(a.Host.IP)
	return UDPAddr{
		IA:   a.IA,
		Host: &host,
	}
}

func (a UDPAddr) Network() string {
	return "scion+udp"
}

func (a UDPAddr) String() string {
	if a.Host.IP.To4() == nil {
		return fmt.Sprintf("%s,[%s]:%d", a.IA, a.Host.IP, a.Host.Port)
	} else {
		return fmt.Sprintf("%s,%s:%d", a.IA, a.Host.IP, a.Host.Port)
	}
}

func UDPAddrFromSnet(a *snet.UDPAddr) UDPAddr {
	return UDPAddr{a.IA, snet.CopyUDPAddr(a.Host)}
}

// Timestamp handling based on studying code from the following projects:
// - https://github.com/bsdphk/Ntimed, file udp.c
// - https://github.com/golang/go, package "golang.org/x/sys/unix"
// - https://github.com/gopacket/gopacket, package "github.com/gopacket/gopacket/pcapgo"
// - https://github.com/facebook/time, package "github.com/facebook/time/ntp/protocol/ntp"

func TimestampLen() int {
	return unix.CmsgSpace(3 * 16)
}

func SetsockoptReuseAddrPort(network, address string, c syscall.RawConn) error {
	var res struct {
		err error
	}
	err := c.Control(func(fd uintptr) {
		res.err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if res.err != nil {
			return
		}
		res.err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return res.err
}

func SetDSCP(conn syscall.Conn, dscp uint8) error {
	// Based on Meta's time libraries at https://github.com/facebook/time
	if dscp > 63 {
		panic("invalid argument: dscp must not be greater than 63")
	}
	if c, ok := conn.(interface{ setDSCP(uint8) error }); ok {
		return c.setDSCP(dscp)
	}
	return setDSCP(conn, dscp)
}

func getDSCP(conn syscall.Conn) (uint8, error) {
	sconn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var res struct {
		dscp uint8
		err  error
	}
	err = sconn.Control(func(fd uintptr) {
		var level, opt int
		sa, err := unix.Getsockname(int(fd))
		if err != nil {
			res.err = err
			return
		}
		switch sa.(type) {
		case *unix.SockaddrInet4:
			level, opt = unix.IPPROTO_IP, unix.IP_TOS
		case *unix.SockaddrInet6:
			level, opt = unix.IPPROTO_IPV6, unix.IPV6_TCLASS
		default:
			res.err = fmt.Errorf("unexpected socket address type %T", sa)
			return
		}
		value, err := unix.GetsockoptInt(int(fd), level, opt)
		if err != nil {
			res.err = err
			return
		}
		res.dscp = uint8(value >> 2)
	})
	if err != nil {
		return 0, err
	}
	return res.dscp, res.err
}

func setDSCP(conn syscall.Conn, dscp uint8) error {
	sconn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var res struct {
		err error
	}
	err = sconn.Control(func(fd uintptr) {
		var level, opt int
		sa, err := unix.Getsockname(int(fd))
		if err != nil {
			res.err = err
			return
		}
		switch sa.(type) {
		case *unix.SockaddrInet4:
			level, opt = unix.IPPROTO_IP, unix.IP_TOS
		case *unix.SockaddrInet6:
			level, opt = unix.IPPROTO_IPV6, unix.IPV6_TCLASS
		default:
			res.err = fmt.Errorf("unexpected socket address type %T", sa)
			return
		}
		res.err = unix.SetsockoptInt(int(fd), level, opt, int(dscp<<2))
	})
	if err != nil {
		return err
	}
	return res.err
}
