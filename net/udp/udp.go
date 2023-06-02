package udp

import (
	"errors"
	"fmt"
	"net"

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

type UDPAddr struct {
	IA   addr.IA
	Host *net.UDPAddr
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
// - https://github.com/google/gopacket, package "github.com/google/gopacket/pcapgo"
// - https://github.com/facebook/time, package "github.com/facebook/time/ntp/protocol/ntp"

func TimestampLen() int {
	return unix.CmsgSpace(3 * 16)
}

func SetDSCP(conn *net.UDPConn, dscp uint8) error {
	// Based on Meta's time libraries at https://github.com/facebook/time
	if dscp > 63 {
		panic("invalid argument: dscp must not be greater than 63")
	}
	sconn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var res struct {
		err error
	}
	err = sconn.Control(func(fd uintptr) {
		ip := conn.LocalAddr().(*net.UDPAddr).IP
		if ip.To4() == nil {
			res.err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, int(dscp<<2))
		} else {
			res.err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, int(dscp<<2))
		}
	})
	if err != nil {
		return err
	}
	return res.err
}
