package udp

import (
	"unsafe"

	"errors"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

var (
	errUnsupportedOperation = errors.New("unsupported operation")
)

func EnableRxTimestamps(conn *net.UDPConn) error {
	sconn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var res struct {
		err error
	}
	err = sconn.Control(func(fd uintptr) {
		res.err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TIMESTAMP, 1)
	})
	if err != nil {
		return err
	}
	return res.err
}

func TimestampFromOOBData(oob []byte) (time.Time, error) {
	for unix.CmsgSpace(0) <= len(oob) {
		h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		if h.Len < unix.SizeofCmsghdr || uint64(h.Len) > uint64(len(oob)) {
			return time.Time{}, errUnexpectedData
		}
		if h.Level == unix.SOL_SOCKET && h.Type == unix.SCM_TIMESTAMP {
			if uint64(h.Len) != uint64(unix.CmsgSpace(int(unsafe.Sizeof(unix.Timeval{})))) {
				return time.Time{}, errUnexpectedData
			}
			ts := (*unix.Timeval)(unsafe.Pointer(&oob[unix.CmsgSpace(0)]))
			return time.Unix(ts.Unix()).UTC(), nil
		}
		oob = oob[unix.CmsgSpace(int(h.Len))-unix.CmsgSpace(0):]
	}
	return time.Time{}, errTimestampNotFound
}

func EnableTimestamping(conn *net.UDPConn, iface string) error {
	return errUnsupportedOperation
}

func ReadTXTimestamp(conn *net.UDPConn) (time.Time, uint32, error) {
	return time.Time{}, 0, errUnsupportedOperation
}
