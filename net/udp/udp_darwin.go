package udp

import (
	"sync"
	"unsafe"

	"errors"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	errUnsupportedOperation = errors.New("unsupported operation")
)

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
		oob = oob[unix.CmsgSpace(int(h.Len)-unix.SizeofCmsghdr):]
	}
	return time.Time{}, errTimestampNotFound
}

func EnableRXTimestamping(conn syscall.Conn, iface string, index int) error {
	return errUnsupportedOperation
}

func EnableTimestamping(conn syscall.Conn, iface string, index int) error {
	if c, ok := conn.(interface {
		enableTimestamping(string, int) error
	}); ok {
		return c.enableTimestamping(iface, index)
	}
	return enableTimestamping(conn, iface, index)
}

func enableTimestamping(conn syscall.Conn, iface string, index int) error {
	return errUnsupportedOperation
}

func ReadTXTimestamp(conn syscall.Conn, id uint32) (time.Time, uint32, error) {
	if c, ok := conn.(interface {
		readTXTimestamp(uint32) (time.Time, uint32, error)
	}); ok {
		return c.readTXTimestamp(id)
	}
	return readTXTimestamp(conn, id, nil)
}

func readTXTimestamp(conn syscall.Conn, id uint32, locker sync.Locker) (time.Time, uint32, error) {
	return time.Time{}, 0, errUnsupportedOperation
}
