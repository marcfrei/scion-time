package udp

import (
	"unsafe"

	"net"
	"time"

	"golang.org/x/sys/unix"
)

func TimestampFromOOBData(oob []byte) (time.Time, error) {
	for unix.CmsgSpace(0) <= len(oob) {
		h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		if h.Len < unix.SizeofCmsghdr || h.Len > uint64(len(oob)) {
			return time.Time{}, errUnexpectedData
		}
		if h.Level == unix.SOL_SOCKET {
			if h.Type == unix.SO_TIMESTAMPING_NEW {
				if h.Len != uint64(unix.CmsgSpace(3*16)) {
					return time.Time{}, errUnexpectedData
				}
				i := unix.CmsgSpace(0)
				sec0 := *(*int64)(unsafe.Pointer(&oob[i+0]))
				nsec0 := *(*int64)(unsafe.Pointer(&oob[i+8]))
				sec1 := *(*int64)(unsafe.Pointer(&oob[i+16]))
				nsec1 := *(*int64)(unsafe.Pointer(&oob[i+24]))
				sec2 := *(*int64)(unsafe.Pointer(&oob[i+32]))
				nsec2 := *(*int64)(unsafe.Pointer(&oob[i+40]))
				var ts time.Time
				if sec2 != 0 || nsec2 != 0 {
					if sec0 != 0 || nsec0 != 0 || sec1 != 0 || nsec1 != 0 {
						panic("unexpected timestamping behavior")
					}
					ts = time.Unix(sec2, nsec2).UTC()
				} else {
					if sec1 != 0 || nsec1 != 0 {
						panic("unexpected timestamping behavior")
					}
					ts = time.Unix(sec0, nsec0).UTC()
				}
				return ts, nil
			} else if h.Type == unix.SCM_TIMESTAMPNS {
				if h.Len != uint64(unix.CmsgSpace(int(unsafe.Sizeof(unix.Timespec{})))) {
					return time.Time{}, errUnexpectedData
				}
				ts := (*unix.Timespec)(unsafe.Pointer(&oob[unix.CmsgSpace(0)]))
				return time.Unix(ts.Unix()).UTC(), nil
			}
		}
		oob = oob[unix.CmsgSpace(int(h.Len)-unix.SizeofCmsghdr):]
	}
	return time.Time{}, errTimestampNotFound
}

// For details on hardware timestamping configuration, see
// - https://docs.kernel.org/networking/timestamping.html
// - https://github.com/torvalds/linux/blob/master/include/uapi/linux/net_tstamp.h

const (
	//lint:ignore ST1003 maintain consistency with package 'unix'
	HWTSTAMP_TX_ON = 1
	//lint:ignore ST1003 maintain consistency with package 'unix'
	HWTSTAMP_FILTER_ALL = 1
)

type hwtstampConfig struct {
	flags    int32
	txType   int32
	rxFilter int32
}

type soTimestamping struct {
	flags   int32
	bindPHC int32
}

// See https://man7.org/linux/man-pages/man7/netdevice.7.html
type ifreq struct {
	ifrName [unix.IFNAMSIZ]byte
	ifrData uintptr
}

func initNetworkInterface(fd int, ifname string, filter int32) error {
	// Based on Meta's time libraries at https://github.com/facebook/time
	var req ifreq
	var cfg hwtstampConfig

	copy(req.ifrName[:cap(req.ifrName)-1], ifname)
	req.ifrData = uintptr(unsafe.Pointer(&cfg))

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		unix.SIOCGHWTSTAMP, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return errno
	}

	if cfg.txType == HWTSTAMP_TX_ON && cfg.rxFilter == filter {
		return nil
	}

	cfg.txType = HWTSTAMP_TX_ON
	cfg.rxFilter = filter
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		unix.SIOCSHWTSTAMP, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return errno
	}

	return nil
}

func EnableTimestamping(conn *net.UDPConn, iface string, index int) error {
	sconn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var res struct {
		err error
	}

	if index >= 0 {
		err = sconn.Control(func(fd uintptr) {
			res.err = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		})
		if err != nil {
			return err
		}
		if res.err != nil {
			return res.err
		}
	}

	sockopts := unix.SOF_TIMESTAMPING_OPT_ID |
		unix.SOF_TIMESTAMPING_OPT_TSONLY

	if iface != "" {
		sockopts |= unix.SOF_TIMESTAMPING_RAW_HARDWARE |
			unix.SOF_TIMESTAMPING_RX_HARDWARE |
			unix.SOF_TIMESTAMPING_TX_HARDWARE

		err = sconn.Control(func(fd uintptr) {
			res.err = initNetworkInterface(int(fd), iface, HWTSTAMP_FILTER_ALL)
		})
		if err != nil {
			return err
		}
		if res.err != nil {
			return res.err
		}
	} else {
		sockopts |= unix.SOF_TIMESTAMPING_SOFTWARE |
			unix.SOF_TIMESTAMPING_RX_SOFTWARE |
			unix.SOF_TIMESTAMPING_TX_SOFTWARE
	}

	ts := soTimestamping{
		flags: int32(sockopts),
	}
	if index >= 0 {
		sockopts |= unix.SOF_TIMESTAMPING_BIND_PHC
		ts.flags = int32(sockopts)
		ts.bindPHC = int32(index)
	}

	err = sconn.Control(func(fd uintptr) {
		_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT,
			fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPING_NEW,
			uintptr(unsafe.Pointer(&ts)), unsafe.Sizeof(ts), 0)
		if errno != 0 {
			res.err = errno
		}
	})
	if err != nil {
		return err
	}
	if res.err != nil {
		return res.err
	}

	return nil
}

func timestampFromOOBData(oob []byte) (time.Time, uint32, error) {
	var tsSet, idSet bool
	var ts time.Time
	var id uint32
	for unix.CmsgSpace(0) <= len(oob) {
		h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		if h.Len < unix.SizeofCmsghdr || h.Len > uint64(len(oob)) {
			return time.Time{}, 0, errUnexpectedData
		}
		if h.Level == unix.SOL_SOCKET {
			if h.Type == unix.SO_TIMESTAMPING_NEW {
				if h.Len != uint64(unix.CmsgSpace(3*16)) {
					return time.Time{}, 0, errUnexpectedData
				}
				i := unix.CmsgSpace(0)
				sec0 := *(*int64)(unsafe.Pointer(&oob[i+0]))
				nsec0 := *(*int64)(unsafe.Pointer(&oob[i+8]))
				sec1 := *(*int64)(unsafe.Pointer(&oob[i+16]))
				nsec1 := *(*int64)(unsafe.Pointer(&oob[i+24]))
				sec2 := *(*int64)(unsafe.Pointer(&oob[i+32]))
				nsec2 := *(*int64)(unsafe.Pointer(&oob[i+40]))
				if sec2 != 0 || nsec2 != 0 {
					if sec0 != 0 || nsec0 != 0 || sec1 != 0 || nsec1 != 0 {
						panic("unexpected timestamping behavior")
					}
					ts = time.Unix(sec2, nsec2).UTC()
				} else {
					if sec1 != 0 || nsec1 != 0 {
						panic("unexpected timestamping behavior")
					}
					ts = time.Unix(sec0, nsec0).UTC()
				}
				tsSet = true
			}
		} else if h.Level == unix.SOL_IP && h.Type == unix.IP_RECVERR ||
			h.Level == unix.SOL_IPV6 && h.Type == unix.IPV6_RECVERR {
			if h.Len < uint64(unix.CmsgSpace(int(unsafe.Sizeof(unix.SockExtendedErr{})))) {
				return time.Time{}, 0, errUnexpectedData
			}
			seerr := *(*unix.SockExtendedErr)(unsafe.Pointer(&oob[unix.CmsgSpace(0)]))
			if seerr.Errno != uint32(unix.ENOMSG) {
				return time.Time{}, 0, errUnexpectedData
			}
			if seerr.Origin != unix.SO_EE_ORIGIN_TIMESTAMPING {
				return time.Time{}, 0, errUnexpectedData
			}
			if seerr.Info != unix.SCM_TSTAMP_SND {
				return time.Time{}, 0, errUnexpectedData
			}
			id = seerr.Data
			idSet = true
		}
		oob = oob[unix.CmsgSpace(int(h.Len)-unix.SizeofCmsghdr):]
	}
	if !tsSet || !idSet {
		return time.Time{}, 0, errTimestampNotFound
	}
	return ts, id, nil
}

func ReadTXTimestamp(conn *net.UDPConn, id uint32) (time.Time, uint32, error) {
	sconn, err := conn.SyscallConn()
	if err != nil {
		return time.Time{}, 0, err
	}
	var res struct {
		ts  time.Time
		id  uint32
		err error
	}
	err = sconn.Control(func(fd uintptr) {
		for range 8192 {
			pollFds := []unix.PollFd{
				{Fd: int32(fd), Events: unix.POLLPRI},
			}
			var n int
			for {
				n, err = unix.Poll(pollFds, 0)
				if err == unix.EINTR {
					continue
				}
				break
			}
			if err != nil {
				res.err = err
				return
			}
			if n != len(pollFds) {
				continue
			}
			buf := make([]byte, 0)
			oob := make([]byte, 128)
			var oobn, flags int
			var srcAddr unix.Sockaddr
			for {
				n, oobn, flags, srcAddr, err = unix.Recvmsg(int(fd), buf, oob, unix.MSG_ERRQUEUE)
				if err == unix.EINTR {
					continue
				}
				break
			}
			if err != nil {
				res.err = err
				return
			}
			if n != 0 {
				res.err = errUnexpectedData
				return
			}
			if flags&unix.MSG_ERRQUEUE != unix.MSG_ERRQUEUE {
				res.err = errUnexpectedData
				return
			}
			if srcAddr != nil {
				res.err = errUnexpectedData
				return
			}
			rests, resid, err := timestampFromOOBData(oob[:oobn])
			if err != nil {
				res.err = err
				return
			}
			if resid >= id {
				res.ts, res.id = rests, resid
				return
			}
		}
		res.err = errTimestampNotFound
	})
	if err != nil {
		return time.Time{}, 0, err
	}
	return res.ts, res.id, res.err
}
