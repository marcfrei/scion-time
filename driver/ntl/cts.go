package ntl

// References:
// https://github.com/NetTimeLogic-Release/eth

import (
	"context"
	"log/slog"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// See https://man7.org/linux/man-pages/man2/ioctl.2.html#NOTES

	ioctlWrite = 1
	ioctlRead  = 2

	ioctlDirBits  = 2
	ioctlSizeBits = 14
	ioctlTypeBits = 8
	ioctlSNBits   = 8

	ioctlDirMask  = (1 << ioctlDirBits) - 1
	ioctlSizeMask = (1 << ioctlSizeBits) - 1
	ioctlTypeMask = (1 << ioctlTypeBits) - 1
	ioctlSNMask   = (1 << ioctlSNBits) - 1

	ioctlSNShift   = 0
	ioctlTypeShift = ioctlSNShift + ioctlSNBits
	ioctlSizeShift = ioctlTypeShift + ioctlTypeBits
	ioctlDirShift  = ioctlSizeShift + ioctlSizeBits

	ntlCTSIOCTLMagic = 'c'

	ntlCTSFlagInSync     = 0x00000001
	ntlCTSFlagInHoldover = 0x00000002
	ntlCTSFlagTimeValid  = 0x00000010

	sizeofNTLCTSTimestamp = 16 // sizeof(struct ntl_cts_timestamp)

	offsetofNTLCTSTimestampSourceIndex = 0  // offsetof(struct ntl_cts_timestamp, source_index)
	offsetofNTLCTSTimestampSecond      = 4  // offsetof(struct ntl_cts_timestamp, second)
	offsetofNTLCTSTimestampNanosecond  = 8  // offsetof(struct ntl_cts_timestamp, nanosecond)
	offsetofNTLCTSTimestampFlags       = 12 // offsetof(struct ntl_cts_timestamp, flags)
)

type ntlCTSTimestamp struct {
	sourceIndex uint8
	_           [3]byte
	second      uint32
	nanosecond  uint32
	flags       uint32
}

type CrossTimestamp struct {
	Index int
	Time  time.Time
	flags uint32
}

type CrossTimestamper struct {
	log *slog.Logger
	dev string
	fd  int
}

func init() {
	var t ntlCTSTimestamp
	if unsafe.Sizeof(t) != sizeofNTLCTSTimestamp ||
		unsafe.Offsetof(t.sourceIndex) != offsetofNTLCTSTimestampSourceIndex ||
		unsafe.Offsetof(t.second) != offsetofNTLCTSTimestampSecond ||
		unsafe.Offsetof(t.nanosecond) != offsetofNTLCTSTimestampNanosecond ||
		unsafe.Offsetof(t.flags) != offsetofNTLCTSTimestampFlags {
		panic("unexpected memory layout")
	}
}

func (t CrossTimestamp) Valid() bool {
	return t.flags&ntlCTSFlagTimeValid == ntlCTSFlagTimeValid
}

func (t CrossTimestamp) InSync() bool {
	return t.flags&ntlCTSFlagInSync == ntlCTSFlagInSync
}

func (t CrossTimestamp) InHoldover() bool {
	return t.flags&ntlCTSFlagInHoldover == ntlCTSFlagInHoldover
}

func ioctlRequest(d, s, t, n int) uint {
	// See https://man7.org/linux/man-pages/man2/ioctl.2.html#NOTES

	return (uint(d&ioctlDirMask) << ioctlDirShift) |
		(uint(s&ioctlSizeMask) << ioctlSizeShift) |
		(uint(t&ioctlTypeMask) << ioctlTypeShift) |
		(uint(n&ioctlSNMask) << ioctlSNShift)
}

func OpenCrossTimestamper(log *slog.Logger, dev string) (*CrossTimestamper, error) {
	if dev == "" {
		panic("invalid device name")
	}

	fd, err := unix.Open(dev, unix.O_RDWR, 0)
	if err != nil {
		log.LogAttrs(context.Background(), slog.LevelError,
			"unix.Open failed",
			slog.String("dev", dev),
			slog.Any("error", err),
		)
		return nil, err
	}
	if fd < 0 {
		panic("unexpected file handle value")
	}

	c := &CrossTimestamper{
		log: log,
		dev: dev,
		fd:  fd,
	}

	c.log.LogAttrs(context.Background(), slog.LevelDebug,
		"opened cross timestamper",
		slog.String("dev", c.dev),
	)

	return c, nil
}

func (c *CrossTimestamper) Close() error {
	if c.dev == "" || c.fd == -1 {
		return nil
	}

	err := unix.Close(c.fd)
	if err != nil {
		c.log.LogAttrs(context.Background(), slog.LevelError,
			"unix.Close failed",
			slog.String("dev", c.dev),
			slog.Any("error", err),
		)
		return err
	}

	c.fd = -1

	c.log.LogAttrs(context.Background(), slog.LevelDebug,
		"closed cross timestamper",
		slog.String("dev", c.dev),
	)

	return nil
}

func (c *CrossTimestamper) NumSources() (int, error) {
	if c.dev == "" || c.fd == -1 {
		return 0, unix.EBADF
	}

	var n uint32
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(c.fd),
		uintptr(ioctlRequest(ioctlRead, int(unsafe.Sizeof(n)), ntlCTSIOCTLMagic, 3)),
		uintptr(unsafe.Pointer(&n)),
	)
	if errno != 0 {
		c.log.LogAttrs(context.Background(), slog.LevelError,
			"ioctl failed (get num sources)",
			slog.String("dev", c.dev),
			slog.Uint64("errno", uint64(errno)),
		)
		return 0, errno
	}

	c.log.LogAttrs(context.Background(), slog.LevelDebug,
		"cross timestamper num sources",
		slog.String("dev", c.dev),
		slog.Uint64("count", uint64(n)),
	)

	return int(n), nil
}

func (c *CrossTimestamper) Trigger() error {
	if c.dev == "" || c.fd == -1 {
		return unix.EBADF
	}

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(c.fd),
		uintptr(ioctlRequest(0, 0, ntlCTSIOCTLMagic, 1)),
		0,
	)
	if errno != 0 {
		c.log.LogAttrs(context.Background(), slog.LevelError,
			"ioctl failed (trigger)",
			slog.String("dev", c.dev),
			slog.Uint64("errno", uint64(errno)),
		)
		return errno
	}

	c.log.LogAttrs(context.Background(), slog.LevelDebug,
		"triggered cross timestamp",
		slog.String("dev", c.dev),
	)

	return nil
}

func (c *CrossTimestamper) Timestamp(index int) (CrossTimestamp, error) {
	if index < 0 || index > 1<<8-1 {
		panic("invalid source index value")
	}

	if c.dev == "" || c.fd == -1 {
		return CrossTimestamp{}, unix.EBADF
	}

	ts := ntlCTSTimestamp{
		sourceIndex: uint8(index),
	}

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(c.fd),
		uintptr(ioctlRequest(ioctlRead|ioctlWrite, 4, ntlCTSIOCTLMagic, 2)),
		uintptr(unsafe.Pointer(&ts)),
	)
	if errno != 0 {
		c.log.LogAttrs(context.Background(), slog.LevelError,
			"ioctl failed (get timestamp)",
			slog.String("dev", c.dev),
			slog.Uint64("sourceIndex", uint64(index)),
			slog.Uint64("errno", uint64(errno)),
		)
		return CrossTimestamp{}, errno
	}

	t := CrossTimestamp{
		Index: index,
		Time:  time.Unix(int64(ts.second), int64(ts.nanosecond)).UTC(),
		flags: ts.flags,
	}

	c.log.LogAttrs(context.Background(), slog.LevelDebug,
		"cross timestamp sample",
		slog.String("dev", c.dev),
		slog.Uint64("index", uint64(index)),
		slog.Time("time", t.Time),
		slog.Bool("valid", t.Valid()),
		slog.Bool("in_sync", t.InSync()),
		slog.Bool("in_holdover", t.InHoldover()),
	)

	return t, nil
}

func (c *CrossTimestamper) Sample() ([]CrossTimestamp, error) {
	n, err := c.NumSources()
	if err != nil {
		return nil, err
	}

	err = c.Trigger()
	if err != nil {
		return nil, err
	}

	ctss := make([]CrossTimestamp, n)
	for i := range ctss {
		cts, err := c.Timestamp(i)
		if err != nil {
			return nil, err
		}
		ctss[i] = cts
	}
	return ctss, nil
}
