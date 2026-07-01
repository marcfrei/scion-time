package phc

// Reference: https://github.com/torvalds/linux/blob/master/include/uapi/linux/ptp_clock.h

import (
	"unsafe"

	"context"
	"log/slog"
	"syscall"
	"time"

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
)

type ptpClockTime struct {
	sec      int64  /* seconds */
	nsec     uint32 /* nanoseconds */
	reserved uint32
}

type ptpSysOffset struct {
	nSamples uint32
	reserved [3]uint32
	ts       [2*25 + 1]ptpClockTime
}

type ptpSysOffsetExtended struct {
	nSamples uint32
	clockID  int32
	reserved [2]uint32
	ts       [25][3]ptpClockTime
}

type ptpSysOffsetPrecise struct {
	device      ptpClockTime
	sysRealTime ptpClockTime
	sysMonoRaw  ptpClockTime
	reserved    [4]uint32 /* Reserved for future use. */
}

const (
	sizeofPTPClockTime       = 16 // sizeof(struct ptp_clock_time)
	offsetofPTPClockTimeSec  = 0  // offsetof(struct ptp_clock_time, sec)
	offsetofPTPClockTimeNSec = 8  // offsetof(struct ptp_clock_time, nsec)

	sizeofPTPSysOffset     = 832 // sizeof(struct ptp_sys_offset)
	offsetofPTPSysOffsetTS = 16  // offsetof(struct ptp_sys_offset, ts)

	sizeofPTPSysOffsetExtended     = 1216 // sizeof(struct ptp_sys_offset_extended)
	offsetofPTPSysOffsetExtendedTS = 16   // offsetof(struct ptp_sys_offset_extended, ts)

	sizeofPTPSysOffsetPrecise              = 64 // sizeof(struct ptp_sys_offset_precise)
	offsetofPTPSysOffsetPreciseDevice      = 0  // offsetof(struct ptp_sys_offset_precise, device)
	offsetofPTPSysOffsetPreciseSysRealTime = 16 // offsetof(struct ptp_sys_offset_precise, sys_realtime)
)

type ReferenceClock struct {
	log    *slog.Logger
	dev    string
	offset time.Duration
}

func init() {
	var t0 ptpClockTime
	if unsafe.Sizeof(t0) != sizeofPTPClockTime ||
		unsafe.Offsetof(t0.sec) != offsetofPTPClockTimeSec ||
		unsafe.Offsetof(t0.nsec) != offsetofPTPClockTimeNSec {
		panic("unexpected memory layout")
	}
	var t1 ptpSysOffset
	if unsafe.Sizeof(t1) != sizeofPTPSysOffset ||
		unsafe.Offsetof(t1.ts) != offsetofPTPSysOffsetTS {
		panic("unexpected memory layout")
	}
	var t2 ptpSysOffsetExtended
	if unsafe.Sizeof(t2) != sizeofPTPSysOffsetExtended ||
		unsafe.Offsetof(t2.ts) != offsetofPTPSysOffsetExtendedTS {
		panic("unexpected memory layout")
	}
	var t3 ptpSysOffsetPrecise
	if unsafe.Sizeof(t3) != sizeofPTPSysOffsetPrecise ||
		unsafe.Offsetof(t3.device) != offsetofPTPSysOffsetPreciseDevice ||
		unsafe.Offsetof(t3.sysRealTime) != offsetofPTPSysOffsetPreciseSysRealTime {
		panic("unexpected memory layout")
	}
}

func ioctlRequest(d, s, t, n int) uint {
	// See https://man7.org/linux/man-pages/man2/ioctl.2.html#NOTES

	return (uint(d&ioctlDirMask) << ioctlDirShift) |
		(uint(s&ioctlSizeMask) << ioctlSizeShift) |
		(uint(t&ioctlTypeMask) << ioctlTypeShift) |
		(uint(n&ioctlSNMask) << ioctlSNShift)
}

func crossTS(t0TS, phcTS, t2TS ptpClockTime) (sysTime, phcTime time.Time, delay time.Duration) {
	t0 := time.Unix(t0TS.sec, int64(t0TS.nsec)).UTC()
	t2 := time.Unix(t2TS.sec, int64(t2TS.nsec)).UTC()
	delay = t2.Sub(t0)
	sysTime = t0.Add(delay / 2)
	phcTime = time.Unix(phcTS.sec, int64(phcTS.nsec)).UTC()
	return
}

func measureBasic(fd int) (sysTime, phcTime time.Time, errno syscall.Errno) {
	off := ptpSysOffset{nSamples: 7}
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(ioctlRequest(ioctlWrite, int(unsafe.Sizeof(off)), '=', 0x5)),
		uintptr(unsafe.Pointer(&off)),
	)
	if errno != 0 {
		return time.Time{}, time.Time{}, errno
	}
	sysTime, phcTime, delay := crossTS(off.ts[0], off.ts[1], off.ts[2])
	for i := 1; i < int(off.nSamples); i++ {
		sys, phc, d := crossTS(off.ts[2*i], off.ts[2*i+1], off.ts[2*i+2])
		if d < delay {
			sysTime, phcTime, delay = sys, phc, d
		}
	}
	return sysTime, phcTime, 0
}

func measureExtended(fd int) (sysTime, phcTime time.Time, errno syscall.Errno) {
	off := ptpSysOffsetExtended{nSamples: 7}
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(ioctlRequest(ioctlRead|ioctlWrite, int(unsafe.Sizeof(off)), '=', 0x9)),
		uintptr(unsafe.Pointer(&off)),
	)
	if errno != 0 {
		return time.Time{}, time.Time{}, errno
	}
	sysTime, phcTime, delay := crossTS(off.ts[0][0], off.ts[0][1], off.ts[0][2])
	for i := 1; i < int(off.nSamples); i++ {
		sys, phc, d := crossTS(off.ts[i][0], off.ts[i][1], off.ts[i][2])
		if d < delay {
			sysTime, phcTime, delay = sys, phc, d
		}
	}
	return sysTime, phcTime, 0
}

func measurePrecise(fd int) (sysTime, phcTime time.Time, errno syscall.Errno) {
	off := ptpSysOffsetPrecise{}
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(ioctlRequest(ioctlRead|ioctlWrite, int(unsafe.Sizeof(off)), '=', 0x8)),
		uintptr(unsafe.Pointer(&off)),
	)
	if errno != 0 {
		return time.Time{}, time.Time{}, errno
	}
	sysTime = time.Unix(off.sysRealTime.sec, int64(off.sysRealTime.nsec)).UTC()
	phcTime = time.Unix(off.device.sec, int64(off.device.nsec)).UTC()
	return sysTime, phcTime, 0
}

func NewReferenceClock(log *slog.Logger, dev string, offset time.Duration) *ReferenceClock {
	return &ReferenceClock{log: log, dev: dev, offset: offset}
}

func (c *ReferenceClock) MeasureClockOffset(ctx context.Context) (
	time.Time, time.Duration, error) {
	fd, err := unix.Open(c.dev, unix.O_RDWR, 0)
	if err != nil {
		c.log.LogAttrs(ctx, slog.LevelError,
			"unix.Open failed",
			slog.String("dev", c.dev),
			slog.Any("error", err),
		)
		return time.Time{}, 0, err
	}
	defer func() {
		if err := unix.Close(fd); err != nil {
			c.log.LogAttrs(ctx, slog.LevelError,
				"unix.Close failed",
				slog.String("dev", c.dev),
				slog.Any("error", err),
			)
		}
	}()

	sys, phc, errno := measurePrecise(fd)
	if errno != 0 {
		sys, phc, errno = measureExtended(fd)
	}
	if errno != 0 {
		sys, phc, errno = measureBasic(fd)
	}
	if errno != 0 {
		c.log.LogAttrs(ctx, slog.LevelError,
			"ioctl failed",
			slog.String("dev", c.dev),
			slog.Uint64("errno", uint64(errno)),
		)
		return time.Time{}, 0, errno
	}

	offset := phc.Sub(sys)
	offset += c.offset

	c.log.LogAttrs(ctx, slog.LevelDebug,
		"PTP hardware clock sample",
		slog.Time("sysRealTime", sys),
		slog.Time("deviceTime", phc),
		slog.Duration("offset", offset),
	)

	return sys, offset, nil
}
