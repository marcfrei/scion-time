package phc

// Reference: https://github.com/torvalds/linux/blob/master/include/uapi/linux/ptp_clock.h

import (
	"unsafe"

	"context"
	"log/slog"
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

const (
	sizeofPTPClockTime = 16 // sizeof(struct ptp_clock_time)

	offsetofPTPClockTimeSec  = 0 // offsetof(struct ptp_clock_time, sec)
	offsetofPTPClockTimeNSec = 8 // offsetof(struct ptp_clock_time, nsec)
)

type ptpSysOffsetPrecise struct {
	device      ptpClockTime
	sysRealTime ptpClockTime
	sysMonoRaw  ptpClockTime
	reserved    [4]uint32 /* Reserved for future use. */
}

type ptpSysOffsetExtended struct {
	nSamples uint32
	clockID  int32
	reserved [2]uint32
	ts       [25][3]ptpClockTime
}

const (
	sizeofPTPSysOffsetPrecise = 64 // sizeof(struct ptp_sys_offset_precise)

	offsetofPTPSysOffsetPreciseDevice      = 0  // offsetof(struct ptp_sys_offset_precise, device)
	offsetofPTPSysOffsetPreciseSysRealTime = 16 // offsetof(struct ptp_sys_offset_precise, sys_realtime)
	offsetofPTPSysOffsetPreciseSysMonoRaw  = 32 // offsetof(struct ptp_sys_offset_precise, sys_monoraw)
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
	var t1 ptpSysOffsetPrecise
	if unsafe.Sizeof(t1) != sizeofPTPSysOffsetPrecise ||
		unsafe.Offsetof(t1.device) != offsetofPTPSysOffsetPreciseDevice ||
		unsafe.Offsetof(t1.sysRealTime) != offsetofPTPSysOffsetPreciseSysRealTime ||
		unsafe.Offsetof(t1.sysMonoRaw) != offsetofPTPSysOffsetPreciseSysMonoRaw {
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

func extendedTS(extendedTS [3]ptpClockTime) (sysTime, phcTime time.Time, delay time.Duration) {
	t0 := time.Unix(extendedTS[0].sec, int64(extendedTS[0].nsec)).UTC()
	t2 := time.Unix(extendedTS[2].sec, int64(extendedTS[2].nsec)).UTC()
	delay = t2.Sub(t0)
	sysTime = t0.Add(delay / 2)
	phcTime = time.Unix(extendedTS[1].sec, int64(extendedTS[1].nsec)).UTC()
	return
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
		err = unix.Close(fd)
		if err != nil {
			c.log.LogAttrs(ctx, slog.LevelError,
				"unix.Close failed",
				slog.String("dev", c.dev),
				slog.Any("error", err),
			)
		}
	}()

	off := ptpSysOffsetPrecise{}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(ioctlRequest(ioctlRead|ioctlWrite, int(unsafe.Sizeof(off)), '=', 0x8)),
		uintptr(unsafe.Pointer(&off)),
	)
	if errno != 0 {
		off := ptpSysOffsetExtended{nSamples: 7}
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
			uintptr(ioctlRequest(ioctlRead|ioctlWrite, int(unsafe.Sizeof(off)), '=', 0x9)),
			uintptr(unsafe.Pointer(&off)),
		)
		if errno != 0 {
			c.log.LogAttrs(ctx, slog.LevelError,
				"ioctl failed",
				slog.String("dev", c.dev),
				slog.Uint64("errno", uint64(errno)),
			)
			return time.Time{}, 0, errno
		}
		sys, phc, delay := extendedTS(off.ts[0])
		for i := 1; i < int(off.nSamples); i++ {
			s, p, d := extendedTS(off.ts[i])
			if d < delay {
				sys, phc, delay = s, p, d
			}
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

	sysRealTime := time.Unix(off.sysRealTime.sec, int64(off.sysRealTime.nsec)).UTC()
	deviceTime := time.Unix(off.device.sec, int64(off.device.nsec)).UTC()
	offset := deviceTime.Sub(sysRealTime)
	offset += c.offset

	c.log.LogAttrs(ctx, slog.LevelDebug,
		"PTP hardware clock sample",
		slog.Time("sysRealTime", sysRealTime),
		slog.Time("deviceTime", deviceTime),
		slog.Duration("offset", offset),
	)

	return sysRealTime, offset, nil
}
