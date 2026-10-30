package timebase

import (
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

var (
	epochsMu sync.Mutex
	epochs   = map[uint64]*atomic.Uint64{}
)

// ClockEpoch returns the epoch of the clock with the given ID (CLOCK_REALTIME
// or the dynamic ID of an open PTP hardware clock.) The epoch counts the steps
// made of the clock; any step invalidates time measurements that span it. All
// IDs of a PTP hardware clock share its epoch, which is kept for the lifetime
// of the process.
func ClockEpoch(clockID int32) (*atomic.Uint64, error) {
	var key uint64
	if clockID != unix.CLOCK_REALTIME {
		var st unix.Stat_t
		err := unix.Fstat(int(^(clockID >> 3)), &st)
		if err != nil {
			return nil, err
		}
		if st.Rdev == 0 {
			panic("unexpected device ID")
		}
		key = st.Rdev
	}
	epochsMu.Lock()
	defer epochsMu.Unlock()
	e, ok := epochs[key]
	if !ok {
		e = new(atomic.Uint64)
		epochs[key] = e
	}
	return e, nil
}
