package clocks

import "sync/atomic"

// epoch counts the clock steps made through this package. Any step
// invalidates time measurements that span it.
var epoch atomic.Uint64
