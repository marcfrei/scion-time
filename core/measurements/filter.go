package measurements

import "time"

type Filter interface {
	Do(cTxTime, sRxTime, sTxTime, cRxTime time.Time) (offset time.Duration, ok bool)
	Reset()
}
