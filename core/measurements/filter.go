package measurements

import "time"

type Filter interface {
	Do(cTxTime, sRxTime, sTxTime, cRxTime time.Time) (c2s, off, s2c time.Duration)
	Reset()
}
