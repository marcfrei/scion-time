package measurements

import "time"

type Filter interface {
	Do(cTx, sRx, sTx, cRx time.Time) (offset time.Duration, ok bool)
	Reset()
}
