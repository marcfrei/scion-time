// Driver for quick experiments

package main

import (
	"time"

	"go.uber.org/zap"

	"example.com/scion-time/driver/clock"
)

func runX() {
	initLogger(true /* verbose */)

	clk := &clock.SystemClock{Log: log}
	log.Debug("local clock", zap.Stringer("now", clk.Now()))
	clk.Step(-1 * time.Second)
	log.Debug("local clock", zap.Stringer("now", clk.Now()))
}
