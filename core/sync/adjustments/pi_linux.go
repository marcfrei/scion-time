//go:build linux

/*
 * Based on flashptpd, https://github.com/meinberg-sync/flashptpd
 *
 * @file pidController.h and pidController.cpp
 * @note Copyright 2023, Meinberg Funkuhren GmbH & Co. KG, All rights reserved.
 * @author Thomas Behn <thomas.behn@meinberg.de>
 *
 * PI controller adjustment algorithm; applies an integral adjustment part by
 * keeping a small part of the previous adjustment when performing a new
 * adjustment with a proportional part.
 *
 * =============================================================================
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * =============================================================================
 *
 */

package adjustments

import (
	"context"
	"log/slog"
	"math"
	"time"

	"golang.org/x/sys/unix"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/base/unixutil"
)

type PIController struct {
	// Clock ID of the clock to be adjusted. A value of 0 defaults to
	// CLOCK_REALTIME.
	ClockID int32

	// Ratio (gain factor) of the proportional control output value (applied to
	// the measured offset).
	KP float64

	// Ratio of the integral control output value. The integral value is applied
	// by reverting only a part of the previous adjustment. This ratio defines the
	// part of the previous adjustment that is to be kept. That means, that the
	// size of the integral control output depends on both of the configurable
	// ratios of the PI controller.
	KI float64

	// Offset threshold indicating that, if raeched, a clock step is to be applied
	StepThreshold time.Duration

	p, i, freq, freqAddend float64
}

var _ Adjustment = (*PIController)(nil)

var (
	linuxMinFreqAdj = unixutil.FreqFromScaledPPM(-32768000)
	linuxMaxFreqAdj = unixutil.FreqFromScaledPPM(32768000)
)

func (c *PIController) Do(offset time.Duration) {
	ctx := context.Background()
	log := slog.Default()

	cid := int32(unix.CLOCK_REALTIME)
	if c.ClockID != 0 {
		cid = c.ClockID
	}

	tx := unix.Timex{}
	_, err := unix.ClockAdjtime(cid, &tx)
	if err != nil {
		logbase.Fatal(log, "unix.ClockAdjtime failed", slog.Any("error", err))
	}
	freq := unixutil.FreqFromScaledPPM(tx.Freq)

	if c.freq != 0 &&
		c.freq >= linuxMinFreqAdj &&
		c.freq <= linuxMaxFreqAdj &&
		math.Abs(c.freq-freq) >= unixutil.FreqFromScaledPPM(1) {
		log.LogAttrs(ctx, slog.LevelError, "unexpected clock behavior",
			slog.Float64("cfreq", c.freq),
			slog.Float64("freq", freq))
	}

	// "fake integral" (partial reversion of previous adjustment)
	c.i += c.freqAddend * c.KI
	freq -= c.freqAddend - (c.freqAddend * c.KI)

	if c.StepThreshold != 0 && offset.Abs() >= c.StepThreshold {
		log.LogAttrs(ctx, slog.LevelDebug, "adjusting clock",
			slog.Duration("offset", offset))
		tx = unix.Timex{
			Modes: unix.ADJ_SETOFFSET | unix.ADJ_NANO,
			Time:  unixutil.TimevalFromNsec(offset.Nanoseconds()),
		}
		_, err = unix.ClockAdjtime(cid, &tx)
		if err != nil {
			logbase.Fatal(log, "unix.ClockAdjtime failed", slog.Any("error", err))
		}
		c.freqAddend = 0
		c.freq = 0
	} else {
		c.freqAddend = offset.Seconds() * c.KP
		c.p = c.freqAddend
		freq += c.freqAddend
		if freq < linuxMinFreqAdj {
			freq = linuxMinFreqAdj
		} else if freq > linuxMaxFreqAdj {
			freq = linuxMaxFreqAdj
		}
		log.LogAttrs(ctx, slog.LevelDebug, "adjusting clock frequency",
			slog.Float64("frequency", freq))
		tx = unix.Timex{
			Modes: unix.ADJ_FREQUENCY,
			Freq:  unixutil.ScaledPPMFromFreq(freq),
		}
		_, err = unix.ClockAdjtime(cid, &tx)
		if err != nil {
			logbase.Fatal(log, "unix.ClockAdjtime failed", slog.Any("error", err))
		}
		c.freq = freq
	}
}
