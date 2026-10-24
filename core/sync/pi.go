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

package sync

import (
	"context"
	"log/slog"
	"time"
)

const (
	PIControllerMinPRatio     = 0.001
	PIControllerDefaultPRatio = 0.2
	PIControllerMaxPRatio     = 1.0
	PIControllerMinIRatio     = 0.0005
	PIControllerDefaultIRatio = 0.05
	PIControllerMaxIRatio     = 0.5

	PIControllerDefaultStepThreshold = 10 * time.Millisecond
)

type Clock interface {
	MaxFrequency() float64
	Frequency() float64
	SetFrequency(frequency float64)
	Step(offset time.Duration)
}

type PIController struct {
	// Clock to be adjusted.
	Clock Clock

	// Ratio (gain factor) of the proportional control output value (applied to
	// the measured offset).
	KP float64

	// Ratio of the integral control output value. The integral value is applied
	// by reverting only a part of the previous adjustment. This ratio defines the
	// part of the previous adjustment that is to be kept. That means, that the
	// size of the integral control output depends on both of the configurable
	// ratios of the PI controller.
	KI float64

	// Offset threshold indicating that, if reached, a clock step is to be applied.
	StepThreshold time.Duration

	// Level of the log messages on clock adjustments.
	LogLevel slog.Level

	running bool
	p, i    float64
}

func (c *PIController) Do(offset time.Duration) {
	ctx := context.Background()
	log := slog.Default()

	maxFreq := c.Clock.MaxFrequency()
	if !c.running {
		c.i = c.Clock.Frequency()
		c.running = true
	}

	c.i = min(max(-maxFreq, c.i+c.p*c.KI), maxFreq)

	if c.StepThreshold != 0 && offset.Abs() >= c.StepThreshold {
		log.LogAttrs(ctx, c.LogLevel, "adjusting clock",
			slog.Duration("offset", offset))
		c.Clock.Step(offset)
		c.p = 0
		return
	}

	c.p = offset.Seconds() * c.KP
	freq := min(max(-maxFreq, c.i+c.p), maxFreq)
	log.LogAttrs(ctx, c.LogLevel, "adjusting clock frequency",
		slog.Float64("frequency", freq))
	c.Clock.SetFrequency(freq)
}
