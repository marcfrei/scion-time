/*
 * Based on flashptpd, https://github.com/meinberg-sync/flashptpd
 *
 * @file pidController.cpp
 * @note Copyright 2023, Meinberg Funkuhren GmbH & Co. KG, All rights reserved.
 * @author Thomas Behn <thomas.behn@meinberg.de>
 *
 * PID controller adjustment algorithm. Unlike many other PID controller
 * implementations, this one applies an integral adjustment part by keeping a
 * small part of the previous adjustment when performing a new adjustment with a
 * proportional and (optional) differential part. Ratios of all parts (iRatio,
 * pRatio, dRatio) as well as a step threshold in nanoseconds can be configured,
 * individually.
 *
 * Minimum:     p = 0.01, i = 0.005, d = 0.0
 * Maximum:     p = 1.0, i = 0.5, d = 1.0
 * Default:     p = 0.2, i = 0.05, d = 0.0
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
	"time"
)

const (
	//lint:ignore U1000 WIP
	pidControllerPRatioMin = 0.01
	//lint:ignore U1000 WIP
	pidControllerPRatioDefault = 0.2
	//lint:ignore U1000 WIP
	pidControllerPRatioMax = 1.0
	//lint:ignore U1000 WIP
	pidControllerIRatioMin = 0.005
	//lint:ignore U1000 WIP
	pidControllerIRatioDefault = 0.05
	//lint:ignore U1000 WIP
	pidControllerIRatioMax = 0.5
	//lint:ignore U1000 WIP
	pidControllerDRatioMin = 0.0
	//lint:ignore U1000 WIP
	pidControllerDRatioDefault = 0.0
	//lint:ignore U1000 WIP
	pidControllerDRatioMax = 1.0

	//lint:ignore U1000 WIP
	pidControllerStepThresholdDefault = 1000000 * time.Nanosecond
)

type PIDController struct {
	// Ratio (gain factor) of the proportional control output value (applied to
	// the measured offset).
	kp float64 //lint:ignore U1000 WIP

	// Ratio of the integral control output value. In this PID controller
	// implementation, the integral value is applied by reverting only a part of
	// the previous adjustment. This ratio defines the part of the previous
	// adjustment that is to be kept. That means, that the size of the integral
	// control output depends on all of the configurable ratios (kp, ki or kd) of
	// the PID controller.
	ki float64 //lint:ignore U1000 WIP

	// Ratio of the differential control output value (applied to the measured
	// drift).
	kd float64 //lint:ignore U1000 WIP

	p, i, d float64 //lint:ignore U1000 WIP

	// Offset threshold (ns) indicating that - if exceeded - a clock step is to be
	// applied
	stepThreshold int64 //lint:ignore U1000 WIP
}