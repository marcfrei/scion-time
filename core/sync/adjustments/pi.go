package adjustments

import "time"

const (
	PIControllerMinPRatio     = 0.01
	PIControllerDefaultPRatio = 0.2
	PIControllerMaxPRatio     = 1.0
	PIControllerMinIRatio     = 0.005
	PIControllerDefaultIRatio = 0.05
	PIControllerMaxIRatio     = 0.5

	PIControllerDefaultStepThreshold = 10 * time.Millisecond
)

type PIController struct {
	// Clock defaults to CLOCK_REALTIME when empty. On Linux, a device path such
	// as /dev/ptp0 selects a PTP hardware clock.
	Clock string

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

	clockID, clockFD       int
	p, i, freq, freqAddend float64
}
