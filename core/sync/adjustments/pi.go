package adjustments

import "time"

const (
	PIControllerMinPRatio     = 0.01
	PIControllerDefaultPRatio = 0.1
	PIControllerMaxPRatio     = 1.0
	PIControllerMinIRatio     = 0.005
	PIControllerDefaultIRatio = 0.02
	PIControllerMaxIRatio     = 0.5

	PIControllerDefaultStepThreshold = 10 * time.Millisecond
)
