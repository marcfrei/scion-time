package adjustments

import "time"

const (
	PIControllerMinPRatio     = 0.001
	PIControllerDefaultPRatio = 0.2
	PIControllerMaxPRatio     = 1.0
	PIControllerMinIRatio     = 0.0005
	PIControllerDefaultIRatio = 0.05
	PIControllerMaxIRatio     = 0.5

	PIControllerDefaultStepThreshold = 10 * time.Millisecond
)
