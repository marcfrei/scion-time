package sync

import (
	"testing"
)

func TestTheilSenIdentityLine(t *testing.T) {
	identityLinePts := []point{{x: -1.0, y: -1.0}, {x: 3.5, y: 3.5}, {x: 11.2, y: 11.2}}

	slope := slope(identityLinePts)
	if slope != 1.0 {
		t.Errorf("slope of y = x line: got %f, want 1.0", slope)
	}

	intercept := intercept(slope, identityLinePts)
	if intercept != 0.0 {
		t.Errorf("intercept of y = x line: got %f, want 0.0", slope)
	}
}
