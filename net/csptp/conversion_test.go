package csptp_test

import (
	"testing"
	"time"

	"example.com/scion-time/net/csptp"
)

func TestTimestampConversion(t *testing.T) {
	// Based on an Claude AI interaction

	tests := []struct {
		name string
		time time.Time
	}{
		{
			name: "epoch",
			time: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "some time",
			time: time.Date(2024, 1, 17, 12, 0, 0, 0, time.UTC),
		},
		{
			name: "max time",
			time: time.Date(8921556, 12, 7, 10, 44, 15, 999999999, time.UTC),
		},
		{
			name: "with nanoseconds",
			time: time.Date(2024, 1, 17, 12, 0, 0, 123456789, time.UTC),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := csptp.TimestampFromTime(tc.time)
			tt := csptp.TimeFromTimestamp(ts)

			if !tt.Equal(tc.time) {
				t.Errorf("Time conversion roundtrip failed for %v: got %v", tc.time, tt)
			}
		})
	}
}

func TestTimestampFromTimeEdgeCases(t *testing.T) {
	// Based on an Claude AI interaction

	tests := []struct {
		name         string
		input        time.Time
		shouldPanic  bool
		panicMessage string
	}{
		{
			name:         "before epoch",
			input:        time.Date(1969, 12, 31, 23, 59, 59, 999999999, time.UTC),
			shouldPanic:  true,
			panicMessage: "invalid argument: t must not be before 1970-01-01T00:00:00Z",
		},
		{
			name:         "after max time",
			input:        time.Date(8921556, 12, 7, 10, 44, 16, 0, time.UTC),
			shouldPanic:  true,
			panicMessage: "invalid argument: t must not be after 8921556-12-07T10:44:15.999999999Z",
		},
		{
			name:        "exactly epoch",
			input:       time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
			shouldPanic: false,
		},
		{
			name:        "exactly max time",
			input:       time.Date(8921556, 12, 7, 10, 44, 15, 999999999, time.UTC),
			shouldPanic: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.shouldPanic {
				defer func() {
					r := recover()
					if r == nil {
						t.Errorf("Expected panic for %v", tc.input)
					}
					if r != tc.panicMessage {
						t.Errorf("Expected panic message %q, got %q", tc.panicMessage, r)
					}
				}()
			}

			ts := csptp.TimestampFromTime(tc.input)
			if !tc.shouldPanic {
				tt := csptp.TimeFromTimestamp(ts)
				if !tt.Equal(tc.input) {
					t.Errorf("Time conversion failed for %v: got %v", tc.input, tt)
				}
			}
		})
	}
}

func TestTimestampBitPatterns(t *testing.T) {
	// Based on an Claude AI interaction

	tests := []struct {
		name     string
		seconds  [6]uint8
		nanos    uint32
		expected time.Time
	}{
		{
			name:     "all zeros",
			seconds:  [6]uint8{0, 0, 0, 0, 0, 0},
			nanos:    0,
			expected: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "all ones in seconds",
			seconds:  [6]uint8{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			nanos:    0,
			expected: time.Date(8921556, 12, 7, 10, 44, 15, 0, time.UTC),
		},
		{
			name:     "max nanoseconds",
			seconds:  [6]uint8{0, 0, 0, 0, 0, 0},
			nanos:    999999999,
			expected: time.Date(1970, 1, 1, 0, 0, 0, 999999999, time.UTC),
		},
		{
			name:     "mixed bit pattern",
			seconds:  [6]uint8{0x00, 0x01, 0x23, 0x45, 0x67, 0x89},
			nanos:    123456789,
			expected: time.Date(2124, 11, 8, 5, 45, 45, 123456789, time.UTC),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := csptp.Timestamp{
				Seconds:     tc.seconds,
				Nanoseconds: tc.nanos,
			}
			tt := csptp.TimeFromTimestamp(ts)
			if !tt.Equal(tc.expected) {
				t.Errorf("TimeFromTimestamp(%v) = %v, expected %v", ts, tt, tc.expected)
			}
		})
	}
}

func TestTimeIntervalConversion(t *testing.T) {
	tests := []struct {
		name string
		ti   int64
		td   time.Duration
	}{
		{
			name: "max",
			ti:   (1<<47 - 1) << 16,
			td:   1<<47 - 1,
		},
		{
			name: "positive",
			ti:   1 << 16,
			td:   1,
		},
		{
			name: "zero",
			ti:   0,
			td:   0,
		},
		{
			name: "negative",
			ti:   -1 << 16,
			td:   -1,
		},
		{
			name: "min",
			ti:   -(1 << 47) << 16,
			td:   -(1 << 47),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			td := csptp.DurationFromTimeInterval(tc.ti)
			if td != tc.td {
				t.Errorf("DurationFromTimeInterval(%016x) = %v, expected %v", tc.ti, td.Nanoseconds(), tc.td.Nanoseconds())
			}
		})
	}
}

func TestClockIdentityFromMAC(t *testing.T) {
	mac := [6]uint8{0x2c, 0xcf, 0x67, 0x3a, 0x1a, 0xdb}
	want := [8]uint8{0x2c, 0xcf, 0x67, 0xff, 0xfe, 0x3a, 0x1a, 0xdb}
	if got := csptp.ClockIdentityFromMAC(mac); got != want {
		t.Errorf("ClockIdentityFromMAC(% x) = % x, want % x", mac, got, want)
	}
}
