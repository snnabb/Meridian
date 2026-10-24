package main

import (
	"testing"
	"time"
)

func TestTrafficCycleResetUsesBillingCalendar(t *testing.T) {
	previous := time.Local
	time.Local = time.FixedZone("billing", 8*60*60)
	t.Cleanup(func() { time.Local = previous })
	for _, tc := range []struct {
		now, want string
		day       int
	}{
		{"2026-02-20T12:00:00+08:00", "2026-02-28T00:00:00+08:00", 31},
		{"2026-02-28T00:00:00+08:00", "2026-03-31T00:00:00+08:00", 31},
		{"2028-02-01T00:00:00+08:00", "2028-02-29T00:00:00+08:00", 31},
		{"2026-12-31T23:59:00+08:00", "2027-01-01T00:00:00+08:00", 1},
		{"2026-10-31T16:00:00Z", "2026-12-01T00:00:00+08:00", 1},
	} {
		now, err := time.Parse(time.RFC3339, tc.now)
		if err != nil {
			t.Fatal(err)
		}
		if got := trafficCycleReset(now, tc.day).Format(time.RFC3339); got != tc.want {
			t.Errorf("%s day %d: got %s, want %s", tc.now, tc.day, got, tc.want)
		}
	}
	if !trafficCycleReset(time.Now(), 0).IsZero() {
		t.Fatal("disabled reset has a date")
	}
}
