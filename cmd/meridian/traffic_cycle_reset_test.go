package main

import (
	"testing"
	"time"
)

func TestBillingCalendarPreservesLegacyBoundaryAcrossPanelTimezones(t *testing.T) {
	previous := time.Local
	time.Local = time.UTC
	t.Cleanup(func() { time.Local = previous })
	app := newTestApp(t)
	site, err := app.db.CreateSite("timezone-boundary", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	// November in Shanghai, but still October on the UTC server. Changing
	// panel display/schedule timezone must not move the existing quota cycle.
	sample := time.Date(2026, time.October, 31, 17, 0, 0, 0, time.UTC)
	if err := app.db.addTrafficWithRequestsAt(site.ID, 100, 200, 1, sample); err != nil {
		t.Fatal(err)
	}
	before := time.Date(2026, time.October, 31, 23, 0, 0, 0, time.UTC)
	boundary := time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC)
	inst := &ProxyInstance{Site: *site}
	for _, zone := range []string{"Asia/Shanghai", "UTC", "America/New_York"} {
		settings := app.db.currentSystemSettings()
		settings.ScheduleTimezoneName = zone
		settings.TrafficResetDay = 1
		if err := app.db.saveSystemSettings(settings); err != nil {
			t.Fatal(err)
		}
		if got := trafficCycleReset(before, settings.TrafficResetDay); !got.Equal(boundary) {
			t.Fatalf("%s: reset = %s, want %s", zone, got, boundary)
		}
		for _, row := range []struct {
			now  time.Time
			want int64
		}{{before, 300}, {boundary, 0}} {
			got, err := app.pm.currentTrafficCycleUsage(inst, row.now)
			if err != nil || got != row.want {
				t.Fatalf("%s at %s: usage = %d, %v; want %d", zone, row.now, got, err, row.want)
			}
		}
	}
}

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
