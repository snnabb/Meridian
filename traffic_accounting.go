package main

import "time"

const (
	trafficBillingModeBidirectional = "bidirectional"
	trafficBillingModeOutbound      = "outbound"
)

// trafficBillableBytes translates the two logical proxy payload directions into
// the amount charged by the selected VPS billing policy. Every payload byte
// relayed by Meridian crosses two VPS network legs: it is received once and
// sent once. Outbound mode intentionally keeps the existing product meaning of
// counting only responses delivered to clients.
func trafficBillableBytes(mode string, bytesIn, bytesOut int64) int64 {
	if bytesIn < 0 {
		bytesIn = 0
	}
	if bytesOut < 0 {
		bytesOut = 0
	}
	if mode == trafficBillingModeOutbound {
		return bytesOut
	}
	const maxInt64 = int64(^uint64(0) >> 1)
	if bytesIn > maxInt64-bytesOut {
		return maxInt64
	}
	total := bytesIn + bytesOut
	if total > maxInt64/2 {
		return maxInt64
	}
	return total * 2
}

func trafficBillingModeLabel(mode string) string {
	if mode == trafficBillingModeOutbound {
		return "outbound"
	}
	return trafficBillingModeBidirectional
}

// trafficCycleStart returns the start of the active billing cycle in the
// server's local timezone. Reset days beyond a month's length use that
// month's last day (for example, day 31 becomes February 28/29).
func trafficCycleStart(now time.Time, resetDay int) time.Time {
	if resetDay == 0 {
		return time.Time{}
	}
	if resetDay < 0 || resetDay > 31 {
		resetDay = 1
	}
	local := now.In(time.Local)
	monthStart := time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, time.Local)
	dayInMonth := func(month time.Time) int {
		return time.Date(month.Year(), month.Month()+1, 0, 0, 0, 0, 0, time.Local).Day()
	}
	currentDay := resetDay
	if currentDay > dayInMonth(monthStart) {
		currentDay = dayInMonth(monthStart)
	}
	candidate := time.Date(monthStart.Year(), monthStart.Month(), currentDay, 0, 0, 0, 0, time.Local)
	if !local.Before(candidate) {
		return candidate
	}
	previousMonth := monthStart.AddDate(0, -1, 0)
	previousDay := resetDay
	if previousDay > dayInMonth(previousMonth) {
		previousDay = dayInMonth(previousMonth)
	}
	return time.Date(previousMonth.Year(), previousMonth.Month(), previousDay, 0, 0, 0, 0, time.Local)
}

func siteTrafficDirections(site Site) (int64, int64) {
	if site.TrafficUsedIn == 0 && site.TrafficUsedOut == 0 && site.TrafficUsed > 0 {
		return legacyTrafficDirections(site.TrafficUsed)
	}
	return site.TrafficUsedIn, site.TrafficUsedOut
}

// legacyTrafficDirections provides a stable best-effort baseline for database
// rows created before traffic directions were persisted independently.
func legacyTrafficDirections(total int64) (int64, int64) {
	if total <= 0 {
		return 0, 0
	}
	in := total / 2
	return in, total - in
}
