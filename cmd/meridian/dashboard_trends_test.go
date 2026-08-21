package main

import (
	"testing"
	"time"
)

func sumDashboardTrend(points []dashboardTrendPoint) (traffic, requests int64) {
	for _, point := range points {
		traffic += point.Traffic
		requests += point.Requests
	}
	return traffic, requests
}

func TestDashboardTrendsAggregateAllAndSingleSite(t *testing.T) {
	app := newTestApp(t)
	first, err := app.db.CreateSite("first", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite first: %v", err)
	}
	second, err := app.db.CreateSite("second", freePort(t), "http://127.0.0.1:8097", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite second: %v", err)
	}
	now := time.Now().In(time.Local)
	if err := app.db.addTrafficWithRequestsAt(first.ID, 100, 200, 3, now.Add(-10*time.Minute)); err != nil {
		t.Fatalf("add first traffic: %v", err)
	}
	if err := app.db.addTrafficWithRequestsAt(second.ID, 50, 50, 2, now.Add(-5*time.Minute)); err != nil {
		t.Fatalf("add second traffic: %v", err)
	}
	inst := &ProxyInstance{Site: *first}
	inst.bytesIn.Store(10)
	inst.bytesOut.Store(20)
	inst.pendingRequests.Store(1)
	app.pm.proxies[first.ID] = inst

	all, err := app.pm.dashboardTrends(nil, "hour")
	if err != nil {
		t.Fatalf("dashboardTrends all: %v", err)
	}
	if all.SiteID != "all" || all.Range != "hour" || all.BucketSeconds != 60 || len(all.Points) != 60 {
		t.Fatalf("all metadata = %+v", all)
	}
	traffic, requests := sumDashboardTrend(all.Points)
	if traffic != 430 || requests != 6 {
		t.Fatalf("all totals = traffic %d requests %d, want 430/6", traffic, requests)
	}
	if len(all.SiteSeries) != 2 || all.SiteSeries[0].SiteName != "first" || all.SiteSeries[1].SiteName != "second" {
		t.Fatalf("all site series = %+v, want both named sites", all.SiteSeries)
	}
	firstTraffic, firstRequests := sumDashboardTrend(all.SiteSeries[0].Points)
	secondTraffic, secondRequests := sumDashboardTrend(all.SiteSeries[1].Points)
	if firstTraffic != 330 || firstRequests != 4 || secondTraffic != 100 || secondRequests != 2 {
		t.Fatalf("all site series totals = first %d/%d second %d/%d, want 330/4 and 100/2", firstTraffic, firstRequests, secondTraffic, secondRequests)
	}

	single, err := app.pm.dashboardTrends(&first.ID, "hour")
	if err != nil {
		t.Fatalf("dashboardTrends single: %v", err)
	}
	traffic, requests = sumDashboardTrend(single.Points)
	if traffic != 330 || requests != 4 {
		t.Fatalf("single totals = traffic %d requests %d, want 330/4", traffic, requests)
	}
	last := single.Points[len(single.Points)-1]
	if last.Traffic < 30 || last.Requests < 1 {
		t.Fatalf("current bucket = %+v, want pending traffic and request", last)
	}
	if len(single.SiteSeries) != 1 || single.SiteSeries[0].SiteID != first.ID || single.SiteSeries[0].SiteName != "first" {
		t.Fatalf("single site series = %+v, want first only", single.SiteSeries)
	}
}

func TestDashboardTrendRangesAndMonthlyTraffic(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("monthly", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	now := time.Now().In(time.Local)
	if err := app.db.addTrafficWithRequestsAt(site.ID, 70, 30, 2, now.Add(-time.Minute)); err != nil {
		t.Fatalf("add traffic: %v", err)
	}
	inst := &ProxyInstance{Site: *site}
	inst.Site.TrafficUsed = 100
	inst.persistedTraffic.Store(100)
	inst.bytesIn.Store(5)
	inst.bytesOut.Store(15)
	app.pm.proxies[site.ID] = inst

	for rangeName, expectedPoints := range map[string]int{"realtime": 30, "hour": 60, "6h": 72, "day": 24, "7d": 168} {
		trend, err := app.pm.dashboardTrends(nil, rangeName)
		if err != nil {
			t.Fatalf("range %s: %v", rangeName, err)
		}
		if len(trend.Points) != expectedPoints {
			t.Fatalf("range %s points = %d, want %d", rangeName, len(trend.Points), expectedPoints)
		}
	}
	monthName, monthStart, monthEnd, monthBucket, err := dashboardTrendWindowWithLocation("month", now, time.Time{}, time.Time{}, time.Local)
	if err != nil {
		t.Fatalf("month range: %v", err)
	}
	if monthName != "month" || monthStart.Day() != 1 || monthStart.Hour() != 0 || !monthEnd.After(now) || monthBucket <= 0 {
		t.Fatalf("month window = name %q start %s end %s bucket %s", monthName, monthStart, monthEnd, monthBucket)
	}
	if monthBucket > 30*time.Minute {
		t.Fatalf("month bucket = %s, want at most 30 minutes for precise peaks", monthBucket)
	}
	monthTrend, err := app.pm.dashboardTrends(nil, "month")
	if err != nil {
		t.Fatalf("month dashboardTrends: %v", err)
	}
	if monthTrend.Range != "month" || len(monthTrend.Points) == 0 {
		t.Fatalf("month metadata = %+v", monthTrend)
	}
	if _, err := app.pm.dashboardTrends(nil, "invalid"); err == nil {
		t.Fatal("invalid range accepted")
	}

	snapshot, err := app.pm.TrafficSnapshot()
	if err != nil {
		t.Fatalf("TrafficSnapshot: %v", err)
	}
	if snapshot.MonthlyTraffic != 120 || snapshot.TotalTraffic != 120 {
		t.Fatalf("snapshot traffic = monthly %d total %d, want 120/120", snapshot.MonthlyTraffic, snapshot.TotalTraffic)
	}
	if len(snapshot.LiveSites) != 1 || snapshot.LiveSites[0].MonthlyTraffic != 120 {
		t.Fatalf("site monthly traffic = %+v, want 120", snapshot.LiveSites)
	}
}

func TestDashboardTrendCustomWindowUsesMinutePrecisionAndAggregates(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("custom", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	now := time.Now().In(time.Local).Truncate(time.Minute)
	start := now.Add(-10 * time.Minute)
	end := now
	if err := app.db.addTrafficWithRequestsAt(site.ID, 100, 40, 3, start.Add(4*time.Minute+10*time.Second)); err != nil {
		t.Fatalf("add custom traffic: %v", err)
	}

	trend, err := app.pm.dashboardTrends(&site.ID, "custom", start.Add(17*time.Second), end.Add(42*time.Second))
	if err != nil {
		t.Fatalf("custom dashboardTrends: %v", err)
	}
	if trend.Range != "custom" || trend.BucketSeconds != 60 || len(trend.Points) != 10 {
		t.Fatalf("custom metadata = %+v", trend)
	}
	if trend.StartMS != start.UnixMilli() || trend.EndMS != end.UnixMilli() {
		t.Fatalf("custom bounds = %d/%d, want %d/%d", trend.StartMS, trend.EndMS, start.UnixMilli(), end.UnixMilli())
	}
	traffic, requests := sumDashboardTrend(trend.Points)
	if traffic != 140 || requests != 3 {
		t.Fatalf("custom totals = traffic %d requests %d, want 140/3", traffic, requests)
	}
}

func TestDashboardTrendHistoricalCustomWindowExcludesCurrentPendingTraffic(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("historical", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	inst := &ProxyInstance{Site: *site}
	inst.bytesIn.Store(10)
	inst.bytesOut.Store(20)
	inst.pendingRequests.Store(1)
	app.pm.proxies[site.ID] = inst

	now := time.Now().In(time.Local).Truncate(time.Minute)
	trend, err := app.pm.dashboardTrends(&site.ID, "custom", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("historical dashboardTrends: %v", err)
	}
	traffic, requests := sumDashboardTrend(trend.Points)
	if traffic != 0 || requests != 0 {
		t.Fatalf("historical totals = traffic %d requests %d, want no current pending data", traffic, requests)
	}
}

func TestDashboardTrendCustomWindowValidation(t *testing.T) {
	now := time.Now().In(time.Local)
	if _, _, _, _, err := dashboardTrendWindowWithCustom("custom", now, now, now); err == nil {
		t.Fatal("equal custom bounds accepted")
	}
	if _, _, _, _, err := dashboardTrendWindowWithCustom("custom", now, now.Add(-367*24*time.Hour), now); err == nil {
		t.Fatal("custom range over 366 days accepted")
	}
	parsed, err := parseDashboardTrendCustomTime("2026-08-18T12:34", time.FixedZone("UTC+08:00", 8*60*60))
	if err != nil || parsed.Minute() != 34 || parsed.Hour() != 12 {
		t.Fatalf("parse custom time = %v, %v", parsed, err)
	}
	if _, err := parseDashboardTrendCustomTime("2026-08-18 12:34", time.FixedZone("UTC+08:00", 8*60*60)); err == nil {
		t.Fatal("invalid custom time format accepted")
	}
}
