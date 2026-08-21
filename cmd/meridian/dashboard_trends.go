package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type dashboardTrendPoint struct {
	TimestampMS int64   `json:"timestamp_ms"`
	Traffic     int64   `json:"traffic_bytes"`
	BytesIn     int64   `json:"bytes_in"`
	BytesOut    int64   `json:"bytes_out"`
	Requests    int64   `json:"requests"`
	DownloadBPS float64 `json:"download_bps"`
	UploadBPS   float64 `json:"upload_bps"`
}

type dashboardTrendsResponse struct {
	SiteID         string                `json:"site_id"`
	Range          string                `json:"range"`
	BillingMode    string                `json:"billing_mode"`
	TimezoneOffset int                   `json:"timezone_offset_minutes"`
	Timezone       string                `json:"timezone"`
	StartMS        int64                 `json:"start_ms"`
	EndMS          int64                 `json:"end_ms"`
	BucketSeconds  int64                 `json:"bucket_seconds"`
	Points         []dashboardTrendPoint `json:"points"`
	SiteSeries     []dashboardTrendSite  `json:"site_series"`
}

// dashboardTrendSite carries the same time buckets as the aggregate chart,
// allowing the hover card to explain which sites contributed to a point when
// the selector is set to “全部站点”.
type dashboardTrendSite struct {
	SiteID   int64                 `json:"site_id"`
	SiteName string                `json:"site_name"`
	Points   []dashboardTrendPoint `json:"points"`
}

type dashboardPendingTraffic struct {
	BytesIn  int64
	BytesOut int64
	Requests int64
}

func dashboardTrendWindow(name string, now time.Time) (string, time.Time, time.Time, time.Duration, error) {
	return dashboardTrendWindowWithLocation(name, now, time.Time{}, time.Time{}, time.Local)
}

func dashboardTrendWindowWithCustom(name string, now, customStart, customEnd time.Time) (string, time.Time, time.Time, time.Duration, error) {
	return dashboardTrendWindowWithLocation(name, now, customStart, customEnd, time.Local)
}

func dashboardTrendWindowWithLocation(name string, now, customStart, customEnd time.Time, location *time.Location) (string, time.Time, time.Time, time.Duration, error) {
	if location == nil {
		location = time.Local
	}
	var duration, bucket time.Duration
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "realtime":
		name, duration, bucket = "realtime", 30*time.Minute, time.Minute
	case "hour", "1h":
		name, duration, bucket = "hour", time.Hour, time.Minute
	case "6h", "6-hour":
		name, duration, bucket = "6h", 6*time.Hour, 5*time.Minute
	case "day", "24h":
		name, duration, bucket = "day", 24*time.Hour, time.Hour
	case "7d", "week":
		name, duration, bucket = "7d", 7*24*time.Hour, time.Hour
	case "month", "monthly":
		// “本月” means the natural calendar month: from the first day at
		// 00:00 through the current moment. It intentionally does not use the
		// configurable traffic billing reset day.
		name = "month"
		localNow := now.In(location)
		start := time.Date(localNow.Year(), localNow.Month(), 1, 0, 0, 0, 0, location)
		elapsed := localNow.Sub(start)
		if elapsed < time.Minute {
			elapsed = time.Minute
		}
		// Keep month samples fine enough to expose short traffic spikes. A
		// 15-minute bucket is preferred for the first three weeks; longer
		// months fall back to 30 minutes so the response stays compact.
		const maxMonthPoints = 2048
		candidates := []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour}
		bucket = 24 * time.Hour
		for _, candidate := range candidates {
			count := (elapsed + candidate - time.Nanosecond) / candidate
			if count <= maxMonthPoints {
				bucket = candidate
				break
			}
		}
		count := (elapsed + bucket - time.Nanosecond) / bucket
		if count < 1 {
			count = 1
		}
		return name, start, start.Add(count * bucket), bucket, nil
	case "custom":
		name = "custom"
		start := customStart.In(location).Truncate(time.Minute)
		end := customEnd.In(location).Truncate(time.Minute)
		if start.IsZero() || end.IsZero() {
			return "", time.Time{}, time.Time{}, 0, errors.New("custom trend range requires start and end")
		}
		if !end.After(start) {
			return "", time.Time{}, time.Time{}, 0, errors.New("custom trend range end must be after start")
		}
		const maxCustomDuration = 366 * 24 * time.Hour
		if end.Sub(start) > maxCustomDuration {
			return "", time.Time{}, time.Time{}, 0, errors.New("custom trend range cannot exceed 366 days")
		}
		// Keep the response compact while preserving minute precision for short
		// windows. The largest range returns at most roughly 720 points.
		candidates := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour}
		duration = end.Sub(start)
		bucket = 24 * time.Hour
		for _, candidate := range candidates {
			if (duration+candidate-time.Nanosecond)/candidate <= 720 {
				bucket = candidate
				break
			}
		}
		return name, start, end, bucket, nil
	default:
		return "", time.Time{}, time.Time{}, 0, errors.New("invalid dashboard trend range")
	}
	localNow := now.In(location)
	seconds := int64(bucket / time.Second)
	bucketStart := time.Unix((localNow.Unix()/seconds)*seconds, 0).In(location)
	end := bucketStart.Add(bucket)
	start := end.Add(-duration)
	return name, start, end, bucket, nil
}

func (pm *ProxyManager) pendingDashboardTraffic(siteID *int64) map[int64]dashboardPendingTraffic {
	result := make(map[int64]dashboardPendingTraffic)
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for id, inst := range pm.proxies {
		if siteID != nil && *siteID != id {
			continue
		}
		inst.trafficMu.Lock()
		result[id] = dashboardPendingTraffic{
			BytesIn:  inst.bytesIn.Load(),
			BytesOut: inst.bytesOut.Load(),
			Requests: inst.pendingRequests.Load(),
		}
		inst.trafficMu.Unlock()
	}
	return result
}

func dashboardTrendPoints(start, end time.Time, bucket time.Duration, rangeName string, billingMode string, logs []TrafficLog, pending dashboardPendingTraffic, pendingAt time.Time) []dashboardTrendPoint {
	count := int((end.Sub(start) + bucket - time.Nanosecond) / bucket)
	if count < 1 {
		count = 1
	}
	points := make([]dashboardTrendPoint, count)
	for i := range points {
		points[i].TimestampMS = start.Add(time.Duration(i) * bucket).UnixMilli()
	}
	bucketMS := bucket.Milliseconds()
	if bucketMS <= 0 {
		bucketMS = 1
	}
	for _, logRow := range logs {
		index := int((logRow.RecordedAtMS - start.UnixMilli()) / bucketMS)
		if index < 0 || index >= len(points) {
			continue
		}
		if logRow.BytesIn > 0 {
			points[index].BytesIn += logRow.BytesIn
		}
		if logRow.BytesOut > 0 {
			points[index].BytesOut += logRow.BytesOut
		}
		if logRow.Requests > 0 {
			points[index].Requests += logRow.Requests
		}
	}
	if !pendingAt.IsZero() && !pendingAt.Before(start) && pendingAt.Before(end) {
		index := int((pendingAt.UnixMilli() - start.UnixMilli()) / bucketMS)
		current := &points[index]
		if pending.BytesIn > 0 {
			current.BytesIn += pending.BytesIn
		}
		if pending.BytesOut > 0 {
			current.BytesOut += pending.BytesOut
		}
		if pending.Requests > 0 {
			current.Requests += pending.Requests
		}
	}
	for i := range points {
		points[i].Traffic = maxInt64(0, trafficBillableBytes(billingMode, points[i].BytesIn, points[i].BytesOut))
		seconds := bucket.Seconds()
		if rangeName == "custom" {
			bucketStart := start.Add(time.Duration(i) * bucket)
			bucketEnd := start.Add(time.Duration(i+1) * bucket)
			if bucketEnd.After(end) {
				seconds = end.Sub(bucketStart).Seconds()
			}
		}
		if seconds <= 0 {
			seconds = bucket.Seconds()
		}
		points[i].DownloadBPS = maxFloat64(0, float64(points[i].BytesOut)/seconds)
		points[i].UploadBPS = maxFloat64(0, float64(points[i].BytesIn)/seconds)
	}
	return points
}

func maxInt64(value, floor int64) int64 {
	if value < floor {
		return floor
	}
	return value
}

func maxFloat64(value, floor float64) float64 {
	if value < floor || value != value {
		return floor
	}
	return value
}

func (pm *ProxyManager) dashboardTrends(siteID *int64, rangeName string, customWindow ...time.Time) (*dashboardTrendsResponse, error) {
	settings := pm.database.currentSystemSettings()
	billingMode := settings.TrafficBillingMode
	trendLocation := timezoneLocationByName(settings.ScheduleTimezoneName, settings.ScheduleTimezone)
	var customStart, customEnd time.Time
	if len(customWindow) > 0 {
		if len(customWindow) != 2 {
			return nil, errors.New("custom trend range requires start and end")
		}
		customStart, customEnd = customWindow[0], customWindow[1]
	}
	now := time.Now()
	name, start, end, bucket, err := dashboardTrendWindowWithLocation(rangeName, now, customStart, customEnd, trendLocation)
	if err != nil {
		return nil, err
	}
	logs, err := pm.database.GetTrafficTrendLogs(siteID, start, end)
	if err != nil {
		return nil, err
	}
	sites, err := pm.database.ListSites()
	if err != nil {
		return nil, err
	}
	selectedSites := make([]Site, 0, len(sites))
	for _, site := range sites {
		if siteID == nil || site.ID == *siteID {
			selectedSites = append(selectedSites, site)
		}
	}
	logsBySite := make(map[int64][]TrafficLog)
	for _, logRow := range logs {
		logsBySite[logRow.SiteID] = append(logsBySite[logRow.SiteID], logRow)
	}
	pendingBySite := pm.pendingDashboardTraffic(siteID)
	var aggregatePending dashboardPendingTraffic
	for _, value := range pendingBySite {
		aggregatePending.BytesIn += value.BytesIn
		aggregatePending.BytesOut += value.BytesOut
		aggregatePending.Requests += value.Requests
	}
	points := dashboardTrendPoints(start, end, bucket, name, billingMode, logs, aggregatePending, now)
	siteSeries := make([]dashboardTrendSite, 0, len(selectedSites))
	for _, site := range selectedSites {
		siteSeries = append(siteSeries, dashboardTrendSite{
			SiteID:   site.ID,
			SiteName: site.Name,
			Points:   dashboardTrendPoints(start, end, bucket, name, billingMode, logsBySite[site.ID], pendingBySite[site.ID], now),
		})
	}
	return &dashboardTrendsResponse{
		SiteID: func() string {
			if siteID == nil {
				return "all"
			}
			return strconv.FormatInt(*siteID, 10)
		}(),
		Range:          name,
		BillingMode:    trafficBillingModeLabel(billingMode),
		TimezoneOffset: settings.ScheduleTimezone,
		Timezone:       settings.ScheduleTimezoneName,
		StartMS:        start.UnixMilli(),
		EndMS:          end.UnixMilli(),
		BucketSeconds:  int64(bucket / time.Second),
		Points:         points,
		SiteSeries:     siteSeries,
	}, nil
}

func parseDashboardTrendCustomTime(value string, location *time.Location) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, errors.New("custom trend time is required")
	}
	if location == nil {
		location = time.Local
	}
	parsed, err := time.ParseInLocation("2006-01-02T15:04", value, location)
	if err != nil {
		return time.Time{}, errors.New("custom trend time must use YYYY-MM-DDTHH:MM")
	}
	return parsed, nil
}

func (a *App) handleDashboardTrends(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rangeName := r.URL.Query().Get("range")
	siteText := strings.TrimSpace(r.URL.Query().Get("site_id"))
	var siteID *int64
	if siteText != "" && !strings.EqualFold(siteText, "all") {
		id, err := strconv.ParseInt(siteText, 10, 64)
		if err != nil || id <= 0 {
			a.jsonErr(w, http.StatusBadRequest, "invalid site id")
			return
		}
		if _, err := a.db.GetSite(id); err != nil {
			a.jsonErr(w, http.StatusNotFound, "site not found")
			return
		}
		siteID = &id
	}
	var customWindow []time.Time
	if strings.EqualFold(strings.TrimSpace(rangeName), "custom") {
		settings := a.db.currentSystemSettings()
		location := timezoneLocationByName(settings.ScheduleTimezoneName, settings.ScheduleTimezone)
		start, startErr := parseDashboardTrendCustomTime(r.URL.Query().Get("start"), location)
		end, endErr := parseDashboardTrendCustomTime(r.URL.Query().Get("end"), location)
		if startErr != nil || endErr != nil {
			a.jsonErr(w, http.StatusBadRequest, "invalid custom trend time; use YYYY-MM-DDTHH:MM")
			return
		}
		customWindow = []time.Time{start, end}
	}
	trend, err := a.pm.dashboardTrends(siteID, rangeName, customWindow...)
	if err != nil {
		a.jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.jsonOK(w, trend)
}
