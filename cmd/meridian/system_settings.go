package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	_ "time/tzdata"
)

const beijingTimezoneOffsetMinutes = 480
const defaultTimezoneName = "Asia/Shanghai"

var commonTimezoneAllowlist = map[string]struct{}{
	"UTC": {}, "Asia/Shanghai": {}, "Asia/Tokyo": {}, "Asia/Seoul": {}, "Asia/Singapore": {}, "Asia/Hong_Kong": {},
	"Asia/Bangkok": {}, "Asia/Kolkata": {}, "Asia/Dubai": {}, "Asia/Jakarta": {},
	"Europe/London": {}, "Europe/Paris": {}, "Europe/Berlin": {}, "Europe/Moscow": {},
	"America/New_York": {}, "America/Chicago": {}, "America/Denver": {}, "America/Los_Angeles": {},
	"America/Toronto": {}, "America/Vancouver": {}, "Australia/Perth": {}, "Australia/Sydney": {},
	"Pacific/Auckland": {},
}

var legacyTimezoneNames = map[int]string{
	-480: "America/Los_Angeles", -420: "America/Denver", -360: "America/Chicago", -300: "America/New_York",
	0: "UTC", 330: "Asia/Kolkata", 420: "Asia/Bangkok", 480: defaultTimezoneName, 540: "Asia/Tokyo",
	600: "Australia/Sydney", 660: "Pacific/Auckland",
}

func timezoneNameForOffset(offsetMinutes int) string {
	if name, ok := legacyTimezoneNames[offsetMinutes]; ok {
		return name
	}
	return defaultTimezoneName
}

func validTimezoneName(name string) bool {
	_, ok := commonTimezoneAllowlist[strings.TrimSpace(name)]
	return ok
}

func timezoneLocationByName(name string, legacyOffset int) *time.Location {
	name = strings.TrimSpace(name)
	if !validTimezoneName(name) {
		name = timezoneNameForOffset(legacyOffset)
	}
	if location, err := time.LoadLocation(name); err == nil {
		return location
	}
	return timezoneLocation(legacyOffset)
}

func timezoneOffsetAt(location *time.Location, now time.Time) int {
	if location == nil {
		location = time.UTC
	}
	_, offset := now.In(location).Zone()
	return offset / 60
}

func timezoneLocation(offsetMinutes int) *time.Location {
	if offsetMinutes < -720 || offsetMinutes > 840 {
		offsetMinutes = beijingTimezoneOffsetMinutes
	}
	sign := "+"
	value := offsetMinutes
	if value < 0 {
		sign = "-"
		value = -value
	}
	return time.FixedZone(fmt.Sprintf("UTC%s%02d:%02d", sign, value/60, value%60), offsetMinutes*60)
}

func timezoneLabel(offsetMinutes int) string {
	return timezoneNameForOffset(offsetMinutes)
}

type SystemSettings struct {
	UIMode                   string `json:"ui_mode"`
	UIRadius                 int    `json:"ui_radius"`
	TrafficBillingMode       string `json:"traffic_billing_mode"`
	TrafficResetDay          int    `json:"traffic_reset_day"`
	ProbeTimeoutMS           int    `json:"probe_timeout_ms"`
	PingCacheMinutes         int    `json:"ping_cache_minutes"`
	ScheduleTimezone         int    `json:"schedule_timezone_offset"`
	ScheduleTimezoneName     string `json:"schedule_timezone"`
	LogEnabled               bool   `json:"log_enabled"`
	LogLevel                 string `json:"log_level"`
	LogRetentionDays         int    `json:"log_retention_days"`
	LogWriteDelayMinutes     int    `json:"log_write_delay_minutes"`
	LogFlushThreshold        int    `json:"log_flush_threshold"`
	LogBatchSize             int    `json:"log_batch_size"`
	LogRetryCount            int    `json:"log_retry_count"`
	LogRetryBackoffMS        int    `json:"log_retry_backoff_ms"`
	LogTaskLeaseMS           int    `json:"log_task_lease_ms"`
	LogWriteImage            bool   `json:"log_write_image"`
	LogWritePlayback         bool   `json:"log_write_playback"`
	LogWriteMetadata         bool   `json:"log_write_metadata"`
	LogWriteVideo            bool   `json:"log_write_video"`
	LogWriteSubtitle         bool   `json:"log_write_subtitle"`
	LogWriteAsset            bool   `json:"log_write_asset"`
	LogWriteWebSocket        bool   `json:"log_write_websocket"`
	LogWriteAPI              bool   `json:"log_write_api"`
	LogWriteAuth             bool   `json:"log_write_auth"`
	LogWriteNode             bool   `json:"log_write_node"`
	LogWriteCategory         bool   `json:"log_write_category"`
	LogWriteStatus           bool   `json:"log_write_status"`
	LogWriteClientIP         bool   `json:"log_write_client_ip"`
	LogWriteColo             bool   `json:"log_write_colo"`
	LogWriteUA               bool   `json:"log_write_ua"`
	LogWriteUpstreamUA       bool   `json:"log_write_upstream_ua"`
	LogWriteBackendAddress   bool   `json:"log_write_backend_address"`
	LogWriteTimeline         bool   `json:"log_write_timeline"`
	LogDisplayClientIP       bool   `json:"log_display_client_ip"`
	LogDisplayColo           bool   `json:"log_display_colo"`
	LogDisplayUA             bool   `json:"log_display_ua"`
	LogDisplayUpstreamUA     bool   `json:"log_display_upstream_ua"`
	LogDisplayBackendAddress bool   `json:"log_display_backend_address"`
	LogDisplayNode           bool   `json:"log_display_node"`
	LogDisplayCategory       bool   `json:"log_display_category"`
	LogDisplayStatus         bool   `json:"log_display_status"`
	LogDisplayTimeline       bool   `json:"log_display_timeline"`
	LogSearchMode            string `json:"log_search_mode"`
}

func defaultSystemSettings() SystemSettings {
	return SystemSettings{
		UIMode: "novice", UIRadius: 10, TrafficBillingMode: trafficBillingModeBidirectional, TrafficResetDay: 1, ProbeTimeoutMS: 5000, PingCacheMinutes: 10,
		ScheduleTimezone:     beijingTimezoneOffsetMinutes,
		ScheduleTimezoneName: defaultTimezoneName,
		LogEnabled:           true, LogLevel: "info", LogRetentionDays: 30, LogFlushThreshold: 1,
		LogBatchSize: 50, LogRetryCount: 2, LogRetryBackoffMS: 75, LogTaskLeaseMS: 300000,
		LogWriteImage: false, LogWritePlayback: true, LogWriteMetadata: false, LogWriteVideo: true, LogWriteSubtitle: true, LogWriteAsset: true, LogWriteWebSocket: true, LogWriteAPI: true, LogWriteAuth: true,
		LogWriteNode: true, LogWriteCategory: true, LogWriteStatus: true, LogWriteClientIP: true, LogWriteUA: true, LogWriteUpstreamUA: true, LogWriteBackendAddress: true, LogWriteTimeline: true,
		LogDisplayClientIP: true, LogDisplayUA: true, LogDisplayUpstreamUA: true, LogDisplayBackendAddress: true, LogDisplayNode: true, LogDisplayCategory: true, LogDisplayStatus: true, LogDisplayTimeline: true, LogSearchMode: "like",
	}
}

func normalizeSystemSettings(settings SystemSettings) (SystemSettings, error) {
	settings.UIMode = strings.ToLower(strings.TrimSpace(settings.UIMode))
	settings.TrafficBillingMode = strings.ToLower(strings.TrimSpace(settings.TrafficBillingMode))
	if settings.TrafficBillingMode == "" {
		settings.TrafficBillingMode = trafficBillingModeBidirectional
	}
	settings.LogLevel = strings.ToLower(strings.TrimSpace(settings.LogLevel))
	settings.LogSearchMode = strings.ToLower(strings.TrimSpace(settings.LogSearchMode))
	settings.ScheduleTimezoneName = strings.TrimSpace(settings.ScheduleTimezoneName)
	legacyOffsetMode := settings.ScheduleTimezoneName == "" || (settings.ScheduleTimezoneName == defaultTimezoneName && settings.ScheduleTimezone != beijingTimezoneOffsetMinutes)
	if settings.ScheduleTimezoneName == "" || (settings.ScheduleTimezoneName == defaultTimezoneName && settings.ScheduleTimezone != beijingTimezoneOffsetMinutes) {
		settings.ScheduleTimezoneName = timezoneNameForOffset(settings.ScheduleTimezone)
	}
	if !validTimezoneName(settings.ScheduleTimezoneName) {
		return settings, fmt.Errorf("schedule_timezone must be a supported IANA timezone")
	}
	if !legacyOffsetMode {
		settings.ScheduleTimezone = timezoneOffsetAt(timezoneLocationByName(settings.ScheduleTimezoneName, settings.ScheduleTimezone), time.Now())
	}
	if settings.UIMode != "novice" && settings.UIMode != "expert" {
		return settings, fmt.Errorf("ui_mode must be novice or expert")
	}
	if settings.TrafficBillingMode != trafficBillingModeBidirectional && settings.TrafficBillingMode != trafficBillingModeOutbound {
		return settings, fmt.Errorf("traffic_billing_mode must be outbound or bidirectional")
	}
	if settings.TrafficResetDay < 0 || settings.TrafficResetDay > 31 {
		return settings, fmt.Errorf("traffic_reset_day must be 0 (disabled) or between 1 and 31")
	}
	if settings.ScheduleTimezone < -720 || settings.ScheduleTimezone > 840 {
		return settings, fmt.Errorf("schedule_timezone_offset must be between -720 and 840 minutes")
	}
	if settings.UIRadius < 0 || settings.UIRadius > 24 || settings.ProbeTimeoutMS < 1000 || settings.ProbeTimeoutMS > 180000 || settings.PingCacheMinutes < 0 || settings.PingCacheMinutes > 1440 {
		return settings, fmt.Errorf("invalid system UI settings")
	}
	if settings.LogLevel != "info" && settings.LogLevel != "error" {
		return settings, fmt.Errorf("log_level must be info or error")
	}
	if settings.LogSearchMode != "like" && settings.LogSearchMode != "fts" {
		return settings, fmt.Errorf("log_search_mode must be like or fts")
	}
	if settings.LogRetentionDays < 1 || settings.LogRetentionDays > 365 || settings.LogWriteDelayMinutes < 0 || settings.LogWriteDelayMinutes > 60 || settings.LogFlushThreshold < 1 || settings.LogFlushThreshold > 1000 || settings.LogBatchSize < 1 || settings.LogBatchSize > 100 || settings.LogRetryCount < 0 || settings.LogRetryCount > 10 || settings.LogRetryBackoffMS < 0 || settings.LogRetryBackoffMS > 5000 || settings.LogTaskLeaseMS < 1000 || settings.LogTaskLeaseMS > 900000 {
		return settings, fmt.Errorf("invalid log storage settings")
	}
	return settings, nil
}

func (d *DB) loadSystemSettings() (SystemSettings, error) {
	settings := defaultSystemSettings()
	var enabled, writeImage, writePlayback, writeMetadata, writeVideo, writeSubtitle, writeAsset, writeWebSocket, writeAPI, writeAuth, writeNode, writeCategory, writeStatus, writeIP, writeColo, writeUA, writeUpstreamUA, writeBackendAddress, writeTimeline, displayIP, displayColo, displayUA, displayUpstreamUA, displayBackendAddress, displayNode, displayCategory, displayStatus, displayTimeline int
	err := d.db.QueryRow(`SELECT ui_mode, ui_radius, traffic_billing_mode, traffic_reset_day, probe_timeout_ms, ping_cache_minutes, schedule_timezone_offset, schedule_timezone,
		log_enabled, log_level, log_retention_days, log_write_delay_minutes, log_flush_threshold, log_batch_size,
		log_retry_count, log_retry_backoff_ms, log_task_lease_ms, log_write_image, log_write_playback, log_write_metadata, log_write_video, log_write_subtitle, log_write_asset, log_write_websocket, log_write_api, log_write_auth,
		log_write_node, log_write_category, log_write_status, log_write_client_ip, log_write_colo, log_write_ua, log_write_upstream_ua, log_write_backend_address, log_write_timeline, log_display_client_ip, log_display_colo,
		log_display_ua, log_display_upstream_ua, log_display_backend_address, log_display_node, log_display_category, log_display_status, log_display_timeline, log_search_mode FROM system_settings WHERE id=1`).Scan(
		&settings.UIMode, &settings.UIRadius, &settings.TrafficBillingMode, &settings.TrafficResetDay, &settings.ProbeTimeoutMS, &settings.PingCacheMinutes, &settings.ScheduleTimezone, &settings.ScheduleTimezoneName,
		&enabled, &settings.LogLevel, &settings.LogRetentionDays, &settings.LogWriteDelayMinutes, &settings.LogFlushThreshold, &settings.LogBatchSize,
		&settings.LogRetryCount, &settings.LogRetryBackoffMS, &settings.LogTaskLeaseMS, &writeImage, &writePlayback, &writeMetadata, &writeVideo, &writeSubtitle, &writeAsset, &writeWebSocket, &writeAPI, &writeAuth,
		&writeNode, &writeCategory, &writeStatus, &writeIP, &writeColo, &writeUA, &writeUpstreamUA, &writeBackendAddress, &writeTimeline, &displayIP, &displayColo, &displayUA, &displayUpstreamUA, &displayBackendAddress, &displayNode, &displayCategory, &displayStatus, &displayTimeline, &settings.LogSearchMode)
	if err != nil {
		return settings, err
	}
	settings.LogEnabled = enabled == 1
	settings.LogWriteImage, settings.LogWritePlayback, settings.LogWriteMetadata = writeImage == 1, writePlayback == 1, writeMetadata == 1
	settings.LogWriteVideo, settings.LogWriteAPI, settings.LogWriteAuth = writeVideo == 1, writeAPI == 1, writeAuth == 1
	settings.LogWriteSubtitle, settings.LogWriteAsset, settings.LogWriteWebSocket = writeSubtitle == 1, writeAsset == 1, writeWebSocket == 1
	settings.LogWriteNode, settings.LogWriteCategory, settings.LogWriteStatus = writeNode == 1, writeCategory == 1, writeStatus == 1
	settings.LogWriteClientIP, settings.LogWriteColo, settings.LogWriteUA, settings.LogWriteUpstreamUA, settings.LogWriteBackendAddress = writeIP == 1, writeColo == 1, writeUA == 1, writeUpstreamUA == 1, writeBackendAddress == 1
	settings.LogWriteTimeline = writeTimeline == 1
	settings.LogDisplayClientIP, settings.LogDisplayColo, settings.LogDisplayUA, settings.LogDisplayUpstreamUA, settings.LogDisplayBackendAddress = displayIP == 1, displayColo == 1, displayUA == 1, displayUpstreamUA == 1, displayBackendAddress == 1
	settings.LogDisplayNode, settings.LogDisplayCategory, settings.LogDisplayStatus, settings.LogDisplayTimeline = displayNode == 1, displayCategory == 1, displayStatus == 1, displayTimeline == 1
	return normalizeSystemSettings(settings)
}

func (d *DB) currentSystemSettings() SystemSettings {
	if d != nil {
		if current := d.systemSettings.Load(); current != nil {
			return *current
		}
	}
	return defaultSystemSettings()
}

func (d *DB) saveSystemSettings(settings SystemSettings) error {
	settings, err := normalizeSystemSettings(settings)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`UPDATE system_settings SET ui_mode=?, ui_radius=?, traffic_billing_mode=?, traffic_reset_day=?, probe_timeout_ms=?, ping_cache_minutes=?, schedule_timezone_offset=?, schedule_timezone=?,
		log_enabled=?, log_level=?, log_retention_days=?, log_write_delay_minutes=?, log_flush_threshold=?, log_batch_size=?,
		log_retry_count=?, log_retry_backoff_ms=?, log_task_lease_ms=?, log_write_image=?, log_write_playback=?, log_write_metadata=?, log_write_video=?, log_write_subtitle=?, log_write_asset=?, log_write_websocket=?, log_write_api=?, log_write_auth=?,
		log_write_node=?, log_write_category=?, log_write_status=?, log_write_client_ip=?, log_write_colo=?, log_write_ua=?, log_write_upstream_ua=?, log_write_backend_address=?, log_write_timeline=?, log_display_client_ip=?, log_display_colo=?,
		log_display_ua=?, log_display_upstream_ua=?, log_display_backend_address=?, log_display_node=?, log_display_category=?, log_display_status=?, log_display_timeline=?, log_search_mode=?, updated_at=CURRENT_TIMESTAMP WHERE id=1`,
		settings.UIMode, settings.UIRadius, settings.TrafficBillingMode, settings.TrafficResetDay, settings.ProbeTimeoutMS, settings.PingCacheMinutes, settings.ScheduleTimezone, settings.ScheduleTimezoneName,
		sqliteBool(settings.LogEnabled), settings.LogLevel, settings.LogRetentionDays, settings.LogWriteDelayMinutes, settings.LogFlushThreshold, settings.LogBatchSize,
		settings.LogRetryCount, settings.LogRetryBackoffMS, settings.LogTaskLeaseMS, sqliteBool(settings.LogWriteImage), sqliteBool(settings.LogWritePlayback), sqliteBool(settings.LogWriteMetadata), sqliteBool(settings.LogWriteVideo), sqliteBool(settings.LogWriteSubtitle), sqliteBool(settings.LogWriteAsset), sqliteBool(settings.LogWriteWebSocket), sqliteBool(settings.LogWriteAPI), sqliteBool(settings.LogWriteAuth),
		sqliteBool(settings.LogWriteNode), sqliteBool(settings.LogWriteCategory), sqliteBool(settings.LogWriteStatus), sqliteBool(settings.LogWriteClientIP), sqliteBool(settings.LogWriteColo), sqliteBool(settings.LogWriteUA), sqliteBool(settings.LogWriteUpstreamUA), sqliteBool(settings.LogWriteBackendAddress), sqliteBool(settings.LogWriteTimeline), sqliteBool(settings.LogDisplayClientIP), sqliteBool(settings.LogDisplayColo),
		sqliteBool(settings.LogDisplayUA), sqliteBool(settings.LogDisplayUpstreamUA), sqliteBool(settings.LogDisplayBackendAddress), sqliteBool(settings.LogDisplayNode), sqliteBool(settings.LogDisplayCategory), sqliteBool(settings.LogDisplayStatus), sqliteBool(settings.LogDisplayTimeline), settings.LogSearchMode)
	if err != nil {
		return err
	}
	d.systemSettings.Store(&settings)
	configureProbeClient(time.Duration(settings.ProbeTimeoutMS) * time.Millisecond)
	return nil
}

func (a *App) handleSystemSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.jsonOK(w, a.db.currentSystemSettings())
	case http.MethodPost:
		settings := a.db.currentSystemSettings()
		if err := decodeJSONBody(w, r, &settings); err != nil {
			a.jsonErr(w, http.StatusBadRequest, "invalid system settings")
			return
		}
		if err := a.db.saveSystemSettings(settings); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// Return the normalized persisted value (including the current legacy
		// offset compatibility field) so clients immediately render the same
		// timezone the server will use for trends, logs, and scheduling.
		a.jsonOK(w, a.db.currentSystemSettings())
	default:
		w.Header().Set("Allow", "GET, POST")
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

type dashboardInsights struct {
	LogHealthy      bool    `json:"log_healthy"`
	LatestLogMS     int64   `json:"latest_log_ms"`
	LogCountToday   int64   `json:"log_count_today"`
	DroppedLogs     uint64  `json:"dropped_logs"`
	ScheduleEnabled bool    `json:"schedule_enabled"`
	ScheduleLabel   string  `json:"schedule_label"`
	LastSentKey     string  `json:"last_sent_key"`
	HourlyRequests  []int64 `json:"hourly_requests"`
}

func (a *App) handleDashboardInsights(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	currentSettings := a.db.currentSystemSettings()
	location := timezoneLocationByName(currentSettings.ScheduleTimezoneName, currentSettings.ScheduleTimezone)
	now := time.Now().In(location)
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, location)
	insights := dashboardInsights{HourlyRequests: make([]int64, 24), LogHealthy: a.db.currentSystemSettings().LogEnabled}
	_ = a.db.db.QueryRow(`SELECT COALESCE(MAX(recorded_at_ms),0), COUNT(*) FROM request_logs WHERE recorded_at_ms>=? AND recorded_at_ms<?`, start.UnixMilli(), start.AddDate(0, 0, 1).UnixMilli()).Scan(&insights.LatestLogMS, &insights.LogCountToday)
	rows, err := a.db.db.Query(`SELECT recorded_at_ms FROM request_logs WHERE recorded_at_ms>=? AND recorded_at_ms<?`, start.UnixMilli(), start.AddDate(0, 0, 1).UnixMilli())
	if err == nil {
		for rows.Next() {
			var timestamp int64
			if rows.Scan(&timestamp) == nil {
				hour := time.UnixMilli(timestamp).In(location).Hour()
				insights.HourlyRequests[hour]++
			}
		}
		rows.Close()
	}
	insights.DroppedLogs = a.db.DroppedRequestLogs()
	if stored, err := a.db.telegramReportSettings(); err == nil {
		insights.ScheduleEnabled = stored.Enabled
		insights.LastSentKey = stored.LastSentKey
		insights.ScheduleLabel = stored.ScheduleTime + " " + currentSettings.ScheduleTimezoneName
		if stored.Frequency == "weekly" {
			insights.ScheduleLabel = "每周 " + insights.ScheduleLabel
		} else {
			insights.ScheduleLabel = "每天 " + insights.ScheduleLabel
		}
	}
	a.jsonOK(w, insights)
}
