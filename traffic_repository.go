package main

import (
	"log"
	"time"
)

type TrafficLog struct {
	ID         int64  `json:"id"`
	SiteID     int64  `json:"site_id"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	Requests   int64  `json:"requests"`
	RecordedAt string `json:"recorded_at"`
	// RecordedAtMS is the local wall-clock bucket represented as an epoch in
	// the server's local timezone. traffic_logs intentionally stores wall-clock
	// text for backwards compatibility, so clients must not interpret the
	// driver's RFC3339/Z rendering as a UTC instant.
	RecordedAtMS int64 `json:"recorded_at_ms,omitempty"`
}

// SiteTraffic is the authoritative per-site traffic state: the persisted
// baseline plus in-memory pending bytes. TrafficUsed is always
// the configured billing projection of persisted and pending raw directions.
type SiteTraffic struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Running            bool   `json:"running"`
	TrafficQuota       int64  `json:"traffic_quota"`
	PersistedTraffic   int64  `json:"persisted_traffic"`
	BytesIn            int64  `json:"bytes_in"`
	BytesOut           int64  `json:"bytes_out"`
	CumulativeBytesIn  int64  `json:"cumulative_bytes_in"`
	CumulativeBytesOut int64  `json:"cumulative_bytes_out"`
	TrafficUsed        int64  `json:"traffic_used"`
	MonthlyTraffic     int64  `json:"monthly_traffic"`
	Requests           int64  `json:"requests"`
}

// TrafficSnapshot is the single authoritative global traffic payload shared by
// /api/dashboard, /api/traffic/overview and SSE events.
type TrafficSnapshot struct {
	TotalSites      int           `json:"total_sites"`
	OnlineSites     int           `json:"online_sites"`
	RunningSites    int           `json:"running_sites"`
	TotalTraffic    int64         `json:"total_traffic"`
	MonthlyTraffic  int64         `json:"monthly_traffic"`
	BillingMode     string        `json:"billing_mode"`
	TrafficResetDay int           `json:"traffic_reset_day"`
	TotalRequests   int64         `json:"total_requests"`
	UptimeSeconds   int64         `json:"uptime_seconds"`
	PanelDomain     string        `json:"panel_domain,omitempty"`
	PanelAccessURL  string        `json:"panel_access_url,omitempty"`
	LiveSites       []SiteTraffic `json:"live_sites"`
}

// TrafficHistory is the single-site envelope returned by
// /api/traffic/{id}/snapshot: an atomically captured live snapshot plus the
// log window with pending bytes and requests merged into the current-minute bucket.
type TrafficHistory struct {
	Snapshot    SiteTraffic  `json:"snapshot"`
	Logs        []TrafficLog `json:"logs"`
	BillingMode string       `json:"billing_mode"`
}

func (d *DB) AddTraffic(siteID, bytesIn, bytesOut int64) {
	if err := d.addTraffic(siteID, bytesIn, bytesOut); err != nil {
		log.Printf("[traffic] failed to persist usage for site %d: %v", siteID, err)
	}
}

func (d *DB) addTraffic(siteID, bytesIn, bytesOut int64) error {
	return d.addTrafficWithRequests(siteID, bytesIn, bytesOut, 0)
}

func trafficMinuteBucket(now time.Time) string {
	nowLocal := now.In(time.Local)
	return time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day(), nowLocal.Hour(), nowLocal.Minute(), 0, 0, time.Local).Format("2006-01-02 15:04:05")
}

// trafficWallClockMillis converts the wall-clock bucket text stored in
// traffic_logs into an epoch using the server's local timezone. The SQLite
// driver may render the same text as RFC3339 with a trailing Z, but that Z is
// not the original instant; it is only the driver's representation of a
// timezone-less DATETIME value.
func trafficWallClockMillis(recordedAt string) int64 {
	t, err := time.Parse(time.RFC3339Nano, recordedAt)
	if err != nil {
		t, err = time.ParseInLocation("2006-01-02 15:04:05", recordedAt, time.Local)
	}
	if err != nil {
		return 0
	}
	wall := time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.Local)
	return wall.UnixMilli()
}

func (d *DB) addTrafficWithRequests(siteID, bytesIn, bytesOut, requests int64) error {
	return d.addTrafficWithRequestsAt(siteID, bytesIn, bytesOut, requests, time.Now())
}

func (d *DB) addTrafficWithRequestsAt(siteID, bytesIn, bytesOut, requests int64, now time.Time) error {
	minute := trafficMinuteBucket(now)
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`INSERT INTO traffic_logs (site_id, bytes_in, bytes_out, requests, recorded_at)
		 VALUES (?,?,?,?,?)
		 ON CONFLICT(site_id, recorded_at) DO UPDATE SET
			bytes_in = traffic_logs.bytes_in + excluded.bytes_in,
			bytes_out = traffic_logs.bytes_out + excluded.bytes_out,
			requests = traffic_logs.requests + excluded.requests`,
		siteID, bytesIn, bytesOut, requests, minute,
	); err != nil {
		return err
	}

	// Request-only checkpoints must not issue a no-op traffic_used update. In
	// addition to avoiding unnecessary writes, lifecycle shutdown relies on the
	// pre-close request-count checkpoint remaining independent from a later
	// byte-persistence failure after ingress has irreversibly closed.
	if bytesIn != 0 || bytesOut != 0 {
		if _, err := tx.Exec(
			"UPDATE sites SET traffic_used=traffic_used+?+?, traffic_used_in=traffic_used_in+?, traffic_used_out=traffic_used_out+?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
			bytesIn, bytesOut, bytesIn, bytesOut, siteID,
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (d *DB) GetTrafficLogs(siteID int64, hours int) ([]TrafficLog, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Format("2006-01-02 15:04:05")
	rows, err := d.db.Query(
		"SELECT id, site_id, bytes_in, bytes_out, requests, recorded_at FROM traffic_logs WHERE site_id=? AND recorded_at>=? ORDER BY recorded_at",
		siteID, since,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []TrafficLog
	for rows.Next() {
		var l TrafficLog
		if err := rows.Scan(&l.ID, &l.SiteID, &l.BytesIn, &l.BytesOut, &l.Requests, &l.RecordedAt); err != nil {
			return nil, err
		}
		l.RecordedAtMS = trafficWallClockMillis(l.RecordedAt)
		logs = append(logs, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if logs == nil {
		logs = []TrafficLog{}
	}
	return logs, nil
}

// SumTrafficSince returns persisted bidirectional traffic from the supplied
// local wall-clock boundary. The traffic log table intentionally stores local
// wall-clock buckets for backwards compatibility, so the comparison uses the
// same text format as trafficMinuteBucket instead of UTC serialization.
func (d *DB) SumTrafficSince(start time.Time, billingMode string) (int64, error) {
	var bytesIn, bytesOut int64
	err := d.db.QueryRow(
		"SELECT COALESCE(SUM(bytes_in), 0), COALESCE(SUM(bytes_out), 0) FROM traffic_logs WHERE recorded_at >= ?",
		start.In(time.Local).Format("2006-01-02 15:04:05"),
	).Scan(&bytesIn, &bytesOut)
	return trafficBillableBytes(billingMode, bytesIn, bytesOut), err
}

// SumTrafficSinceBySite returns the same billing-mode projection as
// SumTrafficSince, grouped by site so dashboards can show each node's current
// month usage without issuing one query per site.
func (d *DB) SumTrafficSinceBySite(start time.Time, billingMode string) (map[int64]int64, error) {
	rows, err := d.db.Query(
		"SELECT site_id, COALESCE(SUM(bytes_in), 0), COALESCE(SUM(bytes_out), 0) FROM traffic_logs WHERE recorded_at >= ? GROUP BY site_id",
		start.In(time.Local).Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[int64]int64)
	for rows.Next() {
		var siteID, bytesIn, bytesOut int64
		if err := rows.Scan(&siteID, &bytesIn, &bytesOut); err != nil {
			return nil, err
		}
		result[siteID] = trafficBillableBytes(billingMode, bytesIn, bytesOut)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// SumTrafficSinceForSite returns the billable bytes for one site and cycle.
// Directional columns remain raw so changing the billing mode never destroys
// the information needed to recalculate the current cycle.
func (d *DB) SumTrafficSinceForSite(siteID int64, start time.Time, billingMode string) (int64, error) {
	var bytesIn, bytesOut int64
	err := d.db.QueryRow(
		"SELECT COALESCE(SUM(bytes_in), 0), COALESCE(SUM(bytes_out), 0) FROM traffic_logs WHERE site_id=? AND recorded_at >= ?",
		siteID, start.In(time.Local).Format("2006-01-02 15:04:05"),
	).Scan(&bytesIn, &bytesOut)
	return trafficBillableBytes(billingMode, bytesIn, bytesOut), err
}

// GetTrafficTrendLogs returns minute/hour buckets in the requested wall-clock
// window. The caller performs aggregation so that one endpoint can support all
// dashboard ranges without adding a schema migration.
func (d *DB) GetTrafficTrendLogs(siteID *int64, start, end time.Time) ([]TrafficLog, error) {
	query := "SELECT site_id, bytes_in, bytes_out, requests, recorded_at FROM traffic_logs WHERE recorded_at >= ? AND recorded_at < ?"
	args := []interface{}{start.In(time.Local).Format("2006-01-02 15:04:05"), end.In(time.Local).Format("2006-01-02 15:04:05")}
	if siteID != nil {
		query += " AND site_id = ?"
		args = append(args, *siteID)
	}
	query += " ORDER BY recorded_at"
	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	logs := make([]TrafficLog, 0)
	for rows.Next() {
		var l TrafficLog
		if err := rows.Scan(&l.SiteID, &l.BytesIn, &l.BytesOut, &l.Requests, &l.RecordedAt); err != nil {
			return nil, err
		}
		l.RecordedAtMS = trafficWallClockMillis(l.RecordedAt)
		logs = append(logs, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return logs, nil
}
