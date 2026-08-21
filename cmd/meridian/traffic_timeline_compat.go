package main

import (
	"fmt"
	"time"
)

const (
	trafficMinuteSeconds        int64 = 60
	trafficTimelineMaxMinutes         = 7 * 24 * 60
	trafficMinuteRetention            = 7 * 24 * time.Hour
	trafficMinutePruneBatchSize       = 256
)

type TrafficMinuteLog struct {
	MinuteStartUnix int64 `json:"minute_start_unix"`
	BytesIn         int64 `json:"bytes_in"`
	BytesOut        int64 `json:"bytes_out"`
	Requests        int64 `json:"requests"`
}

type trafficMinuteDelta struct {
	BytesIn  int64
	BytesOut int64
	Requests int64
}

func trafficMinuteStart(at time.Time) int64 { return at.UTC().Truncate(time.Minute).Unix() }

func validTrafficTimelineMinutes(minutes int) bool {
	switch minutes {
	case 60, 360, 1440, trafficTimelineMaxMinutes:
		return true
	default:
		return false
	}
}

func (d *DB) addTrafficMinuteBuckets(siteID, bytesIn, bytesOut int64, buckets map[int64]trafficMinuteDelta, now time.Time) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var bucketRequests int64
	for _, delta := range buckets {
		bucketRequests += delta.Requests
	}
	if bytesIn != 0 || bytesOut != 0 || bucketRequests != 0 {
		if _, err := tx.Exec(`INSERT INTO traffic_logs (site_id, bytes_in, bytes_out, requests, recorded_at)
			VALUES (?,?,?,?,?)
			ON CONFLICT(site_id, recorded_at) DO UPDATE SET
			bytes_in=traffic_logs.bytes_in+excluded.bytes_in,
			bytes_out=traffic_logs.bytes_out+excluded.bytes_out,
			requests=traffic_logs.requests+excluded.requests`, siteID, bytesIn, bytesOut, bucketRequests, trafficMinuteBucket(now)); err != nil {
			return err
		}
	}
	for minute, delta := range buckets {
		if minute%trafficMinuteSeconds != 0 || delta.BytesIn < 0 || delta.BytesOut < 0 || delta.Requests < 0 {
			return fmt.Errorf("invalid traffic minute bucket")
		}
		if _, err := tx.Exec(`INSERT INTO traffic_minute_logs (site_id, minute_start_unix, bytes_in, bytes_out, requests)
			VALUES (?,?,?,?,?)
			ON CONFLICT(site_id, minute_start_unix) DO UPDATE SET
			bytes_in=traffic_minute_logs.bytes_in+excluded.bytes_in,
			bytes_out=traffic_minute_logs.bytes_out+excluded.bytes_out,
			requests=traffic_minute_logs.requests+excluded.requests`, siteID, minute, delta.BytesIn, delta.BytesOut, delta.Requests); err != nil {
			return err
		}
	}
	if bytesIn != 0 || bytesOut != 0 {
		if _, err := tx.Exec(`UPDATE sites SET traffic_used=traffic_used+?+?, traffic_used_in=traffic_used_in+?, traffic_used_out=traffic_used_out+?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, bytesIn, bytesOut, bytesIn, bytesOut, siteID); err != nil {
			return err
		}
	}
	cutoff := trafficMinuteStart(now.Add(-trafficMinuteRetention))
	if _, err := tx.Exec(`DELETE FROM traffic_minute_logs
		WHERE rowid IN (
			SELECT rowid FROM traffic_minute_logs WHERE minute_start_unix < ? ORDER BY minute_start_unix, site_id LIMIT ?
		)`, cutoff, trafficMinutePruneBatchSize); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) GetTrafficTimeline(siteID int64, minutes int, now time.Time) ([]TrafficMinuteLog, error) {
	if !validTrafficTimelineMinutes(minutes) {
		return nil, fmt.Errorf("invalid traffic timeline range: %d", minutes)
	}
	end := trafficMinuteStart(now)
	start := end - int64(minutes-1)*trafficMinuteSeconds
	result := make([]TrafficMinuteLog, minutes)
	for i := range result {
		result[i].MinuteStartUnix = start + int64(i)*trafficMinuteSeconds
	}
	rows, err := d.db.Query(`SELECT minute_start_unix, bytes_in, bytes_out, requests FROM traffic_minute_logs WHERE site_id=? AND minute_start_unix>=? AND minute_start_unix<=? ORDER BY minute_start_unix`, siteID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var bucket TrafficMinuteLog
		if err := rows.Scan(&bucket.MinuteStartUnix, &bucket.BytesIn, &bucket.BytesOut, &bucket.Requests); err != nil {
			return nil, err
		}
		offset := bucket.MinuteStartUnix - start
		if offset < 0 || offset%trafficMinuteSeconds != 0 {
			continue
		}
		index := int(offset / trafficMinuteSeconds)
		if index < len(result) {
			result[index] = bucket
		}
	}
	return result, rows.Err()
}
