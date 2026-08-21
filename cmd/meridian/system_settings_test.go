package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSystemSettingsDefaultsUseBeijingSchedule(t *testing.T) {
	settings := defaultSystemSettings()
	if settings.ScheduleTimezone != 480 {
		t.Fatalf("schedule timezone = %d, want 480", settings.ScheduleTimezone)
	}
	if settings.ScheduleTimezoneName != defaultTimezoneName {
		t.Fatalf("schedule timezone name = %q, want %q", settings.ScheduleTimezoneName, defaultTimezoneName)
	}
	if settings.LogEnabled != true || settings.LogBatchSize != 50 || !settings.LogDisplayUA || !settings.LogDisplayUpstreamUA || settings.LogWriteImage || !settings.LogWritePlayback || settings.LogWriteMetadata || !settings.LogWriteVideo || !settings.LogWriteSubtitle || !settings.LogWriteAsset || !settings.LogWriteWebSocket || !settings.LogWriteAPI || !settings.LogWriteAuth || !settings.LogWriteNode || !settings.LogWriteCategory || !settings.LogWriteStatus || !settings.LogWriteClientIP || !settings.LogWriteUA || !settings.LogWriteUpstreamUA || !settings.LogWriteTimeline {
		t.Fatalf("unexpected defaults: %+v", settings)
	}
}

func TestTelegramReportDueNormalizesToBeijing(t *testing.T) {
	settings := telegramReportSettingsView{Enabled: true, Configured: true, ScheduleTime: "20:00", Frequency: "daily", Timezone: 480}
	utc := time.Date(2026, time.August, 8, 12, 1, 0, 0, time.UTC)
	key, due := telegramReportDue(utc, settings)
	if !due || key != "daily:2026-08-08" {
		t.Fatalf("due = (%q, %v)", key, due)
	}
}

func TestSystemSettingsAllowManualScheduleTimezone(t *testing.T) {
	settings := defaultSystemSettings()
	settings.ScheduleTimezone = -300
	normalized, err := normalizeSystemSettings(settings)
	if err != nil || normalized.ScheduleTimezone != -300 {
		t.Fatalf("manual timezone = %d, err = %v", normalized.ScheduleTimezone, err)
	}
}

func TestSystemSettingsCanonicalTimezoneAndAllowlist(t *testing.T) {
	settings := defaultSystemSettings()
	settings.ScheduleTimezoneName = "America/New_York"
	normalized, err := normalizeSystemSettings(settings)
	if err != nil || normalized.ScheduleTimezoneName != "America/New_York" {
		t.Fatalf("canonical timezone = %#v, err = %v", normalized, err)
	}
	settings.ScheduleTimezoneName = "Not/IANA"
	if _, err := normalizeSystemSettings(settings); err == nil {
		t.Fatal("unsupported timezone was accepted")
	}
}

func TestLegacyMetadataWriteSettingMigratesToPlayback(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "legacy-log-taxonomy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.db.Exec(`UPDATE system_settings SET
		log_write_playback=0,
		log_write_metadata=1,
		log_resource_taxonomy_version=0
		WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := db.migrateOnce(); err != nil {
		t.Fatal(err)
	}
	var playback, metadata, version int
	if err := db.db.QueryRow("SELECT log_write_playback, log_write_metadata, log_resource_taxonomy_version FROM system_settings WHERE id=1").Scan(&playback, &metadata, &version); err != nil {
		t.Fatal(err)
	}
	if playback != 1 || metadata != 0 || version != 1 {
		t.Fatalf("migrated taxonomy = playback:%d metadata:%d version:%d", playback, metadata, version)
	}
}
