package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const (
	migrationRetryDelay    = 25 * time.Millisecond
	migrationRetryDeadline = 5 * time.Second
)

func (d *DB) migrate() error {
	deadline := time.Now().Add(migrationRetryDeadline)
	for {
		err := d.migrateOnce()
		if err == nil || !isSQLiteBusyError(err) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(migrationRetryDelay)
	}
}

func isSQLiteBusyError(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	// SQLite encodes the primary result code in the low byte of extended errors.
	switch sqliteErr.Code() & 0xff {
	case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
		return true
	default:
		return false
	}
}

func isSQLiteUniqueConstraintError(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	switch sqliteErr.Code() {
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
		return true
	default:
		return false
	}
}

func (d *DB) migrateOnce() error {
	ctx := context.Background()
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	if _, err := conn.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
		CREATE TABLE IF NOT EXISTS sites (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			sort_order INTEGER NOT NULL DEFAULT 0,
			name TEXT NOT NULL,
			listen_port INTEGER NOT NULL UNIQUE,
			public_host TEXT NOT NULL DEFAULT '',
			path_prefix TEXT NOT NULL DEFAULT '',
			ingress_mode TEXT NOT NULL DEFAULT 'port',
			target_url TEXT NOT NULL,
		primary_line_name TEXT NOT NULL DEFAULT '主线路',
		playback_target_url TEXT NOT NULL DEFAULT '',
		playback_mode TEXT NOT NULL DEFAULT 'direct',
		main_video_stream_mode TEXT NOT NULL DEFAULT 'proxy',
		failover_targets TEXT NOT NULL DEFAULT '[]',
		failover_lines TEXT NOT NULL DEFAULT '[]',
		stream_hosts TEXT NOT NULL DEFAULT '[]',
		ua_mode TEXT DEFAULT 'passthrough',
		custom_user_agent TEXT NOT NULL DEFAULT '',
		custom_client TEXT NOT NULL DEFAULT '',
		custom_version TEXT NOT NULL DEFAULT '',
		client_ip_mode TEXT NOT NULL DEFAULT 'both',
		upstream_headers TEXT NOT NULL DEFAULT '[]',
		dynamic_discovery_enabled INTEGER NOT NULL DEFAULT 0,
		dynamic_profile TEXT NOT NULL DEFAULT 'compatible',
		dynamic_discovery_sources TEXT NOT NULL DEFAULT '["redirect","playback_info"]',
		dynamic_domain_rules TEXT NOT NULL DEFAULT '[]',
		dynamic_allow_https_downgrade INTEGER NOT NULL DEFAULT 1,
		dynamic_policy_revision INTEGER NOT NULL DEFAULT 1,
		ping_cache_enabled INTEGER NOT NULL DEFAULT 0,
		image_cache_enabled INTEGER NOT NULL DEFAULT 0,
		progress_coalescing_enabled INTEGER NOT NULL DEFAULT 0,
		asset_cache_enabled INTEGER NOT NULL DEFAULT 0,
		asset_cache_ttl_sec INTEGER NOT NULL DEFAULT 86400,
		asset_cache_max_bytes BIGINT NOT NULL DEFAULT 536870912,
		asset_cache_rules TEXT NOT NULL DEFAULT '*/file/*\n*/emby/Items/*/Images/*',
		enabled INTEGER DEFAULT 1,
		traffic_quota BIGINT DEFAULT 0,
		traffic_used BIGINT DEFAULT 0,
		traffic_used_in BIGINT NOT NULL DEFAULT 0,
		traffic_used_out BIGINT NOT NULL DEFAULT 0,
		speed_limit INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS traffic_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
		bytes_in BIGINT DEFAULT 0,
		bytes_out BIGINT DEFAULT 0,
		requests BIGINT NOT NULL DEFAULT 0,
		recorded_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_traffic_site_time ON traffic_logs(site_id, recorded_at);
	CREATE TABLE IF NOT EXISTS traffic_minute_logs (
		site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
		minute_start_unix INTEGER NOT NULL,
		bytes_in INTEGER NOT NULL DEFAULT 0,
		bytes_out INTEGER NOT NULL DEFAULT 0,
		requests INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY(site_id, minute_start_unix)
	);
	CREATE TABLE IF NOT EXISTS request_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
		site_name TEXT NOT NULL,
		resource_category TEXT NOT NULL,
		status_code INTEGER NOT NULL,
		client_ip TEXT NOT NULL,
		user_agent TEXT NOT NULL,
		upstream_user_agent TEXT NOT NULL DEFAULT '',
		backend_address TEXT NOT NULL DEFAULT '',
		inbound_colo TEXT NOT NULL DEFAULT '',
		outbound_colo TEXT NOT NULL DEFAULT '',
		method TEXT NOT NULL,
		path TEXT NOT NULL,
		recorded_at_ms INTEGER NOT NULL,
		timeline_at_ms INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_request_logs_time ON request_logs(recorded_at_ms DESC, id DESC);
	CREATE INDEX IF NOT EXISTS idx_request_logs_category_status ON request_logs(resource_category, status_code, recorded_at_ms DESC);
	CREATE TABLE IF NOT EXISTS panel_settings (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		panel_domain TEXT NOT NULL DEFAULT '',
		route_domain TEXT NOT NULL DEFAULT '',
		listen_port INTEGER NOT NULL DEFAULT 0,
		tls_enabled INTEGER NOT NULL DEFAULT 0,
		configured INTEGER NOT NULL DEFAULT 0,
		acme_email TEXT NOT NULL DEFAULT '',
		acme_dns_provider TEXT NOT NULL DEFAULT 'cloudflare',
		acme_token_ciphertext TEXT NOT NULL DEFAULT '',
		acme_staging INTEGER NOT NULL DEFAULT 0,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT OR IGNORE INTO panel_settings (id) VALUES (1);
	CREATE TABLE IF NOT EXISTS telegram_report_settings (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		enabled INTEGER NOT NULL DEFAULT 0,
		bot_token_ciphertext TEXT NOT NULL DEFAULT '',
		chat_id TEXT NOT NULL DEFAULT '',
		schedule_time TEXT NOT NULL DEFAULT '20:00',
		frequency TEXT NOT NULL DEFAULT 'daily',
		weekday INTEGER NOT NULL DEFAULT 1,
		last_sent_key TEXT NOT NULL DEFAULT '',
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT OR IGNORE INTO telegram_report_settings (id) VALUES (1);
		CREATE TABLE IF NOT EXISTS system_settings (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		ui_mode TEXT NOT NULL DEFAULT 'novice', ui_radius INTEGER NOT NULL DEFAULT 10,
		traffic_billing_mode TEXT NOT NULL DEFAULT 'bidirectional', traffic_reset_day INTEGER NOT NULL DEFAULT 1,
		probe_timeout_ms INTEGER NOT NULL DEFAULT 5000, ping_cache_minutes INTEGER NOT NULL DEFAULT 10,
		schedule_timezone_offset INTEGER NOT NULL DEFAULT 480, schedule_timezone TEXT NOT NULL DEFAULT 'Asia/Shanghai',
		log_enabled INTEGER NOT NULL DEFAULT 1, log_level TEXT NOT NULL DEFAULT 'info',
		log_retention_days INTEGER NOT NULL DEFAULT 30, log_write_delay_minutes INTEGER NOT NULL DEFAULT 0,
		log_flush_threshold INTEGER NOT NULL DEFAULT 1, log_batch_size INTEGER NOT NULL DEFAULT 50,
		log_retry_count INTEGER NOT NULL DEFAULT 2, log_retry_backoff_ms INTEGER NOT NULL DEFAULT 75,
		log_task_lease_ms INTEGER NOT NULL DEFAULT 300000,
		log_write_image INTEGER NOT NULL DEFAULT 0, log_write_playback INTEGER NOT NULL DEFAULT 1, log_write_metadata INTEGER NOT NULL DEFAULT 0,
		log_write_video INTEGER NOT NULL DEFAULT 1, log_write_api INTEGER NOT NULL DEFAULT 1, log_write_auth INTEGER NOT NULL DEFAULT 1,
		log_write_subtitle INTEGER NOT NULL DEFAULT 1, log_write_asset INTEGER NOT NULL DEFAULT 1, log_write_websocket INTEGER NOT NULL DEFAULT 1,
		log_resource_taxonomy_version INTEGER NOT NULL DEFAULT 1,
		log_write_node INTEGER NOT NULL DEFAULT 1, log_write_category INTEGER NOT NULL DEFAULT 1, log_write_status INTEGER NOT NULL DEFAULT 1,
		log_write_client_ip INTEGER NOT NULL DEFAULT 1, log_write_colo INTEGER NOT NULL DEFAULT 0,
		log_write_ua INTEGER NOT NULL DEFAULT 1, log_write_upstream_ua INTEGER NOT NULL DEFAULT 1, log_write_backend_address INTEGER NOT NULL DEFAULT 1, log_write_timeline INTEGER NOT NULL DEFAULT 1, log_display_client_ip INTEGER NOT NULL DEFAULT 1,
		log_display_colo INTEGER NOT NULL DEFAULT 0, log_display_ua INTEGER NOT NULL DEFAULT 1, log_display_upstream_ua INTEGER NOT NULL DEFAULT 1, log_display_backend_address INTEGER NOT NULL DEFAULT 1,
		log_display_node INTEGER NOT NULL DEFAULT 1, log_display_category INTEGER NOT NULL DEFAULT 1,
		log_display_status INTEGER NOT NULL DEFAULT 1, log_display_timeline INTEGER NOT NULL DEFAULT 1,
			log_search_mode TEXT NOT NULL DEFAULT 'like',
			session_epoch INTEGER NOT NULL DEFAULT 1,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT OR IGNORE INTO system_settings (id) VALUES (1);
	`); err != nil {
		return err
	}
	if err := ensureDynamicObservationSchema(ctx, conn); err != nil {
		return err
	}
	if err := validateDynamicObservationSchema(ctx, conn); err != nil {
		return err
	}
	if err := pruneDynamicObservationRows(ctx, conn, time.Now()); err != nil {
		return fmt.Errorf("prune dynamic observations during migration: %w", err)
	}

	for _, migration := range []struct {
		column string
		sql    string
	}{
		{"playback_target_url", "ALTER TABLE sites ADD COLUMN playback_target_url TEXT NOT NULL DEFAULT ''"},
		{"playback_mode", "ALTER TABLE sites ADD COLUMN playback_mode TEXT NOT NULL DEFAULT 'direct'"},
		{"main_video_stream_mode", "ALTER TABLE sites ADD COLUMN main_video_stream_mode TEXT NOT NULL DEFAULT 'proxy'"},
		{"primary_line_name", "ALTER TABLE sites ADD COLUMN primary_line_name TEXT NOT NULL DEFAULT '主线路'"},
		{"failover_targets", "ALTER TABLE sites ADD COLUMN failover_targets TEXT NOT NULL DEFAULT '[]'"},
		{"failover_lines", "ALTER TABLE sites ADD COLUMN failover_lines TEXT NOT NULL DEFAULT '[]'"},
		{"stream_hosts", "ALTER TABLE sites ADD COLUMN stream_hosts TEXT NOT NULL DEFAULT '[]'"},
		{"custom_user_agent", "ALTER TABLE sites ADD COLUMN custom_user_agent TEXT NOT NULL DEFAULT ''"},
		{"custom_client", "ALTER TABLE sites ADD COLUMN custom_client TEXT NOT NULL DEFAULT ''"},
		{"custom_version", "ALTER TABLE sites ADD COLUMN custom_version TEXT NOT NULL DEFAULT ''"},
		{"client_ip_mode", "ALTER TABLE sites ADD COLUMN client_ip_mode TEXT NOT NULL DEFAULT 'both'"},
		{"public_host", "ALTER TABLE sites ADD COLUMN public_host TEXT NOT NULL DEFAULT ''"},
		{"path_prefix", "ALTER TABLE sites ADD COLUMN path_prefix TEXT NOT NULL DEFAULT ''"},
		{"ingress_mode", "ALTER TABLE sites ADD COLUMN ingress_mode TEXT NOT NULL DEFAULT 'port'"},
		{"upstream_headers", "ALTER TABLE sites ADD COLUMN upstream_headers TEXT NOT NULL DEFAULT '[]'"},
		{"dynamic_discovery_enabled", "ALTER TABLE sites ADD COLUMN dynamic_discovery_enabled INTEGER NOT NULL DEFAULT 0"},
		{"dynamic_profile", "ALTER TABLE sites ADD COLUMN dynamic_profile TEXT NOT NULL DEFAULT 'safe'"},
		{"dynamic_discovery_sources", "ALTER TABLE sites ADD COLUMN dynamic_discovery_sources TEXT NOT NULL DEFAULT '[\"redirect\"]'"},
		{"dynamic_domain_rules", "ALTER TABLE sites ADD COLUMN dynamic_domain_rules TEXT NOT NULL DEFAULT '[]'"},
		{"dynamic_allow_https_downgrade", "ALTER TABLE sites ADD COLUMN dynamic_allow_https_downgrade INTEGER NOT NULL DEFAULT 0"},
		{"dynamic_policy_revision", "ALTER TABLE sites ADD COLUMN dynamic_policy_revision INTEGER NOT NULL DEFAULT 1"},
		{"ping_cache_enabled", "ALTER TABLE sites ADD COLUMN ping_cache_enabled INTEGER NOT NULL DEFAULT 0"},
		{"image_cache_enabled", "ALTER TABLE sites ADD COLUMN image_cache_enabled INTEGER NOT NULL DEFAULT 0"},
		{"progress_coalescing_enabled", "ALTER TABLE sites ADD COLUMN progress_coalescing_enabled INTEGER NOT NULL DEFAULT 0"},
		{"asset_cache_enabled", "ALTER TABLE sites ADD COLUMN asset_cache_enabled INTEGER NOT NULL DEFAULT 0"},
		{"asset_cache_ttl_sec", "ALTER TABLE sites ADD COLUMN asset_cache_ttl_sec INTEGER NOT NULL DEFAULT 86400"},
		{"asset_cache_max_bytes", "ALTER TABLE sites ADD COLUMN asset_cache_max_bytes BIGINT NOT NULL DEFAULT 536870912"},
		{"asset_cache_rules", "ALTER TABLE sites ADD COLUMN asset_cache_rules TEXT NOT NULL DEFAULT '*/file/*\n*/emby/Items/*/Images/*'"},
		{"sort_order", "ALTER TABLE sites ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0"},
	} {
		exists, err := sqliteColumnExists(ctx, conn, migration.column)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := conn.ExecContext(ctx, migration.sql); err != nil {
				return err
			}
			if migration.column == "sort_order" {
				if _, err := conn.ExecContext(ctx, "UPDATE sites SET sort_order=id"); err != nil {
					return err
				}
			}
		}
	}
	for _, migration := range []struct{ column, sql string }{
		{"traffic_billing_mode", "ALTER TABLE system_settings ADD COLUMN traffic_billing_mode TEXT NOT NULL DEFAULT 'bidirectional'"},
		{"traffic_reset_day", "ALTER TABLE system_settings ADD COLUMN traffic_reset_day INTEGER NOT NULL DEFAULT 1"},
		{"schedule_timezone", "ALTER TABLE system_settings ADD COLUMN schedule_timezone TEXT NOT NULL DEFAULT ''"},
		{"log_write_playback", "ALTER TABLE system_settings ADD COLUMN log_write_playback INTEGER NOT NULL DEFAULT 1"},
		{"log_write_video", "ALTER TABLE system_settings ADD COLUMN log_write_video INTEGER NOT NULL DEFAULT 1"},
		{"log_write_api", "ALTER TABLE system_settings ADD COLUMN log_write_api INTEGER NOT NULL DEFAULT 1"},
		{"log_write_auth", "ALTER TABLE system_settings ADD COLUMN log_write_auth INTEGER NOT NULL DEFAULT 1"},
		{"log_write_subtitle", "ALTER TABLE system_settings ADD COLUMN log_write_subtitle INTEGER NOT NULL DEFAULT 1"},
		{"log_write_asset", "ALTER TABLE system_settings ADD COLUMN log_write_asset INTEGER NOT NULL DEFAULT 1"},
		{"log_write_websocket", "ALTER TABLE system_settings ADD COLUMN log_write_websocket INTEGER NOT NULL DEFAULT 1"},
		{"log_resource_taxonomy_version", "ALTER TABLE system_settings ADD COLUMN log_resource_taxonomy_version INTEGER NOT NULL DEFAULT 0"},
		{"log_write_node", "ALTER TABLE system_settings ADD COLUMN log_write_node INTEGER NOT NULL DEFAULT 1"},
		{"log_write_category", "ALTER TABLE system_settings ADD COLUMN log_write_category INTEGER NOT NULL DEFAULT 1"},
		{"log_write_status", "ALTER TABLE system_settings ADD COLUMN log_write_status INTEGER NOT NULL DEFAULT 1"},
		{"log_write_timeline", "ALTER TABLE system_settings ADD COLUMN log_write_timeline INTEGER NOT NULL DEFAULT 1"},
		{"log_write_upstream_ua", "ALTER TABLE system_settings ADD COLUMN log_write_upstream_ua INTEGER NOT NULL DEFAULT 1"},
		{"log_write_backend_address", "ALTER TABLE system_settings ADD COLUMN log_write_backend_address INTEGER NOT NULL DEFAULT 1"},
		{"log_display_node", "ALTER TABLE system_settings ADD COLUMN log_display_node INTEGER NOT NULL DEFAULT 1"},
		{"log_display_category", "ALTER TABLE system_settings ADD COLUMN log_display_category INTEGER NOT NULL DEFAULT 1"},
		{"log_display_status", "ALTER TABLE system_settings ADD COLUMN log_display_status INTEGER NOT NULL DEFAULT 1"},
		{"log_display_timeline", "ALTER TABLE system_settings ADD COLUMN log_display_timeline INTEGER NOT NULL DEFAULT 1"},
		{"log_display_upstream_ua", "ALTER TABLE system_settings ADD COLUMN log_display_upstream_ua INTEGER NOT NULL DEFAULT 1"},
		{"log_display_backend_address", "ALTER TABLE system_settings ADD COLUMN log_display_backend_address INTEGER NOT NULL DEFAULT 1"},
		{"session_epoch", "ALTER TABLE system_settings ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 1"},
	} {
		var exists int
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('system_settings') WHERE name=?", migration.column).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			if _, err := conn.ExecContext(ctx, migration.sql); err != nil {
				return err
			}
		}
	}
	// Older databases only stored a numeric offset. Select the closest
	// canonical IANA zone once and retain the offset field for API clients
	// that still send/consume it.
	var legacyOffset int
	var timezoneName string
	if err := conn.QueryRowContext(ctx, "SELECT schedule_timezone_offset, schedule_timezone FROM system_settings WHERE id=1").Scan(&legacyOffset, &timezoneName); err != nil {
		return err
	}
	if !validTimezoneName(timezoneName) {
		if _, err := conn.ExecContext(ctx, "UPDATE system_settings SET schedule_timezone=? WHERE id=1", timezoneNameForOffset(legacyOffset)); err != nil {
			return err
		}
	}
	for _, migration := range []struct{ column, sql string }{
		{"traffic_used_in", "ALTER TABLE sites ADD COLUMN traffic_used_in BIGINT NOT NULL DEFAULT -1"},
		{"traffic_used_out", "ALTER TABLE sites ADD COLUMN traffic_used_out BIGINT NOT NULL DEFAULT -1"},
	} {
		var exists int
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('sites') WHERE name=?", migration.column).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			if _, err := conn.ExecContext(ctx, migration.sql); err != nil {
				return err
			}
		}
	}
	if _, err := conn.ExecContext(ctx, "UPDATE sites SET traffic_used_in=traffic_used/2, traffic_used_out=traffic_used-(traffic_used/2) WHERE traffic_used_in<0 OR traffic_used_out<0"); err != nil {
		return err
	}
	var logResourceTaxonomyVersion int
	if err := conn.QueryRowContext(ctx, "SELECT log_resource_taxonomy_version FROM system_settings WHERE id=1").Scan(&logResourceTaxonomyVersion); err != nil {
		return err
	}
	if logResourceTaxonomyVersion < 1 {
		if _, err := conn.ExecContext(ctx, `UPDATE system_settings SET
			log_write_playback=log_write_metadata,
			log_write_metadata=0,
			log_resource_taxonomy_version=1
			WHERE id=1`); err != nil {
			return err
		}
	}
	if err := ensurePanelSettingsListenPortSchema(ctx, conn); err != nil {
		return err
	}
	for _, migration := range []struct{ column, sql string }{
		{"inbound_colo", "ALTER TABLE request_logs ADD COLUMN inbound_colo TEXT NOT NULL DEFAULT ''"},
		{"outbound_colo", "ALTER TABLE request_logs ADD COLUMN outbound_colo TEXT NOT NULL DEFAULT ''"},
		{"upstream_user_agent", "ALTER TABLE request_logs ADD COLUMN upstream_user_agent TEXT NOT NULL DEFAULT ''"},
		{"backend_address", "ALTER TABLE request_logs ADD COLUMN backend_address TEXT NOT NULL DEFAULT ''"},
	} {
		var exists int
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('request_logs') WHERE name=?", migration.column).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			if _, err := conn.ExecContext(ctx, migration.sql); err != nil {
				return err
			}
		}
	}
	var hasTimelineColumn int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('request_logs') WHERE name='timeline_at_ms'").Scan(&hasTimelineColumn); err != nil {
		return err
	}
	if hasTimelineColumn == 0 {
		if _, err := conn.ExecContext(ctx, "ALTER TABLE request_logs ADD COLUMN timeline_at_ms INTEGER NOT NULL DEFAULT 0"); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, "UPDATE request_logs SET timeline_at_ms=recorded_at_ms"); err != nil {
			return err
		}
	}
	// public_host was introduced before ingress_mode on the unreleased Issue #28
	// branch. Migrate those rows to the secure host-only behavior instead of
	// silently retaining a public high-port listener.
	if _, err := conn.ExecContext(ctx, "UPDATE sites SET ingress_mode='host' WHERE public_host <> '' AND ingress_mode='port'"); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS idx_sites_public_host ON sites(public_host COLLATE NOCASE) WHERE public_host <> ''"); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS idx_sites_path_prefix ON sites(path_prefix COLLATE NOCASE) WHERE path_prefix <> ''"); err != nil {
		return err
	}

	var hasRequestsColumn int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('traffic_logs') WHERE name='requests'").Scan(&hasRequestsColumn); err != nil {
		return err
	}
	if hasRequestsColumn == 0 {
		if _, err := conn.ExecContext(ctx, "ALTER TABLE traffic_logs ADD COLUMN requests BIGINT NOT NULL DEFAULT 0"); err != nil {
			return err
		}
	}

	// idx_traffic_site_hour and idx_traffic_site_minute enforce the same
	// physical uniqueness (site_id, recorded_at); only the bucket timestamp
	// written by addTrafficWithRequests changes from HH:00 to HH:MM. Preserve
	// every legacy hourly row, and only collapse exact duplicate timestamps on
	// very old databases that predate the unique index.
	var hasTrafficBucketIndex int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('idx_traffic_site_hour','idx_traffic_site_minute')").Scan(&hasTrafficBucketIndex); err != nil {
		return err
	}
	if hasTrafficBucketIndex == 0 {
		if _, err := conn.ExecContext(ctx, `
			CREATE TABLE traffic_logs_dedup (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
				bytes_in BIGINT DEFAULT 0,
				bytes_out BIGINT DEFAULT 0,
				requests BIGINT NOT NULL DEFAULT 0,
				recorded_at DATETIME NOT NULL
			);
			INSERT INTO traffic_logs_dedup (site_id, bytes_in, bytes_out, requests, recorded_at)
			SELECT site_id, SUM(bytes_in), SUM(bytes_out), SUM(requests), recorded_at
			FROM traffic_logs
			GROUP BY site_id, recorded_at;
			DELETE FROM traffic_logs;
			INSERT INTO traffic_logs (site_id, bytes_in, bytes_out, requests, recorded_at)
			SELECT site_id, bytes_in, bytes_out, requests, recorded_at
			FROM traffic_logs_dedup;
			DROP TABLE traffic_logs_dedup;
		`); err != nil {
			return err
		}
	}
	if _, err := conn.ExecContext(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_site_minute ON traffic_logs(site_id, recorded_at)"); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "DROP INDEX IF EXISTS idx_traffic_site_hour"); err != nil {
		return err
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

func ensurePanelSettingsListenPortSchema(ctx context.Context, conn *sql.Conn) error {
	for _, migration := range []struct{ column, sql string }{
		{"listen_port", "ALTER TABLE panel_settings ADD COLUMN listen_port INTEGER NOT NULL DEFAULT 0"},
		{"acme_email", "ALTER TABLE panel_settings ADD COLUMN acme_email TEXT NOT NULL DEFAULT ''"},
		{"acme_dns_provider", "ALTER TABLE panel_settings ADD COLUMN acme_dns_provider TEXT NOT NULL DEFAULT 'cloudflare'"},
		{"acme_token_ciphertext", "ALTER TABLE panel_settings ADD COLUMN acme_token_ciphertext TEXT NOT NULL DEFAULT ''"},
		{"acme_staging", "ALTER TABLE panel_settings ADD COLUMN acme_staging INTEGER NOT NULL DEFAULT 0"},
	} {
		var found int
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('panel_settings') WHERE name=?", migration.column).Scan(&found); err != nil {
			return err
		}
		if found != 0 {
			continue
		}
		if _, err := conn.ExecContext(ctx, migration.sql); err != nil {
			return err
		}
	}
	return nil
}

func sqliteColumnExists(ctx context.Context, conn *sql.Conn, column string) (bool, error) {
	var count int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('sites') WHERE name=?", column).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}
