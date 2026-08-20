package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const dynamicObservationTestInsertSQL = `
	INSERT INTO dynamic_observations
		(site_id, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status, first_seen_ms, last_seen_ms, count)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

const legacyDynamicObservationTestInsertSQL = `
	INSERT INTO dynamic_observations
		(site_id, canonical_authority, source, decision, reason_code, first_seen_ms, last_seen_ms, count)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

var extremeDynamicObservationReasonCases = []struct {
	source string
	reason string
}{
	{dynamicObservationSourcePlaybackInfo, dynamicObservationReasonRequestUnclassified},
	{dynamicObservationSourcePlaybackInfo, dynamicObservationReasonStructuredBodyLimit},
	{dynamicObservationSourcePlaybackInfo, dynamicObservationReasonPlaybackInfoDenied},
	{dynamicObservationSourceHLS, dynamicObservationReasonHLSFeatureDenied},
	{dynamicObservationSourceDASH, dynamicObservationReasonDASHFeatureDenied},
	{dynamicObservationSourceRedirect, dynamicObservationReasonRedirectBodyReplayDenied},
}

func openDynamicObservationTestDB(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dynamic-observations.db")
	db, err := openDB(path)
	if err != nil {
		t.Fatalf("open observation database: %v", err)
	}
	t.Cleanup(db.Close)
	return db, path
}

func createDynamicObservationTestSite(t *testing.T, db *DB, name string) *Site {
	t.Helper()
	var siteCount int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM sites").Scan(&siteCount); err != nil {
		t.Fatalf("count observation sites: %v", err)
	}
	site, err := db.CreateSite(name, 19001+siteCount, "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("create observation site: %v", err)
	}
	return site
}

func allowedDynamicObservationTestEvent(siteID int64, authority string) dynamicObservationEvent {
	return dynamicObservationEvent{
		SiteID:             siteID,
		CanonicalAuthority: authority,
		Source:             dynamicObservationSourceRedirect,
		TargetKind:         dynamicObservationTargetDiscovered,
		Decision:           dynamicObservationDecisionAllowed,
		ReasonCode:         dynamicObservationReasonRedirectAllowed,
		RedirectStatus:     0,
	}
}

func requireExactJSONFields(t *testing.T, raw []byte, fields ...string) map[string]json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatalf("decode JSON object: %v body=%s", err, raw)
	}
	if len(object) != len(fields) {
		t.Fatalf("JSON fields=%v, want exactly %v", object, fields)
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			t.Fatalf("JSON fields=%v, missing %q", object, field)
		}
	}
	return object
}

func requireNoObservationSecrets(t *testing.T, raw []byte, secrets ...string) {
	t.Helper()
	body := string(raw)
	for _, secret := range secrets {
		if secret != "" && strings.Contains(body, secret) {
			t.Fatalf("observation response disclosed %q: %s", secret, body)
		}
	}
}

func createV17ObservationFixture(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open v1.7 fixture: %v", err)
	}
	_, execErr := db.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE sites (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			listen_port INTEGER NOT NULL UNIQUE,
			public_host TEXT NOT NULL DEFAULT '',
			ingress_mode TEXT NOT NULL DEFAULT 'port',
			target_url TEXT NOT NULL,
			playback_target_url TEXT NOT NULL DEFAULT '',
			playback_mode TEXT NOT NULL DEFAULT 'direct',
			stream_hosts TEXT NOT NULL DEFAULT '[]',
			ua_mode TEXT DEFAULT 'infuse',
			custom_user_agent TEXT NOT NULL DEFAULT '',
			custom_client TEXT NOT NULL DEFAULT '',
			custom_version TEXT NOT NULL DEFAULT '',
			upstream_headers TEXT NOT NULL DEFAULT '[]',
			enabled INTEGER DEFAULT 1,
			traffic_quota BIGINT DEFAULT 0,
			traffic_used BIGINT DEFAULT 0,
			speed_limit INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE traffic_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
			bytes_in BIGINT DEFAULT 0,
			bytes_out BIGINT DEFAULT 0,
			recorded_at DATETIME NOT NULL
		);
		CREATE INDEX idx_traffic_site_time ON traffic_logs(site_id, recorded_at);
		CREATE UNIQUE INDEX idx_traffic_site_hour ON traffic_logs(site_id, recorded_at);
		INSERT INTO sites
			(name, listen_port, target_url, stream_hosts, upstream_headers, enabled)
		VALUES ('v1.7-site', 19001, 'http://127.0.0.1:8096', '[]', '[]', 0);
		INSERT INTO traffic_logs (site_id, bytes_in, bytes_out, recorded_at)
		VALUES (1, 11, 13, '2026-01-01T00:00:00Z');
	`)
	if execErr != nil {
		_ = db.Close()
		t.Fatalf("create v1.7 fixture: %v", execErr)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close v1.7 fixture: %v", err)
	}
}

func createLegacyDynamicObservationFixture(t *testing.T, path string) {
	t.Helper()
	createV17ObservationFixture(t, path)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy observation fixture: %v", err)
	}
	_, execErr := db.Exec(`
		CREATE TABLE dynamic_observations (
			site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
			canonical_authority TEXT NOT NULL,
			source TEXT NOT NULL CHECK(source = 'redirect'),
			decision TEXT NOT NULL CHECK(decision IN ('allowed', 'denied')),
			reason_code TEXT NOT NULL CHECK(reason_code IN (
				'redirect_allowed', 'invalid_location', 'unsupported_status', 'redirect_loop',
				'hop_limit', 'scheme_denied', 'port_denied', 'domain_denied',
				'https_downgrade_denied', 'self_target', 'dns_failure', 'address_denied',
				'dial_failure', 'tls_failure', 'capacity_limit', 'rate_limit',
				'response_failure', 'runtime_unavailable'
			)),
			first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
			last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms >= first_seen_ms),
			count INTEGER NOT NULL CHECK(count > 0),
			PRIMARY KEY(site_id, canonical_authority, source, decision, reason_code)
		) WITHOUT ROWID;
		CREATE INDEX idx_dynamic_observations_site_last_seen
			ON dynamic_observations(site_id, last_seen_ms DESC);
		CREATE INDEX idx_dynamic_observations_last_seen
			ON dynamic_observations(last_seen_ms);
		INSERT INTO dynamic_observations
			(site_id, canonical_authority, source, decision, reason_code, first_seen_ms, last_seen_ms, count)
		VALUES (1, 'https://legacy.example.com:443', 'redirect', 'allowed', 'redirect_allowed', CAST(unixepoch('subsec') * 1000 AS INTEGER), CAST(unixepoch('subsec') * 1000 AS INTEGER), 2);
	`)
	if execErr != nil {
		_ = db.Close()
		t.Fatalf("create legacy observation fixture: %v", execErr)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy observation fixture: %v", err)
	}
}

func createPreviousV18DynamicObservationFixture(t *testing.T, path string) map[string]DynamicObservation {
	t.Helper()
	createV17ObservationFixture(t, path)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open previous v1.8 observation fixture: %v", err)
	}
	_, execErr := db.Exec(`
		CREATE TABLE dynamic_observations (
			site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
			canonical_authority TEXT NOT NULL,
			source TEXT NOT NULL CHECK(source IN ('redirect', 'playback_info', 'hls', 'dash')),
			decision TEXT NOT NULL CHECK(decision IN ('allowed', 'denied')),
			reason_code TEXT NOT NULL CHECK(reason_code IN (
				'redirect_allowed', 'candidate_allowed', 'invalid_location', 'unsupported_status',
				'redirect_loop', 'hop_limit', 'scheme_denied', 'port_denied', 'domain_denied',
				'https_downgrade_denied', 'self_target', 'dns_failure', 'address_denied',
				'dial_failure', 'tls_failure', 'capacity_limit', 'rate_limit', 'parse_failure',
				'capability_invalid', 'capability_expired', 'response_failure', 'runtime_unavailable'
			)),
			first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
			last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms >= first_seen_ms),
			count INTEGER NOT NULL CHECK(count > 0),
			PRIMARY KEY(site_id, canonical_authority, source, decision, reason_code)
		) WITHOUT ROWID;
		CREATE INDEX idx_dynamic_observations_site_last_seen
			ON dynamic_observations(site_id, last_seen_ms DESC);
		CREATE INDEX idx_dynamic_observations_last_seen
			ON dynamic_observations(last_seen_ms);
	`)
	if execErr != nil {
		_ = db.Close()
		t.Fatalf("create previous v1.8 observation schema: %v", execErr)
	}
	now := time.Now().UnixMilli()
	rows := []DynamicObservation{
		migratedDynamicObservation(DynamicObservation{SiteID: 1, CanonicalAuthority: "https://previous-redirect.example.com:443", Source: dynamicObservationSourceRedirect, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed, FirstSeenMS: now - 8000, LastSeenMS: now - 7000, Count: 2}),
		migratedDynamicObservation(DynamicObservation{SiteID: 1, CanonicalAuthority: "https://previous-playback.example.com:443", Source: dynamicObservationSourcePlaybackInfo, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonCandidateAllowed, FirstSeenMS: now - 6000, LastSeenMS: now - 5000, Count: 3}),
		migratedDynamicObservation(DynamicObservation{SiteID: 1, CanonicalAuthority: "https://previous-hls.example.com:443", Source: dynamicObservationSourceHLS, Decision: dynamicObservationDecisionDenied, ReasonCode: dynamicObservationReasonParseFailure, FirstSeenMS: now - 4000, LastSeenMS: now - 3000, Count: 4}),
		migratedDynamicObservation(DynamicObservation{SiteID: 1, CanonicalAuthority: "https://previous-dash.example.com:443", Source: dynamicObservationSourceDASH, Decision: dynamicObservationDecisionDenied, ReasonCode: dynamicObservationReasonCapabilityExpired, FirstSeenMS: now - 2000, LastSeenMS: now - 1000, Count: 5}),
	}
	expected := make(map[string]DynamicObservation, len(rows))
	for _, row := range rows {
		if _, err := db.Exec(legacyDynamicObservationTestInsertSQL, row.SiteID, row.CanonicalAuthority, row.Source, row.Decision, row.ReasonCode, row.FirstSeenMS, row.LastSeenMS, row.Count); err != nil {
			_ = db.Close()
			t.Fatalf("insert previous v1.8 observation %q: %v", row.CanonicalAuthority, err)
		}
		expected[row.CanonicalAuthority] = row
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close previous v1.8 observation fixture: %v", err)
	}
	return expected
}

func migratedDynamicObservation(row DynamicObservation) DynamicObservation {
	row.TargetKind = dynamicObservationTargetDiscovered
	row.Stage, _ = dynamicObservationStageForReason(row.ReasonCode)
	row.RedirectStatus = 0
	return row
}

func createPreviousV19DynamicObservationFixture(t *testing.T, path string) map[string]DynamicObservation {
	t.Helper()
	createV17ObservationFixture(t, path)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open previous v1.9 observation fixture: %v", err)
	}
	if _, err := db.Exec(dynamicObservationV19TableDDL + dynamicObservationIndexesDDL); err != nil {
		_ = db.Close()
		t.Fatalf("create previous v1.9 observation schema: %v", err)
	}
	now := time.Now().UnixMilli()
	rows := []DynamicObservation{
		migratedDynamicObservation(DynamicObservation{SiteID: 1, CanonicalAuthority: "https://v19-redirect.example.com:443", Source: dynamicObservationSourceRedirect, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed, FirstSeenMS: now - 7000, LastSeenMS: now - 6000, Count: 7}),
		migratedDynamicObservation(DynamicObservation{SiteID: 1, CanonicalAuthority: "https://v19-playback.example.com:443", Source: dynamicObservationSourcePlaybackInfo, Decision: dynamicObservationDecisionDenied, ReasonCode: dynamicObservationReasonStructuredBodyLimit, FirstSeenMS: now - 5000, LastSeenMS: now - 3000, Count: 11}),
		migratedDynamicObservation(DynamicObservation{SiteID: 1, CanonicalAuthority: "https://v19-runtime.example.com:443", Source: dynamicObservationSourceDASH, Decision: dynamicObservationDecisionDenied, ReasonCode: dynamicObservationReasonRuntimeUnavailable, FirstSeenMS: now - 2000, LastSeenMS: now - 1000, Count: 13}),
	}
	expected := make(map[string]DynamicObservation, len(rows))
	for _, row := range rows {
		if _, err := db.Exec(legacyDynamicObservationTestInsertSQL, row.SiteID, row.CanonicalAuthority, row.Source, row.Decision, row.ReasonCode, row.FirstSeenMS, row.LastSeenMS, row.Count); err != nil {
			_ = db.Close()
			t.Fatalf("insert previous v1.9 observation %q: %v", row.CanonicalAuthority, err)
		}
		expected[row.CanonicalAuthority] = row
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close previous v1.9 observation fixture: %v", err)
	}
	return expected
}

func createPreviousV19DynamicObservationLimitFixture(t *testing.T, path string) (int64, int) {
	t.Helper()
	createV17ObservationFixture(t, path)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open bounded v1.9 observation fixture: %v", err)
	}
	if _, err := db.Exec(dynamicObservationV19TableDDL + dynamicObservationIndexesDDL); err != nil {
		_ = db.Close()
		t.Fatalf("create bounded v1.9 observation schema: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		_ = db.Close()
		t.Fatalf("begin bounded v1.9 observation fixture: %v", err)
	}
	statement, err := tx.Prepare(legacyDynamicObservationTestInsertSQL)
	if err != nil {
		_ = tx.Rollback()
		_ = db.Close()
		t.Fatalf("prepare bounded v1.9 observation fixture: %v", err)
	}
	base := time.Now().Add(-time.Hour).UnixMilli()
	total := dynamicObservationPerSiteRowLimit + 2
	for index := range total {
		authority := fmt.Sprintf("https://v19-limit-%05d.example.com:443", index)
		seen := base + int64(index)
		if _, err := statement.Exec(1, authority, dynamicObservationSourcePlaybackInfo, dynamicObservationDecisionAllowed, dynamicObservationReasonCandidateAllowed, seen, seen, 1); err != nil {
			_ = statement.Close()
			_ = tx.Rollback()
			_ = db.Close()
			t.Fatalf("insert bounded v1.9 observation %d: %v", index, err)
		}
	}
	if err := statement.Close(); err != nil {
		_ = tx.Rollback()
		_ = db.Close()
		t.Fatalf("close bounded v1.9 observation statement: %v", err)
	}
	if err := tx.Commit(); err != nil {
		_ = db.Close()
		t.Fatalf("commit bounded v1.9 observation fixture: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close bounded v1.9 observation fixture: %v", err)
	}
	return base, total
}

func requireDynamicObservationRows(t *testing.T, db *DB, siteID int64, expected map[string]DynamicObservation) {
	t.Helper()
	observations, err := db.ListDynamicObservations(siteID)
	if err != nil {
		t.Fatalf("list dynamic observation rows: %v", err)
	}
	if len(observations) != len(expected) {
		t.Fatalf("dynamic observation rows=%d, want %d: %#v", len(observations), len(expected), observations)
	}
	seen := make(map[string]bool, len(observations))
	for _, observation := range observations {
		want, ok := expected[observation.CanonicalAuthority]
		if !ok || observation != want {
			t.Fatalf("dynamic observation row=%#v, want=%#v present=%t", observation, want, ok)
		}
		if seen[observation.CanonicalAuthority] {
			t.Fatalf("duplicate dynamic observation authority %q", observation.CanonicalAuthority)
		}
		seen[observation.CanonicalAuthority] = true
	}
}

func requirePrunedV19DynamicObservationRows(t *testing.T, db *DB, base int64, total int) {
	t.Helper()
	observations, err := db.ListDynamicObservations(1)
	if err != nil {
		t.Fatalf("list bounded v1.9 observations: %v", err)
	}
	if len(observations) != dynamicObservationPerSiteRowLimit {
		t.Fatalf("bounded v1.9 observations=%d, want %d", len(observations), dynamicObservationPerSiteRowLimit)
	}
	for position, observation := range observations {
		index := total - 1 - position
		seen := base + int64(index)
		want := migratedDynamicObservation(DynamicObservation{
			SiteID:             1,
			CanonicalAuthority: fmt.Sprintf("https://v19-limit-%05d.example.com:443", index),
			Source:             dynamicObservationSourcePlaybackInfo,
			Decision:           dynamicObservationDecisionAllowed,
			ReasonCode:         dynamicObservationReasonCandidateAllowed,
			FirstSeenMS:        seen,
			LastSeenMS:         seen,
			Count:              1,
		})
		if observation != want {
			t.Fatalf("bounded v1.9 observation[%d]=%#v, want=%#v", position, observation, want)
		}
	}
}

func createMalformedDynamicObservationFixture(t *testing.T, path, variant string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open malformed observation fixture: %v", err)
	}
	var schema string
	switch variant {
	case "extra privacy-bearing column":
		schema = strings.Replace(dynamicObservationTableDDL, "\tcount INTEGER NOT NULL CHECK(count > 0),", "\tcount INTEGER NOT NULL CHECK(count > 0),\n\tleaked_url TEXT NOT NULL,", 1) + dynamicObservationIndexesDDL
	case "wrong core index":
		schema = dynamicObservationTableDDL + `
			CREATE INDEX idx_dynamic_observations_site_last_seen
				ON dynamic_observations(canonical_authority, last_seen_ms DESC);
			CREATE INDEX idx_dynamic_observations_last_seen
				ON dynamic_observations(last_seen_ms);`
	case "recognized v1.9 with extra column":
		schema = strings.Replace(dynamicObservationV19TableDDL, "\tcount INTEGER NOT NULL CHECK(count > 0),", "\tcount INTEGER NOT NULL CHECK(count > 0),\n\tleaked_url TEXT NOT NULL,", 1) + dynamicObservationIndexesDDL
	case "recognized previous route schema with extra column":
		schema = strings.Replace(dynamicObservationPreviousTableDDL, "\tcount INTEGER NOT NULL CHECK(count > 0),", "\tcount INTEGER NOT NULL CHECK(count > 0),\n\tleaked_url TEXT NOT NULL,", 1) + dynamicObservationIndexesDDL
	default:
		t.Fatalf("unknown malformed schema variant %q", variant)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		t.Fatalf("create malformed observation schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close malformed observation fixture: %v", err)
	}
}

func TestDynamicObservationMigrationEmptyAndV17IsIdempotent(t *testing.T) {
	t.Run("empty database", func(t *testing.T) {
		db, _ := openDynamicObservationTestDB(t)
		if err := db.migrate(); err != nil {
			t.Fatalf("repeat empty migration: %v", err)
		}
		site := createDynamicObservationTestSite(t, db, "empty-migration")
		db.EnqueueDynamicObservation(allowedDynamicObservationTestEvent(site.ID, "https://empty.example.com:443"))
		observations, err := db.ListDynamicObservations(site.ID)
		if err != nil {
			t.Fatalf("list after empty migration: %v", err)
		}
		if len(observations) != 1 || observations[0].Count != 1 {
			t.Fatalf("observations after empty migration=%#v", observations)
		}
		if err := db.migrate(); err != nil {
			t.Fatalf("repeat populated migration: %v", err)
		}
		observations, err = db.ListDynamicObservations(site.ID)
		if err != nil || len(observations) != 1 || observations[0].Count != 1 {
			t.Fatalf("idempotent migration observations=%#v err=%v", observations, err)
		}
	})

	t.Run("v1.7 database", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "v1.7.db")
		createV17ObservationFixture(t, path)
		db, err := openDB(path)
		if err != nil {
			t.Fatalf("migrate v1.7 database: %v", err)
		}
		t.Cleanup(db.Close)

		site, err := db.GetSite(1)
		if err != nil {
			t.Fatalf("read migrated v1.7 site: %v", err)
		}
		if site.Name != "v1.7-site" || site.DynamicDiscoveryEnabled || site.DynamicProfile != dynamicProfileSafe || site.DynamicAllowHTTPSDowngrade || site.DynamicPolicyRevision != 1 || len(site.DynamicDomainRules) != 0 {
			t.Fatalf("migrated v1.7 site=%#v", site)
		}
		var trafficRows, bytes int64
		if err := db.db.QueryRow("SELECT COUNT(*), COALESCE(SUM(bytes_in+bytes_out), 0) FROM traffic_logs WHERE site_id=1").Scan(&trafficRows, &bytes); err != nil {
			t.Fatalf("read preserved v1.7 traffic: %v", err)
		}
		if trafficRows != 1 || bytes != 24 {
			t.Fatalf("preserved v1.7 traffic rows=%d bytes=%d", trafficRows, bytes)
		}

		db.EnqueueDynamicObservation(allowedDynamicObservationTestEvent(site.ID, "https://migrated.example.com:443"))
		observations, err := db.ListDynamicObservations(site.ID)
		if err != nil || len(observations) != 1 {
			t.Fatalf("v1.7 observation write=%#v err=%v", observations, err)
		}
		for attempt := 0; attempt < 2; attempt++ {
			if err := db.migrate(); err != nil {
				t.Fatalf("idempotent v1.7 migration %d: %v", attempt+1, err)
			}
		}
		observations, err = db.ListDynamicObservations(site.ID)
		if err != nil || len(observations) != 1 || observations[0].Count != 1 {
			t.Fatalf("v1.7 data after repeat migration=%#v err=%v", observations, err)
		}
	})

	t.Run("previous v1.9 observation schema", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "previous-v1.9-observations.db")
		expected := createPreviousV19DynamicObservationFixture(t, path)
		migrated, err := openDB(path)
		if err != nil {
			t.Fatalf("migrate previous v1.9 observations: %v", err)
		}
		t.Cleanup(migrated.Close)
		requireDynamicObservationRows(t, migrated, 1, expected)
		if err := migrated.migrate(); err != nil {
			t.Fatalf("repeat v1.9 observation migration: %v", err)
		}
		requireDynamicObservationRows(t, migrated, 1, expected)
	})

	t.Run("previous v1.9 observation limit is immediate and idempotent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bounded-v1.9-observations.db")
		base, total := createPreviousV19DynamicObservationLimitFixture(t, path)
		migrated, err := openDB(path)
		if err != nil {
			t.Fatalf("migrate bounded v1.9 observations: %v", err)
		}
		t.Cleanup(migrated.Close)
		requirePrunedV19DynamicObservationRows(t, migrated, base, total)
		if err := migrated.migrate(); err != nil {
			t.Fatalf("repeat bounded v1.9 observation migration: %v", err)
		}
		requirePrunedV19DynamicObservationRows(t, migrated, base, total)
		migrated.Close()

		reopened, err := openDB(path)
		if err != nil {
			t.Fatalf("reopen bounded v1.9 observations: %v", err)
		}
		t.Cleanup(reopened.Close)
		requirePrunedV19DynamicObservationRows(t, reopened, base, total)
	})

	t.Run("previous v1.8 observation constraints", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "previous-v1.8-observations.db")
		expected := createPreviousV18DynamicObservationFixture(t, path)

		migrated, err := openDB(path)
		if err != nil {
			t.Fatalf("migrate previous v1.8 observation constraints: %v", err)
		}
		t.Cleanup(migrated.Close)
		requireDynamicObservationRows(t, migrated, 1, expected)
		migrated.Close()

		reopened, err := openDB(path)
		if err != nil {
			t.Fatalf("reopen migrated v1.8 observation database: %v", err)
		}
		t.Cleanup(reopened.Close)
		requireDynamicObservationRows(t, reopened, 1, expected)

		newAuthorities := make([]string, len(extremeDynamicObservationReasonCases))
		for index, reasonCase := range extremeDynamicObservationReasonCases {
			authority := fmt.Sprintf("https://extreme-reason-%02d.example.com:443", index)
			newAuthorities[index] = authority
			reopened.EnqueueDynamicObservation(dynamicObservationEvent{
				SiteID:             1,
				CanonicalAuthority: authority,
				Source:             reasonCase.source,
				TargetKind:         dynamicObservationTargetDiscovered,
				Decision:           dynamicObservationDecisionDenied,
				ReasonCode:         reasonCase.reason,
				RedirectStatus:     0,
			})
		}
		observations, err := reopened.ListDynamicObservations(1)
		if err != nil {
			t.Fatalf("list migrated v1.8 observations after new reason writes: %v", err)
		}
		if len(observations) != len(expected)+len(extremeDynamicObservationReasonCases) {
			t.Fatalf("migrated v1.8 observations=%d, want %d: %#v", len(observations), len(expected)+len(extremeDynamicObservationReasonCases), observations)
		}
		stored := make(map[string]DynamicObservation, len(observations))
		for _, observation := range observations {
			if _, exists := stored[observation.CanonicalAuthority]; exists {
				t.Fatalf("duplicate migrated observation authority %q", observation.CanonicalAuthority)
			}
			stored[observation.CanonicalAuthority] = observation
		}
		for authority, want := range expected {
			if got, ok := stored[authority]; !ok || got != want {
				t.Fatalf("preserved migrated observation %q=%#v, want=%#v present=%t", authority, got, want, ok)
			}
		}
		for index, reasonCase := range extremeDynamicObservationReasonCases {
			authority := newAuthorities[index]
			observation, ok := stored[authority]
			if !ok || observation.SiteID != 1 || observation.Source != reasonCase.source || observation.Decision != dynamicObservationDecisionDenied || observation.ReasonCode != reasonCase.reason || observation.Count != 1 || observation.FirstSeenMS < 0 || observation.LastSeenMS < observation.FirstSeenMS {
				t.Fatalf("new migrated reason %q observation=%#v present=%t", reasonCase.reason, observation, ok)
			}
			expected[authority] = observation
		}
		if dropped := reopened.DroppedDynamicObservations(); dropped != 0 {
			t.Fatalf("migrated v1.8 reason writes dropped=%d", dropped)
		}
		reopened.Close()

		stable, err := openDB(path)
		if err != nil {
			t.Fatalf("second reopen of migrated v1.8 observation database: %v", err)
		}
		t.Cleanup(stable.Close)
		requireDynamicObservationRows(t, stable, 1, expected)
	})

	t.Run("v1.7 redirect-only observation constraints", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "legacy-observations.db")
		createLegacyDynamicObservationFixture(t, path)
		db, err := openDB(path)
		if err != nil {
			t.Fatalf("migrate legacy observation constraints: %v", err)
		}
		t.Cleanup(db.Close)

		for index, source := range []string{dynamicObservationSourcePlaybackInfo, dynamicObservationSourceHLS, dynamicObservationSourceDASH} {
			db.EnqueueDynamicObservation(dynamicObservationEvent{
				SiteID:             1,
				CanonicalAuthority: fmt.Sprintf("https://structured-%d.example.com:443", index),
				Source:             source,
				TargetKind:         dynamicObservationTargetDiscovered,
				Decision:           dynamicObservationDecisionAllowed,
				ReasonCode:         dynamicObservationReasonCandidateAllowed,
				RedirectStatus:     0,
			})
		}
		observations, err := db.ListDynamicObservations(1)
		if err != nil || len(observations) != 4 {
			t.Fatalf("migrated structured observations=%#v err=%v", observations, err)
		}
		if err := db.migrate(); err != nil {
			t.Fatalf("repeat observation constraint migration: %v", err)
		}
	})
}

func TestDynamicObservationMigrationRejectsMalformedCoreSchema(t *testing.T) {
	for _, variant := range []string{"extra privacy-bearing column", "wrong core index", "recognized v1.9 with extra column", "recognized previous route schema with extra column"} {
		t.Run(variant, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "malformed.db")
			createMalformedDynamicObservationFixture(t, path, variant)
			db, err := openDB(path)
			if err == nil {
				db.Close()
				t.Fatal("startup accepted malformed dynamic observation schema")
			}
		})
	}
}

func TestDynamicCapabilityIssuerObservationTargetKindsUseCanonicalAuthority(t *testing.T) {
	db, _ := openDynamicObservationTestDB(t)
	site := createDynamicObservationTestSite(t, db, "structured-target-kinds")
	issuer := &dynamicCapabilityIssuer{
		siteID:           site.ID,
		database:         db,
		primaryAuthority: "https://primary.example.com",
		configuredAuthorities: map[string]bool{
			"https://primary.example.com":         true,
			"https://configured.example.com:8443": true,
		},
	}
	cases := []struct {
		authority  string
		source     string
		targetKind string
	}{
		{authority: "https://primary.example.com:443", source: dynamicObservationSourcePlaybackInfo, targetKind: dynamicObservationTargetSameAuthority},
		{authority: "https://configured.example.com:8443", source: dynamicObservationSourceHLS, targetKind: dynamicObservationTargetConfigured},
		{authority: "https://dynamic.example.com:443", source: dynamicObservationSourceDASH, targetKind: dynamicObservationTargetDiscovered},
	}
	expected := make(map[string]struct {
		source     string
		targetKind string
	}, len(cases))
	for _, observationCase := range cases {
		issuer.observe(observationCase.source, dynamicObservationDecisionAllowed, dynamicObservationReasonCandidateAllowed, observationCase.authority)
		expected[observationCase.authority] = struct {
			source     string
			targetKind string
		}{source: observationCase.source, targetKind: observationCase.targetKind}
	}
	observations, err := db.ListDynamicObservations(site.ID)
	if err != nil {
		t.Fatalf("list structured target-kind observations: %v", err)
	}
	if len(observations) != len(cases) {
		t.Fatalf("structured target-kind observations=%d, want %d: %#v", len(observations), len(cases), observations)
	}
	for _, observation := range observations {
		want, ok := expected[observation.CanonicalAuthority]
		if !ok || observation.Source != want.source || observation.TargetKind != want.targetKind || observation.RedirectStatus != 0 {
			t.Fatalf("structured target-kind observation=%#v, want=%#v present=%t", observation, want, ok)
		}
	}
}

func TestDynamicObservationStageMappingIsExhaustive(t *testing.T) {
	expected := map[string]string{
		dynamicObservationReasonRedirectAllowed:          dynamicObservationStageResponse,
		dynamicObservationReasonUnsupportedStatus:        dynamicObservationStageResponse,
		dynamicObservationReasonResponseFailure:          dynamicObservationStageResponse,
		dynamicObservationReasonInvalidLocation:          dynamicObservationStageLocation,
		dynamicObservationReasonRedirectLoop:             dynamicObservationStageLocation,
		dynamicObservationReasonHopLimit:                 dynamicObservationStageLocation,
		dynamicObservationReasonCandidateAllowed:         dynamicObservationStagePolicy,
		dynamicObservationReasonSchemeDenied:             dynamicObservationStagePolicy,
		dynamicObservationReasonPortDenied:               dynamicObservationStagePolicy,
		dynamicObservationReasonDomainDenied:             dynamicObservationStagePolicy,
		dynamicObservationReasonHTTPSDowngradeDenied:     dynamicObservationStagePolicy,
		dynamicObservationReasonSelfTarget:               dynamicObservationStagePolicy,
		dynamicObservationReasonPlaybackInfoDenied:       dynamicObservationStagePolicy,
		dynamicObservationReasonHLSFeatureDenied:         dynamicObservationStagePolicy,
		dynamicObservationReasonDASHFeatureDenied:        dynamicObservationStagePolicy,
		dynamicObservationReasonDNSFailure:               dynamicObservationStageResolve,
		dynamicObservationReasonAddressDenied:            dynamicObservationStageResolve,
		dynamicObservationReasonDialFailure:              dynamicObservationStageConnect,
		dynamicObservationReasonTLSFailure:               dynamicObservationStageConnect,
		dynamicObservationReasonCapacityLimit:            dynamicObservationStageCapacity,
		dynamicObservationReasonRateLimit:                dynamicObservationStageCapacity,
		dynamicObservationReasonParseFailure:             dynamicObservationStageParse,
		dynamicObservationReasonRequestUnclassified:      dynamicObservationStageParse,
		dynamicObservationReasonStructuredBodyLimit:      dynamicObservationStageParse,
		dynamicObservationReasonRedirectBodyReplayDenied: dynamicObservationStageParse,
		dynamicObservationReasonCapabilityInvalid:        dynamicObservationStageCapability,
		dynamicObservationReasonCapabilityExpired:        dynamicObservationStageCapability,
		dynamicObservationReasonRuntimeUnavailable:       dynamicObservationStageRuntime,
	}
	for reasonCode, wantStage := range expected {
		if gotStage, ok := dynamicObservationStageForReason(reasonCode); !ok || gotStage != wantStage {
			t.Fatalf("stage for %q=%q/%t, want %q/true", reasonCode, gotStage, ok, wantStage)
		}
	}
	if stage, ok := dynamicObservationStageForReason("free_text_stage_secret"); ok || stage != "" {
		t.Fatalf("arbitrary reason derived stage=%q/%t", stage, ok)
	}
}

func TestDynamicObservationEventsAreFiniteAndPrivacySafe(t *testing.T) {
	db, _ := openDynamicObservationTestDB(t)
	site := createDynamicObservationTestSite(t, db, "event-validation")

	deniedReasons := []string{
		dynamicObservationReasonInvalidLocation,
		dynamicObservationReasonUnsupportedStatus,
		dynamicObservationReasonRedirectLoop,
		dynamicObservationReasonHopLimit,
		dynamicObservationReasonSchemeDenied,
		dynamicObservationReasonPortDenied,
		dynamicObservationReasonDomainDenied,
		dynamicObservationReasonHTTPSDowngradeDenied,
		dynamicObservationReasonSelfTarget,
		dynamicObservationReasonDNSFailure,
		dynamicObservationReasonAddressDenied,
		dynamicObservationReasonDialFailure,
		dynamicObservationReasonTLSFailure,
		dynamicObservationReasonCapacityLimit,
		dynamicObservationReasonRateLimit,
		dynamicObservationReasonParseFailure,
		dynamicObservationReasonCapabilityInvalid,
		dynamicObservationReasonCapabilityExpired,
		dynamicObservationReasonResponseFailure,
		dynamicObservationReasonRuntimeUnavailable,
	}
	valid := []dynamicObservationEvent{allowedDynamicObservationTestEvent(site.ID, "https://allowed.example.com:443")}
	for i, reason := range deniedReasons {
		valid = append(valid, dynamicObservationEvent{
			SiteID:             site.ID,
			CanonicalAuthority: fmt.Sprintf("https://denied-%02d.example.com:443", i),
			Source:             dynamicObservationSourceRedirect,
			TargetKind:         dynamicObservationTargetDiscovered,
			Decision:           dynamicObservationDecisionDenied,
			ReasonCode:         reason,
			RedirectStatus:     0,
		})
	}
	structuredTargetKinds := []string{dynamicObservationTargetSameAuthority, dynamicObservationTargetConfigured, dynamicObservationTargetDiscovered}
	for index, source := range []string{dynamicObservationSourcePlaybackInfo, dynamicObservationSourceHLS, dynamicObservationSourceDASH} {
		valid = append(valid,
			dynamicObservationEvent{
				SiteID:             site.ID,
				CanonicalAuthority: fmt.Sprintf("https://allowed-structured-%d.example.com:443", index),
				Source:             source,
				TargetKind:         structuredTargetKinds[index],
				Decision:           dynamicObservationDecisionAllowed,
				ReasonCode:         dynamicObservationReasonCandidateAllowed,
				RedirectStatus:     0,
			},
			dynamicObservationEvent{
				SiteID:             site.ID,
				CanonicalAuthority: fmt.Sprintf("https://denied-structured-%d.example.com:443", index),
				Source:             source,
				TargetKind:         structuredTargetKinds[index],
				Decision:           dynamicObservationDecisionDenied,
				ReasonCode:         dynamicObservationReasonParseFailure,
				RedirectStatus:     0,
			},
		)
	}
	for index, reasonCase := range extremeDynamicObservationReasonCases {
		valid = append(valid, dynamicObservationEvent{
			SiteID:             site.ID,
			CanonicalAuthority: fmt.Sprintf("https://extreme-denied-%02d.example.com:443", index),
			Source:             reasonCase.source,
			TargetKind:         dynamicObservationTargetDiscovered,
			Decision:           dynamicObservationDecisionDenied,
			ReasonCode:         reasonCase.reason,
			RedirectStatus:     0,
		})
	}
	for _, event := range valid {
		db.EnqueueDynamicObservation(event)
	}

	invalid := []dynamicObservationEvent{
		{SiteID: 0, CanonicalAuthority: "https://cdn.example.com:443", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed},
		{SiteID: site.ID, CanonicalAuthority: "https://cdn.example.com:443/private-path-secret", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed},
		{SiteID: site.ID, CanonicalAuthority: "https://cdn.example.com:443?token=query-token-secret", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed},
		{SiteID: site.ID, CanonicalAuthority: "https://user:password-secret@cdn.example.com:443", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed},
		{SiteID: site.ID, CanonicalAuthority: "https://CDN.example.com:443", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed},
		{SiteID: site.ID, CanonicalAuthority: "https://cdn.example.com", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed},
		{SiteID: site.ID, CanonicalAuthority: "https://cdn.example.com:0443", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed},
		{SiteID: site.ID, CanonicalAuthority: " https://cdn.example.com:443", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed},
		{SiteID: site.ID, CanonicalAuthority: "https://cdn.example.com:443", Source: "playback", TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed},
		{SiteID: site.ID, CanonicalAuthority: "https://cdn.example.com:443", Source: dynamicObservationSourceRedirect, TargetKind: "manual_secret", Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed},
		{SiteID: site.ID, CanonicalAuthority: "https://cdn.example.com:443", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: "observed", ReasonCode: dynamicObservationReasonRedirectAllowed},
		{SiteID: site.ID, CanonicalAuthority: "https://cdn.example.com:443", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonDNSFailure},
		{SiteID: site.ID, CanonicalAuthority: "https://cdn.example.com:443", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionDenied, ReasonCode: dynamicObservationReasonRedirectAllowed},
		{SiteID: site.ID, CanonicalAuthority: "https://cdn.example.com:443", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionDenied, ReasonCode: "request_body_secret"},
		{SiteID: site.ID, CanonicalAuthority: "https://" + strings.Repeat("a", dynamicObservationMaxAuthorityBytes) + ":443", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed},
		{SiteID: site.ID, CanonicalAuthority: "https://cdn.example.com:443", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed, RedirectStatus: 299},
		{SiteID: site.ID, CanonicalAuthority: "https://cdn.example.com:443", Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed, RedirectStatus: 400},
		{SiteID: site.ID, CanonicalAuthority: "https://cdn.example.com:443", Source: dynamicObservationSourceHLS, TargetKind: dynamicObservationTargetConfigured, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonCandidateAllowed, RedirectStatus: 302},
	}
	for _, event := range invalid {
		db.EnqueueDynamicObservation(event)
	}

	observations, err := db.ListDynamicObservations(site.ID)
	if err != nil {
		t.Fatalf("list validated events: %v", err)
	}
	if len(observations) != len(valid) {
		t.Fatalf("stored observations=%d, want %d: %#v", len(observations), len(valid), observations)
	}
	if got := db.DroppedDynamicObservations(); got != uint64(len(invalid)) {
		t.Fatalf("dropped observations=%d, want %d", got, len(invalid))
	}

	expected := make(map[string]bool, len(valid))
	for _, event := range valid {
		stage, _ := dynamicObservationStageForReason(event.ReasonCode)
		expected[event.Source+"\x00"+event.TargetKind+"\x00"+stage+"\x00"+event.Decision+"\x00"+event.ReasonCode+"\x00"+fmt.Sprint(event.RedirectStatus)] = true
	}
	for _, observation := range observations {
		key := observation.Source + "\x00" + observation.TargetKind + "\x00" + observation.Stage + "\x00" + observation.Decision + "\x00" + observation.ReasonCode + "\x00" + fmt.Sprint(observation.RedirectStatus)
		if observation.SiteID != site.ID || !expected[key] || observation.Count != 1 {
			t.Fatalf("unexpected stored observation=%#v", observation)
		}
		delete(expected, key)
	}
	if len(expected) != 0 {
		t.Fatalf("missing finite observation tuples=%v", expected)
	}
	now := time.Now().UnixMilli()
	if _, err := db.db.Exec(dynamicObservationTestInsertSQL, site.ID, "https://stage-reject.example.com:443", dynamicObservationSourceRedirect, dynamicObservationTargetDiscovered, "free_text_stage_secret", dynamicObservationDecisionAllowed, dynamicObservationReasonRedirectAllowed, 302, now, now, 1); err == nil {
		t.Fatal("schema accepted arbitrary observation stage")
	}
	if _, err := db.db.Exec(dynamicObservationTestInsertSQL, site.ID, "https://status-reject.example.com:443", dynamicObservationSourceRedirect, dynamicObservationTargetDiscovered, dynamicObservationStageResponse, dynamicObservationDecisionAllowed, dynamicObservationReasonRedirectAllowed, 418, now, now, 1); err == nil {
		t.Fatal("schema accepted a non-3xx redirect status")
	}
	if _, err := db.db.Exec(dynamicObservationTestInsertSQL, site.ID, "https://structured-status-reject.example.com:443", dynamicObservationSourceHLS, dynamicObservationTargetConfigured, dynamicObservationStagePolicy, dynamicObservationDecisionAllowed, dynamicObservationReasonCandidateAllowed, 302, now, now, 1); err == nil {
		t.Fatal("schema accepted redirect status for a non-redirect source")
	}
	var leaked int
	if err := db.db.QueryRow(`
		SELECT COUNT(*) FROM dynamic_observations
		WHERE instr(canonical_authority, 'secret') > 0
		   OR instr(target_kind, 'secret') > 0
		   OR instr(stage, 'secret') > 0
		   OR instr(reason_code, 'secret') > 0`).Scan(&leaked); err != nil {
		t.Fatalf("inspect privacy-safe rows: %v", err)
	}
	if leaked != 0 {
		t.Fatalf("persisted %d privacy-bearing observation rows", leaked)
	}
}

func TestDynamicObservationQueueOverflowIsNonblockingAndCounted(t *testing.T) {
	db := &DB{dynamicObservationQueue: make(chan dynamicObservationCommand, 1)}
	event := allowedDynamicObservationTestEvent(1, "https://overflow.example.com:443")
	db.EnqueueDynamicObservation(event)
	if got := len(db.dynamicObservationQueue); got != 1 {
		t.Fatalf("primed queue length=%d, want 1", got)
	}

	returned := make(chan struct{})
	go func() {
		db.EnqueueDynamicObservation(event)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("full observation queue blocked the caller")
	}
	if got := db.DroppedDynamicObservations(); got != 1 {
		t.Fatalf("overflow drop count=%d, want 1", got)
	}
	if got := len(db.dynamicObservationQueue); got != 1 {
		t.Fatalf("overflow changed queue length to %d", got)
	}
}

func TestDynamicObservationWriterAggregatesBatches(t *testing.T) {
	db, _ := openDynamicObservationTestDB(t)
	site := createDynamicObservationTestSite(t, db, "batch-aggregation")
	for _, statement := range []string{
		`CREATE TABLE dynamic_observation_write_audit (writes INTEGER NOT NULL)`,
		`INSERT INTO dynamic_observation_write_audit (writes) VALUES (0)`,
		`CREATE TEMP TRIGGER audit_dynamic_observation_insert AFTER INSERT ON dynamic_observations BEGIN UPDATE dynamic_observation_write_audit SET writes=writes+1; END`,
		`CREATE TEMP TRIGGER audit_dynamic_observation_update AFTER UPDATE ON dynamic_observations BEGIN UPDATE dynamic_observation_write_audit SET writes=writes+1; END`,
	} {
		if _, err := db.db.Exec(statement); err != nil {
			t.Fatalf("create observation write audit: %v", err)
		}
	}
	auditWrites := func() int {
		var writes int
		if err := db.db.QueryRow(`SELECT writes FROM dynamic_observation_write_audit`).Scan(&writes); err != nil {
			t.Fatalf("read observation write audit: %v", err)
		}
		return writes
	}
	event := allowedDynamicObservationTestEvent(site.ID, "https://aggregate.example.com:443")
	base := time.Now().UnixMilli()
	batch := make([]queuedDynamicObservation, dynamicObservationBatchSize)
	for i := range batch {
		batch[i] = queuedDynamicObservation{event: event, stage: dynamicObservationStageResponse, observedAtMS: base + int64(i)}
	}
	skipped, err := db.writeDynamicObservationBatch(batch)
	if err != nil || skipped != 0 {
		t.Fatalf("write full observation batch skipped=%d err=%v", skipped, err)
	}
	if writes := auditWrites(); writes != 1 {
		t.Fatalf("full duplicate batch executed %d row writes, want 1", writes)
	}
	second := []queuedDynamicObservation{
		{event: event, stage: dynamicObservationStageResponse, observedAtMS: base - 10},
		{event: event, stage: dynamicObservationStageResponse, observedAtMS: base + 1000},
	}
	skipped, err = db.writeDynamicObservationBatch(second)
	if err != nil || skipped != 0 {
		t.Fatalf("write follow-up observation batch skipped=%d err=%v", skipped, err)
	}
	if writes := auditWrites(); writes != 2 {
		t.Fatalf("follow-up duplicate batch cumulative row writes=%d, want 2", writes)
	}

	observations, err := db.ListDynamicObservations(site.ID)
	if err != nil {
		t.Fatalf("list aggregated observations: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("aggregated rows=%d, want 1: %#v", len(observations), observations)
	}
	observation := observations[0]
	if observation.Count != int64(dynamicObservationBatchSize+len(second)) || observation.FirstSeenMS != base-10 || observation.LastSeenMS != base+1000 {
		t.Fatalf("aggregated observation=%#v", observation)
	}
}

func TestDynamicObservationAggregationSeparatesRouteDimensions(t *testing.T) {
	db, _ := openDynamicObservationTestDB(t)
	site := createDynamicObservationTestSite(t, db, "route-dimension-aggregation")
	authority := "https://dimension.example.com:443"
	events := []dynamicObservationEvent{
		{SiteID: site.ID, CanonicalAuthority: authority, Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed, RedirectStatus: 301},
		{SiteID: site.ID, CanonicalAuthority: authority, Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed, RedirectStatus: 302},
		{SiteID: site.ID, CanonicalAuthority: authority, Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetConfigured, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonRedirectAllowed, RedirectStatus: 301},
		{SiteID: site.ID, CanonicalAuthority: authority, Source: dynamicObservationSourceRedirect, TargetKind: dynamicObservationTargetDiscovered, Decision: dynamicObservationDecisionAllowed, ReasonCode: dynamicObservationReasonCandidateAllowed, RedirectStatus: 0},
	}
	for index, event := range events {
		db.EnqueueDynamicObservation(event)
		if index == 0 {
			db.EnqueueDynamicObservation(event)
		}
	}
	observations, err := db.ListDynamicObservations(site.ID)
	if err != nil {
		t.Fatalf("list route dimension observations: %v", err)
	}
	if len(observations) != len(events) {
		t.Fatalf("route dimension rows=%d, want %d: %#v", len(observations), len(events), observations)
	}
	seen := make(map[string]int64, len(observations))
	for _, observation := range observations {
		key := observation.TargetKind + "\x00" + observation.Stage + "\x00" + fmt.Sprint(observation.RedirectStatus)
		seen[key] = observation.Count
	}
	if seen[dynamicObservationTargetDiscovered+"\x00"+dynamicObservationStageResponse+"\x00301"] != 2 ||
		seen[dynamicObservationTargetDiscovered+"\x00"+dynamicObservationStageResponse+"\x00302"] != 1 ||
		seen[dynamicObservationTargetConfigured+"\x00"+dynamicObservationStageResponse+"\x00301"] != 1 ||
		seen[dynamicObservationTargetDiscovered+"\x00"+dynamicObservationStagePolicy+"\x000"] != 1 {
		t.Fatalf("route dimension aggregates=%v", seen)
	}
}

func TestDynamicObservationPruningRetentionPerSiteAndGlobalLimits(t *testing.T) {
	fixedNow := time.UnixMilli(2_000_000_000_000)

	t.Run("thirty day boundary", func(t *testing.T) {
		db, _ := openDynamicObservationTestDB(t)
		site := createDynamicObservationTestSite(t, db, "retention-pruning")
		cutoff := fixedNow.Add(-dynamicObservationRetention).UnixMilli()
		tx, err := db.db.Begin()
		if err != nil {
			t.Fatalf("begin retention fixture: %v", err)
		}
		for _, row := range []struct {
			authority string
			seen      int64
		}{
			{authority: "https://expired.example.com:443", seen: cutoff - 1},
			{authority: "https://boundary.example.com:443", seen: cutoff},
			{authority: "https://recent.example.com:443", seen: fixedNow.UnixMilli()},
		} {
			if _, err := tx.Exec(dynamicObservationTestInsertSQL, site.ID, row.authority, dynamicObservationSourceRedirect, dynamicObservationTargetDiscovered, dynamicObservationStageResponse, dynamicObservationDecisionAllowed, dynamicObservationReasonRedirectAllowed, 0, row.seen, row.seen, 1); err != nil {
				_ = tx.Rollback()
				t.Fatalf("insert retention fixture: %v", err)
			}
		}
		if err := pruneDynamicObservationRows(context.Background(), tx, fixedNow); err != nil {
			_ = tx.Rollback()
			t.Fatalf("prune retention fixture: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit retention fixture: %v", err)
		}
		var total, expired, boundary int
		if err := db.db.QueryRow(`
			SELECT COUNT(*),
			       SUM(CASE WHEN canonical_authority='https://expired.example.com:443' THEN 1 ELSE 0 END),
			       SUM(CASE WHEN canonical_authority='https://boundary.example.com:443' THEN 1 ELSE 0 END)
			FROM dynamic_observations WHERE site_id=?`, site.ID).Scan(&total, &expired, &boundary); err != nil {
			t.Fatalf("inspect retention result: %v", err)
		}
		if total != 2 || expired != 0 || boundary != 1 {
			t.Fatalf("retention rows total=%d expired=%d boundary=%d", total, expired, boundary)
		}
	})

	t.Run("five hundred newest rows per site", func(t *testing.T) {
		db, _ := openDynamicObservationTestDB(t)
		site := createDynamicObservationTestSite(t, db, "per-site-pruning")
		tx, err := db.db.Begin()
		if err != nil {
			t.Fatalf("begin per-site fixture: %v", err)
		}
		statement, err := tx.Prepare(dynamicObservationTestInsertSQL)
		if err != nil {
			_ = tx.Rollback()
			t.Fatalf("prepare per-site fixture: %v", err)
		}
		base := fixedNow.Add(-time.Hour).UnixMilli()
		for i := range dynamicObservationPerSiteRowLimit + 2 {
			authority := fmt.Sprintf("https://site-row-%05d.example.com:443", i)
			seen := base + int64(i)
			if _, err := statement.Exec(site.ID, authority, dynamicObservationSourceRedirect, dynamicObservationTargetDiscovered, dynamicObservationStageResponse, dynamicObservationDecisionAllowed, dynamicObservationReasonRedirectAllowed, 0, seen, seen, 1); err != nil {
				_ = statement.Close()
				_ = tx.Rollback()
				t.Fatalf("insert per-site fixture %d: %v", i, err)
			}
		}
		_ = statement.Close()
		if err := pruneDynamicObservationRows(context.Background(), tx, fixedNow); err != nil {
			_ = tx.Rollback()
			t.Fatalf("prune per-site fixture: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit per-site fixture: %v", err)
		}
		var total int
		var oldest, newest int64
		if err := db.db.QueryRow("SELECT COUNT(*), MIN(last_seen_ms), MAX(last_seen_ms) FROM dynamic_observations WHERE site_id=?", site.ID).Scan(&total, &oldest, &newest); err != nil {
			t.Fatalf("inspect per-site limit: %v", err)
		}
		if total != dynamicObservationPerSiteRowLimit || oldest != base+2 || newest != base+int64(dynamicObservationPerSiteRowLimit+1) {
			t.Fatalf("per-site limit total=%d oldest=%d newest=%d", total, oldest, newest)
		}
	})

	t.Run("ten thousand newest rows globally", func(t *testing.T) {
		db, _ := openDynamicObservationTestDB(t)
		siteIDs := make([]int64, 21)
		for i := range siteIDs {
			siteIDs[i] = createDynamicObservationTestSite(t, db, fmt.Sprintf("global-pruning-%02d", i)).ID
		}
		tx, err := db.db.Begin()
		if err != nil {
			t.Fatalf("begin global fixture: %v", err)
		}
		statement, err := tx.Prepare(dynamicObservationTestInsertSQL)
		if err != nil {
			_ = tx.Rollback()
			t.Fatalf("prepare global fixture: %v", err)
		}
		base := fixedNow.Add(-time.Hour).UnixMilli()
		for i := range dynamicObservationGlobalRowLimit + 2 {
			authority := fmt.Sprintf("https://global-row-%05d.example.com:443", i)
			seen := base + int64(i)
			if _, err := statement.Exec(siteIDs[i%len(siteIDs)], authority, dynamicObservationSourceRedirect, dynamicObservationTargetDiscovered, dynamicObservationStageResponse, dynamicObservationDecisionAllowed, dynamicObservationReasonRedirectAllowed, 0, seen, seen, 1); err != nil {
				_ = statement.Close()
				_ = tx.Rollback()
				t.Fatalf("insert global fixture %d: %v", i, err)
			}
		}
		_ = statement.Close()
		if err := pruneDynamicObservationRows(context.Background(), tx, fixedNow); err != nil {
			_ = tx.Rollback()
			t.Fatalf("prune global fixture: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit global fixture: %v", err)
		}
		var total int
		var oldest, newest int64
		if err := db.db.QueryRow("SELECT COUNT(*), MIN(last_seen_ms), MAX(last_seen_ms) FROM dynamic_observations").Scan(&total, &oldest, &newest); err != nil {
			t.Fatalf("inspect global limit: %v", err)
		}
		if total != dynamicObservationGlobalRowLimit || oldest != base+2 || newest != base+int64(dynamicObservationGlobalRowLimit+1) {
			t.Fatalf("global limit total=%d oldest=%d newest=%d", total, oldest, newest)
		}
	})
}

func TestDynamicObservationWriterFailureDegradesAndRecovers(t *testing.T) {
	db, _ := openDynamicObservationTestDB(t)
	site := createDynamicObservationTestSite(t, db, "writer-failure")
	if _, err := db.db.Exec(`
		CREATE TRIGGER fail_dynamic_observation_insert
		BEFORE INSERT ON dynamic_observations
		BEGIN
			SELECT RAISE(FAIL, 'forced optional observation failure');
		END`); err != nil {
		t.Fatalf("install writer failure trigger: %v", err)
	}

	event := allowedDynamicObservationTestEvent(site.ID, "https://failure.example.com:443")
	db.EnqueueDynamicObservation(event)
	if err := db.flushDynamicObservations(); err != nil {
		t.Fatalf("writer failure barrier propagated optional failure: %v", err)
	}
	if got := db.DroppedDynamicObservations(); got != 1 {
		t.Fatalf("writer failure drop count=%d, want 1", got)
	}
	var rows int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM dynamic_observations WHERE site_id=?", site.ID).Scan(&rows); err != nil {
		t.Fatalf("inspect failed writer transaction: %v", err)
	}
	if rows != 0 {
		t.Fatalf("failed writer transaction persisted %d rows", rows)
	}

	if _, err := db.db.Exec("DROP TRIGGER fail_dynamic_observation_insert"); err != nil {
		t.Fatalf("remove writer failure trigger: %v", err)
	}
	db.EnqueueDynamicObservation(event)
	observations, err := db.ListDynamicObservations(site.ID)
	if err != nil {
		t.Fatalf("writer did not recover: %v", err)
	}
	if len(observations) != 1 || observations[0].Count != 1 || db.DroppedDynamicObservations() != 1 {
		t.Fatalf("writer recovery observations=%#v dropped=%d", observations, db.DroppedDynamicObservations())
	}
}

func TestDynamicObservationCloseFlushesAcceptedEvents(t *testing.T) {
	db, path := openDynamicObservationTestDB(t)
	site := createDynamicObservationTestSite(t, db, "close-flush")
	event := allowedDynamicObservationTestEvent(site.ID, "https://close.example.com:443")
	accepted := dynamicObservationBatchSize + 7
	for range accepted {
		db.EnqueueDynamicObservation(event)
	}
	db.Close()

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("reopen closed observation database: %v", err)
	}
	defer raw.Close()
	var rows, count int64
	if err := raw.QueryRow("SELECT COUNT(*), COALESCE(SUM(count), 0) FROM dynamic_observations WHERE site_id=?", site.ID).Scan(&rows, &count); err != nil {
		t.Fatalf("read close-flushed observations: %v", err)
	}
	if rows != 1 || count != int64(accepted) {
		t.Fatalf("close-flushed rows=%d count=%d, want 1/%d", rows, count, accepted)
	}
}

func TestDynamicObservationClearIsAnOrderedDeleteBarrier(t *testing.T) {
	db, _ := openDynamicObservationTestDB(t)
	site := createDynamicObservationTestSite(t, db, "clear-barrier")
	event := allowedDynamicObservationTestEvent(site.ID, "https://clear.example.com:443")
	for range dynamicObservationBatchSize*2 + 1 {
		db.EnqueueDynamicObservation(event)
	}
	if err := db.ClearDynamicObservations(site.ID); err != nil {
		t.Fatalf("clear queued observations: %v", err)
	}
	observations, err := db.ListDynamicObservations(site.ID)
	if err != nil {
		t.Fatalf("list after clear barrier: %v", err)
	}
	if len(observations) != 0 {
		t.Fatalf("queued observations crossed clear barrier: %#v", observations)
	}
	if db.DroppedDynamicObservations() != 0 {
		t.Fatalf("clear barrier dropped accepted observations: %d", db.DroppedDynamicObservations())
	}

	db.EnqueueDynamicObservation(event)
	observations, err = db.ListDynamicObservations(site.ID)
	if err != nil || len(observations) != 1 || observations[0].Count != 1 {
		t.Fatalf("post-clear writer observations=%#v err=%v", observations, err)
	}
}

func TestDynamicObservationSiteDeleteCleansChildrenAndDropsOrphans(t *testing.T) {
	db, _ := openDynamicObservationTestDB(t)
	site := createDynamicObservationTestSite(t, db, "site-delete")
	if _, err := db.db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
		t.Fatalf("disable foreign-key cascade for cleanup proof: %v", err)
	}
	now := time.Now().UnixMilli()
	if _, err := db.db.Exec(dynamicObservationTestInsertSQL, site.ID, "https://stored-child.example.com:443", dynamicObservationSourceRedirect, dynamicObservationTargetDiscovered, dynamicObservationStageResponse, dynamicObservationDecisionAllowed, dynamicObservationReasonRedirectAllowed, 0, now, now, 1); err != nil {
		t.Fatalf("insert explicit child fixture: %v", err)
	}
	db.EnqueueDynamicObservation(allowedDynamicObservationTestEvent(site.ID, "https://queued-child.example.com:443"))
	if err := db.DeleteSite(site.ID); err != nil {
		t.Fatalf("delete site with observation children: %v", err)
	}
	if got := db.DroppedDynamicObservations(); got != 0 {
		t.Fatalf("pre-delete queued observation was treated as orphan: dropped=%d", got)
	}
	var sites, children int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM sites WHERE id=?", site.ID).Scan(&sites); err != nil {
		t.Fatalf("inspect deleted site: %v", err)
	}
	if err := db.db.QueryRow("SELECT COUNT(*) FROM dynamic_observations WHERE site_id=?", site.ID).Scan(&children); err != nil {
		t.Fatalf("inspect deleted observation children: %v", err)
	}
	if sites != 0 || children != 0 {
		t.Fatalf("site delete left sites=%d observation_children=%d", sites, children)
	}

	db.EnqueueDynamicObservation(allowedDynamicObservationTestEvent(site.ID, "https://orphan.example.com:443"))
	if err := db.flushDynamicObservations(); err != nil {
		t.Fatalf("flush orphan observation: %v", err)
	}
	if got := db.DroppedDynamicObservations(); got != 1 {
		t.Fatalf("orphan queued event drop count=%d, want 1", got)
	}
	if err := db.db.QueryRow("SELECT COUNT(*) FROM dynamic_observations WHERE site_id=?", site.ID).Scan(&children); err != nil {
		t.Fatalf("inspect orphan observation rows: %v", err)
	}
	if children != 0 {
		t.Fatalf("orphan queued event created %d child rows", children)
	}
}

func TestDynamicObservationAPIAuthAndExactPrivateEnvelope(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.db.CreateInitialUser("observation-admin", "test-password-123456"); err != nil {
		t.Fatalf("create test administrator: %v", err)
	}
	site, err := app.db.CreateSite(
		"observation-api",
		19001,
		"https://origin.example.com/library/site-url-secret?api_key=site-query-secret",
		"",
		"direct",
		"[]",
		"infuse",
		0,
		0,
	)
	if err != nil {
		t.Fatalf("create API observation site: %v", err)
	}
	apiExpected := map[string]DynamicObservation{
		"https://cdn.example.com:443": {
			SiteID:             site.ID,
			CanonicalAuthority: "https://cdn.example.com:443",
			Source:             dynamicObservationSourceRedirect,
			TargetKind:         dynamicObservationTargetDiscovered,
			Stage:              dynamicObservationStageResponse,
			Decision:           dynamicObservationDecisionAllowed,
			ReasonCode:         dynamicObservationReasonRedirectAllowed,
			RedirectStatus:     0,
			Count:              1,
		},
	}
	app.db.EnqueueDynamicObservation(allowedDynamicObservationTestEvent(site.ID, "https://cdn.example.com:443"))
	for index, reasonCase := range extremeDynamicObservationReasonCases {
		authority := fmt.Sprintf("https://api-reason-%02d.example.com:443", index)
		app.db.EnqueueDynamicObservation(dynamicObservationEvent{
			SiteID:             site.ID,
			CanonicalAuthority: authority,
			Source:             reasonCase.source,
			TargetKind:         dynamicObservationTargetDiscovered,
			Decision:           dynamicObservationDecisionDenied,
			ReasonCode:         reasonCase.reason,
			RedirectStatus:     0,
		})
		apiExpected[authority] = DynamicObservation{
			SiteID:             site.ID,
			CanonicalAuthority: authority,
			Source:             reasonCase.source,
			TargetKind:         dynamicObservationTargetDiscovered,
			Stage:              func() string { stage, _ := dynamicObservationStageForReason(reasonCase.reason); return stage }(),
			Decision:           dynamicObservationDecisionDenied,
			ReasonCode:         reasonCase.reason,
			RedirectStatus:     0,
			Count:              1,
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sites/", cors(app.authMiddleware(app.handleSiteByID)))
	endpoint := fmt.Sprintf("http://panel.example.com/api/sites/%d/dynamic-observations", site.ID)
	requireMetadata := func(envelope map[string]json.RawMessage) {
		t.Helper()
		for field, want := range map[string]int{
			"retention_days":     dynamicObservationRetentionDays,
			"per_site_row_limit": dynamicObservationPerSiteRowLimit,
			"global_row_limit":   dynamicObservationGlobalRowLimit,
		} {
			var got int
			if err := json.Unmarshal(envelope[field], &got); err != nil || got != want {
				t.Fatalf("%s=%d err=%v, want %d", field, got, err, want)
			}
		}
	}

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		secret := "unauthenticated-" + strings.ToLower(method) + "-body-secret"
		req := httptest.NewRequest(method, endpoint+"?token=unauthenticated-query-secret", strings.NewReader(secret))
		req.Header.Set("Authorization", "Bearer unauthenticated-header-secret")
		if method == http.MethodDelete {
			req.Header.Set("Origin", "http://panel.example.com")
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s status=%d body=%s", method, rr.Code, rr.Body.String())
		}
		requireExactJSONFields(t, rr.Body.Bytes(), "error")
		requireNoObservationSecrets(t, rr.Body.Bytes(), secret, "unauthenticated-query-secret", "unauthenticated-header-secret", "site-url-secret", "site-query-secret")
	}

	token, err := generateToken(1, "observation-admin")
	if err != nil {
		t.Fatalf("generate observation API session: %v", err)
	}
	csrfRequest := httptest.NewRequest(http.MethodDelete, endpoint+"?token=csrf-query-secret", strings.NewReader("csrf-body-secret"))
	csrfRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	csrfRequest.Header.Set("X-Private", "csrf-header-secret")
	csrfResponse := httptest.NewRecorder()
	mux.ServeHTTP(csrfResponse, csrfRequest)
	if csrfResponse.Code != http.StatusForbidden {
		t.Fatalf("cross-site DELETE status=%d body=%s", csrfResponse.Code, csrfResponse.Body.String())
	}
	requireExactJSONFields(t, csrfResponse.Body.Bytes(), "error")
	requireNoObservationSecrets(t, csrfResponse.Body.Bytes(), token, "csrf-query-secret", "csrf-body-secret", "csrf-header-secret", "site-url-secret", "site-query-secret")

	getRequest := httptest.NewRequest(http.MethodGet, endpoint+"?token=get-query-secret", strings.NewReader("get-body-secret"))
	getRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	getRequest.Header.Set("Authorization", "Bearer get-header-secret")
	getResponse := httptest.NewRecorder()
	mux.ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK {
		t.Fatalf("authenticated GET status=%d body=%s", getResponse.Code, getResponse.Body.String())
	}
	if getResponse.Header().Get("Cache-Control") != "no-store" || getResponse.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("GET headers Cache-Control=%q Content-Type=%q", getResponse.Header().Get("Cache-Control"), getResponse.Header().Get("Content-Type"))
	}
	getEnvelope := requireExactJSONFields(t, getResponse.Body.Bytes(), "observations", "dropped_observations_global", "retention_days", "per_site_row_limit", "global_row_limit")
	requireMetadata(getEnvelope)
	var getDropped uint64
	if err := json.Unmarshal(getEnvelope["dropped_observations_global"], &getDropped); err != nil || getDropped != 0 {
		t.Fatalf("GET dropped_observations_global=%d err=%v", getDropped, err)
	}
	var observationItems []json.RawMessage
	if err := json.Unmarshal(getEnvelope["observations"], &observationItems); err != nil {
		t.Fatalf("decode GET observations: %v", err)
	}
	if len(observationItems) != len(apiExpected) {
		t.Fatalf("GET observations=%s, want %d rows", getEnvelope["observations"], len(apiExpected))
	}
	seenAPIObservations := make(map[string]bool, len(observationItems))
	for _, item := range observationItems {
		requireExactJSONFields(
			t,
			item,
			"site_id",
			"canonical_authority",
			"source",
			"target_kind",
			"stage",
			"decision",
			"reason_code",
			"redirect_status",
			"first_seen_ms",
			"last_seen_ms",
			"count",
		)
		var observation DynamicObservation
		if err := json.Unmarshal(item, &observation); err != nil {
			t.Fatalf("decode GET observation: %v", err)
		}
		want, ok := apiExpected[observation.CanonicalAuthority]
		if !ok || observation.SiteID != want.SiteID || observation.Source != want.Source || observation.TargetKind != want.TargetKind || observation.Stage != want.Stage || observation.Decision != want.Decision || observation.ReasonCode != want.ReasonCode || observation.RedirectStatus != want.RedirectStatus || observation.Count != want.Count || observation.FirstSeenMS < 0 || observation.LastSeenMS < observation.FirstSeenMS {
			t.Fatalf("GET observation=%#v, want=%#v present=%t", observation, want, ok)
		}
		if seenAPIObservations[observation.CanonicalAuthority] {
			t.Fatalf("GET repeated observation authority %q", observation.CanonicalAuthority)
		}
		seenAPIObservations[observation.CanonicalAuthority] = true
	}
	if len(seenAPIObservations) != len(apiExpected) {
		t.Fatalf("GET observation authorities=%v, want=%v", seenAPIObservations, apiExpected)
	}
	requireNoObservationSecrets(t, getResponse.Body.Bytes(), token, "get-query-secret", "get-body-secret", "get-header-secret", "site-url-secret", "site-query-secret")

	deleteRequest := httptest.NewRequest(http.MethodDelete, endpoint+"?token=delete-query-secret", strings.NewReader("delete-body-secret"))
	deleteRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	deleteRequest.Header.Set("Origin", "http://panel.example.com")
	deleteRequest.Header.Set("Authorization", "Bearer delete-header-secret")
	deleteResponse := httptest.NewRecorder()
	mux.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusOK {
		t.Fatalf("authenticated DELETE status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}
	if deleteResponse.Header().Get("Cache-Control") != "no-store" || deleteResponse.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("DELETE headers Cache-Control=%q Content-Type=%q", deleteResponse.Header().Get("Cache-Control"), deleteResponse.Header().Get("Content-Type"))
	}
	deleteEnvelope := requireExactJSONFields(t, deleteResponse.Body.Bytes(), "observations", "dropped_observations_global", "retention_days", "per_site_row_limit", "global_row_limit")
	requireMetadata(deleteEnvelope)
	if strings.TrimSpace(string(deleteEnvelope["observations"])) != "[]" {
		t.Fatalf("DELETE observations=%s, want []", deleteEnvelope["observations"])
	}
	var deleteDropped uint64
	if err := json.Unmarshal(deleteEnvelope["dropped_observations_global"], &deleteDropped); err != nil || deleteDropped != 0 {
		t.Fatalf("DELETE dropped_observations_global=%d err=%v", deleteDropped, err)
	}
	requireNoObservationSecrets(t, deleteResponse.Body.Bytes(), token, "delete-query-secret", "delete-body-secret", "delete-header-secret", "site-url-secret", "site-query-secret")

	verifyRequest := httptest.NewRequest(http.MethodGet, endpoint, nil)
	verifyRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	verifyResponse := httptest.NewRecorder()
	mux.ServeHTTP(verifyResponse, verifyRequest)
	if verifyResponse.Code != http.StatusOK {
		t.Fatalf("GET after DELETE status=%d body=%s", verifyResponse.Code, verifyResponse.Body.String())
	}
	verifyEnvelope := requireExactJSONFields(t, verifyResponse.Body.Bytes(), "observations", "dropped_observations_global", "retention_days", "per_site_row_limit", "global_row_limit")
	requireMetadata(verifyEnvelope)
	if strings.TrimSpace(string(verifyEnvelope["observations"])) != "[]" {
		t.Fatalf("GET after DELETE observations=%s, want []", verifyEnvelope["observations"])
	}
}
