package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

type featureToggleExpectation struct {
	ping     bool
	image    bool
	progress bool
}

func assertFeatureToggleSite(t *testing.T, site *Site, want featureToggleExpectation) {
	t.Helper()
	if site.PingCacheEnabled != want.ping || site.ImageCacheEnabled != want.image || site.ProgressCoalescingEnabled != want.progress {
		t.Fatalf(
			"feature toggles = ping:%v image:%v progress:%v, want ping:%v image:%v progress:%v",
			site.PingCacheEnabled,
			site.ImageCacheEnabled,
			site.ProgressCoalescingEnabled,
			want.ping,
			want.image,
			want.progress,
		)
	}
}

func assertFeatureToggleJSON(t *testing.T, object map[string]json.RawMessage, want featureToggleExpectation) {
	t.Helper()
	for _, field := range []struct {
		name string
		want bool
	}{
		{name: "ping_cache_enabled", want: want.ping},
		{name: "image_cache_enabled", want: want.image},
		{name: "progress_coalescing_enabled", want: want.progress},
	} {
		raw, exists := object[field.name]
		if !exists {
			t.Fatalf("serialized Site omitted %q", field.name)
		}
		var got bool
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("decode %s: %v", field.name, err)
		}
		if got != field.want {
			t.Fatalf("serialized %s=%v, want %v", field.name, got, field.want)
		}
	}
}

func assertFeatureToggleJSONDocument(t *testing.T, raw []byte, want featureToggleExpectation) {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatalf("decode Site JSON: %v", err)
	}
	assertFeatureToggleJSON(t, object, want)
}

func assertFeatureToggleColumns(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, column := range []string{"ping_cache_enabled", "image_cache_enabled", "progress_coalescing_enabled"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('sites') WHERE name=?", column).Scan(&count); err != nil {
			t.Fatalf("inspect %s count: %v", column, err)
		}
		if count != 1 {
			t.Fatalf("column %s count=%d, want 1", column, count)
		}
		var typeName string
		var notNull int
		var defaultValue sql.NullString
		if err := db.QueryRow("SELECT type, `notnull`, dflt_value FROM pragma_table_info('sites') WHERE name=?", column).Scan(&typeName, &notNull, &defaultValue); err != nil {
			t.Fatalf("inspect %s definition: %v", column, err)
		}
		if typeName != "INTEGER" || notNull != 1 || !defaultValue.Valid || defaultValue.String != "0" {
			t.Fatalf("column %s definition = type:%q notnull:%d default:%#v, want INTEGER NOT NULL DEFAULT 0", column, typeName, notNull, defaultValue)
		}
	}
}

func TestFeatureToggleFreshSchemaAndRecordCreation(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "fresh-feature-toggles.db"))
	if err != nil {
		t.Fatalf("open fresh database: %v", err)
	}
	defer db.Close()

	assertFeatureToggleColumns(t, db.db)
	sites, err := db.ListSites()
	if err != nil {
		t.Fatalf("list fresh database: %v", err)
	}
	if len(sites) != 0 {
		t.Fatalf("fresh database sites=%#v, want empty", sites)
	}

	defaults, err := db.CreateSiteRecord(Site{
		Name:         "feature-defaults",
		ListenPort:   19101,
		TargetURL:    "http://127.0.0.1:8096",
		PlaybackMode: "direct",
		UAMode:       "infuse",
	})
	if err != nil {
		t.Fatalf("create default feature site: %v", err)
	}
	assertFeatureToggleSite(t, defaults, featureToggleExpectation{})

	enabled, err := db.CreateSiteRecord(Site{
		Name:                      "feature-explicit",
		ListenPort:                19102,
		TargetURL:                 "http://127.0.0.1:8096",
		PlaybackMode:              "direct",
		UAMode:                    "infuse",
		PingCacheEnabled:          true,
		ImageCacheEnabled:         true,
		ProgressCoalescingEnabled: true,
	})
	if err != nil {
		t.Fatalf("create explicit feature site: %v", err)
	}
	assertFeatureToggleSite(t, enabled, featureToggleExpectation{ping: true, image: true, progress: true})

	var ping, image, progress int
	if err := db.db.QueryRow(
		"SELECT ping_cache_enabled, image_cache_enabled, progress_coalescing_enabled FROM sites WHERE id=?",
		enabled.ID,
	).Scan(&ping, &image, &progress); err != nil {
		t.Fatalf("read explicitly stored feature toggles: %v", err)
	}
	if ping != 1 || image != 1 || progress != 1 {
		t.Fatalf("stored feature toggles = %d,%d,%d, want 1,1,1", ping, image, progress)
	}
}

func createV18FeatureToggleMigrationFixture(t *testing.T, path string) {
	t.Helper()
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open v1.8 database: %v", err)
	}
	if _, err := legacy.Exec(`
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
			site_id INTEGER NOT NULL,
			bytes_in BIGINT DEFAULT 0,
			bytes_out BIGINT DEFAULT 0,
			recorded_at DATETIME NOT NULL
		);
		INSERT INTO sites (name, listen_port, target_url, ua_mode, enabled)
		VALUES ('v1.8-site', 19103, 'http://127.0.0.1:8096', 'infuse', 0);
	`); err != nil {
		legacy.Close()
		t.Fatalf("create v1.8 feature-toggle fixture: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close v1.8 database: %v", err)
	}
}

func TestFeatureToggleMigrationFromV18IsRepeatableAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.8-feature-toggles.db")
	createV18FeatureToggleMigrationFixture(t, path)

	db, err := openDB(path)
	if err != nil {
		t.Fatalf("migrate v1.8 database: %v", err)
	}
	assertFeatureToggleColumns(t, db.db)
	for attempt := range 2 {
		if err := db.migrate(); err != nil {
			db.Close()
			t.Fatalf("repeat migration %d: %v", attempt+1, err)
		}
	}
	migrated, err := db.GetSite(1)
	if err != nil {
		db.Close()
		t.Fatalf("read migrated site: %v", err)
	}
	if migrated.Name != "v1.8-site" || migrated.ListenPort != 19103 {
		db.Close()
		t.Fatalf("migration changed v1.8 site identity: %#v", migrated)
	}
	assertFeatureToggleSite(t, migrated, featureToggleExpectation{})
	db.Close()

	reopened, err := openDB(path)
	if err != nil {
		t.Fatalf("reopen migrated database: %v", err)
	}
	defer reopened.Close()
	if err := reopened.migrate(); err != nil {
		t.Fatalf("migrate after reopen: %v", err)
	}
	assertFeatureToggleColumns(t, reopened.db)
	migrated, err = reopened.GetSite(1)
	if err != nil {
		t.Fatalf("read migrated site after reopen: %v", err)
	}
	assertFeatureToggleSite(t, migrated, featureToggleExpectation{})

	var ping, image, progress int
	if err := reopened.db.QueryRow(
		"SELECT ping_cache_enabled, image_cache_enabled, progress_coalescing_enabled FROM sites WHERE id=1",
	).Scan(&ping, &image, &progress); err != nil {
		t.Fatalf("read migrated feature defaults: %v", err)
	}
	if ping != 0 || image != 0 || progress != 0 {
		t.Fatalf("migrated feature toggles = %d,%d,%d, want 0,0,0", ping, image, progress)
	}
}

func createFeatureToggleAPISite(t *testing.T, app *App, name, publicHost string, explicit *featureToggleExpectation) Site {
	t.Helper()
	payload := map[string]interface{}{
		"name":         name,
		"listen_port":  freePort(t),
		"public_host":  publicHost,
		"ingress_mode": ingressModeHost,
		"target_url":   "http://127.0.0.1:8096",
		"ua_mode":      "infuse",
	}
	want := featureToggleExpectation{}
	if explicit != nil {
		want = *explicit
		payload["ping_cache_enabled"] = explicit.ping
		payload["image_cache_enabled"] = explicit.image
		payload["progress_coalescing_enabled"] = explicit.progress
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal site create: %v", err)
	}
	rr := httptest.NewRecorder()
	app.handleSites(rr, httptest.NewRequest(http.MethodPost, "/api/sites", bytes.NewReader(raw)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create site status=%d body=%s", rr.Code, rr.Body.String())
	}
	assertFeatureToggleJSONDocument(t, rr.Body.Bytes(), want)
	var site Site
	if err := json.Unmarshal(rr.Body.Bytes(), &site); err != nil {
		t.Fatalf("decode created site: %v", err)
	}
	assertFeatureToggleSite(t, &site, want)
	t.Cleanup(func() { _ = app.pm.StopSite(site.ID) })
	return site
}

func putFeatureToggleSite(t *testing.T, app *App, site Site, explicit *featureToggleExpectation) Site {
	t.Helper()
	payload := map[string]interface{}{
		"name":        site.Name,
		"listen_port": site.ListenPort,
		"target_url":  site.TargetURL,
	}
	if explicit != nil {
		payload["ping_cache_enabled"] = explicit.ping
		payload["image_cache_enabled"] = explicit.image
		payload["progress_coalescing_enabled"] = explicit.progress
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal site update: %v", err)
	}
	rr := httptest.NewRecorder()
	app.handleSiteByID(
		rr,
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/sites/%d", site.ID), bytes.NewReader(raw)),
	)
	if rr.Code != http.StatusOK {
		t.Fatalf("update site status=%d body=%s", rr.Code, rr.Body.String())
	}
	want := featureToggleExpectation{
		ping:     site.PingCacheEnabled,
		image:    site.ImageCacheEnabled,
		progress: site.ProgressCoalescingEnabled,
	}
	if explicit != nil {
		want = *explicit
	}
	assertFeatureToggleJSONDocument(t, rr.Body.Bytes(), want)
	var updated Site
	if err := json.Unmarshal(rr.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode updated site: %v", err)
	}
	return updated
}

func TestFeatureToggleSitesAPIInputsPreservationAndSerialization(t *testing.T) {
	app := newTestApp(t)
	defaults := createFeatureToggleAPISite(t, app, "api-feature-defaults", "api-feature-defaults.example.test", nil)
	assertFeatureToggleSite(t, &defaults, featureToggleExpectation{})

	pingOnly := featureToggleExpectation{ping: true}
	explicit := createFeatureToggleAPISite(t, app, "api-feature-explicit", "api-feature-explicit.example.test", &pingOnly)
	originalRevision := explicit.DynamicPolicyRevision

	preserved := putFeatureToggleSite(t, app, explicit, nil)
	assertFeatureToggleSite(t, &preserved, pingOnly)
	assertFeatureToggleJSONDocument(t, mustMarshalFeatureToggleSite(t, preserved), pingOnly)
	if preserved.DynamicPolicyRevision != originalRevision {
		t.Fatalf("toggle omission changed dynamic policy revision from %d to %d", originalRevision, preserved.DynamicPolicyRevision)
	}

	listResponse := httptest.NewRecorder()
	app.handleSites(listResponse, httptest.NewRequest(http.MethodGet, "/api/sites", nil))
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list sites status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	var listed []map[string]json.RawMessage
	if err := json.Unmarshal(listResponse.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode listed sites: %v", err)
	}
	wantByID := map[int64]featureToggleExpectation{
		defaults.ID: {},
		explicit.ID: pingOnly,
	}
	seen := make(map[int64]bool, len(wantByID))
	for _, object := range listed {
		var id int64
		if err := json.Unmarshal(object["id"], &id); err != nil {
			t.Fatalf("decode listed site id: %v", err)
		}
		want, relevant := wantByID[id]
		if !relevant {
			continue
		}
		assertFeatureToggleJSON(t, object, want)
		seen[id] = true
	}
	for id := range wantByID {
		if !seen[id] {
			t.Fatalf("list response omitted site %d", id)
		}
	}

	got, err := app.db.GetSite(explicit.ID)
	if err != nil {
		t.Fatalf("GetSite explicit site: %v", err)
	}
	assertFeatureToggleSite(t, got, pingOnly)
	assertFeatureToggleJSONDocument(t, mustMarshalFeatureToggleSite(t, *got), pingOnly)

	imageOnly := featureToggleExpectation{image: true}
	changed := putFeatureToggleSite(t, app, preserved, &imageOnly)
	assertFeatureToggleSite(t, &changed, imageOnly)
	if changed.DynamicPolicyRevision != originalRevision {
		t.Fatalf("first explicit toggle update changed dynamic policy revision from %d to %d", originalRevision, changed.DynamicPolicyRevision)
	}

	progressOnly := featureToggleExpectation{progress: true}
	changed = putFeatureToggleSite(t, app, changed, &progressOnly)
	assertFeatureToggleSite(t, &changed, progressOnly)
	if changed.DynamicPolicyRevision != originalRevision {
		t.Fatalf("second explicit toggle update changed dynamic policy revision from %d to %d", originalRevision, changed.DynamicPolicyRevision)
	}
	reloaded, err := app.db.GetSite(explicit.ID)
	if err != nil {
		t.Fatalf("reload explicitly changed site: %v", err)
	}
	assertFeatureToggleSite(t, reloaded, progressOnly)
	assertFeatureToggleJSONDocument(t, mustMarshalFeatureToggleSite(t, *reloaded), progressOnly)

	var ping, image, progress int
	if err := app.db.db.QueryRow(
		"SELECT ping_cache_enabled, image_cache_enabled, progress_coalescing_enabled FROM sites WHERE id=?",
		explicit.ID,
	).Scan(&ping, &image, &progress); err != nil {
		t.Fatalf("read explicitly updated toggles: %v", err)
	}
	if ping != 0 || image != 0 || progress != 1 {
		t.Fatalf("explicitly updated toggles = %d,%d,%d, want 0,0,1", ping, image, progress)
	}
}

func mustMarshalFeatureToggleSite(t *testing.T, site Site) []byte {
	t.Helper()
	raw, err := json.Marshal(site)
	if err != nil {
		t.Fatalf("marshal Site: %v", err)
	}
	return raw
}

func TestFeatureToggleFailedDatabaseUpdatePreservesValues(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "failed-feature-update.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	first, err := db.CreateSiteRecord(Site{Name: "first", ListenPort: 19104, TargetURL: "http://127.0.0.1:8096", PlaybackMode: "direct", UAMode: "infuse"})
	if err != nil {
		t.Fatalf("create first site: %v", err)
	}
	second, err := db.CreateSiteRecord(Site{Name: "second", ListenPort: 19105, TargetURL: "http://127.0.0.1:8096", PlaybackMode: "direct", UAMode: "infuse"})
	if err != nil {
		t.Fatalf("create second site: %v", err)
	}

	candidate := *first
	candidate.ListenPort = second.ListenPort
	candidate.PingCacheEnabled = true
	candidate.ImageCacheEnabled = true
	candidate.ProgressCoalescingEnabled = true
	if err := db.UpdateSiteRecord(candidate); err == nil {
		t.Fatal("conflicting update unexpectedly succeeded")
	}
	restored, err := db.GetSite(first.ID)
	if err != nil {
		t.Fatalf("read site after failed update: %v", err)
	}
	assertFeatureToggleSite(t, restored, featureToggleExpectation{})
	if restored.ListenPort != first.ListenPort {
		t.Fatalf("failed update changed listen_port to %d, want %d", restored.ListenPort, first.ListenPort)
	}
}

func TestFeatureToggleStartFailureRollsBackPersistedAndRunningSite(t *testing.T) {
	app := newTestApp(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)

	oldPort := freePort(t)
	site, err := app.db.CreateSiteRecord(Site{
		Name:         "feature-start-rollback",
		ListenPort:   oldPort,
		IngressMode:  ingressModePort,
		TargetURL:    upstream.URL,
		PlaybackMode: "direct",
		UAMode:       "infuse",
	})
	if err != nil {
		t.Fatalf("create rollback site: %v", err)
	}
	releasePort(oldPort)
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("start rollback site: %v", err)
	}
	t.Cleanup(func() { _ = app.pm.StopSite(site.ID) })

	occupied, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("occupy replacement port: %v", err)
	}
	defer occupied.Close()
	occupiedPort := occupied.Addr().(*net.TCPAddr).Port
	payload, err := json.Marshal(map[string]interface{}{
		"name":                        "feature-start-rollback-updated",
		"listen_port":                 occupiedPort,
		"target_url":                  upstream.URL,
		"ping_cache_enabled":          true,
		"image_cache_enabled":         true,
		"progress_coalescing_enabled": true,
	})
	if err != nil {
		t.Fatalf("marshal failing update: %v", err)
	}
	rr := httptest.NewRecorder()
	app.handleSiteByID(
		rr,
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/sites/%d", site.ID), bytes.NewReader(payload)),
	)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("failed replacement status=%d body=%s, want 500", rr.Code, rr.Body.String())
	}

	restored, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite after start rollback: %v", err)
	}
	assertFeatureToggleSite(t, restored, featureToggleExpectation{})
	if restored.Name != site.Name || restored.ListenPort != oldPort || restored.DynamicPolicyRevision != site.DynamicPolicyRevision {
		t.Fatalf("rolled-back Site = name:%q port:%d revision:%d, want name:%q port:%d revision:%d", restored.Name, restored.ListenPort, restored.DynamicPolicyRevision, site.Name, oldPort, site.DynamicPolicyRevision)
	}
	if !app.pm.IsRunning(site.ID) {
		t.Fatal("old site stopped running after replacement start failed")
	}
	app.pm.mu.RLock()
	running := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if running == nil {
		t.Fatal("running site disappeared after replacement start failed")
	}
	assertFeatureToggleSite(t, &running.Site, featureToggleExpectation{})

	var ping, image, progress int
	if err := app.db.db.QueryRow(
		"SELECT ping_cache_enabled, image_cache_enabled, progress_coalescing_enabled FROM sites WHERE id=?",
		site.ID,
	).Scan(&ping, &image, &progress); err != nil {
		t.Fatalf("read rolled-back persisted toggles: %v", err)
	}
	if ping != 0 || image != 0 || progress != 0 {
		t.Fatalf("rolled-back persisted toggles = %d,%d,%d, want 0,0,0", ping, image, progress)
	}
}
