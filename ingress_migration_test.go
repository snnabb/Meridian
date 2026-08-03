package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// Issue #28 briefly introduced public_host before ingress_mode. Preserve that
// pre-release database shape as host-only during migration so an upgrade does
// not silently expose the legacy high-port listener as well.
func TestMigratePublicHostOnlyPrereleaseDatabaseToHostIngress(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "prerelease-public-host.db")
	createLegacySiteDatabase(t, dbPath, false)

	legacy, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec("ALTER TABLE sites ADD COLUMN public_host TEXT NOT NULL DEFAULT ''"); err != nil {
		legacy.Close()
		t.Fatalf("add prerelease public_host: %v", err)
	}
	if _, err := legacy.Exec("UPDATE sites SET public_host='Media.Example.COM' WHERE id=1"); err != nil {
		legacy.Close()
		t.Fatalf("set prerelease public_host: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := openDB(dbPath)
	if err != nil {
		t.Fatalf("migrate prerelease database: %v", err)
	}
	defer db.Close()
	site, err := db.GetSite(1)
	if err != nil {
		t.Fatal(err)
	}
	if site.PublicHost != "media.example.com" || site.IngressMode != ingressModeHost {
		t.Fatalf("migrated ingress=(%q,%q), want normalized host-only", site.PublicHost, site.IngressMode)
	}
}

func TestIngressCapabilitiesReflectHostOnlySafety(t *testing.T) {
	app := newTestApp(t)
	app.panelBindLoopback = false
	app.trustedProxies = nil
	app.pm.SetHostOnlyIngressSafe(false)

	rr := httptest.NewRecorder()
	app.handleIngressCapabilities(rr, httptest.NewRequest(http.MethodGet, "/api/ingress-capabilities", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := decodeBody(t, rr)
	if available, ok := body["host_only_available"].(bool); !ok || available {
		t.Fatalf("host_only_available=%#v, want false", body["host_only_available"])
	}
	if available, ok := body["upstream_headers_available"].(bool); !ok || !available {
		t.Fatalf("upstream_headers_available=%#v, want true with test key", body["upstream_headers_available"])
	}
	if got := int(body["max_playback_addresses"].(float64)); got != maxPlaybackAddresses {
		t.Fatalf("max_playback_addresses=%d, want %d", got, maxPlaybackAddresses)
	}

	app.panelBindLoopback = true
	app.pm.SetHostOnlyIngressSafe(true)
	rr = httptest.NewRecorder()
	app.handleIngressCapabilities(rr, httptest.NewRequest(http.MethodGet, "/api/ingress-capabilities", nil))
	body = decodeBody(t, rr)
	if available, ok := body["host_only_available"].(bool); !ok || !available {
		t.Fatalf("host_only_available=%#v, want true", body["host_only_available"])
	}
}

func TestSitesAPIRoundTripsOneHundredPlaybackAddressesAsArray(t *testing.T) {
	app := newTestApp(t)
	addresses := make([]string, 100)
	longPath := strings.Repeat("segment/", 100)
	for i := range addresses {
		addresses[i] = fmt.Sprintf("https://cdn-%03d.example.test:8443/%s%d", i, longPath, i)
	}
	payload, err := json.Marshal(map[string]interface{}{
		"name":                "one-hundred-playback-addresses",
		"listen_port":         freePort(t),
		"public_host":         "hundred-playback.example.test",
		"ingress_mode":        ingressModeHost,
		"target_url":          "https://origin.example.test",
		"playback_target_url": addresses[0],
		"playback_mode":       "redirect",
		"stream_hosts":        addresses[1:],
		"ua_mode":             "infuse",
	})
	if err != nil {
		t.Fatal(err)
	}
	createResponse := httptest.NewRecorder()
	app.handleSites(createResponse, httptest.NewRequest(http.MethodPost, "/api/sites", bytes.NewReader(payload)))
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", createResponse.Code, createResponse.Body.String())
	}
	var created Site
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created site: %v", err)
	}
	if len(created.StreamHostList) != 99 {
		t.Fatalf("created stream_hosts length=%d, want 99", len(created.StreamHostList))
	}
	if created.StreamHostList[98] != addresses[99] {
		t.Fatalf("created final stream host=%q, want %q", created.StreamHostList[98], addresses[99])
	}
	t.Cleanup(func() { _ = app.pm.StopSite(created.ID) })

	listResponse := httptest.NewRecorder()
	app.handleSites(listResponse, httptest.NewRequest(http.MethodGet, "/api/sites", nil))
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	var listed []Site
	if err := json.Unmarshal(listResponse.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode site list: %v", err)
	}
	if len(listed) != 1 || len(listed[0].StreamHostList) != 99 {
		t.Fatalf("listed sites/stream_hosts=%d/%d, want 1/99", len(listed), len(listed[0].StreamHostList))
	}
}

func TestSitesAPIRejectsMoreThanMaximumPlaybackAddresses(t *testing.T) {
	app := newTestApp(t)
	extra := make([]string, maxPlaybackAddresses)
	for i := range extra {
		extra[i] = fmt.Sprintf("https://overflow-%03d.example.test", i)
	}
	payload, err := json.Marshal(map[string]interface{}{
		"name":                "too-many-playback-addresses",
		"listen_port":         freePort(t),
		"public_host":         "overflow-playback.example.test",
		"ingress_mode":        ingressModeHost,
		"target_url":          "https://origin.example.test",
		"playback_target_url": "https://primary-playback.example.test",
		"playback_mode":       "redirect",
		"stream_hosts":        extra,
		"ua_mode":             "infuse",
	})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	app.handleSites(rr, httptest.NewRequest(http.MethodPost, "/api/sites", bytes.NewReader(payload)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rr.Code, rr.Body.String())
	}
}

func TestResolvePlaybackConfigurationUsesFirstStreamHostAsFallback(t *testing.T) {
	playback, hosts, err := resolvePlaybackConfiguration("", `["https://first.example.test:8443","https://second.example.test"]`)
	if err != nil {
		t.Fatal(err)
	}
	if playback == nil || playback.String() != "https://first.example.test:8443" {
		t.Fatalf("effective playback=%v, want first stream host", playback)
	}
	if len(hosts) != 2 || !hosts[redirectHostKey(playback)] {
		t.Fatalf("allowed playback hosts=%v, want both configured authorities", hosts)
	}
}

func TestDiagnosticsUsesFirstStreamHostWhenDedicatedPlaybackTargetIsEmpty(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()
	playback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer playback.Close()

	rawHosts, err := json.Marshal([]string{playback.URL})
	if err != nil {
		t.Fatal(err)
	}
	result := diagnoseSite(&Site{
		TargetURL:    primary.URL,
		PlaybackMode: "direct",
		StreamHosts:  string(rawHosts),
		UAMode:       "infuse",
	}, NewProxyManager(nil, nil))
	got := result.Upstreams.Playback
	if !got.Configured || got.UsingFallback || got.SameAsPrimary {
		t.Fatalf("playback diagnostics flags configured/fallback/same=%v/%v/%v, want true/false/false", got.Configured, got.UsingFallback, got.SameAsPrimary)
	}
	if got.EffectiveURL != playback.URL {
		t.Fatalf("playback effective URL=%q, want %q", got.EffectiveURL, playback.URL)
	}
}

func TestCreateSiteReportsReservedPortConflictAsBadRequest(t *testing.T) {
	app := newTestApp(t)
	port := freePort(t)
	if _, err := app.db.CreateSiteRecord(Site{
		Name:         "first-host-only",
		ListenPort:   port,
		PublicHost:   "first.example.test",
		IngressMode:  ingressModeHost,
		TargetURL:    "http://127.0.0.1:8096",
		PlaybackMode: "direct",
		StreamHosts:  "[]",
		UAMode:       "infuse",
	}); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]interface{}{
		"name":          "second-host-only",
		"listen_port":   port,
		"public_host":   "second.example.test",
		"ingress_mode":  ingressModeHost,
		"target_url":    "http://127.0.0.1:8096",
		"playback_mode": "direct",
		"ua_mode":       "infuse",
	})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	app.handleSites(rr, httptest.NewRequest(http.MethodPost, "/api/sites", bytes.NewReader(payload)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); body == "" || bytes.Contains([]byte(body), []byte("UNIQUE constraint")) {
		t.Fatalf("unsafe or empty conflict response: %q", body)
	}
}
