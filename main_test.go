package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func newTestApp(t *testing.T) *App {
	t.Helper()

	db, err := openDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	return &App{
		db: db,
		pm: NewProxyManager(db),
	}
}

func freePort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port listen: %v", err)
	}
	defer ln.Close()

	return ln.Addr().(*net.TCPAddr).Port
}

func decodeBody(t *testing.T, rr *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rr.Body.String())
	}
	return body
}

func TestGenerateTokenPreservesSpecialCharacters(t *testing.T) {
	jwtSecret = []byte("test-secret")

	token, err := generateToken(7, `bad"name\user`)
	if err != nil {
		t.Fatalf("generateToken error: %v", err)
	}

	userID, username, err := validateToken(token)
	if err != nil {
		t.Fatalf("validateToken error: %v", err)
	}

	if userID != 7 {
		t.Fatalf("userID = %d, want 7", userID)
	}
	if username != `bad"name\user` {
		t.Fatalf("username = %q", username)
	}
}

func TestResolveJWTSecretGeneratesRandomFallback(t *testing.T) {
	secretA, ephemeralA, err := resolveJWTSecret("")
	if err != nil {
		t.Fatalf("resolveJWTSecret A: %v", err)
	}
	secretB, ephemeralB, err := resolveJWTSecret("")
	if err != nil {
		t.Fatalf("resolveJWTSecret B: %v", err)
	}

	if !ephemeralA || !ephemeralB {
		t.Fatalf("expected ephemeral fallback secrets")
	}
	if len(secretA) == 0 || len(secretB) == 0 {
		t.Fatalf("expected non-empty secrets")
	}
	if bytes.Equal(secretA, secretB) {
		t.Fatalf("expected random fallback secrets to differ")
	}
}

func TestTLSIssuerNameFallsBackSafely(t *testing.T) {
	name := tlsIssuerName(nil)
	if name != "" {
		t.Fatalf("nil issuer name = %q, want empty", name)
	}
}

func TestDiagnoseSiteUsesRootSystemInfoProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/System/Info/Public" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"Version":"4.8.0.80"}`))
	}))
	defer server.Close()

	app := newTestApp(t)
	site, err := app.db.CreateSite("diag", freePort(t), server.URL, "", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	result := diagnoseSite(site, app.pm)
	if result.Health.Status != "online" {
		t.Fatalf("health.status = %q, want online (error=%q)", result.Health.Status, result.Health.Error)
	}
	if result.Health.EmbyVer != "4.8.0.80" {
		t.Fatalf("emby_version = %q, want 4.8.0.80", result.Health.EmbyVer)
	}
	if result.Health.Probe.Kind != "metadata_api" {
		t.Fatalf("probe.kind = %q, want metadata_api", result.Health.Probe.Kind)
	}
	if result.Health.Probe.Method != http.MethodGet {
		t.Fatalf("probe.method = %q, want GET", result.Health.Probe.Method)
	}
	if !strings.HasSuffix(result.Health.Probe.URL, "/System/Info/Public") {
		t.Fatalf("probe.url = %q, want suffix /System/Info/Public", result.Health.Probe.URL)
	}
	if result.Health.Probe.HTTPStatus != http.StatusOK {
		t.Fatalf("probe.http_status = %d, want 200", result.Health.Probe.HTTPStatus)
	}
}

func TestDiagnoseSiteTreatsReachable4xxAsOnline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "blocked", http.StatusForbidden)
	}))
	defer server.Close()

	app := newTestApp(t)
	site, err := app.db.CreateSite("diag", freePort(t), server.URL, "", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	result := diagnoseSite(site, app.pm)
	if result.Health.Status != "online" {
		t.Fatalf("health.status = %q, want online (error=%q)", result.Health.Status, result.Health.Error)
	}
	if result.Health.Error != "" {
		t.Fatalf("health.error = %q, want empty for reachable upstream", result.Health.Error)
	}
	if result.Health.Probe.HTTPStatus != http.StatusForbidden {
		t.Fatalf("probe.http_status = %d, want 403", result.Health.Probe.HTTPStatus)
	}
}

func TestDiagnoseSiteMarksRootReachabilityFallbackProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	app := newTestApp(t)
	site, err := app.db.CreateSite("diag", freePort(t), server.URL, "", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	result := diagnoseSite(site, app.pm)
	if result.Health.Status != "online" {
		t.Fatalf("health.status = %q, want online (error=%q)", result.Health.Status, result.Health.Error)
	}
	if result.Health.Probe.Kind != "reachability_fallback" {
		t.Fatalf("probe.kind = %q, want reachability_fallback", result.Health.Probe.Kind)
	}
	if result.Health.Probe.Method != http.MethodGet {
		t.Fatalf("probe.method = %q, want GET", result.Health.Probe.Method)
	}
	if result.Health.Probe.URL != server.URL+"/" {
		t.Fatalf("probe.url = %q, want %q", result.Health.Probe.URL, server.URL+"/")
	}
	if result.Health.Probe.HTTPStatus != http.StatusOK {
		t.Fatalf("probe.http_status = %d, want 200", result.Health.Probe.HTTPStatus)
	}
}

func TestHandleSiteDiagReturnsPlaybackFallbackMetadata(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/System/Info/Public" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"Version":"4.8.1.0"}`))
	}))
	defer apiServer.Close()

	app := newTestApp(t)
	site, err := app.db.CreateSite("diag", freePort(t), apiServer.URL, "", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/sites/"+jsonNumber64(site.ID)+"/diag", nil)

	app.handleSiteByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	body := decodeBody(t, rr)
	upstreams := mustMapValue(t, body, "upstreams")
	primary := mustMapValue(t, upstreams, "primary")
	playback := mustMapValue(t, upstreams, "playback")

	if got := mustStringValue(t, primary, "effective_url"); got != apiServer.URL {
		t.Fatalf("primary effective_url = %q, want %q", got, apiServer.URL)
	}
	if got := mustBoolValue(t, primary, "show_health"); !got {
		t.Fatalf("primary show_health = %v, want true", got)
	}
	primaryHealth := mustMapValue(t, primary, "health")
	primaryProbe := mustMapValue(t, primaryHealth, "probe")
	if got := mustStringValue(t, primaryProbe, "kind"); got != "metadata_api" {
		t.Fatalf("primary probe.kind = %q, want metadata_api", got)
	}
	if got := mustStringValue(t, primaryProbe, "method"); got != http.MethodGet {
		t.Fatalf("primary probe.method = %q, want GET", got)
	}
	if got := mustStringValue(t, playback, "effective_url"); got != apiServer.URL {
		t.Fatalf("playback effective_url = %q, want %q", got, apiServer.URL)
	}
	if got := mustBoolValue(t, playback, "configured"); got {
		t.Fatalf("playback configured = %v, want false", got)
	}
	if got := mustBoolValue(t, playback, "using_fallback"); !got {
		t.Fatalf("playback using_fallback = %v, want true", got)
	}
	if got := mustBoolValue(t, playback, "same_as_primary"); !got {
		t.Fatalf("playback same_as_primary = %v, want true", got)
	}
	if got := mustBoolValue(t, playback, "show_health"); got {
		t.Fatalf("playback show_health = %v, want false", got)
	}
	if got := mustBoolValue(t, playback, "show_tls"); got {
		t.Fatalf("playback show_tls = %v, want false", got)
	}
	playbackProbe := mustMapValue(t, mustMapValue(t, playback, "health"), "probe")
	if got := mustStringValue(t, playbackProbe, "kind"); got != "metadata_api" {
		t.Fatalf("fallback playback probe.kind = %q, want metadata_api", got)
	}
}

func TestHandleSiteDiagMarksSharedPlaybackTarget(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/System/Info/Public" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"Version":"4.8.1.0"}`))
	}))
	defer apiServer.Close()

	app := newTestApp(t)
	site, err := app.db.CreateSite("diag", freePort(t), apiServer.URL, apiServer.URL, "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/sites/"+jsonNumber64(site.ID)+"/diag", nil)

	app.handleSiteByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	body := decodeBody(t, rr)
	playback := mustMapValue(t, mustMapValue(t, body, "upstreams"), "playback")

	if got := mustBoolValue(t, playback, "configured"); !got {
		t.Fatalf("playback configured = %v, want true", got)
	}
	if got := mustBoolValue(t, playback, "using_fallback"); got {
		t.Fatalf("playback using_fallback = %v, want false", got)
	}
	if got := mustBoolValue(t, playback, "same_as_primary"); !got {
		t.Fatalf("playback same_as_primary = %v, want true", got)
	}
	if got := mustBoolValue(t, playback, "show_health"); got {
		t.Fatalf("playback show_health = %v, want false", got)
	}
	playbackProbe := mustMapValue(t, mustMapValue(t, playback, "health"), "probe")
	if got := mustStringValue(t, playbackProbe, "kind"); got != "metadata_api" {
		t.Fatalf("shared playback probe.kind = %q, want metadata_api", got)
	}
}

func TestHandleSiteDiagExposesSeparatePlaybackTLS(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/System/Info/Public" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"Version":"4.8.1.0"}`))
	}))
	defer apiServer.Close()

	var playbackMethod string
	var playbackPath string
	playbackServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		playbackMethod = r.Method
		playbackPath = r.URL.Path
		if r.Method == http.MethodHead && r.URL.Path == "/Videos" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		http.NotFound(w, r)
	}))
	defer playbackServer.Close()

	app := newTestApp(t)
	site, err := app.db.CreateSite("diag", freePort(t), apiServer.URL, playbackServer.URL, "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/sites/"+jsonNumber64(site.ID)+"/diag", nil)

	app.handleSiteByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	body := decodeBody(t, rr)
	upstreams := mustMapValue(t, body, "upstreams")
	primary := mustMapValue(t, upstreams, "primary")
	playback := mustMapValue(t, upstreams, "playback")
	playbackHealth := mustMapValue(t, playback, "health")
	playbackProbe := mustMapValue(t, playbackHealth, "probe")
	playbackTLS := mustMapValue(t, playback, "tls")

	if got := mustBoolValue(t, primary, "show_tls"); got {
		t.Fatalf("primary show_tls = %v, want false", got)
	}
	if got := mustBoolValue(t, playback, "configured"); !got {
		t.Fatalf("playback configured = %v, want true", got)
	}
	if got := mustBoolValue(t, playback, "same_as_primary"); got {
		t.Fatalf("playback same_as_primary = %v, want false", got)
	}
	if got := mustBoolValue(t, playback, "show_health"); !got {
		t.Fatalf("playback show_health = %v, want true", got)
	}
	if got := mustBoolValue(t, playback, "show_tls"); !got {
		t.Fatalf("playback show_tls = %v, want true", got)
	}
	if got := mustStringValue(t, playbackProbe, "kind"); got != "playback_path" {
		t.Fatalf("playback probe.kind = %q, want playback_path", got)
	}
	if got := mustStringValue(t, playbackProbe, "method"); got != http.MethodHead {
		t.Fatalf("playback probe.method = %q, want HEAD", got)
	}
	if got := mustNumberValue(t, playbackProbe, "http_status"); got != http.StatusMethodNotAllowed {
		t.Fatalf("playback probe.http_status = %d, want 405", got)
	}
	if got := mustStringValue(t, playbackHealth, "status"); got != "online" {
		t.Fatalf("playback health.status = %q, want online", got)
	}
	if got := mustBoolValue(t, playbackTLS, "enabled"); !got {
		t.Fatalf("playback tls.enabled = %v, want true", got)
	}
	if got := mustStringValue(t, playback, "effective_url"); got != playbackServer.URL {
		t.Fatalf("playback effective_url = %q, want %q", got, playbackServer.URL)
	}
	if playbackMethod != http.MethodHead {
		t.Fatalf("playback request method = %q, want HEAD", playbackMethod)
	}
	if playbackPath != "/Videos" {
		t.Fatalf("playback request path = %q, want /Videos", playbackPath)
	}
}

func TestApplyUAProfileHeadersRewritesClientIdentity(t *testing.T) {
	header := http.Header{}
	header.Set("User-Agent", "OldUA/1.0")
	header.Set("X-Emby-Authorization", `MediaBrowser Client="Old Client", Device="TV"`)
	header.Set("Authorization", `MediaBrowser Client="Old Client", Device="TV"`)

	applyUAProfileHeaders(header, uaProfiles["client"])

	if got := header.Get("User-Agent"); got != uaProfiles["client"].UserAgent {
		t.Fatalf("User-Agent = %q, want %q", got, uaProfiles["client"].UserAgent)
	}
	if got := header.Get("X-Emby-Authorization"); !strings.Contains(got, `Client="Emby Theater"`) {
		t.Fatalf("X-Emby-Authorization = %q", got)
	}
	if got := header.Get("Authorization"); !strings.Contains(got, `Client="Emby Theater"`) {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestHandleSitesCreateRollsBackOnStartFailure(t *testing.T) {
	app := newTestApp(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupied listen: %v", err)
	}
	port := occupied.Addr().(*net.TCPAddr).Port
	occupied.Close()
	occupied, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("occupied wildcard listen: %v", err)
	}
	defer occupied.Close()

	body := strings.NewReader(`{"name":"conflict","listen_port":` + jsonNumber(port) + `,"target_url":"http://127.0.0.1:8096","ua_mode":"infuse"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/sites", body)
	rr := httptest.NewRecorder()

	app.handleSites(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if count := lenMust(app.db.ListSites()); count != 0 {
		t.Fatalf("site count = %d, want 0", count)
	}
}

func TestHandleSiteToggleRevertsWhenStartFails(t *testing.T) {
	app := newTestApp(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupied listen: %v", err)
	}
	port := occupied.Addr().(*net.TCPAddr).Port
	occupied.Close()
	occupied, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("occupied wildcard listen: %v", err)
	}
	defer occupied.Close()

	site, err := app.db.CreateSite("disabled", port, "http://127.0.0.1:8096", "", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if _, err := app.db.db.Exec("UPDATE sites SET enabled=0 WHERE id=?", site.ID); err != nil {
		t.Fatalf("disable site: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/sites/"+jsonNumber64(site.ID)+"/toggle", nil)
	rr := httptest.NewRecorder()

	app.handleSiteByID(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.Enabled {
		t.Fatalf("site enabled = true, want false")
	}
}

func TestHandleSiteUpdateRollsBackOnStartFailure(t *testing.T) {
	app := newTestApp(t)
	initialPort := freePort(t)
	site, err := app.db.CreateSite("stable", initialPort, "http://127.0.0.1:8096", "", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	t.Cleanup(func() { app.pm.StopSite(site.ID) })

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupied listen: %v", err)
	}
	conflictPort := occupied.Addr().(*net.TCPAddr).Port
	occupied.Close()
	occupied, err = net.Listen("tcp", fmt.Sprintf(":%d", conflictPort))
	if err != nil {
		t.Fatalf("occupied wildcard listen: %v", err)
	}
	defer occupied.Close()

	body := strings.NewReader(`{"name":"stable","listen_port":` + jsonNumber(conflictPort) + `,"target_url":"http://127.0.0.1:8096","ua_mode":"infuse"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/sites/"+jsonNumber64(site.ID), body)
	rr := httptest.NewRecorder()

	app.handleSiteByID(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.ListenPort != initialPort {
		t.Fatalf("listen_port = %d, want %d", reloaded.ListenPort, initialPort)
	}
	if !app.pm.IsRunning(site.ID) {
		t.Fatalf("expected original site to keep running")
	}
}

func TestFlushTrafficUpdatesBaselineAndStopPersistsPendingUsage(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("traffic", freePort(t), "http://127.0.0.1:8096", "", "infuse", 1024, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	inst := &ProxyInstance{Site: *site, server: &http.Server{}}
	inst.bytesIn.Store(120)
	inst.bytesOut.Store(80)
	app.pm.proxies[site.ID] = inst

	app.pm.FlushTraffic()

	if got := inst.persistedTraffic.Load(); got != 200 {
		t.Fatalf("persistedTraffic after flush = %d, want 200", got)
	}
	inst.bytesIn.Store(10)
	inst.bytesOut.Store(5)
	app.pm.StopSite(site.ID)

	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.TrafficUsed != 215 {
		t.Fatalf("traffic_used = %d, want 215", reloaded.TrafficUsed)
	}
}

func TestAddTrafficAggregatesSameHour(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("aggregate", freePort(t), "http://127.0.0.1:8096", "", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	app.db.AddTraffic(site.ID, 10, 20)
	app.db.AddTraffic(site.ID, 5, 7)

	logs, err := app.db.GetTrafficLogs(site.ID, 1)
	if err != nil {
		t.Fatalf("GetTrafficLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("len(logs) = %d, want 1", len(logs))
	}
	if logs[0].BytesIn != 15 || logs[0].BytesOut != 27 {
		t.Fatalf("aggregated log = in:%d out:%d", logs[0].BytesIn, logs[0].BytesOut)
	}
}

func TestHandleSitesCreatePersistsPlaybackTargetURL(t *testing.T) {
	app := newTestApp(t)

	body := strings.NewReader(`{"name":"split","listen_port":` + jsonNumber(freePort(t)) + `,"target_url":"http://127.0.0.1:8096","playback_target_url":"https://media.example.com","ua_mode":"infuse"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/sites", body)
	rr := httptest.NewRecorder()

	app.handleSites(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	var site Site
	if err := json.Unmarshal(rr.Body.Bytes(), &site); err != nil {
		t.Fatalf("decode site: %v body=%s", err, rr.Body.String())
	}
	if site.PlaybackTargetURL != "https://media.example.com" {
		t.Fatalf("playback_target_url = %q, want %q", site.PlaybackTargetURL, "https://media.example.com")
	}

	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.PlaybackTargetURL != "https://media.example.com" {
		t.Fatalf("persisted playback_target_url = %q, want %q", reloaded.PlaybackTargetURL, "https://media.example.com")
	}
}

func TestProxyRoutesPlaybackRequestsToPlaybackTarget(t *testing.T) {
	app := newTestApp(t)

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("api:" + r.URL.Path))
	}))
	defer apiServer.Close()

	playbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("playback:" + r.URL.Path))
	}))
	defer playbackServer.Close()

	site, err := app.db.CreateSite("split", freePort(t), apiServer.URL, playbackServer.URL, "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	t.Cleanup(func() { app.pm.StopSite(site.ID) })

	mainResp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/System/Info", site.ListenPort))
	if err != nil {
		t.Fatalf("GET main route: %v", err)
	}
	defer mainResp.Body.Close()

	playbackResp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/emby/Videos/123/stream", site.ListenPort))
	if err != nil {
		t.Fatalf("GET playback route: %v", err)
	}
	defer playbackResp.Body.Close()

	if body := mustReadBody(t, mainResp); !strings.Contains(body, "api:/System/Info") {
		t.Fatalf("main route body = %q", body)
	}
	if body := mustReadBody(t, playbackResp); !strings.Contains(body, "playback:/emby/Videos/123/stream") {
		t.Fatalf("playback route body = %q", body)
	}
}

func TestProxyPlaybackRequestsFallBackToMainTarget(t *testing.T) {
	app := newTestApp(t)

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("api:" + r.URL.Path))
	}))
	defer apiServer.Close()

	site, err := app.db.CreateSite("single", freePort(t), apiServer.URL, "", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	t.Cleanup(func() { app.pm.StopSite(site.ID) })

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/Videos/42/stream", site.ListenPort))
	if err != nil {
		t.Fatalf("GET fallback playback route: %v", err)
	}
	defer resp.Body.Close()

	if body := mustReadBody(t, resp); !strings.Contains(body, "api:/Videos/42/stream") {
		t.Fatalf("fallback playback body = %q", body)
	}
}

func lenMust(sites []Site, err error) int {
	if err != nil {
		panic(err)
	}
	return len(sites)
}

func jsonNumber(v int) string {
	return strconv.Itoa(v)
}

func jsonNumber64(v int64) string {
	return strconv.FormatInt(v, 10)
}

func mustReadBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

func mustMapValue(t *testing.T, body map[string]interface{}, key string) map[string]interface{} {
	t.Helper()

	value, ok := body[key]
	if !ok {
		t.Fatalf("missing key %q in %#v", key, body)
	}
	result, ok := value.(map[string]interface{})
	if !ok {
		t.Fatalf("key %q = %#v, want object", key, value)
	}
	return result
}

func mustStringValue(t *testing.T, body map[string]interface{}, key string) string {
	t.Helper()

	value, ok := body[key]
	if !ok {
		t.Fatalf("missing key %q in %#v", key, body)
	}
	result, ok := value.(string)
	if !ok {
		t.Fatalf("key %q = %#v, want string", key, value)
	}
	return result
}

func mustBoolValue(t *testing.T, body map[string]interface{}, key string) bool {
	t.Helper()

	value, ok := body[key]
	if !ok {
		t.Fatalf("missing key %q in %#v", key, body)
	}
	result, ok := value.(bool)
	if !ok {
		t.Fatalf("key %q = %#v, want bool", key, value)
	}
	return result
}

func mustNumberValue(t *testing.T, body map[string]interface{}, key string) int {
	t.Helper()

	value, ok := body[key]
	if !ok {
		t.Fatalf("missing key %q in %#v", key, body)
	}
	result, ok := value.(float64)
	if !ok {
		t.Fatalf("key %q = %#v, want number", key, value)
	}
	return int(result)
}
