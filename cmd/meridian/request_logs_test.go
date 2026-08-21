package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRequestLogQueueFiltersAndClear(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "request-logs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	settings := db.currentSystemSettings()
	settings.LogWriteImage = true
	settings.LogWriteMetadata = true
	if err := db.saveSystemSettings(settings); err != nil {
		t.Fatal(err)
	}
	site, err := db.CreateSite("edge-one", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	for _, event := range []requestLogEvent{
		{SiteID: site.ID, SiteName: site.Name, ResourceCategory: requestLogCategoryPlayback, StatusCode: 200, ClientIP: "203.0.113.10", UserAgent: "CapyPlayer/1.1.3", UpstreamUserAgent: "MeridianCustom/2.0", BackendAddress: "https://media.example:443", Method: http.MethodPost, Path: "/Items/abc/PlaybackInfo"},
		{SiteID: site.ID, SiteName: site.Name, ResourceCategory: requestLogCategoryStream, StatusCode: 206, ClientIP: "203.0.113.14", UserAgent: "StreamPlayer/1.0", Method: http.MethodGet, Path: "/Videos/abc/stream"},
		{SiteID: site.ID, SiteName: site.Name, ResourceCategory: requestLogCategoryImage, StatusCode: 404, ClientIP: "203.0.113.11", UserAgent: "Hills/1.8", Method: http.MethodGet, Path: "/Items/abc/Images/Primary"},
		{SiteID: site.ID, SiteName: site.Name, ResourceCategory: requestLogCategoryAuth, StatusCode: 401, ClientIP: "203.0.113.12", UserAgent: "Hills/1.8", Method: http.MethodPost, Path: "/Users/AuthenticateByName"},
		{SiteID: site.ID, SiteName: site.Name, ResourceCategory: requestLogCategoryAPI, StatusCode: 503, ClientIP: "203.0.113.13", UserAgent: "Browser/1.0", Method: http.MethodGet, Path: "/System/Info"},
	} {
		db.EnqueueRequestLog(event)
	}

	all, err := db.ListRequestLogs(RequestLogFilter{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Fatalf("logs=%d, want 5: %#v", len(all), all)
	}
	playback, err := db.ListRequestLogs(RequestLogFilter{Category: requestLogCategoryPlayback})
	if err != nil || len(playback) != 1 || playback[0].Path != "/Items/abc/PlaybackInfo" {
		t.Fatalf("playback logs=%#v err=%v", playback, err)
	}
	if playback[0].BackendAddress != "https://media.example:443" {
		t.Fatalf("backend address=%q", playback[0].BackendAddress)
	}
	backendSearch, err := db.ListRequestLogs(RequestLogFilter{Query: "media.example"})
	if err != nil || len(backendSearch) != 1 {
		t.Fatalf("backend search logs=%#v err=%v", backendSearch, err)
	}
	upstreamUASearch, err := db.ListRequestLogs(RequestLogFilter{Query: "meridiancustom"})
	if err != nil || len(upstreamUASearch) != 1 || upstreamUASearch[0].UpstreamUserAgent != "MeridianCustom/2.0" {
		t.Fatalf("upstream UA search logs=%#v err=%v", upstreamUASearch, err)
	}
	video, err := db.ListRequestLogs(RequestLogFilter{Category: requestLogCategoryVideo})
	if err != nil || len(video) != 1 || video[0].Path != "/Videos/abc/stream" {
		t.Fatalf("video logs=%#v err=%v", video, err)
	}
	clientErrors, err := db.ListRequestLogs(RequestLogFilter{StatusGroup: "4xx"})
	if err != nil || len(clientErrors) != 2 {
		t.Fatalf("4xx logs=%#v err=%v", clientErrors, err)
	}
	searched, err := db.ListRequestLogs(RequestLogFilter{Query: "capyplayer"})
	if err != nil || len(searched) != 1 || searched[0].StatusCode != 200 {
		t.Fatalf("searched logs=%#v err=%v", searched, err)
	}
	pathSearch, err := db.ListRequestLogs(RequestLogFilter{Query: "playbackinfo"})
	if err != nil || len(pathSearch) != 1 {
		t.Fatalf("path logs=%#v err=%v", pathSearch, err)
	}
	if _, err := db.db.Exec("UPDATE sites SET name=? WHERE id=?", "edge-renamed", site.ID); err != nil {
		t.Fatal(err)
	}
	renamedSiteSearch, err := db.ListRequestLogs(RequestLogFilter{Query: "edge-renamed"})
	if err != nil || len(renamedSiteSearch) != 5 {
		t.Fatalf("current node-name search logs=%#v err=%v, want all historical rows", renamedSiteSearch, err)
	}
	now := time.Now().UnixMilli()
	ranged, err := db.ListRequestLogs(RequestLogFilter{FromMS: now - int64(time.Minute/time.Millisecond), ToMS: now + int64(time.Minute/time.Millisecond)})
	if err != nil || len(ranged) != 5 {
		t.Fatalf("ranged logs=%#v err=%v", ranged, err)
	}

	beforeDropped := db.DroppedRequestLogs()
	db.EnqueueRequestLog(requestLogEvent{SiteID: site.ID, ResourceCategory: "unknown"})
	if db.DroppedRequestLogs() != beforeDropped+1 {
		t.Fatalf("dropped logs=%d, want %d", db.DroppedRequestLogs(), beforeDropped+1)
	}
	if err := db.ClearRequestLogs(); err != nil {
		t.Fatal(err)
	}
	empty, err := db.ListRequestLogs(RequestLogFilter{})
	if err != nil || len(empty) != 0 {
		t.Fatalf("logs after clear=%#v err=%v", empty, err)
	}
}

func TestRequestLogWriteFieldSettingsOmitOnlyNewLogValues(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "request-log-write-fields.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	site, err := db.CreateSite("write-fields-node", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	settings := db.currentSystemSettings()
	settings.LogWriteNode = false
	settings.LogWriteCategory = false
	settings.LogWriteStatus = false
	settings.LogWriteClientIP = false
	settings.LogWriteUA = false
	settings.LogWriteUpstreamUA = false
	settings.LogWriteBackendAddress = false
	settings.LogWriteTimeline = false
	if err := db.saveSystemSettings(settings); err != nil {
		t.Fatal(err)
	}
	db.EnqueueRequestLog(requestLogEvent{
		SiteID: site.ID, SiteName: site.Name, ResourceCategory: requestLogCategoryAPI,
		StatusCode: http.StatusOK, ClientIP: "203.0.113.40", UserAgent: "Test/1", UpstreamUserAgent: "Custom/1", BackendAddress: "https://media.example:443",
		Method: http.MethodGet, Path: "/System/Info",
	})
	logs, err := db.ListRequestLogs(RequestLogFilter{Limit: 10})
	if err != nil || len(logs) != 1 {
		t.Fatalf("logs=%#v err=%v", logs, err)
	}
	entry := logs[0]
	if entry.SiteName != "" || entry.ResourceCategory != "" || entry.StatusCode != 0 || entry.ClientIP != "" || entry.UserAgent != "" || entry.UpstreamUserAgent != "" || entry.BackendAddress != "" || entry.RecordedAtMS != 0 {
		t.Fatalf("disabled fields were still written: %#v", entry)
	}
	var recordedAtMS, timelineAtMS int64
	if err := db.db.QueryRow("SELECT recorded_at_ms, timeline_at_ms FROM request_logs WHERE id=?", entry.ID).Scan(&recordedAtMS, &timelineAtMS); err != nil {
		t.Fatal(err)
	}
	if recordedAtMS <= 0 || timelineAtMS != 0 {
		t.Fatalf("internal time=%d timeline=%d", recordedAtMS, timelineAtMS)
	}
}

func TestRequestLogPlaybackAndMetadataWriteSettingsAreIndependent(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "request-log-resource-settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	site, err := db.CreateSite("resource-settings-node", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	db.EnqueueRequestLog(requestLogEvent{SiteID: site.ID, SiteName: site.Name, ResourceCategory: requestLogCategoryPlayback, StatusCode: 200, Method: http.MethodPost, Path: "/Items/abc/PlaybackInfo"})
	db.EnqueueRequestLog(requestLogEvent{SiteID: site.ID, SiteName: site.Name, ResourceCategory: requestLogCategoryMetadata, StatusCode: 200, Method: http.MethodGet, Path: "/Items"})
	logs, err := db.ListRequestLogs(RequestLogFilter{Limit: 10})
	if err != nil || len(logs) != 1 || logs[0].ResourceCategory != requestLogCategoryPlayback {
		t.Fatalf("default resource logs=%#v err=%v", logs, err)
	}

	settings := db.currentSystemSettings()
	settings.LogWritePlayback = false
	settings.LogWriteMetadata = true
	if err := db.saveSystemSettings(settings); err != nil {
		t.Fatal(err)
	}
	db.EnqueueRequestLog(requestLogEvent{SiteID: site.ID, SiteName: site.Name, ResourceCategory: requestLogCategoryPlayback, StatusCode: 200, Method: http.MethodPost, Path: "/Items/def/PlaybackInfo"})
	db.EnqueueRequestLog(requestLogEvent{SiteID: site.ID, SiteName: site.Name, ResourceCategory: requestLogCategoryMetadata, StatusCode: 200, Method: http.MethodGet, Path: "/Shows/NextUp"})
	metadata, err := db.ListRequestLogs(RequestLogFilter{Category: requestLogCategoryMetadata, Limit: 10})
	if err != nil || len(metadata) != 1 || metadata[0].Path != "/Shows/NextUp" {
		t.Fatalf("metadata logs=%#v err=%v", metadata, err)
	}
	playback, err := db.ListRequestLogs(RequestLogFilter{Category: requestLogCategoryPlayback, Limit: 10})
	if err != nil || len(playback) != 1 || playback[0].Path != "/Items/abc/PlaybackInfo" {
		t.Fatalf("playback logs=%#v err=%v", playback, err)
	}
}

func TestRequestLogClassificationAndSanitization(t *testing.T) {
	cases := []struct {
		path    string
		want    string
		upgrade bool
	}{
		{path: "/Items/abc/PlaybackInfo", want: requestLogCategoryPlayback},
		{path: "/Sessions/Playing/Progress", want: requestLogCategoryPlaybackSync},
		{path: "/Videos/abc/stream", want: requestLogCategoryStream},
		{path: "/_meridian/d/capability", want: requestLogCategoryStream},
		{path: "/Videos/abc/master.m3u8", want: requestLogCategoryManifest},
		{path: "/Videos/abc/segment.m4s", want: requestLogCategorySegment},
		{path: "/Items/abc/Images/Primary", want: requestLogCategoryImage},
		{path: "/Items?Recursive=true", want: requestLogCategoryMetadata},
		{path: "/Shows/NextUp", want: requestLogCategoryMetadata},
		{path: "/Videos/abc/Subtitles/0/Stream.vtt", want: requestLogCategorySubtitle},
		{path: "/web/app.js", want: requestLogCategoryAsset},
		{path: "/socket", want: requestLogCategoryWebSocket, upgrade: true},
		{path: "/Users/AuthenticateByName", want: requestLogCategoryAuth},
		{path: "/System/Info", want: requestLogCategoryAPI},
	}
	for _, tc := range cases {
		requestURL := "http://media.example" + tc.path
		if !strings.Contains(requestURL, "?") {
			requestURL += "?api_key=secret"
		}
		req := httptest.NewRequest(http.MethodGet, requestURL, nil)
		req.RemoteAddr = "203.0.113.20:12345"
		req.Header.Set("User-Agent", "Capy\r\nPlayer")
		if tc.upgrade {
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
		}
		event := newRequestLogEvent(Site{ID: 7, Name: "node"}, req, nil, UAHeaderPolicy{Rewrite: true, Profile: UAProfile{UserAgent: "Upstream/2"}})
		if event.ResourceCategory != tc.want {
			t.Fatalf("path %s category=%s want=%s", tc.path, event.ResourceCategory, tc.want)
		}
		wantPath := strings.SplitN(tc.path, "?", 2)[0]
		if event.Path != wantPath || event.ClientIP != "203.0.113.20" || event.UserAgent != "CapyPlayer" || event.UpstreamUserAgent != "Upstream/2" {
			t.Fatalf("event=%#v", event)
		}
	}
}

func TestRequestLogPlaybackSyncFilterIncludesLegacyRows(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "request-log-playback-sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	site, err := db.CreateSite("playback-sync-node", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []requestLogEvent{
		{SiteID: site.ID, SiteName: site.Name, ResourceCategory: requestLogCategoryPlaybackSync, StatusCode: 204, Method: http.MethodPost, Path: "/Sessions/Playing/Progress"},
		{SiteID: site.ID, SiteName: site.Name, ResourceCategory: requestLogCategoryPlayback, StatusCode: 204, Method: http.MethodPost, Path: "/emby/Sessions/Playing/Stopped"},
		{SiteID: site.ID, SiteName: site.Name, ResourceCategory: requestLogCategoryPlayback, StatusCode: 200, Method: http.MethodPost, Path: "/Items/abc/PlaybackInfo"},
	} {
		db.EnqueueRequestLog(event)
	}

	syncLogs, err := db.ListRequestLogs(RequestLogFilter{Category: requestLogCategoryPlaybackSync, Limit: 10})
	if err != nil || len(syncLogs) != 2 {
		t.Fatalf("playback sync logs=%#v err=%v", syncLogs, err)
	}
	for _, entry := range syncLogs {
		if entry.ResourceCategory != requestLogCategoryPlaybackSync {
			t.Fatalf("legacy playback sync row was not normalized: %#v", entry)
		}
	}
	playbackLogs, err := db.ListRequestLogs(RequestLogFilter{Category: requestLogCategoryPlayback, Limit: 10})
	if err != nil || len(playbackLogs) != 1 || playbackLogs[0].Path != "/Items/abc/PlaybackInfo" {
		t.Fatalf("playback info logs=%#v err=%v", playbackLogs, err)
	}
}

func TestRequestLogResponseWriterAndAPI(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := &requestLogResponseWriter{ResponseWriter: recorder}
	writer.WriteHeader(http.StatusNotFound)
	_, _ = writer.Write([]byte("missing"))
	writer.WriteHeader(http.StatusOK)
	if writer.StatusCode() != http.StatusNotFound || recorder.Code != http.StatusNotFound {
		t.Fatalf("status writer=%d recorder=%d", writer.StatusCode(), recorder.Code)
	}

	app := newTestApp(t)
	site, err := app.db.CreateSite("api-node", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	app.db.EnqueueRequestLog(requestLogEvent{SiteID: site.ID, SiteName: site.Name, ResourceCategory: requestLogCategoryAPI, StatusCode: 200, ClientIP: "203.0.113.30", UserAgent: "Test/1", Method: http.MethodGet, Path: "/System/Info"})

	response := httptest.NewRecorder()
	app.handleRequestLogs(response, httptest.NewRequest(http.MethodGet, "/api/request-logs?status=all&limit=10", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", response.Code, response.Body.String())
	}
	var payload RequestLogsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || len(payload.Logs) != 1 {
		t.Fatalf("payload=%#v err=%v", payload, err)
	}

	cleared := httptest.NewRecorder()
	app.handleRequestLogs(cleared, httptest.NewRequest(http.MethodDelete, "/api/request-logs", nil))
	if cleared.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s", cleared.Code, cleared.Body.String())
	}
}

func TestClientRequestCancellationClassification(t *testing.T) {
	clientCtx, clientCancel := context.WithCancel(context.Background())
	derivedClientCtx := context.WithValue(clientCtx, originalRequestContextKey{}, clientCtx)
	clientCancel()
	if !isClientRequestCancellation(derivedClientCtx, context.Canceled) {
		t.Fatal("canceled original request was not classified as a client cancellation")
	}

	clientRequestCtx := context.Background()
	serverCtx, serverCancel := context.WithCancel(context.Background())
	derivedCtx, derivedCancel := context.WithCancel(serverCtx)
	if isClientRequestCancellation(context.WithValue(derivedCtx, originalRequestContextKey{}, clientRequestCtx), context.Canceled) {
		t.Fatal("server-side derived cancellation was misclassified as a client cancellation")
	}
	serverCancel()
	derivedCancel()
	if originalRequestContext(derivedCtx) != derivedCtx {
		t.Fatal("context without an original marker should be returned unchanged")
	}

	marked := context.WithValue(derivedCtx, originalRequestContextKey{}, serverCtx)
	if originalRequestContext(marked) != serverCtx {
		t.Fatal("original request context marker was not recovered")
	}
}

func TestNewSiteLogsImmediatelyAndDefaultsToPassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusPartialContent)
	}))
	defer upstream.Close()

	app := newTestApp(t)
	port := freePort(t)
	releasePort(port)
	payload, err := json.Marshal(map[string]interface{}{
		"name":        "live-log-site",
		"listen_port": port,
		"target_url":  upstream.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	created := httptest.NewRecorder()
	app.handleSites(created, httptest.NewRequest(http.MethodPost, "/api/sites", bytes.NewReader(payload)))
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var site Site
	if err := json.Unmarshal(created.Body.Bytes(), &site); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.pm.StopSite(site.ID) })
	if site.UAMode != passthroughUAMode {
		t.Fatalf("new site ua_mode=%q want %q", site.UAMode, passthroughUAMode)
	}

	response, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://127.0.0.1:" + strconv.Itoa(port) + "/Videos/item/stream")
	if err != nil {
		t.Fatalf("request new site without restart: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusPartialContent {
		t.Fatalf("new site response status=%d want %d", response.StatusCode, http.StatusPartialContent)
	}

	logs, err := app.db.ListRequestLogs(RequestLogFilter{Category: requestLogCategoryVideo, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range logs {
		if entry.SiteID == site.ID && entry.StatusCode == http.StatusPartialContent && entry.Path == "/Videos/item/stream" {
			return
		}
	}
	t.Fatalf("new site request was not logged immediately: %#v", logs)
}
