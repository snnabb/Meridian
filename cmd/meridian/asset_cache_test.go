package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAssetCacheEligibilityExcludesPlaybackAndSensitiveRequests(t *testing.T) {
	site := Site{AssetCacheEnabled: true, AssetCacheTTLSec: 3600, AssetCacheMaxBytes: 16 << 20, AssetCacheRules: "*/file/*\n*/emby/Items/*/Images/*\n*/web/*"}
	base, _ := url.Parse("https://media.example")
	cases := []struct {
		path        string
		rangeHeader string
		want        bool
	}{
		{path: "/emby/Items/1/Images/Primary.jpg", want: true},
		{path: "/web/app.js", want: true},
		{path: "/Videos/1/stream.mp4", want: false},
		{path: "/live/master.m3u8", want: false},
		{path: "/_meridian/d/token", want: false},
		{path: "/emby/Items/1/Images/Primary.jpg", rangeHeader: "bytes=0-9", want: false},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "https://proxy.example"+tc.path, nil)
		req.Header.Set("Range", tc.rangeHeader)
		if got := assetCacheRequestEligible(site, req, assetCacheTargetURL(req, base)); got != tc.want {
			t.Fatalf("path=%s range=%q eligible=%v want=%v", tc.path, tc.rangeHeader, got, tc.want)
		}
	}
}

func TestAssetCacheReadWriteAndIdentityIsolation(t *testing.T) {
	cache := newAssetCache(t.TempDir())
	site := Site{ID: 7, AssetCacheEnabled: true, AssetCacheTTLSec: 3600, AssetCacheMaxBytes: 16 << 20, AssetCacheRules: "*/emby/Items/*/Images/*"}
	target, _ := url.Parse("https://media.example/emby/Items/1/Images/Primary.jpg")
	request := httptest.NewRequest(http.MethodGet, "https://proxy.example/emby/Items/1/Images/Primary.jpg", nil)
	request.Header.Set("Authorization", "Bearer user-one")
	cacheReq := cache.request(site, request, target)
	response := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"image/jpeg"}, "Cache-Control": []string{"public, max-age=60"}},
		ContentLength: 5,
	}
	now := time.Now()
	if err := cache.write(site, cacheReq, response, []byte("image"), now); err != nil {
		t.Fatal(err)
	}
	hit, err := cache.read(cacheReq, now.Add(time.Second))
	if err != nil || hit == nil || string(hit.body) != "image" {
		t.Fatalf("hit=%#v err=%v", hit, err)
	}
	other := httptest.NewRequest(http.MethodGet, request.URL.String(), nil)
	other.Header.Set("Authorization", "Bearer user-two")
	if cache.request(site, other, target).key == cacheReq.key {
		t.Fatal("cache key did not isolate authenticated identities")
	}
}

func TestAssetCacheRejectsPrivateCookieAndMediaResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header http.Header
	}{
		{name: "private", header: http.Header{"Content-Type": []string{"image/jpeg"}, "Cache-Control": []string{"private"}}},
		{name: "cookie", header: http.Header{"Content-Type": []string{"image/jpeg"}, "Set-Cookie": []string{"session=secret"}}},
		{name: "video", header: http.Header{"Content-Type": []string{"video/mp4"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: http.StatusOK, Header: tc.header}
			if assetCacheResponseEligible(resp, []byte("body")) {
				t.Fatal("unsafe response was cacheable")
			}
		})
	}
}

func TestAssetCacheEvictsLeastRecentlyUsedEntryPerSite(t *testing.T) {
	cache := newAssetCache(t.TempDir())
	site := Site{ID: 9, AssetCacheEnabled: true, AssetCacheTTLSec: 3600, AssetCacheMaxBytes: 7, AssetCacheRules: "*/web/*"}
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/css"}}}
	now := time.Now()

	makeRequest := func(name string) *assetCacheRequest {
		target, _ := url.Parse("https://media.example/web/" + name + ".css")
		request := httptest.NewRequest(http.MethodGet, "https://proxy.example/web/"+name+".css", nil)
		return cache.request(site, request, target)
	}
	oldest := makeRequest("oldest")
	newest := makeRequest("newest")
	if err := cache.write(site, oldest, response, []byte("old"), now); err != nil {
		t.Fatal(err)
	}
	if err := cache.write(site, newest, response, []byte("newer"), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldest.bodyPath); !os.IsNotExist(err) {
		t.Fatalf("oldest body should be evicted, stat err=%v", err)
	}
	if _, err := os.Stat(newest.bodyPath); err != nil {
		t.Fatalf("newest body should remain: %v", err)
	}
}

func TestAssetCacheSizeBySiteAndClear(t *testing.T) {
	cache := newAssetCache(t.TempDir())
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"image/jpeg"}}}
	now := time.Now()

	write := func(siteID int64, name, body string) {
		t.Helper()
		site := Site{ID: siteID, AssetCacheEnabled: true, AssetCacheTTLSec: 3600, AssetCacheMaxBytes: 16 << 20, AssetCacheRules: "*/file/*"}
		target, _ := url.Parse("https://media.example/file/" + name + ".jpg")
		request := httptest.NewRequest(http.MethodGet, "https://proxy.example/file/"+name+".jpg", nil)
		if err := cache.write(site, cache.request(site, request, target), response, []byte(body), now); err != nil {
			t.Fatalf("write site %d: %v", siteID, err)
		}
	}

	write(11, "one", "12345")
	write(11, "two", "123")
	write(12, "three", "1234567")
	sizes, total, err := cache.sizeBySite()
	if err != nil {
		t.Fatal(err)
	}
	if sizes[11] != 8 || sizes[12] != 7 || total != 15 {
		t.Fatalf("sizes=%v total=%d, want site 11=8 site 12=7 total=15", sizes, total)
	}
	if err := cache.clear(); err != nil {
		t.Fatal(err)
	}
	sizes, total, err = cache.sizeBySite()
	if err != nil || len(sizes) != 0 || total != 0 {
		t.Fatalf("after clear sizes=%v total=%d err=%v", sizes, total, err)
	}

	missing := newAssetCache(filepath.Join(t.TempDir(), "missing"))
	if _, total, err := missing.sizeBySite(); err != nil || total != 0 {
		t.Fatalf("missing cache statistics total=%d err=%v", total, err)
	}
	if err := missing.clear(); err != nil {
		t.Fatalf("clear missing cache: %v", err)
	}
}

func TestHandleAssetCacheReportsAndClearsCache(t *testing.T) {
	app := newTestApp(t)
	cache := newAssetCache(t.TempDir())
	app.pm.SetAssetCache(cache)
	site := Site{ID: 21, AssetCacheEnabled: true, AssetCacheTTLSec: 3600, AssetCacheMaxBytes: 16 << 20, AssetCacheRules: "*/file/*"}
	target, _ := url.Parse("https://media.example/file/poster.jpg")
	request := httptest.NewRequest(http.MethodGet, "https://proxy.example/file/poster.jpg", nil)
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"image/jpeg"}}}
	if err := cache.write(site, cache.request(site, request, target), response, []byte("poster"), time.Now()); err != nil {
		t.Fatal(err)
	}

	get := httptest.NewRecorder()
	app.handleAssetCache(get, httptest.NewRequest(http.MethodGet, "/api/asset-cache", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", get.Code, get.Body.String())
	}
	var stats struct {
		TotalBytes int64            `json:"total_bytes"`
		Sites      map[string]int64 `json:"sites"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if stats.TotalBytes != 6 || stats.Sites["21"] != 6 {
		t.Fatalf("stats=%+v, want total/site=6", stats)
	}

	deleted := httptest.NewRecorder()
	app.handleAssetCache(deleted, httptest.NewRequest(http.MethodDelete, "/api/asset-cache", nil))
	if deleted.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	_, total, err := cache.sizeBySite()
	if err != nil || total != 0 {
		t.Fatalf("cache after DELETE total=%d err=%v", total, err)
	}
}

func TestAssetCacheProxyHitAndMediaBypass(t *testing.T) {
	var imageRequests atomic.Int64
	var mediaRequests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Ext(r.URL.Path) {
		case ".jpg":
			imageRequests.Add(1)
			w.Header().Set("Content-Type", "image/jpeg")
			w.Header().Set("Content-Length", "5")
			_, _ = w.Write([]byte("image"))
		case ".mp4":
			mediaRequests.Add(1)
			w.Header().Set("Content-Type", "video/mp4")
			w.Header().Set("Content-Length", "5")
			_, _ = w.Write([]byte("video"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	app := newTestApp(t)
	app.pm.SetAssetCache(newAssetCache(t.TempDir()))
	port := freePort(t)
	releasePort(port)
	site := Site{
		ID: 19, Name: "cache-proxy", ListenPort: port, IngressMode: ingressModePort,
		TargetURL: upstream.URL, PlaybackMode: "direct", StreamHosts: "[]", UAMode: passthroughUAMode,
		AssetCacheEnabled: true, AssetCacheTTLSec: 3600, AssetCacheMaxBytes: 16 << 20, AssetCacheRules: "*/file/*\n*/emby/Items/*/Images/*",
	}
	if err := app.pm.StartSite(site); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.pm.StopSite(site.ID) })
	if app.pm.assetCache == nil {
		t.Fatal("proxy manager cache is nil")
	}
	probeRequest := httptest.NewRequest(http.MethodGet, "http://proxy.example/emby/Items/1/Images/Primary.jpg", nil)
	upstreamURL, _ := url.Parse(upstream.URL)
	probeTarget := assetCacheTargetURL(probeRequest, upstreamURL)
	if cacheReq := app.pm.assetCache.request(site, probeRequest, probeTarget); cacheReq == nil {
		t.Fatalf("image request was not eligible: target=%s rule=%v reserved=%v redirect=%v info=%v structured=%q ext=%q", probeTarget, assetCacheRuleMatches(site.AssetCacheRules, probeTarget), isReservedDynamicRoute(probeRequest.URL.Path), isPlaybackRedirectEndpoint(probeRequest.URL.Path), isPlaybackInfoRequest(probeRequest.URL.Path), dynamicStructuredRequestSource(probeRequest.URL.Path), filepath.Ext(probeTarget.Path))
	}

	client := &http.Client{Timeout: 3 * time.Second}
	get := func(path string) *http.Response {
		response, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + path)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		return response
	}
	if response := get("/emby/Items/1/Images/Primary.jpg"); response.Header.Get("X-Meridian-Cache") != "MISS" {
		t.Fatalf("first image cache header=%q want MISS", response.Header.Get("X-Meridian-Cache"))
	}
	if response := get("/emby/Items/1/Images/Primary.jpg"); response.Header.Get("X-Meridian-Cache") != "HIT" {
		t.Fatalf("second image cache header=%q want HIT", response.Header.Get("X-Meridian-Cache"))
	}
	if got := imageRequests.Load(); got != 1 {
		t.Fatalf("image upstream requests=%d want 1", got)
	}
	get("/file/movie.mp4")
	get("/file/movie.mp4")
	if got := mediaRequests.Load(); got != 2 {
		t.Fatalf("media upstream requests=%d want 2", got)
	}
}

func TestPrepareAssetCacheResponseSupportsChunkedBodies(t *testing.T) {
	cache := newAssetCache(t.TempDir())
	site := Site{ID: 31, AssetCacheEnabled: true, AssetCacheTTLSec: 3600, AssetCacheMaxBytes: 16 << 20, AssetCacheRules: "*/file/*"}
	target, _ := url.Parse("https://media.example/file/poster.jpg")
	inbound := httptest.NewRequest(http.MethodGet, "https://proxy.example/file/poster.jpg", nil)
	cacheReq := cache.request(site, inbound, target)
	request := inbound.WithContext(context.WithValue(inbound.Context(), assetCacheContextKey{}, cacheReq))
	response := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"image/jpeg"}},
		ContentLength: -1,
		Body:          io.NopCloser(strings.NewReader("chunked-image")),
		Request:       request,
	}
	if err := prepareAssetCacheResponse(response, cache, site); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "chunked-image" || response.Header.Get("X-Meridian-Cache") != "MISS" || response.ContentLength != int64(len(body)) {
		t.Fatalf("body=%q cache=%q content_length=%d", body, response.Header.Get("X-Meridian-Cache"), response.ContentLength)
	}
	hit, err := cache.read(cacheReq, time.Now())
	if err != nil || hit == nil || string(hit.body) != "chunked-image" {
		t.Fatalf("cached hit=%#v err=%v", hit, err)
	}
}
