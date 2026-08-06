package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func imageCacheTestTarget(t *testing.T, raw string) *url.URL {
	t.Helper()
	target, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	return target
}

func imageCacheTestRequest(site *imageCacheSite, target *url.URL, next http.Handler, method, requestURI string, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://meridian.example"+requestURI, nil)
	if header != nil {
		req.Header = header.Clone()
	}
	rr := httptest.NewRecorder()
	site.serve(rr, req, target, next)
	return rr
}

func newImageCacheTestSite(now *time.Time, processBytes, siteBytes int64, siteID int64) *imageCacheSite {
	runtime := newImageCacheRuntimeWithLimits(processBytes, siteBytes, imageCacheTTL, []byte("image-cache-test-master-key"))
	runtime.now = func() time.Time { return *now }
	return runtime.newSite(siteID)
}

func TestNormalizeEmbyImageCachePath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/Items/42/Images/Primary", "/Items/42/Images/Primary"},
		{"/emby/Items/42/Images/Backdrop/0", "/emby/Items/42/Images/Backdrop/0"},
		{"/EMBY/items/42/images/Primary", "/emby/Items/42/Images/Primary"},
		{"/%49tems/42/%49mages/Primary", "/Items/42/Images/Primary"},
	}
	for _, test := range tests {
		u, err := url.Parse(test.path)
		if err != nil {
			t.Fatalf("parse %q: %v", test.path, err)
		}
		if got, ok := normalizeEmbyImageCachePath(u); !ok || got != test.want {
			t.Errorf("normalize %q = %q, %v; want %q, true", test.path, got, ok, test.want)
		}
	}

	falsePositives := []string{
		"/Items/42/Images", "/Items/42/ImagesX/Primary", "/ItemsX/42/Images/Primary",
		"/prefix/Items/42/Images/Primary", "/embyItems/42/Images/Primary",
		"/emby/Items/42/Images", "/Items//Images/Primary", "/Items/../Images/Primary",
		"/Items/42/Images/Primary%2F0", "/_meridian/d/token",
	}
	for _, raw := range falsePositives {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if got, ok := normalizeEmbyImageCachePath(u); ok {
			t.Errorf("false-positive path %q normalized to %q", raw, got)
		}
	}
}

func TestImageCacheKeyCanonicalQueryAndCredentialIsolation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	site := newImageCacheTestSite(&now, imageCacheMaxProcessBytes, imageCacheMaxSiteBytes, 7)
	target := imageCacheTestTarget(t, "https://Media.Example:443/base?fixed=z&token=target-secret")

	request := func(raw, token, apiKey string) imageCacheKey {
		req := httptest.NewRequest(http.MethodGet, "http://site.example"+raw, nil)
		req.Header.Set("X-Api-Key", apiKey)
		req.Header.Set("X-Emby-Token", token)
		key, ok := imageCacheRequestKeyFor(site, target, req)
		if !ok {
			t.Fatalf("request %q was not cache eligible", raw)
		}
		return key
	}
	first := request("/Items/42/Images/Primary?b=2&api_key=first-secret&a=1", "header-secret", "api-header-secret")
	reordered := request("/Items/42/Images/Primary?a=1&api_key=first-secret&b=2", "header-secret", "api-header-secret")
	if first != reordered {
		t.Fatal("equivalent query order produced different keys")
	}
	if first.canonicalQuery != "a=1&b=2&fixed=z" {
		t.Fatalf("canonical query = %q", first.canonicalQuery)
	}
	if first.primaryAuthority != "https://media.example" || first.canonicalPath != "/base/Items/42/Images/Primary" {
		t.Fatalf("canonical target fields = %#v", first)
	}
	queryIsolated := request("/Items/42/Images/Primary?a=1&api_key=other-secret&b=2", "header-secret", "api-header-secret")
	if first == queryIsolated {
		t.Fatal("query credentials shared a cache key")
	}
	headerIsolated := request("/Items/42/Images/Primary?a=1&api_key=first-secret&b=2", "other-header-secret", "api-header-secret")
	if first == headerIsolated {
		t.Fatal("Emby header credentials shared a cache key")
	}
	apiKeyIsolated := request("/Items/42/Images/Primary?a=1&api_key=first-secret&b=2", "header-secret", "other-api-header-secret")
	if first == apiKeyIsolated {
		t.Fatal("X-Api-Key credentials shared a cache key")
	}

	repeated := request("/Items/42/Images/Primary?b=2&a=first&a=second&api_key=first-secret", "header-secret", "api-header-secret")
	repeatedReordered := request("/Items/42/Images/Primary?a=first&a=second&api_key=first-secret&b=2", "header-secret", "api-header-secret")
	if repeated != repeatedReordered || repeated.canonicalQuery != "a=first&a=second&b=2&fixed=z" {
		t.Fatalf("stable repeated values were not key-canonical: %#v / %#v", repeated, repeatedReordered)
	}
	repeatedReversed := request("/Items/42/Images/Primary?a=second&a=first&api_key=first-secret&b=2", "header-secret", "api-header-secret")
	if repeated == repeatedReversed {
		t.Fatal("reversed repeated query values shared a cache key")
	}

	printed := fmt.Sprintf("%#v", []imageCacheKey{first, queryIsolated, headerIsolated, apiKeyIsolated, repeated, repeatedReversed})
	for _, secret := range []string{
		"first-secret", "other-secret", "header-secret", "other-header-secret",
		"api-header-secret", "other-api-header-secret", "target-secret",
	} {
		if strings.Contains(printed, secret) {
			t.Fatalf("cache key retained raw credential %q: %s", secret, printed)
		}
	}
}

func TestImageCacheHitMissTTLAndSafeHeaderReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	originDate := now.Add(-7 * time.Second)
	site := newImageCacheTestSite(&now, imageCacheMaxProcessBytes, imageCacheMaxSiteBytes, 1)
	target := imageCacheTestTarget(t, "https://media.example")
	var calls int
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Age", "5")
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Date", originDate.UTC().Format(http.TimeFormat))
		w.Header().Set("Server", "test-upstream")
		w.Header().Set("ETag", `"image-v1"`)
		w.Header().Set("X-Upstream-Secret", "do-not-replay")
		_, _ = w.Write([]byte("image-body"))
	})

	first := imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary?width=200", nil)
	second := imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary?width=200", nil)
	if calls != 1 || first.Body.String() != "image-body" || second.Body.String() != "image-body" {
		t.Fatalf("calls=%d first=%q second=%q", calls, first.Body.String(), second.Body.String())
	}
	if second.Header().Get("ETag") != `"image-v1"` || second.Header().Get("X-Upstream-Secret") != "" || second.Header().Get("Age") != "7" || second.Header().Get("Date") != originDate.UTC().Format(http.TimeFormat) {
		t.Fatalf("cached replay headers = %#v", second.Header())
	}

	now = now.Add(10 * time.Second)
	resident := imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary?width=200", nil)
	if resident.Header().Get("Age") != "17" || calls != 1 {
		t.Fatalf("resident HIT age=%q calls=%d", resident.Header().Get("Age"), calls)
	}
	now = now.Add(imageCacheTTL)
	_ = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary?width=200", nil)
	if calls != 2 {
		t.Fatalf("expired entry upstream calls = %d, want 2", calls)
	}
}

func TestImageCacheCachesCompleteReverseProxyResponse(t *testing.T) {
	now := time.Now()
	site := newImageCacheTestSite(&now, imageCacheMaxProcessBytes, imageCacheMaxSiteBytes, 1)
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		body := []byte("image-body")
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	defer upstream.Close()
	target := imageCacheTestTarget(t, upstream.URL)
	proxy := &httputil.ReverseProxy{Rewrite: func(request *httputil.ProxyRequest) {
		applyUpstreamURL(request.Out.URL, target)
		request.Out.Host = target.Host
	}}

	first := imageCacheTestRequest(site, target, proxy, http.MethodGet, "/Items/1/Images/Primary", nil)
	second := imageCacheTestRequest(site, target, proxy, http.MethodGet, "/Items/1/Images/Primary", nil)
	if calls.Load() != 1 || first.Body.String() != "image-body" || second.Body.String() != "image-body" {
		t.Fatalf("reverse proxy cache calls=%d first=%q second=%q", calls.Load(), first.Body.String(), second.Body.String())
	}
}

func TestImageCacheFullHandlerCachesBodylessGETAndMetersHits(t *testing.T) {
	app := newTestApp(t)
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		body := []byte("image-body")
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	defer upstream.Close()
	site := Site{
		ID: 901, Name: "image-handler", ListenPort: freePort(t), PublicHost: "image-handler.example.com",
		IngressMode: ingressModeHost, TargetURL: upstream.URL, PlaybackMode: "direct", StreamHosts: "[]",
		UAMode: "infuse", ImageCacheEnabled: true,
	}
	if err := app.pm.StartSite(site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	t.Cleanup(func() { _ = app.pm.StopSite(site.ID) })
	app.pm.mu.RLock()
	inst := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	proxyServer := httptest.NewServer(inst.handler)
	defer proxyServer.Close()

	for range 2 {
		response, err := http.Get(proxyServer.URL + "/Items/1/Images/Primary") // #nosec G107 -- local test server.
		if err != nil {
			t.Fatalf("GET image: %v", err)
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || string(body) != "image-body" {
			t.Fatalf("image response status=%d body=%q readErr=%v", response.StatusCode, body, readErr)
		}
	}
	if calls.Load() != 1 || inst.reqCount.Load() != 2 || inst.bytesOut.Load() != int64(2*len("image-body")) {
		t.Fatalf("full handler calls=%d requests=%d bytesOut=%d", calls.Load(), inst.reqCount.Load(), inst.bytesOut.Load())
	}
}

func TestImageCacheBypassesRangePartialAndClientRevalidation(t *testing.T) {
	now := time.Now()
	target := imageCacheTestTarget(t, "https://media.example")

	for _, header := range []http.Header{
		{"Range": []string{"bytes=0-9"}},
		{"If-Range": []string{`"etag"`}},
		{"If-None-Match": []string{`"etag"`}},
		{"If-Modified-Since": []string{"Wed, 21 Oct 2015 07:28:00 GMT"}},
		{"Cache-Control": []string{"no-cache"}},
		{"Cache-Control": []string{"no-store"}},
		{"Pragma": []string{"no-cache"}},
	} {
		site := newImageCacheTestSite(&now, imageCacheMaxProcessBytes, imageCacheMaxSiteBytes, 1)
		calls := 0
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("body"))
		})
		_ = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary", header)
		_ = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary", header)
		if calls != 2 {
			t.Fatalf("header %#v was cached; calls=%d", header, calls)
		}
	}

	site := newImageCacheTestSite(&now, imageCacheMaxProcessBytes, imageCacheMaxSiteBytes, 2)
	partialCalls := 0
	partial := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		partialCalls++
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Range", "bytes 0-3/10")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte("part"))
	})
	_ = imageCacheTestRequest(site, target, partial, http.MethodGet, "/Items/2/Images/Primary", nil)
	_ = imageCacheTestRequest(site, target, partial, http.MethodGet, "/Items/2/Images/Primary", nil)
	if partialCalls != 2 {
		t.Fatalf("206 response was cached; calls=%d", partialCalls)
	}
}

func TestImageCacheRejectsUnsafeResponses(t *testing.T) {
	now := time.Now()
	target := imageCacheTestTarget(t, "https://media.example")
	tests := []struct {
		name   string
		status int
		header http.Header
		body   string
	}{
		{"non image MIME", 200, http.Header{"Content-Type": []string{"application/octet-stream"}}, "body"},
		{"wildcard image MIME", 200, http.Header{"Content-Type": []string{"image/*"}}, "body"},
		{"set cookie", 200, http.Header{"Content-Type": []string{"image/png"}, "Set-Cookie": []string{"session=secret"}}, "body"},
		{"private", 200, http.Header{"Content-Type": []string{"image/png"}, "Cache-Control": []string{"private"}}, "body"},
		{"no store", 200, http.Header{"Content-Type": []string{"image/png"}, "Cache-Control": []string{"no-store"}}, "body"},
		{"no cache", 200, http.Header{"Content-Type": []string{"image/png"}, "Cache-Control": []string{"no-cache"}}, "body"},
		{"unsafe vary", 200, http.Header{"Content-Type": []string{"image/png"}, "Vary": []string{"Origin"}}, "body"},
		{"vary star", 200, http.Header{"Content-Type": []string{"image/png"}, "Vary": []string{"*"}}, "body"},
		{"warning", 200, http.Header{"Content-Type": []string{"image/png"}, "Warning": []string{"110 stale"}}, "body"},
		{"length mismatch", 200, http.Header{"Content-Type": []string{"image/png"}, "Content-Length": []string{"100"}}, "short"},
		{"partial status", 206, http.Header{"Content-Type": []string{"image/png"}}, "part"},
		{"oversized", 200, http.Header{"Content-Type": []string{"image/png"}}, strings.Repeat("x", int(imageCacheMaxBodyBytes)+1)},
		{"invalid age", 200, http.Header{"Content-Type": []string{"image/png"}, "Age": []string{"not-a-number"}}, "body"},
		{"overflow age", 200, http.Header{"Content-Type": []string{"image/png"}, "Age": []string{strings.Repeat("9", 40)}}, "body"},
		{"invalid date", 200, http.Header{"Content-Type": []string{"image/png"}, "Date": []string{"not-a-date"}}, "body"},
		{"stale max age", 200, http.Header{"Content-Type": []string{"image/png"}, "Age": []string{"10"}, "Cache-Control": []string{"public, max-age=10"}}, "body"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			site := newImageCacheTestSite(&now, imageCacheMaxProcessBytes, imageCacheMaxSiteBytes, 1)
			calls := 0
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				for name, values := range test.header {
					for _, value := range values {
						w.Header().Add(name, value)
					}
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			})
			_ = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary", nil)
			_ = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary", nil)
			if calls != 2 {
				t.Fatalf("unsafe response was cached; calls=%d", calls)
			}
		})
	}
}

func TestImageCacheSingleflightIdenticalMisses(t *testing.T) {
	now := time.Now()
	site := newImageCacheTestSite(&now, imageCacheMaxProcessBytes, imageCacheMaxSiteBytes, 1)
	target := imageCacheTestTarget(t, "https://media.example")
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("coalesced"))
	})

	const clients = 12
	responses := make([]*httptest.ResponseRecorder, clients)
	var wg sync.WaitGroup
	wg.Add(clients)
	for i := range clients {
		go func(index int) {
			defer wg.Done()
			responses[index] = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary?width=300", nil)
		}(i)
	}
	<-entered
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", calls.Load())
	}
	for i, response := range responses {
		if response.Body.String() != "coalesced" {
			t.Fatalf("response %d body = %q", i, response.Body.String())
		}
	}
}

func TestImageCacheInflightReservationsBoundProcessAndSiteBudgets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	target := imageCacheTestTarget(t, "https://media.example")
	probeRuntime := newImageCacheRuntimeWithLimits(imageCacheMaxProcessBytes, imageCacheMaxSiteBytes, imageCacheTTL, []byte("reservation-probe"))
	probeSite := probeRuntime.newSite(1)
	probeRequest := httptest.NewRequest(http.MethodGet, "http://meridian.example/Items/1/Images/Primary?v=a", nil)
	probeKey, ok := imageCacheRequestKeyFor(probeSite, target, probeRequest)
	if !ok {
		t.Fatal("reservation probe was not cache eligible")
	}
	reservation := imageCacheMaximumFlightReservation(probeKey)

	tests := []struct {
		name             string
		processBytes     int64
		secondSiteUnique bool
	}{
		{name: "process", processBytes: reservation, secondSiteUnique: true},
		{name: "site", processBytes: reservation * 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := newImageCacheRuntimeWithLimits(test.processBytes, reservation, imageCacheTTL, []byte("bounded-reservation"))
			runtime.now = func() time.Time { return now }
			firstSite := runtime.newSite(1)
			secondSite := firstSite
			if test.secondSiteUnique {
				secondSite = runtime.newSite(2)
			}

			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			var releaseOnce sync.Once
			var requests sync.WaitGroup
			defer func() {
				releaseOnce.Do(func() { close(release) })
				requests.Wait()
			}()
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				entered <- struct{}{}
				<-release
				w.WriteHeader(http.StatusServiceUnavailable)
			})
			launch := func(site *imageCacheSite, query string) {
				requests.Add(1)
				go func() {
					defer requests.Done()
					_ = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary?"+query, nil)
				}()
			}

			launch(firstSite, "v=a")
			<-entered
			launch(secondSite, "v=b")
			<-entered
			runtime.mu.Lock()
			accounted := runtime.bytes
			firstAccounted := firstSite.bytes
			secondAccounted := secondSite.bytes
			flights := len(firstSite.flights)
			if secondSite != firstSite {
				flights += len(secondSite.flights)
			}
			runtime.mu.Unlock()
			if accounted != reservation || accounted > test.processBytes || firstAccounted > reservation || secondAccounted > reservation || flights != 1 {
				t.Fatalf("in-flight accounting process=%d/%d first=%d second=%d flights=%d", accounted, test.processBytes, firstAccounted, secondAccounted, flights)
			}

			releaseOnce.Do(func() { close(release) })
			requests.Wait()
			runtime.mu.Lock()
			accounted = runtime.bytes
			firstAccounted = firstSite.bytes
			secondAccounted = secondSite.bytes
			flights = len(firstSite.flights)
			if secondSite != firstSite {
				flights += len(secondSite.flights)
			}
			runtime.mu.Unlock()
			if accounted != 0 || firstAccounted != 0 || secondAccounted != 0 || flights != 0 {
				t.Fatalf("released accounting process=%d first=%d second=%d flights=%d", accounted, firstAccounted, secondAccounted, flights)
			}

			enteredAgain := make(chan struct{})
			releaseAgain := make(chan struct{})
			var again sync.WaitGroup
			again.Add(1)
			go func() {
				defer again.Done()
				nextAgain := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					close(enteredAgain)
					<-releaseAgain
					w.WriteHeader(http.StatusServiceUnavailable)
				})
				_ = imageCacheTestRequest(firstSite, target, nextAgain, http.MethodGet, "/Items/1/Images/Primary?v=c", nil)
			}()
			<-enteredAgain
			runtime.mu.Lock()
			reused := runtime.bytes
			reusedFlights := len(firstSite.flights)
			runtime.mu.Unlock()
			close(releaseAgain)
			again.Wait()
			if reused != reservation || reusedFlights != 1 {
				t.Fatalf("released reservation was not reusable: bytes=%d flights=%d", reused, reusedFlights)
			}
			runtime.mu.Lock()
			finalBytes := runtime.bytes
			runtime.mu.Unlock()
			if finalBytes != 0 {
				t.Fatalf("reused reservation leaked %d bytes", finalBytes)
			}
		})
	}
}

func TestImageCachePublicationConvertsFlightReservation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	target := imageCacheTestTarget(t, "https://media.example")
	probeRuntime := newImageCacheRuntimeWithLimits(imageCacheMaxProcessBytes, imageCacheMaxSiteBytes, imageCacheTTL, []byte("publication-probe"))
	probeSite := probeRuntime.newSite(1)
	probeRequest := httptest.NewRequest(http.MethodGet, "http://meridian.example/Items/1/Images/Primary?v=a", nil)
	key, ok := imageCacheRequestKeyFor(probeSite, target, probeRequest)
	if !ok {
		t.Fatal("publication probe was not cache eligible")
	}
	reservation := imageCacheMaximumFlightReservation(key)
	runtime := newImageCacheRuntimeWithLimits(reservation, reservation, imageCacheTTL, []byte("publication-accounting"))
	runtime.now = func() time.Time { return now }
	site := runtime.newSite(1)
	actualRequest := httptest.NewRequest(http.MethodGet, "http://meridian.example/Items/1/Images/Primary?v=a", nil)
	key, ok = imageCacheRequestKeyFor(site, target, actualRequest)
	if !ok {
		t.Fatal("publication request was not cache eligible")
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4")
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("body"))
	})
	_ = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary?v=a", nil)

	runtime.mu.Lock()
	entry := site.entries[key]
	accounted := runtime.bytes
	siteAccounted := site.bytes
	flights := len(site.flights)
	expected := int64(0)
	if entry != nil {
		expected = entry.cost
	}
	runtime.mu.Unlock()
	if entry == nil || flights != 0 || accounted != expected || siteAccounted != expected || accounted >= reservation {
		t.Fatalf("publication accounting entry=%v process=%d site=%d expected=%d reservation=%d flights=%d", entry != nil, accounted, siteAccounted, expected, reservation, flights)
	}
	site.close()
	runtime.mu.Lock()
	accounted = runtime.bytes
	runtime.mu.Unlock()
	if accounted != 0 {
		t.Fatalf("published entry retained %d bytes after close", accounted)
	}
}

func TestImageCachePerSiteAndGlobalLRUEviction(t *testing.T) {
	now := time.Now()
	target := imageCacheTestTarget(t, "https://m.example")
	oneEntryBudget := imageCacheEntryOverhead + 320
	body := strings.Repeat("x", 128)

	t.Run("per-site", func(t *testing.T) {
		site := newImageCacheTestSite(&now, 1<<20, oneEntryBudget, 1)
		calls := 0
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte(body))
		})
		_ = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary?v=a", nil)
		_ = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary?v=a", nil)
		_ = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary?v=b", nil)
		_ = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary?v=a", nil)
		if calls != 3 {
			t.Fatalf("per-site LRU calls=%d, want 3", calls)
		}
	})

	t.Run("global", func(t *testing.T) {
		runtime := newImageCacheRuntimeWithLimits(oneEntryBudget, 1<<20, imageCacheTTL, []byte("global-lru-key"))
		runtime.now = func() time.Time { return now }
		firstSite, secondSite := runtime.newSite(1), runtime.newSite(2)
		calls := 0
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte(body))
		})
		_ = imageCacheTestRequest(firstSite, target, next, http.MethodGet, "/Items/1/Images/Primary", nil)
		_ = imageCacheTestRequest(firstSite, target, next, http.MethodGet, "/Items/1/Images/Primary", nil)
		_ = imageCacheTestRequest(secondSite, target, next, http.MethodGet, "/Items/1/Images/Primary", nil)
		_ = imageCacheTestRequest(firstSite, target, next, http.MethodGet, "/Items/1/Images/Primary", nil)
		if calls != 3 {
			t.Fatalf("global LRU calls=%d, want 3", calls)
		}
	})
}

func TestImageCacheHEADAndMeteredHits(t *testing.T) {
	now := time.Now()
	site := newImageCacheTestSite(&now, imageCacheMaxProcessBytes, imageCacheMaxSiteBytes, 1)
	target := imageCacheTestTarget(t, "https://media.example")
	body := "metered-image"
	calls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte(body))
	})
	var bytesOut atomic.Int64
	serveMetered := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://site.example"+path, nil)
		rr := httptest.NewRecorder()
		site.serve(&meteredWriter{ResponseWriter: rr, written: &bytesOut}, req, target, next)
		return rr
	}
	_ = serveMetered(http.MethodGet, "/Items/1/Images/Primary")
	head := serveMetered(http.MethodHead, "/Items/1/Images/Primary")
	_ = serveMetered(http.MethodGet, "/Items/1/Images/Primary")
	if calls != 1 || head.Body.Len() != 0 || head.Header().Get("Content-Length") != fmt.Sprint(len(body)) {
		t.Fatalf("HEAD calls=%d body=%q headers=%#v", calls, head.Body.String(), head.Header())
	}
	if bytesOut.Load() != int64(2*len(body)) {
		t.Fatalf("metered bytesOut=%d, want %d", bytesOut.Load(), 2*len(body))
	}

	_ = serveMetered(http.MethodHead, "/Items/1/Images/Primary?v=miss")
	_ = serveMetered(http.MethodGet, "/Items/1/Images/Primary?v=miss")
	if calls != 3 {
		t.Fatalf("HEAD miss poisoned GET cache; calls=%d, want 3", calls)
	}
}

func TestImageCacheLifecycleInvalidationAndDynamicExclusion(t *testing.T) {
	now := time.Now()
	runtime := newImageCacheRuntimeWithLimits(imageCacheMaxProcessBytes, imageCacheMaxSiteBytes, imageCacheTTL, []byte("lifecycle-key"))
	runtime.now = func() time.Time { return now }
	site := runtime.newSite(1)
	target := imageCacheTestTarget(t, "https://media.example")
	calls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("body"))
	})
	_ = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary", nil)
	_ = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary", nil)
	if calls != 1 {
		t.Fatalf("pre-shutdown calls=%d", calls)
	}
	inst := &ProxyInstance{imageCache: site, hijackedConns: make(map[net.Conn]struct{})}
	if err := inst.shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	runtime.mu.Lock()
	remaining := runtime.bytes
	runtime.mu.Unlock()
	if remaining != 0 || !site.closed {
		t.Fatalf("lifecycle retained image cache: bytes=%d closed=%v", remaining, site.closed)
	}
	_ = imageCacheTestRequest(site, target, next, http.MethodGet, "/Items/1/Images/Primary", nil)
	if calls != 2 {
		t.Fatalf("closed cache served stale entry; calls=%d", calls)
	}

	// Update replacement receives a fresh per-instance generation even with the
	// same site ID; stopping/deleting that replacement drops its global entries.
	replacement := runtime.newSite(1)
	_ = imageCacheTestRequest(replacement, target, next, http.MethodGet, "/Items/1/Images/Primary", nil)
	_ = imageCacheTestRequest(replacement, target, next, http.MethodGet, "/Items/1/Images/Primary", nil)
	if calls != 3 {
		t.Fatalf("replacement cache reused stopped state; calls=%d", calls)
	}
	replacement.close()
	runtime.mu.Lock()
	remaining = runtime.bytes
	runtime.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("replacement stop/delete retained %d cache bytes", remaining)
	}

	dynamicSite := runtime.newSite(2)
	_ = imageCacheTestRequest(dynamicSite, target, next, http.MethodGet, dynamicRoutePrefix+"capability", nil)
	_ = imageCacheTestRequest(dynamicSite, target, next, http.MethodGet, dynamicRoutePrefix+"capability", nil)
	if calls != 5 {
		t.Fatalf("dynamic route was cached; calls=%d", calls)
	}
}
