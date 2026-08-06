package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newUnitPingCache(t *testing.T, now func() time.Time, base http.RoundTripper) (*pingCache, http.RoundTripper) {
	t.Helper()
	primary, err := url.Parse("https://PRIMARY.example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	cache, err := newPingCache(41, primary, now)
	if err != nil {
		t.Fatalf("newPingCache: %v", err)
	}
	return cache, &pingCacheTransport{base: base, cache: cache}
}

func newUnitPingRequest(t *testing.T, method, requestURL string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, requestURL, nil)
	route, ok := pingCacheRouteForRequest(req)
	if !ok {
		t.Fatalf("request is not ping-cache eligible: %s %s", method, requestURL)
	}
	return req.WithContext(context.WithValue(req.Context(), pingCacheRequestContextKey{}, route))
}

func unitPingResponse(req *http.Request, status int, header http.Header, body string) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	responseBody := io.ReadCloser(io.NopCloser(strings.NewReader(body)))
	if req.Method == http.MethodHead {
		responseBody = http.NoBody
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Header:        header,
		Body:          responseBody,
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

func readUnitPingResponse(t *testing.T, transport http.RoundTripper, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read response: %v", readErr)
	}
	if closeErr != nil {
		t.Fatalf("close response: %v", closeErr)
	}
	return resp, body
}

func pingCacheEntryCount(cache *pingCache) int {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return len(cache.entries)
}

func TestPingCacheHitMissExpiryAndSafeReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var calls atomic.Int64
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		call := calls.Add(1)
		header := http.Header{
			"Content-Type":        {"text/plain; charset=utf-8"},
			"X-Upstream-Internal": {"not-safe-to-replay"},
		}
		return unitPingResponse(req, http.StatusOK, header, fmt.Sprintf("pong-%d", call)), nil
	})
	cache, transport := newUnitPingCache(t, func() time.Time { return now }, base)

	first, firstBody := readUnitPingResponse(t, transport, newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping?mode=full"))
	if string(firstBody) != "pong-1" || first.Header.Get("X-Upstream-Internal") == "" {
		t.Fatalf("MISS response body=%q headers=%#v", firstBody, first.Header)
	}
	second, secondBody := readUnitPingResponse(t, transport, newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping?mode=full"))
	if string(secondBody) != "pong-1" || calls.Load() != 1 {
		t.Fatalf("HIT body=%q upstream calls=%d", secondBody, calls.Load())
	}
	if second.Header.Get("Content-Type") != "text/plain; charset=utf-8" || second.Header.Get("X-Upstream-Internal") != "" {
		t.Fatalf("safe replay headers=%#v", second.Header)
	}

	represented := newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping?mode=full")
	represented.Header.Set("Accept", "application/json")
	_, representedBody := readUnitPingResponse(t, transport, represented)
	if string(representedBody) != "pong-2" || calls.Load() != 2 {
		t.Fatalf("representation MISS body=%q calls=%d", representedBody, calls.Load())
	}

	now = now.Add(pingCacheTTL - time.Nanosecond)
	_, beforeExpiry := readUnitPingResponse(t, transport, newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping?mode=full"))
	if string(beforeExpiry) != "pong-1" || calls.Load() != 2 {
		t.Fatalf("pre-expiry response=%q calls=%d", beforeExpiry, calls.Load())
	}
	now = now.Add(time.Nanosecond)
	_, expired := readUnitPingResponse(t, transport, newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping?mode=full"))
	if string(expired) != "pong-3" || calls.Load() != 3 {
		t.Fatalf("expired response=%q calls=%d", expired, calls.Load())
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()
	for key := range cache.entries {
		if key.siteID != 41 || key.primaryAuthority != "https://primary.example.test" {
			t.Fatalf("cache key site/authority=%d/%q", key.siteID, key.primaryAuthority)
		}
	}
}

func TestPingCacheReplayAgeTracksResidenceAndOriginFreshness(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	originDate := now.Add(-50 * time.Second)
	var calls atomic.Int64
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		call := calls.Add(1)
		return unitPingResponse(req, http.StatusOK, http.Header{
			"Age":           {"45"},
			"Cache-Control": {"public, max-age=52"},
			"Content-Type":  {"text/plain"},
			"Date":          {originDate.UTC().Format(http.TimeFormat)},
		}, fmt.Sprintf("pong-%d", call)), nil
	})
	_, transport := newUnitPingCache(t, func() time.Time { return now }, base)
	request := func() (*http.Response, []byte) {
		return readUnitPingResponse(t, transport, newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping?mode=age"))
	}

	_, _ = request()
	immediate, body := request()
	if string(body) != "pong-1" || immediate.Header.Get("Age") != "50" || immediate.Header.Get("Date") != originDate.UTC().Format(http.TimeFormat) {
		t.Fatalf("immediate HIT body=%q age=%q date=%q", body, immediate.Header.Get("Age"), immediate.Header.Get("Date"))
	}
	now = now.Add(time.Second)
	resident, body := request()
	if string(body) != "pong-1" || resident.Header.Get("Age") != "51" || calls.Load() != 1 {
		t.Fatalf("resident HIT body=%q age=%q calls=%d", body, resident.Header.Get("Age"), calls.Load())
	}
	now = now.Add(time.Second)
	_, refreshed := request()
	if string(refreshed) != "pong-2" || calls.Load() != 2 {
		t.Fatalf("origin expiry body=%q calls=%d", refreshed, calls.Load())
	}
}

func TestPingCacheCredentialIsolationAndNoRawSecretRetention(t *testing.T) {
	var calls atomic.Int64
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return unitPingResponse(req, http.StatusOK, http.Header{"Content-Type": {"text/plain"}}, "pong"), nil
	})
	cache, transport := newUnitPingCache(t, nil, base)

	makeRequest := func(auth, cookie, embyToken, queryToken, apiKey string, reversed bool) *http.Request {
		rawQuery := "mode=full&api_key=" + url.QueryEscape(queryToken)
		if reversed {
			rawQuery = "api_key=" + url.QueryEscape(queryToken) + "&mode=full"
		}
		req := newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping?"+rawQuery)
		req.Header.Set("Authorization", "Bearer "+auth)
		req.Header.Set("Cookie", "emby_session="+cookie)
		req.Header.Set("X-Api-Key", apiKey)
		req.Header.Set("X-Emby-Token", embyToken)
		req.Header.Set("X-MediaBrowser-Token", "media-"+embyToken)
		req.Header.Set("X-Emby-Authorization", `Emby Client="test", Token="`+embyToken+`"`)
		return req
	}

	secrets := []string{
		"raw-auth-alpha", "raw-cookie-alpha", "raw-emby-alpha", "raw-query-alpha", "raw-api-alpha",
		"raw-auth-beta", "raw-query-beta", "raw-api-beta",
	}
	readUnitPingResponse(t, transport, makeRequest(secrets[0], secrets[1], secrets[2], secrets[3], secrets[4], false))
	readUnitPingResponse(t, transport, makeRequest(secrets[0], secrets[1], secrets[2], secrets[3], secrets[4], true))
	if calls.Load() != 1 {
		t.Fatalf("canonical query order did not HIT: calls=%d", calls.Load())
	}
	readUnitPingResponse(t, transport, makeRequest(secrets[5], secrets[1], secrets[2], secrets[3], secrets[4], false))
	if calls.Load() != 2 {
		t.Fatalf("authorization identity was not isolated: calls=%d", calls.Load())
	}
	readUnitPingResponse(t, transport, makeRequest(secrets[5], secrets[1], secrets[2], secrets[6], secrets[4], false))
	readUnitPingResponse(t, transport, makeRequest(secrets[5], secrets[1], secrets[2], secrets[6], secrets[4], true))
	if calls.Load() != 3 {
		t.Fatalf("query credential identity was not isolated: calls=%d", calls.Load())
	}
	readUnitPingResponse(t, transport, makeRequest(secrets[5], secrets[1], secrets[2], secrets[6], secrets[7], false))
	if calls.Load() != 4 {
		t.Fatalf("X-Api-Key identity was not isolated: calls=%d", calls.Load())
	}

	cache.mu.Lock()
	state := fmt.Sprintf("%#v", cache)
	entryCount := len(cache.entries)
	cache.mu.Unlock()
	if entryCount != 4 {
		t.Fatalf("credential-isolated entries=%d, want 4", entryCount)
	}
	for _, secret := range secrets {
		if strings.Contains(state, secret) {
			t.Fatalf("cache retained raw credential %q", secret)
		}
	}
}

func TestPingCacheRepeatedQueryValueOrderIsSignificant(t *testing.T) {
	var calls atomic.Int64
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return unitPingResponse(req, http.StatusOK, http.Header{"Content-Type": {"text/plain"}}, "pong"), nil
	})
	_, transport := newUnitPingCache(t, nil, base)
	request := func(rawQuery string) {
		readUnitPingResponse(t, transport, newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping?"+rawQuery))
	}

	request("z=last&mode=first&mode=second")
	request("mode=first&mode=second&z=last")
	if calls.Load() != 1 {
		t.Fatalf("key reordering with stable repeated values missed: calls=%d", calls.Load())
	}
	request("mode=second&mode=first&z=last")
	if calls.Load() != 2 {
		t.Fatalf("reversed repeated values shared a cache key: calls=%d", calls.Load())
	}
}

func TestProgressCredentialDigestIncludesForwardedXAPIKey(t *testing.T) {
	runtime := &progressGlobalRuntime{credentialKeyGood: true}
	copy(runtime.credentialKey[:], []byte("fixed-progress-credential-key"))
	digestFor := func(apiKey string) [32]byte {
		req := httptest.NewRequest(http.MethodPost, "http://site.example/Sessions/Playing/Progress", nil)
		req.Header.Set("X-Api-Key", apiKey)
		digest, ok := progressCredentialDigest(runtime, req)
		if !ok {
			t.Fatal("progress credential digest rejected a valid request")
		}
		return digest
	}

	first := digestFor("forwarded-key-alpha")
	if first != digestFor("forwarded-key-alpha") {
		t.Fatal("identical forwarded X-Api-Key values produced different progress identities")
	}
	if first == digestFor("forwarded-key-beta") {
		t.Fatal("distinct forwarded X-Api-Key values shared a progress identity")
	}
}

func TestPingCacheGETHEADAndEligibilityBoundaries(t *testing.T) {
	var calls atomic.Int64
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return unitPingResponse(req, http.StatusOK, http.Header{"Content-Type": {"text/plain"}}, "pong"), nil
	})
	_, transport := newUnitPingCache(t, nil, base)

	_, getBody := readUnitPingResponse(t, transport, newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping"))
	readUnitPingResponse(t, transport, newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping"))
	if string(getBody) != "pong" || calls.Load() != 1 {
		t.Fatalf("GET behavior body=%q calls=%d", getBody, calls.Load())
	}
	head, headBody := readUnitPingResponse(t, transport, newUnitPingRequest(t, http.MethodHead, "https://primary.example.test/System/Ping"))
	_, secondHeadBody := readUnitPingResponse(t, transport, newUnitPingRequest(t, http.MethodHead, "https://primary.example.test/System/Ping"))
	if len(headBody) != 0 || len(secondHeadBody) != 0 || head.ContentLength != 4 || calls.Load() != 2 {
		t.Fatalf("HEAD behavior lengths=%d/%d contentLength=%d calls=%d", len(headBody), len(secondHeadBody), head.ContentLength, calls.Load())
	}
	readUnitPingResponse(t, transport, newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/emby/System/Ping"))
	if calls.Load() != 3 {
		t.Fatalf("route identity was not isolated: calls=%d", calls.Load())
	}

	tests := []struct {
		name   string
		method string
		path   string
		header http.Header
		body   string
		want   bool
	}{
		{name: "system get", method: http.MethodGet, path: "/System/Ping", want: true},
		{name: "emby head", method: http.MethodHead, path: "/emby/System/Ping", want: true},
		{name: "post", method: http.MethodPost, path: "/System/Ping"},
		{name: "case alias", method: http.MethodGet, path: "/system/ping"},
		{name: "trailing slash", method: http.MethodGet, path: "/System/Ping/"},
		{name: "encoded alias", method: http.MethodGet, path: "/%53ystem/Ping"},
		{name: "range", method: http.MethodGet, path: "/System/Ping", header: http.Header{"Range": {"bytes=0-1"}}},
		{name: "if none match", method: http.MethodGet, path: "/System/Ping", header: http.Header{"If-None-Match": {`"etag"`}}},
		{name: "if modified", method: http.MethodGet, path: "/System/Ping", header: http.Header{"If-Modified-Since": {time.Now().UTC().Format(http.TimeFormat)}}},
		{name: "request no cache", method: http.MethodGet, path: "/System/Ping", header: http.Header{"Cache-Control": {"no-cache"}}},
		{name: "request no store", method: http.MethodGet, path: "/System/Ping", header: http.Header{"Cache-Control": {"max-age=10, no-store"}}},
		{name: "pragma", method: http.MethodGet, path: "/System/Ping", header: http.Header{"Pragma": {"no-cache"}}},
		{name: "get body", method: http.MethodGet, path: "/System/Ping", body: "unexpected"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var body io.Reader
			if test.body != "" {
				body = strings.NewReader(test.body)
			}
			req := httptest.NewRequest(test.method, "https://primary.example.test"+test.path, body)
			for name, values := range test.header {
				req.Header[name] = append([]string(nil), values...)
			}
			_, got := pingCacheRouteForRequest(req)
			if got != test.want {
				t.Fatalf("eligibility=%v, want %v", got, test.want)
			}
		})
	}
}

func TestPingCacheSingleflightCoalescesConcurrentMisses(t *testing.T) {
	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	var startOnce sync.Once
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		startOnce.Do(func() { close(started) })
		<-release
		return unitPingResponse(req, http.StatusOK, http.Header{"Content-Type": {"text/plain"}}, "pong"), nil
	})
	cache, transport := newUnitPingCache(t, nil, base)
	const workers = 24
	type result struct {
		body string
		err  error
	}
	results := make(chan result, workers)
	launch := func() {
		req := newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping?mode=singleflight")
		go func() {
			resp, err := transport.RoundTrip(req)
			if err != nil {
				results <- result{err: err}
				return
			}
			payload, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			results <- result{body: string(payload), err: readErr}
		}()
	}
	launch()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("leader never reached upstream")
	}
	probe := newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping?mode=singleflight")
	key, ok := cache.requestKey(probe)
	if !ok {
		t.Fatal("singleflight probe did not produce a key")
	}
	for index := 1; index < workers; index++ {
		launch()
	}
	deadline := time.Now().Add(time.Second)
	for {
		cache.mu.Lock()
		flight := cache.inflight[key]
		waiters := 0
		if flight != nil {
			waiters = flight.waiters
		}
		cache.mu.Unlock()
		if waiters == workers-1 {
			break
		}
		if time.Now().After(deadline) {
			close(release)
			t.Fatalf("singleflight waiters=%d, want %d", waiters, workers-1)
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	for index := 0; index < workers; index++ {
		got := <-results
		if got.err != nil || got.body != "pong" {
			t.Fatalf("worker response body=%q err=%v", got.body, got.err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent upstream calls=%d, want 1", calls.Load())
	}
}

func TestPingCacheLRUBound(t *testing.T) {
	var calls atomic.Int64
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return unitPingResponse(req, http.StatusOK, http.Header{"Content-Type": {"text/plain"}}, "pong"), nil
	})
	cache, transport := newUnitPingCache(t, func() time.Time { return time.Unix(1_700_000_000, 0) }, base)
	request := func(index int) {
		readUnitPingResponse(t, transport, newUnitPingRequest(t, http.MethodGet, fmt.Sprintf("https://primary.example.test/System/Ping?mode=%d", index)))
	}
	for index := 0; index < pingCacheMaxEntries; index++ {
		request(index)
	}
	request(0)
	request(pingCacheMaxEntries)
	if count := pingCacheEntryCount(cache); count != pingCacheMaxEntries {
		t.Fatalf("entry count=%d, want %d", count, pingCacheMaxEntries)
	}
	request(1)
	request(0)
	if calls.Load() != pingCacheMaxEntries+2 {
		t.Fatalf("LRU upstream calls=%d, want %d", calls.Load(), pingCacheMaxEntries+2)
	}
	if count := pingCacheEntryCount(cache); count != pingCacheMaxEntries {
		t.Fatalf("post-eviction entry count=%d", count)
	}
}

type incompletePingBody struct {
	sent bool
	err  error
}

func (body *incompletePingBody) Read(p []byte) (int, error) {
	if !body.sent {
		body.sent = true
		return copy(p, "partial"), nil
	}
	return 0, body.err
}

func (*incompletePingBody) Close() error { return nil }

func TestPingCacheUnsafeIncompleteAndFailedResponsesBypass(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		header  http.Header
		body    string
		trailer http.Header
	}{
		{name: "non 200", status: http.StatusServiceUnavailable, body: "unavailable"},
		{name: "partial", status: http.StatusPartialContent, header: http.Header{"Content-Range": {"bytes 0-3/8"}}, body: "part"},
		{name: "content range on 200", status: http.StatusOK, header: http.Header{"Content-Range": {"bytes 0-3/8"}}, body: "part"},
		{name: "set cookie", status: http.StatusOK, header: http.Header{"Set-Cookie": {"session=secret"}}, body: "pong"},
		{name: "private", status: http.StatusOK, header: http.Header{"Cache-Control": {"private, max-age=60"}}, body: "pong"},
		{name: "no store", status: http.StatusOK, header: http.Header{"Cache-Control": {"public, no-store"}}, body: "pong"},
		{name: "no cache", status: http.StatusOK, header: http.Header{"Cache-Control": {"no-cache"}}, body: "pong"},
		{name: "vary cookie", status: http.StatusOK, header: http.Header{"Vary": {"Cookie"}}, body: "pong"},
		{name: "vary wildcard", status: http.StatusOK, header: http.Header{"Vary": {"*"}}, body: "pong"},
		{name: "vary unknown", status: http.StatusOK, header: http.Header{"Vary": {"X-Unknown-Representation"}}, body: "pong"},
		{name: "trailers", status: http.StatusOK, body: "pong", trailer: http.Header{"Digest": {"sha-256=abc"}}},
		{name: "oversized", status: http.StatusOK, body: strings.Repeat("x", pingCacheMaxBodyBytes+1)},
		{name: "invalid age", status: http.StatusOK, header: http.Header{"Age": {"not-a-number"}}, body: "pong"},
		{name: "overflow age", status: http.StatusOK, header: http.Header{"Age": {strings.Repeat("9", 40)}}, body: "pong"},
		{name: "invalid date", status: http.StatusOK, header: http.Header{"Date": {"not-a-date"}}, body: "pong"},
		{name: "stale max age", status: http.StatusOK, header: http.Header{"Age": {"10"}, "Cache-Control": {"public, max-age=10"}}, body: "pong"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int64
			base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls.Add(1)
				resp := unitPingResponse(req, test.status, test.header.Clone(), test.body)
				resp.Trailer = test.trailer.Clone()
				return resp, nil
			})
			cache, transport := newUnitPingCache(t, nil, base)
			for attempt := 0; attempt < 2; attempt++ {
				_, body := readUnitPingResponse(t, transport, newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping"))
				if string(body) != test.body {
					t.Fatalf("attempt %d body length=%d, want %d", attempt, len(body), len(test.body))
				}
			}
			if calls.Load() != 2 || pingCacheEntryCount(cache) != 0 {
				t.Fatalf("unsafe response calls=%d entries=%d", calls.Load(), pingCacheEntryCount(cache))
			}
		})
	}

	t.Run("round trip failure", func(t *testing.T) {
		var calls atomic.Int64
		base := roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return nil, errors.New("upstream failed")
		})
		cache, transport := newUnitPingCache(t, nil, base)
		for attempt := 0; attempt < 2; attempt++ {
			if _, err := transport.RoundTrip(newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping")); err == nil {
				t.Fatal("upstream failure was hidden")
			}
		}
		if calls.Load() != 2 || pingCacheEntryCount(cache) != 0 {
			t.Fatalf("failure calls=%d entries=%d", calls.Load(), pingCacheEntryCount(cache))
		}
	})

	t.Run("incomplete body", func(t *testing.T) {
		var calls atomic.Int64
		readFailure := errors.New("incomplete upstream body")
		base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls.Add(1)
			return &http.Response{Status: "200 OK", StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: &incompletePingBody{err: readFailure}, ContentLength: -1, Request: req}, nil
		})
		cache, transport := newUnitPingCache(t, nil, base)
		for attempt := 0; attempt < 2; attempt++ {
			resp, err := transport.RoundTrip(newUnitPingRequest(t, http.MethodGet, "https://primary.example.test/System/Ping"))
			if err != nil {
				t.Fatalf("RoundTrip attempt %d: %v", attempt, err)
			}
			payload, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if !errors.Is(err, readFailure) || string(payload) != "partial" {
				t.Fatalf("attempt %d incomplete body=%q err=%v", attempt, payload, err)
			}
		}
		if calls.Load() != 2 || pingCacheEntryCount(cache) != 0 {
			t.Fatalf("incomplete body calls=%d entries=%d", calls.Load(), pingCacheEntryCount(cache))
		}
	})
}

func startPingCacheHostSite(t *testing.T, app *App, targetURL string, enabled bool, mutate ...func(*Site)) (*Site, *ProxyInstance) {
	t.Helper()
	siteRecord := Site{Name: "ping-cache-runtime", ListenPort: freePort(t), PublicHost: "ping-cache.example.test", IngressMode: ingressModeHost, TargetURL: targetURL, PlaybackMode: "direct", StreamHosts: "[]", UAMode: "infuse", PingCacheEnabled: enabled}
	for _, apply := range mutate {
		apply(&siteRecord)
	}
	site, err := app.db.CreateSiteRecord(siteRecord)
	if err != nil {
		t.Fatalf("CreateSiteRecord: %v", err)
	}
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	t.Cleanup(func() { _ = app.pm.StopSite(site.ID) })
	app.pm.mu.RLock()
	inst := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if inst == nil {
		t.Fatal("proxy instance was not installed")
	}
	return site, inst
}

func servePingRuntime(inst *ProxyInstance, method, requestPath string, header http.Header) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(method, "http://ping-cache.example.test"+requestPath, nil)
	for name, values := range header {
		req.Header[name] = append([]string(nil), values...)
	}
	inst.handler.ServeHTTP(recorder, req)
	return recorder
}

func TestPingCacheRuntimeToggleTrafficQuotaAndLifecycleInvalidation(t *testing.T) {
	t.Run("toggle off", func(t *testing.T) {
		app := newTestApp(t)
		var calls atomic.Int64
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); _, _ = io.WriteString(w, "pong") }))
		defer upstream.Close()
		_, inst := startPingCacheHostSite(t, app, upstream.URL, false)
		servePingRuntime(inst, http.MethodGet, "/System/Ping", nil)
		servePingRuntime(inst, http.MethodGet, "/System/Ping", nil)
		if inst.pingCache != nil || calls.Load() != 2 {
			t.Fatalf("disabled cache=%p upstream calls=%d", inst.pingCache, calls.Load())
		}
	})

	t.Run("traffic and quota", func(t *testing.T) {
		app := newTestApp(t)
		var calls atomic.Int64
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); _, _ = io.WriteString(w, "pong") }))
		defer upstream.Close()
		_, inst := startPingCacheHostSite(t, app, upstream.URL, true)
		first := servePingRuntime(inst, http.MethodGet, "/System/Ping", nil)
		second := servePingRuntime(inst, http.MethodGet, "/System/Ping", nil)
		if first.Code != http.StatusOK || second.Code != http.StatusOK || calls.Load() != 1 {
			t.Fatalf("runtime statuses=%d/%d upstream calls=%d", first.Code, second.Code, calls.Load())
		}
		if inst.reqCount.Load() != 2 || inst.bytesOut.Load() != 8 {
			t.Fatalf("runtime accounting requests=%d bytesOut=%d", inst.reqCount.Load(), inst.bytesOut.Load())
		}

		quotaApp := newTestApp(t)
		var quotaCalls atomic.Int64
		quotaUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { quotaCalls.Add(1); _, _ = io.WriteString(w, "pong") }))
		defer quotaUpstream.Close()
		_, quotaInst := startPingCacheHostSite(t, quotaApp, quotaUpstream.URL, true, func(site *Site) { site.TrafficQuota = 4 })
		if got := servePingRuntime(quotaInst, http.MethodGet, "/System/Ping", nil); got.Code != http.StatusOK {
			t.Fatalf("first quota response=%d", got.Code)
		}
		if got := servePingRuntime(quotaInst, http.MethodGet, "/System/Ping", nil); got.Code != http.StatusForbidden {
			t.Fatalf("cached quota response=%d, want 403", got.Code)
		}
		if quotaCalls.Load() != 1 || quotaInst.reqCount.Load() != 2 {
			t.Fatalf("quota upstream calls=%d requests=%d", quotaCalls.Load(), quotaInst.reqCount.Load())
		}
	})

	t.Run("stop update delete", func(t *testing.T) {
		app := newTestApp(t)
		var firstCalls atomic.Int64
		firstUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { firstCalls.Add(1); _, _ = io.WriteString(w, "first") }))
		defer firstUpstream.Close()
		site, firstInst := startPingCacheHostSite(t, app, firstUpstream.URL, true)
		servePingRuntime(firstInst, http.MethodGet, "/System/Ping", nil)
		servePingRuntime(firstInst, http.MethodGet, "/System/Ping", nil)
		if firstCalls.Load() != 1 || pingCacheEntryCount(firstInst.pingCache) != 1 {
			t.Fatalf("first runtime calls=%d entries=%d", firstCalls.Load(), pingCacheEntryCount(firstInst.pingCache))
		}

		var secondCalls atomic.Int64
		secondUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { secondCalls.Add(1); _, _ = io.WriteString(w, "second") }))
		defer secondUpstream.Close()
		updated := *site
		updated.TargetURL = secondUpstream.URL
		if err := app.pm.StartSite(updated); err != nil {
			t.Fatalf("replace site runtime: %v", err)
		}
		if pingCacheEntryCount(firstInst.pingCache) != 0 {
			t.Fatal("updated runtime retained the old cache")
		}
		app.pm.mu.RLock()
		secondInst := app.pm.proxies[site.ID]
		app.pm.mu.RUnlock()
		servePingRuntime(secondInst, http.MethodGet, "/System/Ping", nil)
		servePingRuntime(secondInst, http.MethodGet, "/System/Ping", nil)
		if secondCalls.Load() != 1 {
			t.Fatalf("replacement cache calls=%d", secondCalls.Load())
		}
		if err := app.pm.StopSite(site.ID); err != nil {
			t.Fatalf("StopSite: %v", err)
		}
		if pingCacheEntryCount(secondInst.pingCache) != 0 {
			t.Fatal("stopped runtime retained cache entries")
		}

		if err := app.pm.StartSite(updated); err != nil {
			t.Fatalf("restart site: %v", err)
		}
		app.pm.mu.RLock()
		thirdInst := app.pm.proxies[site.ID]
		app.pm.mu.RUnlock()
		servePingRuntime(thirdInst, http.MethodGet, "/System/Ping", nil)
		if secondCalls.Load() != 2 {
			t.Fatalf("restart reused stopped cache: calls=%d", secondCalls.Load())
		}
		deleted := httptest.NewRecorder()
		app.handleSiteByID(deleted, httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/sites/%d", site.ID), nil))
		if deleted.Code != http.StatusOK {
			t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
		}
		if pingCacheEntryCount(thirdInst.pingCache) != 0 {
			t.Fatal("deleted runtime retained cache entries")
		}
	})
}

func TestPingCacheDoesNotInterfereWithDynamicDiscovery(t *testing.T) {
	app := newTestApp(t)
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.URL.Path != "/Items/1/PlaybackInfo" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"MediaSources":[{"DirectStreamUrl":"https://cdn.example.com/movie.mp4?token=discovery-secret"}]}`)
	}))
	defer upstream.Close()

	site, err := app.db.CreateSiteRecord(Site{Name: "ping-cache-discovery", ListenPort: freePort(t), PublicHost: "ping-discovery.example.test", IngressMode: ingressModeHost, TargetURL: upstream.URL, PlaybackMode: "direct", StreamHosts: "[]", UAMode: "infuse", PingCacheEnabled: true, DynamicDiscoveryEnabled: true, DynamicProfile: dynamicProfileCompatible, DynamicDiscoverySources: allDynamicDiscoverySources()})
	if err != nil {
		t.Fatalf("CreateSiteRecord: %v", err)
	}
	key := bytes.Repeat([]byte{0x71}, 32)
	if err := app.pm.ConfigureDynamicDiscovery(key, "panel.example.test", 9090, func() ([]net.Addr, error) { return nil, nil }); err != nil {
		t.Fatalf("ConfigureDynamicDiscovery: %v", err)
	}
	app.pm.dynamicRuntime.resolver = dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	})
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	defer app.pm.StopSite(site.ID)
	app.pm.mu.RLock()
	inst := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()

	for attempt := 0; attempt < 2; attempt++ {
		response := servePingRuntime(inst, http.MethodGet, "/Items/1/PlaybackInfo", nil)
		text := response.Body.String()
		if response.Code != http.StatusOK || !strings.Contains(text, dynamicRoutePrefix) || strings.Contains(text, "cdn.example.com") || strings.Contains(text, "discovery-secret") {
			t.Fatalf("discovery attempt %d status=%d body=%s", attempt, response.Code, text)
		}
	}
	if upstreamCalls.Load() != 2 || pingCacheEntryCount(inst.pingCache) != 0 {
		t.Fatalf("discovery upstream calls=%d ping entries=%d", upstreamCalls.Load(), pingCacheEntryCount(inst.pingCache))
	}
	servePingRuntime(inst, http.MethodGet, dynamicRoutePrefix+"not-a-valid-capability", nil)
	if upstreamCalls.Load() != 2 || pingCacheEntryCount(inst.pingCache) != 0 {
		t.Fatalf("reserved dynamic route reached ping/upstream: calls=%d entries=%d", upstreamCalls.Load(), pingCacheEntryCount(inst.pingCache))
	}
}
