package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type securityDeadlineWriter struct {
	header    http.Header
	deadlines []time.Time
}

func (w *securityDeadlineWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *securityDeadlineWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (w *securityDeadlineWriter) WriteHeader(int) {}

func (w *securityDeadlineWriter) SetReadDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func startSecurityHostSite(t *testing.T, targetURL, playbackTargetURL, playbackMode, publicHost string) http.Handler {
	t.Helper()
	app := newTestApp(t)
	site, err := app.db.CreateSiteRecord(Site{
		Name:              "security-regression-site",
		ListenPort:        freePort(t),
		PublicHost:        publicHost,
		IngressMode:       ingressModeHost,
		TargetURL:         targetURL,
		PlaybackTargetURL: playbackTargetURL,
		PlaybackMode:      playbackMode,
		StreamHosts:       "[]",
		UAMode:            passthroughUAMode,
	})
	if err != nil {
		t.Fatalf("CreateSiteRecord: %v", err)
	}
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	t.Cleanup(func() {
		if err := app.pm.StopSite(site.ID); err != nil {
			t.Errorf("StopSite: %v", err)
		}
	})
	handler, configured := app.pm.PublicHostHandler(publicHost)
	if !configured || handler == nil {
		t.Fatalf("public host %q has no active handler", publicHost)
	}
	return handler
}

func TestSecurityRegressionVendorForwardingHeadersAreStrippedFromHTTPAndWebSocket(t *testing.T) {
	vendorHeaders := []string{
		"CF-Connecting-IP",
		"CF-Connecting-IPv6",
		"Fastly-Client-IP",
		"Fly-Client-IP",
		"True-Client-IP",
		"X-Appengine-User-IP",
		"X-Azure-ClientIP",
		"X-Client-IP",
		"X-Cluster-Client-IP",
		"X-Envoy-External-Address",
		"X-Original-Forwarded-For",
	}

	newRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://media.example.com/socket", nil)
		req.RemoteAddr = "198.51.100.23:45678"
		for _, name := range vendorHeaders {
			req.Header.Set(name, "203.0.113.99")
		}
		return req
	}
	assertSanitized := func(t *testing.T, header http.Header) {
		t.Helper()
		for _, name := range vendorHeaders {
			if got := header.Get(name); got != "" {
				t.Errorf("%s survived forwarding-header sanitization: %q", name, got)
			}
		}
		for _, name := range []string{"X-Real-IP", "X-Forwarded-For"} {
			if got := header.Get(name); got != "198.51.100.23" {
				t.Errorf("%s = %q, want transport peer", name, got)
			}
		}
	}

	t.Run("HTTP", func(t *testing.T) {
		req := newRequest()
		header := req.Header.Clone()
		prepareUpstreamHeaders(header, req, UAHeaderPolicy{})
		assertSanitized(t, header)
	})

	t.Run("WebSocket", func(t *testing.T) {
		req := newRequest()
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		target, err := url.Parse("https://origin.example.com/emby")
		if err != nil {
			t.Fatal(err)
		}
		header := prepareWebSocketUpstreamHeaders(req, target, UAHeaderPolicy{})
		assertSanitized(t, header)
	})
}

func TestSecurityRegressionFixedHeadersRejectAuthAndForwardingIdentity(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	value := "must-not-be-configurable"
	for _, name := range []string{
		"X-MediaBrowser-Token",
		"CF-Connecting-IP",
		"True-Client-IP",
		"X-Client-IP",
		"X-Forwarded-For",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := mergeUpstreamHeaders(
				"[]",
				[]UpstreamHeaderInput{{Name: name, Value: &value}},
				key,
				"https://origin.example.com/emby",
			)
			if err == nil {
				t.Fatalf("managed header %s was accepted as a fixed upstream header", name)
			}
		})
	}
}

func TestSecurityRegressionAuthClientKeyNeverTrustsForwardedForChain(t *testing.T) {
	_, trustedNetwork, err := net.ParseCIDR("172.17.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	trusted := []*net.IPNet{trustedNetwork}

	for _, tc := range []struct {
		name    string
		realIP  string
		wantKey string
	}{
		{name: "missing normalized real IP", wantKey: "172.17.0.1"},
		{name: "invalid normalized real IP", realIP: "not-an-ip", wantKey: "172.17.0.1"},
		{name: "multiple real IP values", realIP: "203.0.113.25, 198.51.100.7", wantKey: "172.17.0.1"},
		{name: "valid normalized real IP", realIP: "203.0.113.25", wantKey: "203.0.113.25"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
			req.RemoteAddr = "172.17.0.1:45678"
			req.Header.Set("X-Forwarded-For", "198.51.100.77, 203.0.113.25")
			if tc.realIP != "" {
				req.Header.Set("X-Real-IP", tc.realIP)
			}
			if got := requestClientKey(req, trusted); got != tc.wantKey {
				t.Fatalf("requestClientKey = %q, want %q", got, tc.wantKey)
			}
		})
	}
}

func TestSecurityRegressionLoopbackHealthExceptionRejectsForwardedRequests(t *testing.T) {
	app := &App{pm: NewProxyManager(nil, nil), panelHost: "panel.example.com"}
	var panelCalls atomic.Int64
	router := app.publicHostRouter(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		panelCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))

	direct := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/api/auth/check", nil)
	direct.RemoteAddr = "127.0.0.1:54321"
	directResponse := httptest.NewRecorder()
	router.ServeHTTP(directResponse, direct)
	if directResponse.Code != http.StatusNoContent || panelCalls.Load() != 1 {
		t.Fatalf("direct loopback health check status=%d panel_calls=%d", directResponse.Code, panelCalls.Load())
	}

	for _, name := range []string{"X-Real-IP", "X-Forwarded-For", "CF-Connecting-IP"} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/api/auth/check", nil)
			req.RemoteAddr = "127.0.0.1:54321"
			req.Header.Set(name, "198.51.100.8")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusMisdirectedRequest {
				t.Fatalf("forwarded loopback health check status=%d, want 421", rr.Code)
			}
			if got := panelCalls.Load(); got != 1 {
				t.Fatalf("forwarded loopback health check reached panel; calls=%d", got)
			}
		})
	}
}

func TestSecurityRegressionReservedDynamicRouteIsNotFoundAndNotCacheable(t *testing.T) {
	app := newTestApp(t)
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	site, err := app.db.CreateSiteRecord(Site{
		Name:         "reserved-security-regression",
		ListenPort:   freePort(t),
		PublicHost:   "reserved-security.example.com",
		IngressMode:  ingressModeHost,
		TargetURL:    upstream.URL,
		PlaybackMode: "direct",
		StreamHosts:  "[]",
		UAMode:       "infuse",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := app.pm.StopSite(site.ID); err != nil {
			t.Errorf("StopSite: %v", err)
		}
	})

	handler, configured := app.pm.PublicHostHandler(site.PublicHost)
	if !configured || handler == nil {
		t.Fatal("host-only site handler was not registered")
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/_meridian/d/stale-token", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("reserved route status=%d, want 404", rr.Code)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("reserved route Cache-Control=%q, want no-store", got)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("reserved route reached upstream %d times", got)
	}
}

func TestSecurityRegressionDirectPlaybackCredentialsRespectAuthorityBoundary(t *testing.T) {
	setClientHeaders := func(req *http.Request) {
		req.Header.Set("Cookie", "emby_session=application-secret; "+sessionCookieName+"=panel-secret")
		req.Header.Set("Authorization", "Bearer application-bearer")
		req.Header.Set("X-Emby-Token", "emby-token")
		req.Header.Set("X-MediaBrowser-Token", "media-browser-token")
		req.Header.Set("X-Emby-Authorization", `MediaBrowser Device="TV", Token="embedded-token", Client="Security Test", Version="1.0"`)
		req.Header.Set("X-Api-Key", "arbitrary-api-key")
		req.Header.Set("Range", "bytes=0-99")
		req.Header.Set("User-Agent", "Meridian-Security-Test/1.0")
	}

	t.Run("cross authority strips credentials", func(t *testing.T) {
		var primaryCalls atomic.Int64
		primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			primaryCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer primary.Close()

		playbackHeaders := make(chan http.Header, 1)
		playback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			playbackHeaders <- r.Header.Clone()
			_, _ = w.Write([]byte("playback"))
		}))
		defer playback.Close()

		handler := startSecurityHostSite(
			t,
			primary.URL,
			playback.URL,
			"direct",
			"cross-playback-security.example.test",
		)
		req := httptest.NewRequest(http.MethodGet, "http://cross-playback-security.example.test/Videos/1/stream", nil)
		setClientHeaders(req)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("direct playback status=%d body=%q", rr.Code, rr.Body.String())
		}
		if got := primaryCalls.Load(); got != 0 {
			t.Fatalf("playback request reached primary %d times", got)
		}

		var header http.Header
		select {
		case header = <-playbackHeaders:
		case <-time.After(2 * time.Second):
			t.Fatal("playback upstream did not receive the request")
		}
		for _, name := range []string{
			"Cookie",
			"Authorization",
			"X-Emby-Token",
			"X-MediaBrowser-Token",
			"X-Api-Key",
		} {
			if got := header.Get(name); got != "" {
				t.Errorf("cross-authority %s leaked: %q", name, got)
			}
		}
		if got := header.Get("X-Emby-Authorization"); strings.Contains(strings.ToLower(got), "token=") || strings.Contains(got, "embedded-token") {
			t.Errorf("cross-authority X-Emby-Authorization retained a token: %q", got)
		}
		if got := header.Get("Range"); got != "bytes=0-99" {
			t.Errorf("Range=%q, want bytes=0-99", got)
		}
		if got := header.Get("User-Agent"); got != "Meridian-Security-Test/1.0" {
			t.Errorf("User-Agent=%q, want passthrough value", got)
		}
	})

	t.Run("same authority preserves application credentials", func(t *testing.T) {
		received := make(chan struct {
			path   string
			header http.Header
		}, 1)
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			received <- struct {
				path   string
				header http.Header
			}{path: r.URL.Path, header: r.Header.Clone()}
			_, _ = w.Write([]byte("playback"))
		}))
		defer upstream.Close()

		handler := startSecurityHostSite(
			t,
			upstream.URL+"/api",
			upstream.URL+"/playback",
			"direct",
			"same-playback-security.example.test",
		)
		req := httptest.NewRequest(http.MethodGet, "http://same-playback-security.example.test/Videos/1/stream", nil)
		setClientHeaders(req)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("direct playback status=%d body=%q", rr.Code, rr.Body.String())
		}

		var got struct {
			path   string
			header http.Header
		}
		select {
		case got = <-received:
		case <-time.After(2 * time.Second):
			t.Fatal("same-authority upstream did not receive the request")
		}
		if got.path != "/playback/Videos/1/stream" {
			t.Errorf("playback path=%q, want /playback/Videos/1/stream", got.path)
		}
		if cookie := got.header.Get("Cookie"); !strings.Contains(cookie, "emby_session=application-secret") || strings.Contains(cookie, sessionCookieName) {
			t.Errorf("same-authority Cookie=%q, want application cookie without panel session", cookie)
		}
		for name, want := range map[string]string{
			"Authorization":        "Bearer application-bearer",
			"X-Emby-Token":         "emby-token",
			"X-MediaBrowser-Token": "media-browser-token",
			"X-Api-Key":            "arbitrary-api-key",
			"Range":                "bytes=0-99",
			"User-Agent":           "Meridian-Security-Test/1.0",
			"X-Emby-Authorization": `MediaBrowser Device="TV", Token="embedded-token", Client="Security Test", Version="1.0"`,
		} {
			if value := got.header.Get(name); value != want {
				t.Errorf("same-authority %s=%q, want %q", name, value, want)
			}
		}
	})
}

func TestSecurityRegressionCrossAuthorityWebSocketHeadersPreserveHandshakeOnly(t *testing.T) {
	source := make(http.Header)
	source.Set("Connection", "keep-alive, Upgrade")
	source.Set("Upgrade", "websocket")
	source.Set("Origin", "https://media.example.test")
	source.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	source.Set("Sec-WebSocket-Version", "13")
	source.Set("Sec-WebSocket-Protocol", "emby")
	source.Set("Sec-WebSocket-Extensions", "permessage-deflate")
	source.Set("Cookie", "emby_session=secret")
	source.Set("Authorization", "Bearer secret")
	source.Set("X-Emby-Token", "emby-token")
	source.Set("X-MediaBrowser-Token", "media-token")
	source.Set("X-Emby-Authorization", `MediaBrowser Device="TV", Token="embedded-token", Client="Security Test"`)
	source.Set("X-Api-Key", "arbitrary-secret")
	source.Set("Range", "bytes=100-199")
	source.Set("User-Agent", "Meridian-WS-Security-Test/1.0")

	header := crossAuthorityWebSocketHeaders(source)
	for name, want := range map[string]string{
		"Connection":               "Upgrade",
		"Upgrade":                  "websocket",
		"Origin":                   "https://media.example.test",
		"Sec-WebSocket-Key":        "dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Version":    "13",
		"Sec-WebSocket-Protocol":   "emby",
		"Sec-WebSocket-Extensions": "permessage-deflate",
		"Range":                    "bytes=100-199",
		"User-Agent":               "Meridian-WS-Security-Test/1.0",
	} {
		if got := header.Get(name); got != want {
			t.Errorf("%s=%q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"Cookie", "Authorization", "X-Emby-Token", "X-MediaBrowser-Token", "X-Api-Key"} {
		if got := header.Get(name); got != "" {
			t.Errorf("cross-authority WebSocket %s leaked: %q", name, got)
		}
	}
	if got := header.Get("X-Emby-Authorization"); strings.Contains(strings.ToLower(got), "token=") || strings.Contains(got, "embedded-token") {
		t.Errorf("cross-authority WebSocket authorization retained a token: %q", got)
	}
}

func TestSecurityRegressionInvalidUpgradeNeverReachesUpstream(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", "websocket")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer upstream.Close()

	handler := startSecurityHostSite(
		t,
		upstream.URL,
		"",
		"direct",
		"upgrade-security.example.test",
	)
	for _, tc := range []struct {
		name       string
		connection string
		upgrade    string
		key        string
	}{
		{name: "websocket without key", connection: "Upgrade", upgrade: "websocket"},
		{name: "unsupported protocol", connection: "keep-alive, Upgrade", upgrade: "h2c", key: "unused-key"},
		{name: "upgrade header without connection token", connection: "keep-alive", upgrade: "websocket", key: "unused-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://upgrade-security.example.test/socket", nil)
			req.Header.Set("Connection", tc.connection)
			req.Header.Set("Upgrade", tc.upgrade)
			if tc.key != "" {
				req.Header.Set("Sec-WebSocket-Key", tc.key)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%q, want 400", rr.Code, rr.Body.String())
			}
		})
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("invalid upgrades reached upstream %d times", got)
	}
}

func TestSecurityRegressionPanelBodyDeadlineIsNotClearedAfterHandler(t *testing.T) {
	writer := &securityDeadlineWriter{}
	handlerCalled := false
	handler := panelBodyReadDeadline(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://panel.example.test/api/auth/login", strings.NewReader(`{"username":"admin"}`))
	started := time.Now()
	handler.ServeHTTP(writer, req)

	if !handlerCalled {
		t.Fatal("wrapped panel handler was not called")
	}
	if len(writer.deadlines) != 1 {
		t.Fatalf("SetReadDeadline calls=%d, want exactly one non-clearing call", len(writer.deadlines))
	}
	if writer.deadlines[0].IsZero() {
		t.Fatal("panel body read deadline was cleared to zero")
	}
	if writer.deadlines[0].Before(started.Add(25 * time.Second)) {
		t.Fatalf("panel body read deadline=%v, want roughly 30 seconds after start", writer.deadlines[0])
	}
}
