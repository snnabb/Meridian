package main

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"meridian/web"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

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

func mustUserCount(t *testing.T, db *DB) int {
	t.Helper()
	count, err := db.UserCount()
	if err != nil {
		t.Fatalf("UserCount: %v", err)
	}
	return count
}

func stringPointer(value string) *string {
	return &value
}

func TestNormalizeCustomUAConfig(t *testing.T) {
	mode, userAgent, client, version, err := normalizeUAConfig(" CUSTOM ", "  Meridian/$1  ", "  Custom Client  ", " 1.2.3 ")
	if err != nil {
		t.Fatalf("normalize custom config: %v", err)
	}
	if mode != customUAMode || userAgent != "Meridian/$1" || client != "Custom Client" || version != "1.2.3" {
		t.Fatalf("normalized custom config = %#v %#v %#v %#v", mode, userAgent, client, version)
	}

	for _, tc := range []struct {
		name      string
		userAgent string
		client    string
		version   string
	}{
		{"missing user agent", "", "Client", "1.0"},
		{"missing client", "UA", "", "1.0"},
		{"missing version", "UA", "Client", ""},
		{"whitespace only", " ", "Client", "1.0"},
		{"too long user agent", strings.Repeat("a", maxCustomUserAgentLen+1), "Client", "1.0"},
		{"too long client", "UA", strings.Repeat("a", maxCustomClientLen+1), "1.0"},
		{"too long version", "UA", "Client", strings.Repeat("a", maxCustomVersionLen+1)},
		{"new line", "UA\nnext", "Client", "1.0"},
		{"non ascii", "UA", "Clïent", "1.0"},
		{"client quote", "UA", "Client\"", "1.0"},
		{"version backslash", "UA", "Client", "1\\0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, _, err := normalizeUAConfig("custom", tc.userAgent, tc.client, tc.version); err == nil {
				t.Fatal("invalid custom UA configuration unexpectedly accepted")
			}
		})
	}

	mode, userAgent, client, version, err = normalizeUAConfig("web", "stale", "stale", "stale")
	if err != nil {
		t.Fatalf("normalize preset config: %v", err)
	}
	if mode != "web" || userAgent != "" || client != "" || version != "" {
		t.Fatalf("preset did not clear custom fields: %#v %#v %#v %#v", mode, userAgent, client, version)
	}
}

func TestMergeSiteUAConfigUsesCompleteSnapshots(t *testing.T) {
	old := Site{
		UAMode:          customUAMode,
		CustomUserAgent: "Old UA",
		CustomClient:    "Old Client",
		CustomVersion:   "1.0",
	}

	mode, userAgent, client, version, err := mergeSiteUAConfig(old, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("preserve existing custom config: %v", err)
	}
	if mode != customUAMode || userAgent != "Old UA" || client != "Old Client" || version != "1.0" {
		t.Fatalf("preserved config = %#v %#v %#v %#v", mode, userAgent, client, version)
	}

	if _, _, _, _, err := mergeSiteUAConfig(old, stringPointer(customUAMode), nil, nil, nil); err == nil {
		t.Fatal("custom mode without its full triplet unexpectedly accepted")
	}
	if _, _, _, _, err := mergeSiteUAConfig(old, nil, stringPointer("New UA"), nil, stringPointer("2.0")); err == nil {
		t.Fatal("partial custom triplet unexpectedly accepted")
	}

	mode, userAgent, client, version, err = mergeSiteUAConfig(old, stringPointer("web"), stringPointer(""), stringPointer(""), stringPointer(""))
	if err != nil {
		t.Fatalf("switch to preset: %v", err)
	}
	if mode != "web" || userAgent != "" || client != "" || version != "" {
		t.Fatalf("preset switch did not clear custom values: %#v %#v %#v %#v", mode, userAgent, client, version)
	}
}

func createLegacySiteDatabase(t *testing.T, dbPath string, withHourlyIndex bool) {
	t.Helper()
	legacy, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	t.Cleanup(func() { legacy.Close() })

	if _, err := legacy.Exec("CREATE TABLE sites (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, listen_port INTEGER NOT NULL UNIQUE, target_url TEXT NOT NULL, ua_mode TEXT DEFAULT 'infuse', enabled INTEGER DEFAULT 1, traffic_quota BIGINT DEFAULT 0, traffic_used BIGINT DEFAULT 0, speed_limit INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)"); err != nil {
		t.Fatalf("create legacy sites: %v", err)
	}
	if _, err := legacy.Exec("CREATE TABLE traffic_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, site_id INTEGER NOT NULL, bytes_in BIGINT DEFAULT 0, bytes_out BIGINT DEFAULT 0, recorded_at DATETIME NOT NULL)"); err != nil {
		t.Fatalf("create legacy traffic logs: %v", err)
	}
	if _, err := legacy.Exec("INSERT INTO sites (name, listen_port, target_url, ua_mode, enabled, traffic_quota, traffic_used, speed_limit) VALUES ('legacy', 19001, 'http://127.0.0.1:8096', 'infuse', 1, 0, 0, 0)"); err != nil {
		t.Fatalf("insert legacy site: %v", err)
	}
	if withHourlyIndex {
		if _, err := legacy.Exec("CREATE UNIQUE INDEX idx_traffic_site_hour ON traffic_logs(site_id, recorded_at)"); err != nil {
			t.Fatalf("create legacy hourly index: %v", err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
}

func TestOpenDBPreservesDataAndConnectionPragmas(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "persistent.db")
	db, err := openDB(dbPath)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if _, err := db.db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", "persisted-admin", "hash"); err != nil {
		db.Close()
		t.Fatalf("insert persisted user: %v", err)
	}
	db.Close()

	db, err = openDB(dbPath)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer db.Close()

	var journalMode string
	if err := db.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("read journal mode: %v", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		t.Fatalf("journal mode = %q, want WAL", journalMode)
	}

	var busyTimeout int
	if err := db.db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("read busy timeout: %v", err)
	}
	if busyTimeout != 5000 {
		t.Fatalf("busy timeout = %d, want 5000", busyTimeout)
	}

	var userCount int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM users WHERE username=?", "persisted-admin").Scan(&userCount); err != nil {
		t.Fatalf("read persisted user: %v", err)
	}
	if userCount != 1 {
		t.Fatalf("persisted user count = %d, want 1", userCount)
	}
}

func TestMigrateAddsCustomUAColumnsForLegacyDatabases(t *testing.T) {
	for _, withHourlyIndex := range []bool{false, true} {
		t.Run(fmt.Sprintf("hourly index=%v", withHourlyIndex), func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "legacy.db")
			createLegacySiteDatabase(t, dbPath, withHourlyIndex)

			db, err := openDB(dbPath)
			if err != nil {
				t.Fatalf("migrate legacy database: %v", err)
			}
			defer db.Close()

			for _, column := range []string{"playback_target_url", "playback_mode", "stream_hosts", "custom_user_agent", "custom_client", "custom_version"} {
				var count int
				if err := db.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('sites') WHERE name=?", column).Scan(&count); err != nil {
					t.Fatalf("inspect %s: %v", column, err)
				}
				if count != 1 {
					t.Fatalf("column %s count=%d, want 1", column, count)
				}
			}
			site, err := db.GetSite(1)
			if err != nil {
				t.Fatalf("read migrated site: %v", err)
			}
			if site.UAMode != "infuse" || site.CustomUserAgent != "" || site.CustomClient != "" || site.CustomVersion != "" {
				t.Fatalf("migrated site UA config = %#v", site)
			}
		})
	}
}

func TestMigrateSerializesConcurrentLegacyDatabaseOpens(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "concurrent-legacy.db")
	createLegacySiteDatabase(t, dbPath, false)

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			db, err := openDB(dbPath)
			if err == nil {
				db.Close()
			}
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent migration: %v", err)
		}
	}
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

func TestResolveJWTSecretRequiresSufficientEntropy(t *testing.T) {
	if _, _, err := resolveJWTSecret("too-short"); err == nil {
		t.Fatal("short JWT_SECRET unexpectedly accepted")
	}
	configured := strings.Repeat("x", 32)
	secret, ephemeral, err := resolveJWTSecret(configured)
	if err != nil {
		t.Fatalf("resolveJWTSecret configured value: %v", err)
	}
	if ephemeral || string(secret) != configured {
		t.Fatalf("configured JWT secret not preserved")
	}
}

func TestTLSIssuerNameFallsBackSafely(t *testing.T) {
	name := tlsIssuerName(nil)
	if name != "" {
		t.Fatalf("nil issuer name = %q, want empty", name)
	}
}

func TestSecureTLSConfigEnablesVerification(t *testing.T) {
	config := secureTLSConfig("emby.example.com")
	if config.InsecureSkipVerify {
		t.Fatal("TLS certificate verification must remain enabled")
	}
	if config.ServerName != "emby.example.com" {
		t.Fatalf("ServerName = %q, want emby.example.com", config.ServerName)
	}
	if config.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %d, want TLS 1.2", config.MinVersion)
	}
}

func TestNormalizeTargetURLRejectsUnsafeForms(t *testing.T) {
	for _, target := range []string{
		"file://server/path",
		"http://user:password@example.com",
		"https://example.com/path#fragment",
		"http://example.com:70000",
	} {
		if _, err := normalizeTargetURL(target); err == nil {
			t.Errorf("normalizeTargetURL(%q) unexpectedly succeeded", target)
		}
	}

	target, err := normalizeTargetURL("example.com:8096")
	if err != nil {
		t.Fatalf("normalizeTargetURL valid target: %v", err)
	}
	if target.String() != "http://example.com:8096" {
		t.Fatalf("normalized target = %q, want http://example.com:8096", target)
	}
}

func TestNormalizeTargetURLInfersHTTPSForPort443(t *testing.T) {
	for _, input := range []string{"example.com:443", "example.com：443"} {
		target, err := normalizeTargetURL(input)
		if err != nil {
			t.Fatalf("normalizeTargetURL(%q): %v", input, err)
		}
		if target.String() != "https://example.com:443" {
			t.Fatalf("normalizeTargetURL(%q) = %q, want https://example.com:443", input, target)
		}
	}

	explicitHTTP, err := normalizeTargetURL("http://example.com:443")
	if err != nil {
		t.Fatalf("normalize explicit HTTP target: %v", err)
	}
	if explicitHTTP.Scheme != "http" {
		t.Fatalf("explicit HTTP scheme = %q, want http", explicitHTTP.Scheme)
	}
}

func TestRedirectModeTreatsExplicit443AsDefaultHTTPSPort(t *testing.T) {
	configured, err := normalizeTargetURL("media.example.com:443")
	if err != nil {
		t.Fatalf("normalize configured playback target: %v", err)
	}
	if got := redirectHostKey(configured); got != "https://media.example.com" {
		t.Fatalf("redirect host key = %q, want https://media.example.com", got)
	}

	calls := 0
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"https://media.example.com/Videos/1/stream"}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("proxied")),
			Request:    req,
		}, nil
	})
	transport := &redirectFollowTransport{
		base:          base,
		playbackHosts: map[string]bool{redirectHostKey(configured): true},
		profile:       getUAProfile("infuse"),
	}
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/Videos/1/stream", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	if calls != 2 || resp.StatusCode != http.StatusOK {
		t.Fatalf("redirect follow calls=%d status=%d, want calls=2 status=200", calls, resp.StatusCode)
	}
	if got := resp.Request.URL.String(); got != "https://media.example.com/Videos/1/stream" {
		t.Fatalf("followed URL = %q", got)
	}

	t.Run("rejects scheme downgrade", func(t *testing.T) {
		calls := 0
		base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"http://media.example.com/Videos/1/stream"}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		})
		transport := &redirectFollowTransport{
			base:          base,
			playbackHosts: map[string]bool{redirectHostKey(configured): true},
			profile:       getUAProfile("infuse"),
		}
		req := httptest.NewRequest(http.MethodGet, "http://api.example.com/Videos/1/stream", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		defer resp.Body.Close()
		if calls != 1 || resp.StatusCode != http.StatusFound {
			t.Fatalf("downgrade redirect calls=%d status=%d, want calls=1 status=302", calls, resp.StatusCode)
		}
	})

	t.Run("follows custom GET redirect path", func(t *testing.T) {
		calls := 0
		base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return &http.Response{
					StatusCode: http.StatusFound,
					Header:     http.Header{"Location": []string{"https://media.example.com/custom/play/path"}},
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    req,
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("proxied")),
				Request:    req,
			}, nil
		})
		transport := &redirectFollowTransport{
			base:          base,
			playbackHosts: map[string]bool{redirectHostKey(configured): true},
			profile:       getUAProfile("infuse"),
		}
		req := httptest.NewRequest(http.MethodGet, "http://api.example.com/custom/play/path", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		defer resp.Body.Close()
		if calls != 2 || resp.StatusCode != http.StatusOK {
			t.Fatalf("custom redirect calls=%d status=%d, want calls=2 status=200", calls, resp.StatusCode)
		}
	})

	t.Run("follows protocol-relative redirect", func(t *testing.T) {
		calls := 0
		base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return &http.Response{
					StatusCode: http.StatusFound,
					Header:     http.Header{"Location": []string{"//media.example.com/custom/play/path"}},
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    req,
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("proxied")),
				Request:    req,
			}, nil
		})
		transport := &redirectFollowTransport{
			base:          base,
			playbackHosts: map[string]bool{redirectHostKey(configured): true},
			profile:       getUAProfile("infuse"),
		}
		req := httptest.NewRequest(http.MethodGet, "https://api.example.com/custom/play/path", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		defer resp.Body.Close()
		if calls != 2 || resp.StatusCode != http.StatusOK {
			t.Fatalf("protocol-relative redirect calls=%d status=%d, want calls=2 status=200", calls, resp.StatusCode)
		}
		if got := resp.Request.URL.String(); got != "https://media.example.com/custom/play/path" {
			t.Fatalf("protocol-relative redirect URL = %q", got)
		}
	})

	t.Run("does not follow POST request", func(t *testing.T) {
		calls := 0
		base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Header:     http.Header{"Location": []string{"https://media.example.com/Users/AuthenticateByName"}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		})
		transport := &redirectFollowTransport{
			base:          base,
			playbackHosts: map[string]bool{redirectHostKey(configured): true},
			profile:       getUAProfile("infuse"),
		}
		req := httptest.NewRequest(http.MethodPost, "http://api.example.com/Users/AuthenticateByName", strings.NewReader(`{"Username":"test"}`))
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		defer resp.Body.Close()
		if calls != 1 || resp.StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("API redirect calls=%d status=%d, want calls=1 status=307", calls, resp.StatusCode)
		}
	})
}

func TestReverseProxyRebuildsForwardingHeadersAfterHopHeaderRemoval(t *testing.T) {
	target, err := normalizeTargetURL("https://upstream.example.com/emby")
	if err != nil {
		t.Fatalf("normalize target: %v", err)
	}
	profile := getUAProfile("infuse")
	var captured *http.Request
	proxy := &httputil.ReverseProxy{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			captured = req.Clone(req.Context())
			captured.Header = req.Header.Clone()
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}),
		Rewrite: func(proxyReq *httputil.ProxyRequest) {
			applyUpstreamURL(proxyReq.Out.URL, target)
			proxyReq.Out.Host = target.Host
			prepareUpstreamHeaders(proxyReq.Out.Header, proxyReq.In, profile)
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://meridian.example:50001/Videos/1/stream", nil)
	req.RemoteAddr = "198.51.100.24:43210"
	req.Header.Set("Connection", "User-Agent, X-Forwarded-For")
	req.Header.Set("User-Agent", "attacker-controlled")
	req.Header.Set("Forwarded", "for=203.0.113.8;proto=https")
	req.Header.Set("X-Forwarded-For", "203.0.113.8")
	req.Header.Set("X-Forwarded-Host", "attacker.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Custom", "must-not-pass")
	req.Header.Set("X-Real-IP", "203.0.113.9")
	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if captured == nil {
		t.Fatal("transport did not receive an outbound request")
	}
	if captured.URL.String() != "https://upstream.example.com/emby/Videos/1/stream" {
		t.Fatalf("outbound URL = %q", captured.URL.String())
	}
	if captured.Host != target.Host {
		t.Fatalf("outbound Host = %q, want %q", captured.Host, target.Host)
	}
	if got := captured.Header.Get("User-Agent"); got != profile.UserAgent {
		t.Fatalf("outbound User-Agent = %q, want profile value %q", got, profile.UserAgent)
	}
	for name, want := range map[string]string{
		"X-Forwarded-For":   "198.51.100.24",
		"X-Real-IP":         "198.51.100.24",
		"X-Forwarded-Host":  "meridian.example:50001",
		"X-Forwarded-Proto": "http",
	} {
		if got := captured.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"Forwarded", "X-Forwarded-Custom"} {
		if got := captured.Header.Get(name); got != "" {
			t.Errorf("untrusted %s leaked upstream: %q", name, got)
		}
	}
}

func TestPrepareWebSocketUpstreamHeadersRebuildsForwardingHeaders(t *testing.T) {
	target, err := normalizeTargetURL("https://upstream.example.com/emby")
	if err != nil {
		t.Fatalf("normalize target: %v", err)
	}
	profile := getUAProfile("infuse")
	req := httptest.NewRequest(http.MethodGet, "http://meridian.example:50001/socket", nil)
	req.RemoteAddr = "198.51.100.25:54321"
	req.Header.Set("Connection", "Upgrade, User-Agent")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("User-Agent", "attacker-controlled")
	req.Header.Set("Forwarded", "for=203.0.113.10")
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("X-Forwarded-Custom", "must-not-pass")
	req.Header.Set("X-Real-IP", "203.0.113.11")
	req.Header.Set("Proxy-Connection", "keep-alive")

	header := prepareWebSocketUpstreamHeaders(req, target, profile)
	if got := req.Header.Get("Forwarded"); got == "" {
		t.Fatal("preparing WebSocket headers mutated the inbound request")
	}
	for name, want := range map[string]string{
		"Connection":        "Upgrade",
		"Upgrade":           "websocket",
		"Host":              target.Host,
		"User-Agent":        profile.UserAgent,
		"X-Forwarded-For":   "198.51.100.25",
		"X-Real-IP":         "198.51.100.25",
		"X-Forwarded-Host":  "meridian.example:50001",
		"X-Forwarded-Proto": "http",
	} {
		if got := header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"Forwarded", "X-Forwarded-Custom", "Proxy-Connection"} {
		if got := header.Get(name); got != "" {
			t.Errorf("untrusted WebSocket header %s leaked upstream: %q", name, got)
		}
	}
}

func TestRateLimitedWriterUsesPerRequestProgress(t *testing.T) {
	var siteTraffic atomic.Int64
	siteTraffic.Store(10 << 20)
	recorder := httptest.NewRecorder()
	writer := &rateLimitedWriter{
		ResponseWriter: recorder,
		bytesPerSec:    1024,
		written:        &siteTraffic,
		start:          time.Now().Add(-time.Second),
	}
	payload := bytes.Repeat([]byte("x"), 512)
	n, err := writer.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(payload) || recorder.Body.Len() != len(payload) {
		t.Fatalf("wrote=%d body=%d, want %d", n, recorder.Body.Len(), len(payload))
	}
	if writer.requestWritten != int64(len(payload)) {
		t.Fatalf("requestWritten = %d, want %d", writer.requestWritten, len(payload))
	}
	if got := siteTraffic.Load(); got != (10<<20)+int64(len(payload)) {
		t.Fatalf("site traffic = %d, want %d", got, (10<<20)+len(payload))
	}
}

func TestMobileModalKeepsBodyScrollableAndActionsVisible(t *testing.T) {
	css, err := web.StaticFiles.ReadFile("static/css/style.css")
	if err != nil {
		t.Fatalf("read embedded CSS: %v", err)
	}
	for _, rule := range []string{
		"max-height: calc(100dvh - 48px)",
		"overflow-y: auto",
		"-webkit-overflow-scrolling: touch",
		".btn-modal { flex: 1; min-height: 44px",
	} {
		if !strings.Contains(string(css), rule) {
			t.Errorf("mobile modal CSS missing %q", rule)
		}
	}

	appJS, err := web.StaticFiles.ReadFile("static/js/app.js")
	if err != nil {
		t.Fatalf("read embedded app JavaScript: %v", err)
	}
	if !strings.Contains(string(appJS), "document.getElementById('modal-body').scrollTop = 0") {
		t.Error("opening a modal must reset the form scroll position")
	}

	sitesJS, err := web.StaticFiles.ReadFile("static/js/pages/sites.js")
	if err != nil {
		t.Fatalf("read embedded sites JavaScript: %v", err)
	}
	if !strings.Contains(string(sitesJS), "openModal({ closeOnBackdrop: false })") {
		t.Error("site add/edit form must not close when its backdrop is clicked")
	}
	for _, snippet := range []string{`id="m-speed"`, "speed_limit: parseInt(document.getElementById('m-speed').value || 0)"} {
		if !strings.Contains(string(sitesJS), snippet) {
			t.Errorf("site form must expose and submit speed limit; missing %q", snippet)
		}
	}

	indexHTML, err := web.StaticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read embedded index HTML: %v", err)
	}
	for _, asset := range []string{"/css/style.css?v=1.5.3", "/js/pages/sites.js?v=1.5.3", "/js/app.js?v=1.5.3"} {
		if !strings.Contains(string(indexHTML), asset) {
			t.Errorf("index must cache-bust updated asset %q", asset)
		}
	}
	if strings.Contains(string(indexHTML), "fonts.googleapis.com") || strings.Contains(string(indexHTML), "fonts.gstatic.com") {
		t.Error("index must not request fonts blocked by the Content-Security-Policy")
	}
}

func TestStaticHandlerDisablesCaching(t *testing.T) {
	staticFS, err := fs.Sub(web.StaticFiles, "static")
	if err != nil {
		t.Fatalf("static fs: %v", err)
	}
	rr := httptest.NewRecorder()
	staticHandler(staticFS).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/js/pages/sites.js", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store, no-cache, must-revalidate" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := rr.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", got)
	}
	if got := rr.Header().Get("Expires"); got != "0" {
		t.Fatalf("Expires = %q, want 0", got)
	}
}

func TestAPIClientUsesHttpOnlyCookieSessions(t *testing.T) {
	apiJS, err := web.StaticFiles.ReadFile("static/js/api.js")
	if err != nil {
		t.Fatalf("read embedded API JavaScript: %v", err)
	}
	source := string(apiJS)
	for _, expected := range []string{"credentials: 'same-origin'", "res.status === 401", "await this.logout()", "window.location.reload()", "/api/auth/logout"} {
		if !strings.Contains(source, expected) {
			t.Errorf("API client missing %q", expected)
		}
	}
	for _, forbidden := range []string{"localStorage", "Authorization", "Bearer "} {
		if strings.Contains(source, forbidden) {
			t.Errorf("API client must not retain browser-accessible bearer state: found %q", forbidden)
		}
	}
}

func TestRequestClientKeyUsesOnlyConfiguredTrustedProxy(t *testing.T) {
	trusted, err := parseTrustedProxyCIDRs("172.17.0.0/16")
	if err != nil {
		t.Fatalf("parse trusted proxies: %v", err)
	}

	trustedRequest := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	trustedRequest.RemoteAddr = "172.17.0.1:45678"
	trustedRequest.Header.Set("X-Real-IP", "203.0.113.25")
	if got := requestClientKey(trustedRequest, trusted); got != "203.0.113.25" {
		t.Fatalf("trusted proxy client key = %q", got)
	}

	untrustedRequest := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	untrustedRequest.RemoteAddr = "198.51.100.7:45678"
	untrustedRequest.Header.Set("X-Real-IP", "203.0.113.25")
	if got := requestClientKey(untrustedRequest, trusted); got != "198.51.100.7" {
		t.Fatalf("untrusted proxy client key = %q", got)
	}

	if _, err := parseTrustedProxyCIDRs("not-a-network"); err == nil {
		t.Fatal("invalid trusted proxy CIDR unexpectedly accepted")
	}
}

func TestSessionCookiesUseTransportSecurity(t *testing.T) {
	trusted, err := parseTrustedProxyCIDRs("127.0.0.1/32")
	if err != nil {
		t.Fatalf("parse trusted proxies: %v", err)
	}
	app := &App{trustedProxies: trusted}
	tests := []struct {
		name             string
		url              string
		remoteAddr       string
		forwardedProto   string
		wantSecureCookie bool
	}{
		{
			name:             "direct HTTPS",
			url:              "https://panel.example/api/auth/login",
			remoteAddr:       "198.51.100.10:12345",
			wantSecureCookie: true,
		},
		{
			name:             "trusted proxy HTTPS",
			url:              "http://panel.example/api/auth/login",
			remoteAddr:       "127.0.0.1:12345",
			forwardedProto:   "https",
			wantSecureCookie: true,
		},
		{
			name:             "untrusted proxy forged HTTPS",
			url:              "http://panel.example/api/auth/login",
			remoteAddr:       "198.51.100.10:12345",
			forwardedProto:   "https",
			wantSecureCookie: false,
		},
		{
			name:             "documented direct HTTP mode",
			url:              "http://panel.example/api/auth/login",
			remoteAddr:       "198.51.100.10:12345",
			wantSecureCookie: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.url, nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.forwardedProto != "" {
				req.Header.Set("X-Forwarded-Proto", tc.forwardedProto)
			}

			setRecorder := httptest.NewRecorder()
			app.setSessionCookie(setRecorder, req, "session-token")
			setCookies := setRecorder.Result().Cookies()
			if len(setCookies) != 1 {
				t.Fatalf("set cookie count = %d, want 1", len(setCookies))
			}
			setCookie := setCookies[0]
			if setCookie.Secure != tc.wantSecureCookie || !setCookie.HttpOnly || setCookie.SameSite != http.SameSiteStrictMode {
				t.Fatalf("set cookie = %#v, want secure=%t, HttpOnly, SameSite=Strict", setCookie, tc.wantSecureCookie)
			}

			clearRecorder := httptest.NewRecorder()
			app.clearSessionCookie(clearRecorder, req)
			clearCookies := clearRecorder.Result().Cookies()
			if len(clearCookies) != 1 {
				t.Fatalf("clear cookie count = %d, want 1", len(clearCookies))
			}
			clearCookie := clearCookies[0]
			if clearCookie.Secure != tc.wantSecureCookie || !clearCookie.HttpOnly || clearCookie.SameSite != http.SameSiteStrictMode || clearCookie.MaxAge >= 0 {
				t.Fatalf("clear cookie = %#v, want secure=%t, HttpOnly, SameSite=Strict, deletion", clearCookie, tc.wantSecureCookie)
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rr.Header().Get("Content-Security-Policy"); !strings.Contains(got, "script-src 'self'") || !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("unexpected Content-Security-Policy: %q", got)
	}
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want DENY", got)
	}
}

func TestHandleAuthCheckExposesSingleAdminModeBeforeSetup(t *testing.T) {
	app := newTestApp(t)
	jwtSecretEphemeral = true
	t.Cleanup(func() { jwtSecretEphemeral = false })

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/check", nil)

	app.handleAuthCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	body := decodeBody(t, rr)
	if got := mustBoolValue(t, body, "needs_setup"); !got {
		t.Fatalf("needs_setup = %v, want true", got)
	}
	if got := mustStringValue(t, body, "mode"); got != "single_admin" {
		t.Fatalf("mode = %q, want single_admin", got)
	}
	if got := mustBoolValue(t, body, "jwt_secret_ephemeral"); !got {
		t.Fatalf("jwt_secret_ephemeral = %v, want true", got)
	}
	if got := mustBoolValue(t, body, "setup_token_required"); !got {
		t.Fatalf("setup_token_required = %v, want true", got)
	}
}

func TestConfiguredSetupTokenRequiresExplicitValue(t *testing.T) {
	if _, err := configuredSetupToken(0, " \t "); err == nil {
		t.Fatal("empty initial setup token unexpectedly accepted")
	}
	if got, err := configuredSetupToken(0, " setup-token "); err != nil || got != "setup-token" {
		t.Fatalf("configured setup token = %q, %v", got, err)
	}
	if got, err := configuredSetupToken(1, "unused-token"); err != nil || got != "" {
		t.Fatalf("configured setup token after initialization = %q, %v", got, err)
	}
}

func TestSetupRequiresTokenAndCreatesOnlyOneAdmin(t *testing.T) {
	app := newTestApp(t)
	app.setupToken = "one-time-setup-token"

	wrong := httptest.NewRecorder()
	wrongReq := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{
		"username":"admin","password":"correct horse battery staple","setup_token":"wrong"
	}`))
	app.handleSetup(wrong, wrongReq)
	if wrong.Code != http.StatusForbidden {
		t.Fatalf("wrong setup token status = %d, want 403", wrong.Code)
	}
	if got := mustUserCount(t, app.db); got != 0 {
		t.Fatalf("user count after rejected setup = %d, want 0", got)
	}

	ok := httptest.NewRecorder()
	okReq := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{
		"username":"admin","password":"correct horse battery staple","setup_token":"one-time-setup-token"
	}`))
	app.handleSetup(ok, okReq)
	if ok.Code != http.StatusOK {
		t.Fatalf("valid setup status = %d body=%s", ok.Code, ok.Body.String())
	}
	if got := mustUserCount(t, app.db); got != 1 {
		t.Fatalf("user count after setup = %d, want 1", got)
	}
	if app.setupToken != "" {
		t.Fatal("setup token remained in application memory after successful setup")
	}
	if _, ok := decodeBody(t, ok)["token"]; ok {
		t.Fatal("setup response exposed a bearer token")
	}
	cookies := ok.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected setup session cookie: %#v", cookies)
	}
}

func TestLoginCookieAuthAndCSRFProtection(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.db.CreateInitialUser("admin", "correct horse battery staple"); err != nil {
		t.Fatalf("CreateInitialUser: %v", err)
	}

	login := httptest.NewRecorder()
	loginRequest := httptest.NewRequest(http.MethodPost, "https://panel.example/api/auth/login", strings.NewReader(`{"username":"admin","password":"correct horse battery staple"}`))
	loginRequest.TLS = &tls.ConnectionState{}
	app.handleLogin(login, loginRequest)
	if login.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.Code, login.Body.String())
	}
	if _, ok := decodeBody(t, login)["token"]; ok {
		t.Fatal("login response exposed a bearer token")
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies=%#v", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookieName || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge <= 0 {
		t.Fatalf("unsafe login cookie: %#v", cookie)
	}

	protected := app.authMiddleware(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	get := httptest.NewRecorder()
	getRequest := httptest.NewRequest(http.MethodGet, "https://panel.example/api/sites", nil)
	getRequest.AddCookie(cookie)
	protected(get, getRequest)
	if get.Code != http.StatusNoContent {
		t.Fatalf("cookie-authenticated GET status=%d body=%s", get.Code, get.Body.String())
	}

	bearer := httptest.NewRecorder()
	bearerRequest := httptest.NewRequest(http.MethodGet, "https://panel.example/api/sites", nil)
	bearerRequest.Header.Set("Authorization", "Bearer should-not-be-accepted")
	protected(bearer, bearerRequest)
	if bearer.Code != http.StatusUnauthorized {
		t.Fatalf("bearer-only request status=%d, want 401", bearer.Code)
	}

	missingOrigin := httptest.NewRecorder()
	missingOriginRequest := httptest.NewRequest(http.MethodPost, "https://panel.example/api/sites", nil)
	missingOriginRequest.AddCookie(cookie)
	protected(missingOrigin, missingOriginRequest)
	if missingOrigin.Code != http.StatusForbidden {
		t.Fatalf("state change without origin status=%d, want 403", missingOrigin.Code)
	}

	sameOrigin := httptest.NewRecorder()
	sameOriginRequest := httptest.NewRequest(http.MethodPost, "https://panel.example/api/sites", nil)
	sameOriginRequest.Header.Set("Origin", "https://panel.example")
	sameOriginRequest.AddCookie(cookie)
	protected(sameOrigin, sameOriginRequest)
	if sameOrigin.Code != http.StatusNoContent {
		t.Fatalf("same-origin state change status=%d body=%s", sameOrigin.Code, sameOrigin.Body.String())
	}

	crossOrigin := httptest.NewRecorder()
	crossOriginRequest := httptest.NewRequest(http.MethodPost, "https://panel.example/api/sites", nil)
	crossOriginRequest.Header.Set("Origin", "https://evil.example")
	crossOriginRequest.AddCookie(cookie)
	protected(crossOrigin, crossOriginRequest)
	if crossOrigin.Code != http.StatusForbidden {
		t.Fatalf("cross-origin state change status=%d, want 403", crossOrigin.Code)
	}
}

func TestLogoutClearsSessionCookie(t *testing.T) {
	app := newTestApp(t)
	handler := app.csrfMiddleware(app.handleLogout)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://panel.example/api/auth/logout", nil)
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Origin", "https://panel.example")
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("logout status=%d body=%s", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName || cookies[0].MaxAge >= 0 || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("logout did not clear protected session cookie: %#v", cookies)
	}
}

func TestCreateInitialUserIsAtomic(t *testing.T) {
	app := newTestApp(t)
	const contenders = 4
	var wg sync.WaitGroup
	results := make(chan error, contenders)
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := app.db.CreateInitialUser(fmt.Sprintf("admin-%d", i), "correct horse battery staple")
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)

	created := 0
	alreadyExists := 0
	for err := range results {
		switch {
		case err == nil:
			created++
		case errors.Is(err, errAdminAlreadyExists):
			alreadyExists++
		default:
			t.Fatalf("unexpected setup error: %v", err)
		}
	}
	if created != 1 || alreadyExists != contenders-1 {
		t.Fatalf("created=%d alreadyExists=%d, want 1 and %d", created, alreadyExists, contenders-1)
	}
	if got := mustUserCount(t, app.db); got != 1 {
		t.Fatalf("user count = %d, want 1", got)
	}
}

func TestVerifyUserAcceptsExistingXCryptoBcryptHash(t *testing.T) {
	app := newTestApp(t)
	// Compatibility vector generated by golang.org/x/crypto/bcrypt. Existing
	// installations must continue to authenticate after switching providers.
	const legacyHash = "$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga"
	result, err := app.db.db.Exec(
		"INSERT INTO users (username, password_hash) VALUES (?, ?)",
		"legacy-admin",
		legacyHash,
	)
	if err != nil {
		t.Fatalf("insert legacy user: %v", err)
	}
	wantID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("legacy user id: %v", err)
	}

	gotID, err := app.db.VerifyUser("legacy-admin", "allmine")
	if err != nil {
		t.Fatalf("VerifyUser rejected a legacy bcrypt hash: %v", err)
	}
	if gotID != wantID {
		t.Fatalf("VerifyUser id = %d, want %d", gotID, wantID)
	}
	if _, err := app.db.VerifyUser("legacy-admin", "not-the-password"); !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("wrong password error = %v, want invalid credentials", err)
	}
}

func TestResetAdminPasswordUpdatesOnlyConfiguredAdministrator(t *testing.T) {
	app := newTestApp(t)
	const oldPassword = "correct horse battery staple"
	const newPassword = "new correct horse battery staple"
	if _, err := app.db.CreateInitialUser("admin", oldPassword); err != nil {
		t.Fatalf("CreateInitialUser: %v", err)
	}
	if err := app.db.ResetAdminPassword(newPassword); err != nil {
		t.Fatalf("ResetAdminPassword: %v", err)
	}
	if _, err := app.db.VerifyUser("admin", oldPassword); !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("old password error = %v, want invalid credentials", err)
	}
	if _, err := app.db.VerifyUser("admin", newPassword); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}
}

func TestResetAdminPasswordRejectsInvalidDatabaseStateAndLength(t *testing.T) {
	app := newTestApp(t)
	if err := app.db.ResetAdminPassword("long enough password"); !errors.Is(err, errAdminNotConfigured) {
		t.Fatalf("empty database error = %v, want administrator not configured", err)
	}
	if _, err := app.db.CreateUser("admin-one", "correct horse battery staple"); err != nil {
		t.Fatalf("CreateUser one: %v", err)
	}
	if _, err := app.db.CreateUser("admin-two", "correct horse battery staple"); err != nil {
		t.Fatalf("CreateUser two: %v", err)
	}
	if err := app.db.ResetAdminPassword("another valid password"); !errors.Is(err, errMultipleAdmins) {
		t.Fatalf("multiple users error = %v, want multiple administrators", err)
	}
	for _, password := range []string{"too-short", strings.Repeat("x", 73)} {
		if err := app.db.ResetAdminPassword(password); !errors.Is(err, errInvalidAdminPassword) {
			t.Fatalf("password length %d error = %v, want invalid password", len(password), err)
		}
	}
}

func TestResetAdminPasswordAcceptsLengthBoundaries(t *testing.T) {
	for _, length := range []int{12, 72} {
		app := newTestApp(t)
		if _, err := app.db.CreateInitialUser("admin", "correct horse battery staple"); err != nil {
			t.Fatalf("CreateInitialUser: %v", err)
		}
		password := strings.Repeat("x", length)
		if err := app.db.ResetAdminPassword(password); err != nil {
			t.Fatalf("length %d rejected: %v", length, err)
		}
		if _, err := app.db.VerifyUser("admin", password); err != nil {
			t.Fatalf("length %d password did not verify: %v", length, err)
		}
	}
}

func TestAdminResetPasswordCommandReadsPasswordOnlyFromStdin(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "command.db")
	db, err := openDB(dbPath)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	if _, err := db.CreateInitialUser("admin", "correct horse battery staple"); err != nil {
		db.Close()
		t.Fatalf("CreateInitialUser: %v", err)
	}
	db.Close()

	const newPassword = "stdin-only replacement password"
	var output bytes.Buffer
	handled, err := runCommandLine(
		[]string{"admin", "reset-password", "--db", dbPath, "--password-stdin"},
		strings.NewReader(newPassword+"\n"),
		&output,
	)
	if err != nil {
		t.Fatalf("runCommandLine: %v", err)
	}
	if !handled {
		t.Fatal("admin command was not handled")
	}
	if strings.Contains(output.String(), newPassword) {
		t.Fatal("command output exposed the password")
	}

	verifyDB, err := openDB(dbPath)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer verifyDB.Close()
	if _, err := verifyDB.VerifyUser("admin", newPassword); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}
}

func TestAdminResetPasswordCommandRejectsUnsafeInputShapes(t *testing.T) {
	const misplacedPassword = "must-not-appear-in-errors"
	for _, tc := range []struct {
		name  string
		args  []string
		input string
	}{
		{name: "missing stdin flag", args: []string{"admin", "reset-password", "--db", "test.db"}, input: "valid replacement password\n"},
		{name: "password argument", args: []string{"admin", "reset-password", "--db", "test.db", "--password", misplacedPassword}},
		{name: "multiple lines", args: []string{"admin", "reset-password", "--db", "test.db", "--password-stdin"}, input: "valid replacement password\nsecond line\n"},
		{name: "too long", args: []string{"admin", "reset-password", "--db", "test.db", "--password-stdin"}, input: strings.Repeat("x", 73) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handled, err := runCommandLine(tc.args, strings.NewReader(tc.input), io.Discard)
			if !handled || err == nil {
				t.Fatalf("handled=%v err=%v, want handled error", handled, err)
			}
			if strings.Contains(err.Error(), misplacedPassword) {
				t.Fatal("command error exposed a password-shaped argument")
			}
		})
	}
}

func TestJWTSecretRotationInvalidatesExistingToken(t *testing.T) {
	originalSecret := jwtSecret
	originalEphemeral := jwtSecretEphemeral
	t.Cleanup(func() {
		jwtSecret = originalSecret
		jwtSecretEphemeral = originalEphemeral
	})

	jwtSecret = []byte("old-test-signing-secret-000000000000")
	token, err := generateToken(1, "admin")
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	jwtSecret = []byte("new-test-signing-secret-000000000000")
	if _, _, err := validateToken(token); err == nil {
		t.Fatal("token signed before JWT secret rotation remained valid")
	}
}

func TestPanelListenAddressSeparatesPanelFromSiteListeners(t *testing.T) {
	for _, tc := range []struct {
		name string
		bind string
		port int
		want string
	}{
		{name: "default", port: 9090, want: "0.0.0.0:9090"},
		{name: "loopback", bind: "127.0.0.1", port: 9090, want: "127.0.0.1:9090"},
		{name: "ipv6", bind: "::1", port: 9090, want: "[::1]:9090"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := panelListenAddress(tc.bind, tc.port)
			if err != nil || got != tc.want {
				t.Fatalf("panelListenAddress() = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		bind string
		port int
	}{
		{bind: "panel.example.com", port: 9090},
		{bind: "127.0.0.1", port: 0},
		{bind: "127.0.0.1", port: 65536},
	} {
		if _, err := panelListenAddress(tc.bind, tc.port); err == nil {
			t.Fatalf("panelListenAddress(%q, %d) unexpectedly succeeded", tc.bind, tc.port)
		}
	}
}

func TestLoginUsesGenericErrorsAndRateLimit(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.db.CreateInitialUser("admin", "correct horse battery staple"); err != nil {
		t.Fatalf("CreateInitialUser: %v", err)
	}

	login := func(username, password string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(fmt.Sprintf(
			`{"username":%q,"password":%q}`, username, password,
		)))
		req.RemoteAddr = "203.0.113.10:12345"
		app.handleLogin(rr, req)
		return rr
	}

	unknown := login("missing", "wrong password")
	badPassword := login("admin", "wrong password")
	if unknown.Code != http.StatusUnauthorized || badPassword.Code != http.StatusUnauthorized {
		t.Fatalf("credential failure statuses = %d, %d; want 401", unknown.Code, badPassword.Code)
	}
	if unknown.Body.String() != badPassword.Body.String() {
		t.Fatalf("credential failure responses differ: %q vs %q", unknown.Body.String(), badPassword.Body.String())
	}

	for i := 0; i < maxLoginFailures-2; i++ {
		login("admin", "wrong password")
	}
	blocked := login("admin", "correct horse battery staple")
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked login status = %d, want 429", blocked.Code)
	}
	if blocked.Header().Get("Retry-After") == "" {
		t.Fatal("blocked login is missing Retry-After")
	}
}

func TestLoginRateLimiterExpiresAndEvictsWithoutSharedOverflow(t *testing.T) {
	limiter := newLoginRateLimiterWithLimit(1)
	now := time.Now()
	for range maxLoginFailures {
		limiter.recordFailure("198.51.100.1", now)
	}
	if allowed, _ := limiter.allow("198.51.100.1", now); allowed {
		t.Fatal("locked client was unexpectedly allowed")
	}

	// A new client gets its own entry after LRU eviction instead of sharing a
	// global overflow bucket and inheriting the first client's lockout.
	limiter.recordFailure("198.51.100.2", now.Add(time.Second))
	if allowed, _ := limiter.allow("198.51.100.2", now.Add(time.Second)); !allowed {
		t.Fatal("new client inherited another client's rate-limit state")
	}
	if _, exists := limiter.attempts["__overflow__"]; exists {
		t.Fatal("rate limiter retained a shared overflow bucket")
	}
	if len(limiter.attempts) > 1 {
		t.Fatalf("rate limiter entries=%d, want bounded to 1", len(limiter.attempts))
	}

	limiter.recordFailure("198.51.100.3", now)
	limiter.allow("198.51.100.3", now.Add(loginFailureWindow))
	if _, exists := limiter.attempts["198.51.100.3"]; exists {
		t.Fatal("expired login rate-limit entry was retained")
	}
}

func TestRedactUpstreamURLRemovesCredentialsPathsAndQueries(t *testing.T) {
	target, err := url.Parse("https://user:secret@media.example:8443/stream?token=signed-value&expires=123")
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	if got := redactUpstreamURL(target); got != "https://media.example:8443" {
		t.Fatalf("redacted upstream URL=%q", got)
	}
}

func TestCORSAllowsSameOriginAndRejectsCrossOrigin(t *testing.T) {
	handler := cors(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	same := httptest.NewRecorder()
	sameReq := httptest.NewRequest(http.MethodGet, "http://panel.example/api/auth/check", nil)
	sameReq.Header.Set("Origin", "https://panel.example")
	handler(same, sameReq)
	if same.Code != http.StatusOK || same.Header().Get("Access-Control-Allow-Origin") != "https://panel.example" {
		t.Fatalf("same-origin request status=%d allow-origin=%q", same.Code, same.Header().Get("Access-Control-Allow-Origin"))
	}

	cross := httptest.NewRecorder()
	crossReq := httptest.NewRequest(http.MethodGet, "http://panel.example/api/auth/check", nil)
	crossReq.Header.Set("Origin", "https://evil.example")
	handler(cross, crossReq)
	if cross.Code != http.StatusForbidden {
		t.Fatalf("cross-origin request status = %d, want 403", cross.Code)
	}
}

func TestHandleAuthCheckExposesConfiguredSingleAdminMode(t *testing.T) {
	app := newTestApp(t)
	jwtSecretEphemeral = false

	if _, err := app.db.CreateUser("admin", "admin123"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/check", nil)

	app.handleAuthCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	body := decodeBody(t, rr)
	if got := mustBoolValue(t, body, "needs_setup"); got {
		t.Fatalf("needs_setup = %v, want false", got)
	}
	if got := mustStringValue(t, body, "mode"); got != "single_admin" {
		t.Fatalf("mode = %q, want single_admin", got)
	}
	if got := mustBoolValue(t, body, "jwt_secret_ephemeral"); got {
		t.Fatalf("jwt_secret_ephemeral = %v, want false", got)
	}
}

func TestDatabaseReadFailuresAreReported(t *testing.T) {
	app := newTestApp(t)
	app.db.Close()
	if _, err := app.db.UserCount(); err == nil {
		t.Fatal("UserCount unexpectedly ignored a closed database")
	}
	if _, err := app.db.DashboardStats(); err == nil {
		t.Fatal("DashboardStats unexpectedly ignored a closed database")
	}
	if _, err := app.pm.StartAllEnabled(); err == nil {
		t.Fatal("StartAllEnabled unexpectedly ignored a closed database")
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/check", nil)
	app.handleAuthCheck(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("auth check status = %d, want 500; body=%s", rr.Code, rr.Body.String())
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
	site, err := app.db.CreateSite("diag", freePort(t), server.URL, "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	inst := &ProxyInstance{Site: *site, startedAt: time.Now().Add(-3 * time.Second)}
	inst.reqCount.Store(7)
	app.pm.proxies[site.ID] = inst

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
	if !result.Proxy.Running {
		t.Fatal("proxy.running = false, want true")
	}
	if result.Proxy.TotalReqs != 7 {
		t.Fatalf("proxy.total_requests = %d, want 7", result.Proxy.TotalReqs)
	}
	if result.Proxy.Uptime == "" {
		t.Fatal("proxy.uptime is empty for a running site")
	}
}

func TestDiagnoseSiteTreatsReachable4xxAsOnline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "blocked", http.StatusForbidden)
	}))
	defer server.Close()

	app := newTestApp(t)
	site, err := app.db.CreateSite("diag", freePort(t), server.URL, "", "direct", "[]", "infuse", 0, 0)
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
	site, err := app.db.CreateSite("diag", freePort(t), server.URL, "", "direct", "[]", "infuse", 0, 0)
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
	site, err := app.db.CreateSite("diag", freePort(t), apiServer.URL, "", "direct", "[]", "infuse", 0, 0)
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
	site, err := app.db.CreateSite("diag", freePort(t), apiServer.URL, apiServer.URL, "direct", "[]", "infuse", 0, 0)
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

	playbackServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/System/Info/Public" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"Version":"4.8.2.0"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer playbackServer.Close()

	app := newTestApp(t)
	site, err := app.db.CreateSite("diag", freePort(t), apiServer.URL, playbackServer.URL, "direct", "[]", "infuse", 0, 0)
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
	if got := mustStringValue(t, playbackProbe, "kind"); got != "metadata_api" {
		t.Fatalf("playback probe.kind = %q, want metadata_api", got)
	}
	if got := mustStringValue(t, playbackProbe, "method"); got != http.MethodGet {
		t.Fatalf("playback probe.method = %q, want GET", got)
	}
	if got := mustStringValue(t, playbackProbe, "url"); got != playbackServer.URL+"/System/Info/Public" {
		t.Fatalf("playback probe.url = %q, want metadata URL", got)
	}
	if got := mustStringValue(t, playbackHealth, "status"); got != "offline" {
		t.Fatalf("playback health.status = %q, want offline for an untrusted test certificate", got)
	}
	if got := mustStringValue(t, playbackHealth, "error"); got == "" {
		t.Fatal("playback health.error should report TLS verification failure")
	}
	if got := mustBoolValue(t, playbackTLS, "enabled"); !got {
		t.Fatalf("playback tls.enabled = %v, want true", got)
	}
	if got := mustBoolValue(t, playbackTLS, "valid"); got {
		t.Fatalf("playback tls.valid = %v, want false for an untrusted test certificate", got)
	}
	if got := mustStringValue(t, playback, "effective_url"); got != playbackServer.URL {
		t.Fatalf("playback effective_url = %q, want %q", got, playbackServer.URL)
	}
}

func TestApplyUAProfileHeadersRewritesClientAndVersionIdentity(t *testing.T) {
	header := http.Header{}
	header.Set("User-Agent", "OldUA/1.0")
	header.Set("X-Emby-Authorization", `MediaBrowser Client="Old Client", Device="TV", Version="9.9.9"`)
	header.Set("Authorization", `MediaBrowser Client="Old Client", Device="TV", Version="9.9.9"`)

	applyUAProfileHeaders(header, uaProfiles["client"])

	if got := header.Get("User-Agent"); got != uaProfiles["client"].UserAgent {
		t.Fatalf("User-Agent = %q, want %q", got, uaProfiles["client"].UserAgent)
	}
	if got := header.Get("X-Emby-Authorization"); !strings.Contains(got, `Client="Emby Theater"`) {
		t.Fatalf("X-Emby-Authorization = %q", got)
	}
	if got := header.Get("X-Emby-Authorization"); !strings.Contains(got, `Version="4.7.0"`) {
		t.Fatalf("X-Emby-Authorization version = %q", got)
	}
	if got := header.Get("Authorization"); !strings.Contains(got, `Client="Emby Theater"`) {
		t.Fatalf("Authorization = %q", got)
	}
	if got := header.Get("Authorization"); !strings.Contains(got, `Version="4.7.0"`) {
		t.Fatalf("Authorization version = %q", got)
	}
}

func TestApplyCustomUAProfileHeadersSafelyRewritesOnlyValidEmbyValues(t *testing.T) {
	profile := UAProfile{
		Name:      "Custom",
		UserAgent: "Meridian/" + "$" + "1/" + "$" + "{1}$",
		Client:    "Client/" + "$" + "1/" + "$" + "{1}$",
		Version:   "1." + "$" + "0$",
	}
	valid := "MediaBrowser Device=\"TV\", DeviceId=\"device-1\", Version=\"old\", Client=\"old\""
	missing := "Emby Device=\"Tablet\", DeviceId=\"device-2\""
	duplicate := "MediaBrowser Client=\"one\", Client=\"two\", Version=\"old\""
	escaped := "MediaBrowser Client=\"bad\\\\\\\"value\", Device=\"TV\""
	header := http.Header{
		"X-Emby-Authorization": []string{valid, missing, duplicate, escaped},
		"Authorization":        []string{"Bearer opaque-token"},
	}

	applyUAProfileHeaders(header, profile)

	if got := header.Get("User-Agent"); got != profile.UserAgent {
		t.Fatalf("User-Agent = %q, want %q", got, profile.UserAgent)
	}
	values := header.Values("X-Emby-Authorization")
	if len(values) != 4 {
		t.Fatalf("authorization values=%d, want 4", len(values))
	}
	wantValid := "MediaBrowser Device=\"TV\", DeviceId=\"device-1\", Version=\"" + profile.Version + "\", Client=\"" + profile.Client + "\""
	if values[0] != wantValid {
		t.Fatalf("rewritten header = %q, want %q", values[0], wantValid)
	}
	if !strings.Contains(values[1], "Device=\"Tablet\"") || !strings.Contains(values[1], "DeviceId=\"device-2\"") || !strings.Contains(values[1], "Client=\""+profile.Client+"\"") || !strings.Contains(values[1], "Version=\""+profile.Version+"\"") {
		t.Fatalf("missing-field header = %q", values[1])
	}
	if values[2] != duplicate {
		t.Fatalf("duplicate Client header was modified: %q", values[2])
	}
	if values[3] != escaped {
		t.Fatalf("escaped header was modified: %q", values[3])
	}
	if got := header.Get("Authorization"); got != "Bearer opaque-token" {
		t.Fatalf("unsupported Authorization scheme was modified: %q", got)
	}
}

func TestCustomUAProfileIsConsistentAcrossHTTPWebSocketAndRedirects(t *testing.T) {
	profile := UAProfile{
		Name:      "Custom",
		UserAgent: "Meridian Test/1.0",
		Client:    "Meridian Test",
		Version:   "1.0.0",
	}
	authorization := "MediaBrowser Device=\"TV\", DeviceId=\"device-1\", Client=\"old\", Version=\"old\""
	assertIdentity := func(t *testing.T, header http.Header) {
		t.Helper()
		if got := header.Get("User-Agent"); got != profile.UserAgent {
			t.Fatalf("User-Agent = %q, want %q", got, profile.UserAgent)
		}
		got := header.Get("X-Emby-Authorization")
		for _, want := range []string{"Device=\"TV\"", "DeviceId=\"device-1\"", "Client=\"" + profile.Client + "\"", "Version=\"" + profile.Version + "\""} {
			if !strings.Contains(got, want) {
				t.Fatalf("authorization = %q, missing %q", got, want)
			}
		}
	}

	t.Run("http", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "http://meridian.example/System/Info", nil)
		request.Header.Set("X-Emby-Authorization", authorization)
		header := request.Header.Clone()
		prepareUpstreamHeaders(header, request, profile)
		assertIdentity(t, header)
	})

	t.Run("websocket", func(t *testing.T) {
		target, err := normalizeTargetURL("https://upstream.example.com")
		if err != nil {
			t.Fatalf("normalize target: %v", err)
		}
		request := httptest.NewRequest(http.MethodGet, "http://meridian.example/socket", nil)
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
		request.Header.Set("X-Emby-Authorization", authorization)
		header := prepareWebSocketUpstreamHeaders(request, target, profile)
		assertIdentity(t, header)
	})

	t.Run("redirect", func(t *testing.T) {
		target, err := normalizeTargetURL("https://media.example.com")
		if err != nil {
			t.Fatalf("normalize target: %v", err)
		}
		calls := 0
		var followedHeaders http.Header
		transport := &redirectFollowTransport{
			playbackHosts: map[string]bool{redirectHostKey(target): true},
			profile:       profile,
			base: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return &http.Response{
						StatusCode: http.StatusFound,
						Header:     http.Header{"Location": []string{"https://media.example.com/Videos/1/stream"}},
						Body:       io.NopCloser(strings.NewReader("")),
						Request:    request,
					}, nil
				}
				followedHeaders = request.Header.Clone()
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("ok")),
					Request:    request,
				}, nil
			}),
		}
		request := httptest.NewRequest(http.MethodGet, "https://api.example.com/Videos/1/stream", nil)
		request.Header.Set("X-Emby-Authorization", authorization)
		applyUAProfileHeaders(request.Header, profile)
		response, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatalf("follow redirect: %v", err)
		}
		response.Body.Close()
		if calls != 2 {
			t.Fatalf("calls = %d, want 2", calls)
		}
		assertIdentity(t, followedHeaders)
	})
}

func TestHandleSiteDiagReturnsSpoofedVersionField(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/System/Info/Public" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"Version":"4.8.1.0"}`))
	}))
	defer apiServer.Close()

	app := newTestApp(t)
	site, err := app.db.CreateSite("diag", freePort(t), apiServer.URL, "", "direct", "[]", "client", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/sites/"+jsonNumber64(site.ID)+"/diag", nil)

	app.handleSiteByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	headers := mustMapValue(t, decodeBody(t, rr), "headers")
	if got := mustBoolValue(t, headers, "ua_applied"); !got {
		t.Fatalf("ua_applied = %v, want true", got)
	}
	if got := mustStringValue(t, headers, "current_ua"); got != uaProfiles["client"].UserAgent {
		t.Fatalf("current_ua = %q, want %q", got, uaProfiles["client"].UserAgent)
	}
	if got := mustStringValue(t, headers, "client_field"); got != uaProfiles["client"].Client {
		t.Fatalf("client_field = %q, want %q", got, uaProfiles["client"].Client)
	}
	if got := mustStringValue(t, headers, "version_field"); got != uaProfiles["client"].Version {
		t.Fatalf("version_field = %q, want %q", got, uaProfiles["client"].Version)
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

	site, err := app.db.CreateSite("disabled", port, "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
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
	site, err := app.db.CreateSite("stable", initialPort, "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
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

func TestHandleSiteUpdateFailureRestoresCustomUAFields(t *testing.T) {
	app := newTestApp(t)
	initialPort := freePort(t)
	site, err := app.db.CreateSiteWithCustomUA("custom-stable", initialPort, "http://127.0.0.1:8096", "", "direct", "[]", customUAMode, "Old UA", "Old Client", "1.0", 0, 0)
	if err != nil {
		t.Fatalf("CreateSiteWithCustomUA: %v", err)
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

	payload, err := json.Marshal(map[string]interface{}{
		"name":              "custom-stable",
		"listen_port":       conflictPort,
		"target_url":        "http://127.0.0.1:8096",
		"ua_mode":           "custom",
		"custom_user_agent": "New UA",
		"custom_client":     "New Client",
		"custom_version":    "2.0",
	})
	if err != nil {
		t.Fatalf("marshal update: %v", err)
	}
	rr := httptest.NewRecorder()
	app.handleSiteByID(rr, httptest.NewRequest(http.MethodPut, "/api/sites/"+jsonNumber64(site.ID), bytes.NewReader(payload)))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	restored, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if restored.ListenPort != initialPort || restored.UAMode != customUAMode || restored.CustomUserAgent != "Old UA" || restored.CustomClient != "Old Client" || restored.CustomVersion != "1.0" {
		t.Fatalf("rollback did not restore full custom snapshot: %#v", restored)
	}
	if !app.pm.IsRunning(site.ID) {
		t.Fatal("original custom proxy should remain running")
	}
}

func TestHandleSiteUpdatePreservesOmittedSpeedLimit(t *testing.T) {
	app := newTestApp(t)
	port := freePort(t)
	site, err := app.db.CreateSite("limited", port, "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 25)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if enabled, err := app.db.ToggleSite(site.ID); err != nil || enabled {
		t.Fatalf("disable site: enabled=%v err=%v", enabled, err)
	}

	body := strings.NewReader(`{"name":"limited","listen_port":` + jsonNumber(port) + `,"target_url":"http://127.0.0.1:8096","ua_mode":"infuse"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/sites/"+jsonNumber64(site.ID), body)
	rr := httptest.NewRecorder()
	app.handleSiteByID(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.SpeedLimit != 25 {
		t.Fatalf("speed_limit = %d, want preserved value 25", reloaded.SpeedLimit)
	}
}

func TestHandleSiteUpdatePreservesOmittedTrafficQuota(t *testing.T) {
	app := newTestApp(t)
	port := freePort(t)
	site, err := app.db.CreateSite("quota", port, "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 5<<30, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if enabled, err := app.db.ToggleSite(site.ID); err != nil || enabled {
		t.Fatalf("disable site: enabled=%v err=%v", enabled, err)
	}

	body := strings.NewReader(`{"name":"quota","listen_port":` + jsonNumber(port) + `,"target_url":"http://127.0.0.1:8096","ua_mode":"infuse"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/sites/"+jsonNumber64(site.ID), body)
	rr := httptest.NewRecorder()
	app.handleSiteByID(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.TrafficQuota != 5<<30 {
		t.Fatalf("traffic_quota = %d, want preserved value %d", reloaded.TrafficQuota, int64(5<<30))
	}
}

// Omitting the field preserves the quota, but sending an explicit 0 must still
// clear it, so the pointer merge cannot be mistaken for "always ignore".
func TestHandleSiteUpdateAppliesExplicitZeroTrafficQuota(t *testing.T) {
	app := newTestApp(t)
	port := freePort(t)
	site, err := app.db.CreateSite("quota-clear", port, "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 5<<30, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if enabled, err := app.db.ToggleSite(site.ID); err != nil || enabled {
		t.Fatalf("disable site: enabled=%v err=%v", enabled, err)
	}

	body := strings.NewReader(`{"name":"quota-clear","listen_port":` + jsonNumber(port) + `,"target_url":"http://127.0.0.1:8096","ua_mode":"infuse","traffic_quota":0}`)
	req := httptest.NewRequest(http.MethodPut, "/api/sites/"+jsonNumber64(site.ID), body)
	rr := httptest.NewRecorder()
	app.handleSiteByID(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.TrafficQuota != 0 {
		t.Fatalf("traffic_quota = %d, want explicit 0", reloaded.TrafficQuota)
	}
}

func TestFlushTrafficUpdatesBaselineAndStopPersistsPendingUsage(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("traffic", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 1024, 0)
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
	site, err := app.db.CreateSite("aggregate", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
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
	if got := rr.Result().Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
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

func TestHandleSitesCreatesCustomUAAndPresetUpdateClearsIt(t *testing.T) {
	app := newTestApp(t)
	createPayload, err := json.Marshal(map[string]interface{}{
		"name":              "custom-identity",
		"listen_port":       freePort(t),
		"target_url":        "http://127.0.0.1:8096",
		"ua_mode":           "custom",
		"custom_user_agent": "Meridian Custom/1.0",
		"custom_client":     "Meridian Custom",
		"custom_version":    "1.0.0",
	})
	if err != nil {
		t.Fatalf("marshal create payload: %v", err)
	}
	createRecorder := httptest.NewRecorder()
	app.handleSites(createRecorder, httptest.NewRequest(http.MethodPost, "/api/sites", bytes.NewReader(createPayload)))
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createRecorder.Code, createRecorder.Body.String())
	}
	var created Site
	if err := json.Unmarshal(createRecorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created site: %v", err)
	}
	t.Cleanup(func() { app.pm.StopSite(created.ID) })
	if created.UAMode != customUAMode || created.CustomUserAgent != "Meridian Custom/1.0" || created.CustomClient != "Meridian Custom" || created.CustomVersion != "1.0.0" {
		t.Fatalf("created custom site = %#v", created)
	}

	updatePayload, err := json.Marshal(map[string]interface{}{
		"name":        created.Name,
		"listen_port": created.ListenPort,
		"target_url":  created.TargetURL,
		"ua_mode":     "web",
	})
	if err != nil {
		t.Fatalf("marshal update payload: %v", err)
	}
	updateRecorder := httptest.NewRecorder()
	app.handleSiteByID(updateRecorder, httptest.NewRequest(http.MethodPut, "/api/sites/"+jsonNumber64(created.ID), bytes.NewReader(updatePayload)))
	if updateRecorder.Code != http.StatusOK {
		t.Fatalf("update status = %d body=%s", updateRecorder.Code, updateRecorder.Body.String())
	}
	reloaded, err := app.db.GetSite(created.ID)
	if err != nil {
		t.Fatalf("load updated site: %v", err)
	}
	if reloaded.UAMode != "web" || reloaded.CustomUserAgent != "" || reloaded.CustomClient != "" || reloaded.CustomVersion != "" {
		t.Fatalf("preset update did not clear custom fields: %#v", reloaded)
	}
}

func TestHandleSitesRejectsInvalidCustomUA(t *testing.T) {
	for _, values := range []map[string]string{
		{"custom_user_agent": "", "custom_client": "Client", "custom_version": "1.0"},
		{"custom_user_agent": "UA", "custom_client": "Bad\"", "custom_version": "1.0"},
		{"custom_user_agent": "UA\nnext", "custom_client": "Client", "custom_version": "1.0"},
	} {
		t.Run(values["custom_client"]+values["custom_user_agent"], func(t *testing.T) {
			app := newTestApp(t)
			payload := map[string]interface{}{
				"name":        "invalid-custom",
				"listen_port": freePort(t),
				"target_url":  "http://127.0.0.1:8096",
				"ua_mode":     "custom",
			}
			for key, value := range values {
				payload[key] = value
			}
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			rr := httptest.NewRecorder()
			app.handleSites(rr, httptest.NewRequest(http.MethodPost, "/api/sites", bytes.NewReader(body)))
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
			}
			if sites, err := app.db.ListSites(); err != nil || len(sites) != 0 {
				t.Fatalf("invalid custom site was persisted: sites=%#v err=%v", sites, err)
			}
		})
	}
}

func TestHandleSiteDiagUsesResolvedCustomUAProfile(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/System/Info/Public" {
			w.Write([]byte("{\"Version\":\"4.9.0\"}"))
			return
		}
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	app := newTestApp(t)
	site, err := app.db.CreateSiteWithCustomUA("diag-custom", freePort(t), upstream.URL, "", "direct", "[]", customUAMode, "Custom UA/1.0", "Custom Client", "1.0.0", 0, 0)
	if err != nil {
		t.Fatalf("create custom site: %v", err)
	}
	rr := httptest.NewRecorder()
	app.handleSiteByID(rr, httptest.NewRequest(http.MethodGet, "/api/sites/"+jsonNumber64(site.ID)+"/diag", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("diag status=%d body=%s", rr.Code, rr.Body.String())
	}
	headers := mustMapValue(t, decodeBody(t, rr), "headers")
	if got := mustStringValue(t, headers, "current_ua"); got != "Custom UA/1.0" {
		t.Fatalf("current_ua = %q", got)
	}
	if got := mustStringValue(t, headers, "client_field"); got != "Custom Client" {
		t.Fatalf("client_field = %q", got)
	}
	if got := mustStringValue(t, headers, "version_field"); got != "1.0.0" {
		t.Fatalf("version_field = %q", got)
	}
}

func TestCleanDatabaseInitializationAPIFlow(t *testing.T) {
	app := newTestApp(t)
	app.setupToken = "clean-database-setup-token"
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/check", cors(app.handleAuthCheck))
	mux.HandleFunc("/api/auth/setup", cors(app.csrfMiddleware(app.handleSetup)))
	mux.HandleFunc("/api/auth/login", cors(app.csrfMiddleware(app.handleLogin)))
	mux.HandleFunc("/api/auth/logout", cors(app.csrfMiddleware(app.handleLogout)))
	mux.HandleFunc("/api/sites", cors(app.authMiddleware(app.handleSites)))
	request := func(method, path string, body io.Reader) *http.Request {
		req := httptest.NewRequest(method, "https://panel.example"+path, body)
		if stateChangingMethod(method) {
			req.Header.Set("Origin", "https://panel.example")
		}
		return req
	}

	check := httptest.NewRecorder()
	mux.ServeHTTP(check, request(http.MethodGet, "/api/auth/check", nil))
	if check.Code != http.StatusOK || !mustBoolValue(t, decodeBody(t, check), "needs_setup") {
		t.Fatalf("initial auth check = status %d body=%s", check.Code, check.Body.String())
	}

	setupBody := strings.NewReader("{\"username\":\"admin\",\"password\":\"correct horse battery staple\",\"setup_token\":\"clean-database-setup-token\"}")
	setup := httptest.NewRecorder()
	mux.ServeHTTP(setup, request(http.MethodPost, "/api/auth/setup", setupBody))
	if setup.Code != http.StatusOK {
		t.Fatalf("setup status=%d body=%s", setup.Code, setup.Body.String())
	}
	if len(setup.Result().Cookies()) != 1 {
		t.Fatalf("setup did not return a session cookie: %#v", setup.Result().Cookies())
	}

	login := httptest.NewRecorder()
	mux.ServeHTTP(login, request(http.MethodPost, "/api/auth/login", strings.NewReader("{\"username\":\"admin\",\"password\":\"correct horse battery staple\"}")))
	if login.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.Code, login.Body.String())
	}
	if _, ok := decodeBody(t, login)["token"]; ok {
		t.Fatal("login response exposed a bearer token")
	}
	loginCookies := login.Result().Cookies()
	if len(loginCookies) != 1 {
		t.Fatalf("login did not return a session cookie: %#v", loginCookies)
	}

	authenticatedCheck := httptest.NewRecorder()
	authenticatedRequest := request(http.MethodGet, "/api/auth/check", nil)
	authenticatedRequest.AddCookie(loginCookies[0])
	mux.ServeHTTP(authenticatedCheck, authenticatedRequest)
	if authenticatedCheck.Code != http.StatusOK || !mustBoolValue(t, decodeBody(t, authenticatedCheck), "authenticated") {
		t.Fatalf("authenticated check = status %d body=%s", authenticatedCheck.Code, authenticatedCheck.Body.String())
	}

	secondSetup := httptest.NewRecorder()
	mux.ServeHTTP(secondSetup, request(http.MethodPost, "/api/auth/setup", strings.NewReader("{\"username\":\"other\",\"password\":\"correct horse battery staple\",\"setup_token\":\"clean-database-setup-token\"}")))
	if secondSetup.Code != http.StatusBadRequest {
		t.Fatalf("second setup status=%d body=%s", secondSetup.Code, secondSetup.Body.String())
	}

	sitesRequest := request(http.MethodGet, "/api/sites", nil)
	sitesRequest.AddCookie(loginCookies[0])
	sites := httptest.NewRecorder()
	mux.ServeHTTP(sites, sitesRequest)
	if sites.Code != http.StatusOK {
		t.Fatalf("authenticated sites status=%d body=%s", sites.Code, sites.Body.String())
	}
}

func TestStartSiteRejectsCorruptStreamHosts(t *testing.T) {
	app := newTestApp(t)
	base := Site{
		ID:           999,
		Name:         "corrupt-stream-hosts",
		ListenPort:   freePort(t),
		TargetURL:    "http://127.0.0.1:8096",
		PlaybackMode: "direct",
		UAMode:       "infuse",
		Enabled:      true,
	}

	invalidJSON := base
	invalidJSON.StreamHosts = "{"
	if err := app.pm.StartSite(invalidJSON); err == nil || !strings.Contains(err.Error(), "invalid stream_hosts") {
		t.Fatalf("invalid JSON error = %v", err)
	}

	invalidURL := base
	invalidURL.StreamHosts = `["file://media.example.com/path"]`
	if err := app.pm.StartSite(invalidURL); err == nil || !strings.Contains(err.Error(), "invalid stream host") {
		t.Fatalf("invalid stream host error = %v", err)
	}
	invalidUA := base
	invalidUA.UAMode = customUAMode
	invalidUA.CustomUserAgent = "Custom UA"
	invalidUA.CustomClient = ""
	invalidUA.CustomVersion = "1.0"
	if err := app.pm.StartSite(invalidUA); err == nil || !strings.Contains(err.Error(), "invalid UA profile") {
		t.Fatalf("invalid custom UA profile error = %v", err)
	}
	if app.pm.IsRunning(base.ID) {
		t.Fatal("corrupt site unexpectedly started")
	}
}

func TestProxyRoutesPlaybackRequestsToPlaybackTarget(t *testing.T) {
	app := newTestApp(t)

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Write([]byte("api:" + r.URL.Path))
	}))
	defer apiServer.Close()

	playbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("playback:" + r.URL.Path))
	}))
	defer playbackServer.Close()

	site, err := app.db.CreateSite("split", freePort(t), apiServer.URL, playbackServer.URL, "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	t.Cleanup(func() { app.pm.StopSite(site.ID) })
	app.pm.mu.RLock()
	proxyServer := app.pm.proxies[site.ID].server
	app.pm.mu.RUnlock()
	if proxyServer.ReadHeaderTimeout != 10*time.Second || proxyServer.IdleTimeout != 120*time.Second || proxyServer.MaxHeaderBytes != 64<<10 {
		t.Fatalf("proxy server limits not configured: %+v", proxyServer)
	}

	mainResp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/System/Info", site.ListenPort))
	if err != nil {
		t.Fatalf("GET main route: %v", err)
	}
	defer mainResp.Body.Close()
	if got := mainResp.Header.Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("upstream X-Frame-Options = %q, want SAMEORIGIN", got)
	}
	if got := mainResp.Header.Get("Content-Security-Policy"); got != "default-src 'none'" {
		t.Fatalf("upstream Content-Security-Policy = %q, want preserved value", got)
	}

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

func TestProxyPreservesConfiguredUpstreamBasePath(t *testing.T) {
	app := newTestApp(t)
	received := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.URL.RequestURI()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	site, err := app.db.CreateSite("base-path", freePort(t), upstream.URL+"/emby?from=base", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	t.Cleanup(func() { app.pm.StopSite(site.ID) })

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/System/Info/Public?client=1", site.ListenPort))
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}

	select {
	case got := <-received:
		if got != "/emby/System/Info/Public?from=base&client=1" {
			t.Fatalf("upstream request URI = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive request")
	}
}

func TestProxyPlaybackRequestsFallBackToMainTarget(t *testing.T) {
	app := newTestApp(t)

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("api:" + r.URL.Path))
	}))
	defer apiServer.Close()

	site, err := app.db.CreateSite("single", freePort(t), apiServer.URL, "", "direct", "[]", "infuse", 0, 0)
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
