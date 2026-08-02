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

// reservedPorts keeps ephemeral ports out of the kernel's free pool between
// allocation and the moment a test actually binds them. Without the
// reservation, the OS could reissue the port to an unrelated outgoing
// connection in that window, producing flaky "address already in use" site
// starts. Callers that bind the port (a site start, or an API call that
// starts a site) must call releasePort immediately beforehand.
var reservedPorts sync.Map // int -> net.Listener

func freePort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("free port listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	reservedPorts.Store(port, ln)
	t.Cleanup(func() {
		if v, ok := reservedPorts.LoadAndDelete(port); ok {
			_ = v.(net.Listener).Close()
		}
	})
	return port
}

// releasePort closes the reservation created by freePort. Call it as the last
// step before the code under test binds the port.
func releasePort(port int) {
	if v, ok := reservedPorts.LoadAndDelete(port); ok {
		_ = v.(net.Listener).Close()
	}
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

func TestNormalizeUAPassthroughMode(t *testing.T) {
	mode, userAgent, client, version, err := normalizeUAConfig(" PASSTHROUGH ", "stale", "stale", "stale")
	if err != nil {
		t.Fatalf("normalize passthrough config: %v", err)
	}
	if mode != passthroughUAMode || userAgent != "" || client != "" || version != "" {
		t.Fatalf("passthrough config = %#v %#v %#v %#v, want mode only with a cleared custom triplet", mode, userAgent, client, version)
	}

	if _, _, _, _, err := normalizeUAConfig("bogus-mode", "", "", ""); err == nil {
		t.Fatal("unknown ua_mode unexpectedly accepted")
	}
}

func TestMergeSiteUAConfigPassthrough(t *testing.T) {
	old := Site{
		UAMode:          customUAMode,
		CustomUserAgent: "Old UA",
		CustomClient:    "Old Client",
		CustomVersion:   "1.0",
	}

	// Switching custom -> passthrough clears the stored custom triplet.
	mode, userAgent, client, version, err := mergeSiteUAConfig(old, stringPointer(passthroughUAMode), nil, nil, nil)
	if err != nil {
		t.Fatalf("switch to passthrough: %v", err)
	}
	if mode != passthroughUAMode || userAgent != "" || client != "" || version != "" {
		t.Fatalf("passthrough switch = %#v %#v %#v %#v", mode, userAgent, client, version)
	}

	// Passthrough with an explicitly empty custom triplet is legal.
	if _, _, _, _, err := mergeSiteUAConfig(old, stringPointer(passthroughUAMode), stringPointer(""), stringPointer(""), stringPointer("")); err != nil {
		t.Fatalf("passthrough with empty custom fields: %v", err)
	}

	// Passthrough with a non-empty custom triplet is rejected like any other
	// non-custom mode: the custom-switch rules do not regress.
	if _, _, _, _, err := mergeSiteUAConfig(old, stringPointer(passthroughUAMode), stringPointer("New UA"), stringPointer("New Client"), stringPointer("2.0")); err == nil {
		t.Fatal("passthrough with non-empty custom fields unexpectedly accepted")
	}

	// PUT omitting ua_mode preserves the stored passthrough mode and clears
	// any stale triplet left in the row.
	passthroughOld := Site{UAMode: passthroughUAMode, CustomUserAgent: "stale", CustomClient: "stale", CustomVersion: "stale"}
	mode, userAgent, client, version, err = mergeSiteUAConfig(passthroughOld, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("preserve passthrough: %v", err)
	}
	if mode != passthroughUAMode || userAgent != "" || client != "" || version != "" {
		t.Fatalf("preserved passthrough = %#v %#v %#v %#v", mode, userAgent, client, version)
	}

	// Passthrough -> custom with a full triplet is legal.
	mode, userAgent, client, version, err = mergeSiteUAConfig(passthroughOld, stringPointer(customUAMode), stringPointer("New UA"), stringPointer("New Client"), stringPointer("2.0"))
	if err != nil {
		t.Fatalf("switch passthrough to custom: %v", err)
	}
	if mode != customUAMode || userAgent != "New UA" || client != "New Client" || version != "2.0" {
		t.Fatalf("custom switch = %#v %#v %#v %#v", mode, userAgent, client, version)
	}

	// Passthrough -> preset.
	if mode, _, _, _, err := mergeSiteUAConfig(passthroughOld, stringPointer("web"), nil, nil, nil); err != nil || mode != "web" {
		t.Fatalf("passthrough to preset: mode=%q err=%v", mode, err)
	}
}

func TestResolveUAHeaderPolicyDiscriminatesModes(t *testing.T) {
	custom, err := resolveUAHeaderPolicy(Site{UAMode: customUAMode, CustomUserAgent: "Custom UA/1.0", CustomClient: "Custom Client", CustomVersion: "1.0.0"})
	if err != nil {
		t.Fatalf("resolve custom: %v", err)
	}
	if !custom.Rewrite || custom.Profile.UserAgent != "Custom UA/1.0" || custom.Profile.Client != "Custom Client" || custom.Profile.Version != "1.0.0" {
		t.Fatalf("custom policy = %#v", custom)
	}

	preset, err := resolveUAHeaderPolicy(Site{UAMode: "web"})
	if err != nil {
		t.Fatalf("resolve preset: %v", err)
	}
	if !preset.Rewrite || preset.Profile != uaProfiles["web"] {
		t.Fatalf("preset policy = %#v", preset)
	}

	// Passthrough is its own policy state, never an empty-UAProfile sentinel;
	// stale custom fields in the row are cleared by normalization.
	pass, err := resolveUAHeaderPolicy(Site{UAMode: passthroughUAMode, CustomUserAgent: "stale", CustomClient: "stale", CustomVersion: "stale"})
	if err != nil {
		t.Fatalf("resolve passthrough: %v", err)
	}
	if pass.Rewrite {
		t.Fatalf("passthrough policy must not rewrite: %#v", pass)
	}

	if _, err := resolveUAHeaderPolicy(Site{UAMode: "bogus"}); err == nil {
		t.Fatal("unknown mode unexpectedly resolved")
	}
}

func TestApplyUAHeaderPolicyPassthroughPreservesIdentityHeaders(t *testing.T) {
	authorization := `MediaBrowser Client="Client", Device="TV", DeviceId="d1", Version="1", Token="secret"`
	header := http.Header{
		"User-Agent":           []string{"ClientUA/9.9"},
		"X-Emby-Authorization": []string{authorization},
		"Authorization":        []string{"Bearer opaque"},
	}
	applyUAHeaderPolicy(header, UAHeaderPolicy{})
	if got := header.Get("User-Agent"); got != "ClientUA/9.9" {
		t.Fatalf("User-Agent = %q, want the client value preserved", got)
	}
	if got := header.Get("X-Emby-Authorization"); got != authorization {
		t.Fatalf("X-Emby-Authorization = %q, want byte-identical passthrough", got)
	}
	if got := header.Get("Authorization"); got != "Bearer opaque" {
		t.Fatalf("Authorization = %q, want byte-identical passthrough", got)
	}

	rewritten := http.Header{
		"User-Agent":           []string{"ClientUA/9.9"},
		"X-Emby-Authorization": []string{authorization},
	}
	applyUAHeaderPolicy(rewritten, UAHeaderPolicy{Rewrite: true, Profile: uaProfiles["client"]})
	if got := rewritten.Get("User-Agent"); got != uaProfiles["client"].UserAgent {
		t.Fatalf("rewrite User-Agent = %q, want %q", got, uaProfiles["client"].UserAgent)
	}
	if got := rewritten.Get("X-Emby-Authorization"); !strings.Contains(got, `Client="Emby Theater"`) || !strings.Contains(got, `Version="4.7.0"`) {
		t.Fatalf("rewrite authorization = %q", got)
	}
}

func TestHTTPPassthroughPreservesClientIdentityAndRebuildsForwarding(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://meridian.example:50001/System/Info", nil)
	request.RemoteAddr = "198.51.100.26:12345"
	request.Header.Set("User-Agent", "ClientUA/9.9")
	request.Header.Set("X-Emby-Authorization", `MediaBrowser Client="Client", Device="TV", Version="1"`)
	request.Header.Set("X-Forwarded-For", "203.0.113.8")

	header := request.Header.Clone()
	prepareUpstreamHeaders(header, request, UAHeaderPolicy{})

	if got := header.Get("User-Agent"); got != "ClientUA/9.9" {
		t.Fatalf("User-Agent = %q, want the client value preserved", got)
	}
	if got := header.Get("X-Emby-Authorization"); !strings.Contains(got, `Client="Client"`) || !strings.Contains(got, `Device="TV"`) {
		t.Fatalf("X-Emby-Authorization = %q, want client identity preserved", got)
	}
	// X-Forwarded-* rebuilding is unchanged in passthrough mode.
	if got := header.Get("X-Forwarded-For"); got != "198.51.100.26" {
		t.Fatalf("X-Forwarded-For = %q, want rebuilt from the peer address", got)
	}
	if got := header.Get("X-Forwarded-Host"); got != "meridian.example:50001" {
		t.Fatalf("X-Forwarded-Host = %q", got)
	}
	if got := header.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("X-Forwarded-Proto = %q", got)
	}
}

func TestPrepareWebSocketUpstreamHeadersRemovesConnectionNominatedHopByHop(t *testing.T) {
	target, err := normalizeTargetURL("https://upstream.example.com")
	if err != nil {
		t.Fatalf("normalize target: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://meridian.example/socket", nil)
	req.Header.Set("Connection", "Upgrade, X-Hop-By-Hop, keep-alive")
	req.Header.Set("X-Hop-By-Hop", "secret")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	header := prepareWebSocketUpstreamHeaders(req, target, UAHeaderPolicy{Rewrite: true, Profile: getUAProfile("infuse")})
	if got := header.Get("X-Hop-By-Hop"); got != "" {
		t.Fatalf("Connection-nominated X-Hop-By-Hop forwarded: %q", got)
	}
	if got := header.Get("Keep-Alive"); got != "" {
		t.Fatalf("Connection-nominated Keep-Alive forwarded: %q", got)
	}
	if got := header.Get("Connection"); got != "Upgrade" {
		t.Fatalf("Connection = %q, want the rebuilt Upgrade value", got)
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
	originalSecret := jwtSecret
	t.Cleanup(func() { jwtSecret = originalSecret })
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
		policy:        UAHeaderPolicy{Rewrite: true, Profile: getUAProfile("infuse")},
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
			policy:        UAHeaderPolicy{Rewrite: true, Profile: getUAProfile("infuse")},
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
			policy:        UAHeaderPolicy{Rewrite: true, Profile: getUAProfile("infuse")},
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
			policy:        UAHeaderPolicy{Rewrite: true, Profile: getUAProfile("infuse")},
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
			policy:        UAHeaderPolicy{Rewrite: true, Profile: getUAProfile("infuse")},
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
	policy := UAHeaderPolicy{Rewrite: true, Profile: getUAProfile("infuse")}
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
			prepareUpstreamHeaders(proxyReq.Out.Header, proxyReq.In, policy)
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
	if got := captured.Header.Get("User-Agent"); got != policy.Profile.UserAgent {
		t.Fatalf("outbound User-Agent = %q, want profile value %q", got, policy.Profile.UserAgent)
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
	policy := UAHeaderPolicy{Rewrite: true, Profile: getUAProfile("infuse")}
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

	header := prepareWebSocketUpstreamHeaders(req, target, policy)
	if got := req.Header.Get("Forwarded"); got == "" {
		t.Fatal("preparing WebSocket headers mutated the inbound request")
	}
	for name, want := range map[string]string{
		"Connection":        "Upgrade",
		"Upgrade":           "websocket",
		"Host":              target.Host,
		"User-Agent":        policy.Profile.UserAgent,
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
	for _, asset := range []string{"/css/style.css?v=1.6.1", "/js/pages/sites.js?v=1.6.1", "/js/app.js?v=1.6.1"} {
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
	longToken := "setup-token-with-more-than-thirty-two-bytes"
	if _, err := configuredSetupToken(0, " \t "); err == nil {
		t.Fatal("empty initial setup token unexpectedly accepted")
	}
	if got, err := configuredSetupToken(0, " "+longToken+" "); err != nil || got != longToken {
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
	// The single-administrator invariant is enforced by ResetAdminPassword;
	// fabricate the second row directly because the public API must never be
	// able to create a second admin.
	if _, err := app.db.db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", "admin-one", "hash-one"); err != nil {
		t.Fatalf("insert user one: %v", err)
	}
	if _, err := app.db.db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", "admin-two", "hash-two"); err != nil {
		t.Fatalf("insert user two: %v", err)
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
	originalEphemeral := jwtSecretEphemeral
	t.Cleanup(func() { jwtSecretEphemeral = originalEphemeral })
	jwtSecretEphemeral = false

	if _, err := app.db.db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", "admin", "hash"); err != nil {
		t.Fatalf("insert admin: %v", err)
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
	if _, err := app.pm.TrafficSnapshot(); err == nil {
		t.Fatal("TrafficSnapshot unexpectedly ignored a closed database")
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
	policy := UAHeaderPolicy{Rewrite: true, Profile: UAProfile{
		Name:      "Custom",
		UserAgent: "Meridian Test/1.0",
		Client:    "Meridian Test",
		Version:   "1.0.0",
	}}
	authorization := "MediaBrowser Device=\"TV\", DeviceId=\"device-1\", Client=\"old\", Version=\"old\""
	assertIdentity := func(t *testing.T, header http.Header) {
		t.Helper()
		if got := header.Get("User-Agent"); got != policy.Profile.UserAgent {
			t.Fatalf("User-Agent = %q, want %q", got, policy.Profile.UserAgent)
		}
		got := header.Get("X-Emby-Authorization")
		for _, want := range []string{"Device=\"TV\"", "DeviceId=\"device-1\"", "Client=\"" + policy.Profile.Client + "\"", "Version=\"" + policy.Profile.Version + "\""} {
			if !strings.Contains(got, want) {
				t.Fatalf("authorization = %q, missing %q", got, want)
			}
		}
	}

	t.Run("http", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "http://meridian.example/System/Info", nil)
		request.Header.Set("X-Emby-Authorization", authorization)
		header := request.Header.Clone()
		prepareUpstreamHeaders(header, request, policy)
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
		header := prepareWebSocketUpstreamHeaders(request, target, policy)
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
			policy:        policy,
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
		applyUAHeaderPolicy(request.Header, policy)
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

func TestRedirectFollowStripsSensitiveHeadersCrossOrigin(t *testing.T) {
	target, err := normalizeTargetURL("https://media.example.com")
	if err != nil {
		t.Fatalf("normalize target: %v", err)
	}
	profile := UAProfile{Name: "Custom", UserAgent: "Meridian Test/1.0", Client: "Meridian Test", Version: "1.0.0"}
	var followedHeaders http.Header
	calls := 0
	transport := &redirectFollowTransport{
		playbackHosts: map[string]bool{redirectHostKey(target): true},
		policy:        UAHeaderPolicy{Rewrite: true, Profile: profile},
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
	request.Header.Set("Cookie", "session=secret-cookie")
	request.Header.Set("Authorization", "Bearer opaque-bearer")
	request.Header.Set("X-Emby-Authorization", `MediaBrowser Device="TV", DeviceId="device-1", Token="emby-access-token", Client="old", Version="old"`)
	request.Header.Set("X-Emby-Token", "emby-access-token")
	request.Header.Set("X-MediaBrowser-Token", "emby-access-token")
	applyUAProfileHeaders(request.Header, profile)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("follow redirect: %v", err)
	}
	response.Body.Close()

	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if got := followedHeaders.Get("Cookie"); got != "" {
		t.Fatalf("Cookie forwarded across origin: %q", got)
	}
	if got := followedHeaders.Get("Authorization"); got != "" {
		t.Fatalf("Authorization forwarded across origin: %q", got)
	}
	if got := followedHeaders.Get("X-Emby-Token"); got != "" {
		t.Fatalf("X-Emby-Token forwarded across origin: %q", got)
	}
	if got := followedHeaders.Get("X-MediaBrowser-Token"); got != "" {
		t.Fatalf("X-MediaBrowser-Token forwarded across origin: %q", got)
	}
	emby := followedHeaders.Get("X-Emby-Authorization")
	if strings.Contains(emby, "emby-access-token") {
		t.Fatalf("Emby access token forwarded across origin: %q", emby)
	}
	if strings.Contains(strings.ToLower(emby), "token=") {
		t.Fatalf("Token attribute survives cross-origin hop: %q", emby)
	}
	if emby != `MediaBrowser Device="TV", DeviceId="device-1", Client="Meridian Test", Version="1.0.0"` {
		t.Fatalf("identity fields altered: %q", emby)
	}
	if got := followedHeaders.Get("User-Agent"); got != profile.UserAgent {
		t.Fatalf("User-Agent = %q, want %q", got, profile.UserAgent)
	}
}

func TestRedirectFollowKeepsHeadersSameOrigin(t *testing.T) {
	target, err := normalizeTargetURL("https://media.example.com")
	if err != nil {
		t.Fatalf("normalize target: %v", err)
	}
	profile := UAProfile{Name: "Custom", UserAgent: "Meridian Test/1.0", Client: "Meridian Test", Version: "1.0.0"}
	var followedHeaders http.Header
	calls := 0
	transport := &redirectFollowTransport{
		playbackHosts: map[string]bool{redirectHostKey(target): true},
		policy:        UAHeaderPolicy{Rewrite: true, Profile: profile},
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
	request := httptest.NewRequest(http.MethodGet, "https://media.example.com/Videos/1/stream", nil)
	request.Header.Set("Cookie", "session=secret-cookie")
	request.Header.Set("Authorization", "Bearer opaque-bearer")
	request.Header.Set("X-Emby-Authorization", `MediaBrowser Device="TV", Token="emby-access-token", Client="old", Version="old"`)
	applyUAProfileHeaders(request.Header, profile)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("follow redirect: %v", err)
	}
	response.Body.Close()

	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if got := followedHeaders.Get("Cookie"); got != "session=secret-cookie" {
		t.Fatalf("Cookie dropped on same-origin redirect: %q", got)
	}
	if got := followedHeaders.Get("Authorization"); got != "Bearer opaque-bearer" {
		t.Fatalf("Authorization dropped on same-origin redirect: %q", got)
	}
	emby := followedHeaders.Get("X-Emby-Authorization")
	if !strings.Contains(emby, "emby-access-token") {
		t.Fatalf("Emby token lost on same-origin redirect: %q", emby)
	}
}

func TestStripEmbyAuthorizationToken(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		want     string
		wantSafe bool
	}{
		{
			name:     "removes token and keeps identity",
			value:    `MediaBrowser Client="App", Device="TV", DeviceId="d1", Token="secret", Version="1"`,
			want:     `MediaBrowser Client="App", Device="TV", DeviceId="d1", Version="1"`,
			wantSafe: true,
		},
		{
			name:     "emby scheme is stripped like mediabrowser",
			value:    `Emby Device="TV", Token="secret"`,
			want:     `Emby Device="TV"`,
			wantSafe: true,
		},
		{
			name:     "token as only attribute leaves bare scheme",
			value:    `MediaBrowser Token="secret"`,
			want:     `MediaBrowser`,
			wantSafe: true,
		},
		{
			name:     "token as first attribute drops delimiter",
			value:    `MediaBrowser Token="secret", Client="App"`,
			want:     `MediaBrowser Client="App"`,
			wantSafe: true,
		},
		{
			name:     "token as last attribute drops preceding delimiter",
			value:    `MediaBrowser Client="App", Device="TV", Token="secret"`,
			want:     `MediaBrowser Client="App", Device="TV"`,
			wantSafe: true,
		},
		{
			name:     "leading whitespace is preserved",
			value:    `  MediaBrowser Token="secret"`,
			want:     `  MediaBrowser`,
			wantSafe: true,
		},
		{
			name:     "token name matching is case-insensitive",
			value:    `MediaBrowser Client="App", tOkEn="secret", Version="1"`,
			want:     `MediaBrowser Client="App", Version="1"`,
			wantSafe: true,
		},
		{
			name:     "irregular whitespace around token is absorbed",
			value:    `MediaBrowser Token="secret"  ,  Client="App"`,
			want:     `MediaBrowser Client="App"`,
			wantSafe: true,
		},
		{
			name:     "whitespace before token attribute is preserved",
			value:    "MediaBrowser\tToken=\"secret\", Client=\"App\"",
			want:     "MediaBrowser\tClient=\"App\"",
			wantSafe: true,
		},
		{
			name:     "token value with comma is still removed",
			value:    `MediaBrowser Client="App", Token="a,b", Version="1"`,
			want:     `MediaBrowser Client="App", Version="1"`,
			wantSafe: true,
		},
		{
			name:     "value without token is unchanged",
			value:    `MediaBrowser Client="App"`,
			want:     `MediaBrowser Client="App"`,
			wantSafe: true,
		},
		{
			name:     "bare scheme has no token",
			value:    `MediaBrowser`,
			want:     `MediaBrowser`,
			wantSafe: true,
		},
		{
			name:     "empty value has no token",
			value:    "",
			want:     "",
			wantSafe: true,
		},
		{
			name:     "duplicate token fails closed",
			value:    `MediaBrowser Token="a", Token="b"`,
			want:     `MediaBrowser Token="a", Token="b"`,
			wantSafe: false,
		},
		{
			name:     "duplicate token with mixed case fails closed",
			value:    `MediaBrowser Token="a", token="b", Client="App"`,
			want:     `MediaBrowser Token="a", token="b", Client="App"`,
			wantSafe: false,
		},
		{
			name:     "unterminated attribute fails closed",
			value:    `MediaBrowser Client="unterminated`,
			want:     `MediaBrowser Client="unterminated`,
			wantSafe: false,
		},
		{
			name:     "unquoted token value fails closed",
			value:    `MediaBrowser Client="App", Token=secret`,
			want:     `MediaBrowser Client="App", Token=secret`,
			wantSafe: false,
		},
		{
			name:     "unknown scheme fails closed",
			value:    `Bearer opaque-bearer`,
			want:     `Bearer opaque-bearer`,
			wantSafe: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, safe := stripEmbyAuthorizationToken(tt.value)
			if got != tt.want {
				t.Fatalf("stripped = %q, want %q", got, tt.want)
			}
			if safe != tt.wantSafe {
				t.Fatalf("safe = %v, want %v", safe, tt.wantSafe)
			}
			if safe && strings.Contains(strings.ToLower(got), "token=") {
				t.Fatalf("stripped value still carries a Token attribute: %q", got)
			}
		})
	}
}

func TestStripSensitiveRedirectHeadersRemovesDedicatedTokenHeaders(t *testing.T) {
	header := http.Header{
		"X-Emby-Authorization": []string{`MediaBrowser Device="TV", Token="emby-access-token", Client="old"`},
		"X-Emby-Token":         []string{"emby-access-token"},
		"X-MediaBrowser-Token": []string{"emby-access-token"},
		"Authorization":        []string{"Bearer opaque-bearer"},
		"Cookie":               []string{"session=secret"},
		"X-Forwarded-For":      []string{"10.0.0.1"},
	}
	stripSensitiveRedirectHeaders(header)
	if got := header.Get("X-Emby-Token"); got != "" {
		t.Fatalf("X-Emby-Token forwarded: %q", got)
	}
	if got := header.Get("X-MediaBrowser-Token"); got != "" {
		t.Fatalf("X-MediaBrowser-Token forwarded: %q", got)
	}
	if got := header.Get("Cookie"); got != "" {
		t.Fatalf("Cookie forwarded: %q", got)
	}
	if got := header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization forwarded: %q", got)
	}
	emby := header.Get("X-Emby-Authorization")
	if strings.Contains(emby, "emby-access-token") {
		t.Fatalf("Emby access token forwarded: %q", emby)
	}
	if strings.Contains(strings.ToLower(emby), "token=") {
		t.Fatalf("Token attribute survives stripping: %q", emby)
	}
	if emby != `MediaBrowser Device="TV", Client="old"` {
		t.Fatalf("identity fields altered: %q", emby)
	}
	if got := header.Get("X-Forwarded-For"); got != "10.0.0.1" {
		t.Fatalf("non-sensitive header dropped: %q", got)
	}
}

func TestStripSensitiveRedirectHeadersDropsUnsafeEmbyAuthorization(t *testing.T) {
	header := http.Header{
		"X-Emby-Authorization": []string{`MediaBrowser Token="a", Token="b", Device="TV"`},
	}
	stripSensitiveRedirectHeaders(header)
	if got := header.Values("X-Emby-Authorization"); len(got) != 0 {
		t.Fatalf("unsafe authorization value forwarded: %q", got)
	}
}

func TestRedirectFollowDropsUnsafeEmbyAuthorizationCrossOrigin(t *testing.T) {
	// A value with a duplicate Token cannot be stripped safely, so the whole
	// header must be dropped on a cross-authority hop instead of being
	// forwarded with a token intact.
	target, err := normalizeTargetURL("https://media.example.com")
	if err != nil {
		t.Fatalf("normalize target: %v", err)
	}
	profile := UAProfile{Name: "Custom", UserAgent: "Meridian Test/1.0", Client: "Meridian Test", Version: "1.0.0"}
	var followedHeaders http.Header
	calls := 0
	transport := &redirectFollowTransport{
		playbackHosts: map[string]bool{redirectHostKey(target): true},
		policy:        UAHeaderPolicy{Rewrite: true, Profile: profile},
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
	request.Header.Set("X-Emby-Authorization", `MediaBrowser Token="first", Token="second", Device="TV"`)
	applyUAProfileHeaders(request.Header, profile)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("follow redirect: %v", err)
	}
	response.Body.Close()

	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if got := followedHeaders.Values("X-Emby-Authorization"); len(got) != 0 {
		t.Fatalf("unsafe X-Emby-Authorization forwarded across origin: %q", got)
	}
}

func TestRedirectFollowPassthroughCrossOriginPreservesIdentityStripsSecrets(t *testing.T) {
	target, err := normalizeTargetURL("https://media.example.com")
	if err != nil {
		t.Fatalf("normalize target: %v", err)
	}
	var followedHeaders http.Header
	calls := 0
	transport := &redirectFollowTransport{
		playbackHosts: map[string]bool{redirectHostKey(target): true},
		policy:        UAHeaderPolicy{},
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
	request.Header.Set("User-Agent", "ClientUA/9.9")
	request.Header.Set("Cookie", "session=secret-cookie")
	request.Header.Set("Authorization", "Bearer opaque-bearer")
	request.Header.Set("X-Emby-Authorization", `MediaBrowser Client="Client", Device="TV", DeviceId="d1", Token="emby-access-token", Version="1"`)
	request.Header.Set("X-Emby-Token", "emby-access-token")
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("follow redirect: %v", err)
	}
	response.Body.Close()

	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if got := followedHeaders.Get("Cookie"); got != "" {
		t.Fatalf("Cookie forwarded across origin: %q", got)
	}
	if got := followedHeaders.Get("Authorization"); got != "" {
		t.Fatalf("Authorization forwarded across origin: %q", got)
	}
	if got := followedHeaders.Get("X-Emby-Token"); got != "" {
		t.Fatalf("X-Emby-Token forwarded across origin: %q", got)
	}
	emby := followedHeaders.Get("X-Emby-Authorization")
	if strings.Contains(emby, "emby-access-token") {
		t.Fatalf("Emby access token forwarded across origin: %q", emby)
	}
	if strings.Contains(strings.ToLower(emby), "token=") {
		t.Fatalf("Token attribute survives cross-origin hop: %q", emby)
	}
	if emby != `MediaBrowser Client="Client", Device="TV", DeviceId="d1", Version="1"` {
		t.Fatalf("identity fields altered: %q", emby)
	}
	// Passthrough keeps the client's own non-secret identity and UA.
	if got := followedHeaders.Get("User-Agent"); got != "ClientUA/9.9" {
		t.Fatalf("User-Agent = %q, want the client value preserved", got)
	}
}

func TestRedirectFollowPassthroughSameOriginKeepsAuth(t *testing.T) {
	target, err := normalizeTargetURL("https://media.example.com")
	if err != nil {
		t.Fatalf("normalize target: %v", err)
	}
	var followedHeaders http.Header
	calls := 0
	transport := &redirectFollowTransport{
		playbackHosts: map[string]bool{redirectHostKey(target): true},
		policy:        UAHeaderPolicy{},
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
	request := httptest.NewRequest(http.MethodGet, "https://media.example.com/Videos/1/stream", nil)
	request.Header.Set("User-Agent", "ClientUA/9.9")
	request.Header.Set("Cookie", "session=secret-cookie")
	request.Header.Set("Authorization", "Bearer opaque-bearer")
	request.Header.Set("X-Emby-Authorization", `MediaBrowser Client="Client", Device="TV", Token="emby-access-token", Version="1"`)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("follow redirect: %v", err)
	}
	response.Body.Close()

	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if got := followedHeaders.Get("Cookie"); got != "session=secret-cookie" {
		t.Fatalf("Cookie dropped on same-origin redirect: %q", got)
	}
	if got := followedHeaders.Get("Authorization"); got != "Bearer opaque-bearer" {
		t.Fatalf("Authorization dropped on same-origin redirect: %q", got)
	}
	if got := followedHeaders.Get("User-Agent"); got != "ClientUA/9.9" {
		t.Fatalf("User-Agent = %q, want the client value preserved", got)
	}
	emby := followedHeaders.Get("X-Emby-Authorization")
	if !strings.Contains(emby, "emby-access-token") {
		t.Fatalf("Emby token lost on same-origin redirect: %q", emby)
	}
	if !strings.Contains(emby, `Client="Client"`) {
		t.Fatalf("Emby identity lost on same-origin redirect: %q", emby)
	}
}

func TestRedirectFollowDropsUnsafeEmbyAuthorizationCrossOriginInPassthrough(t *testing.T) {
	// Duplicate or malformed Token attributes cannot be stripped safely, so the
	// whole X-Emby-Authorization header must be dropped on a cross-authority hop
	// even in passthrough mode. The non-secret User-Agent still survives.
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"duplicate token", `MediaBrowser Token="first", Token="second", Device="TV", Client="Client"`},
		{"malformed token", `MediaBrowser Client="Client", Device="TV", Token="unterminated`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, err := normalizeTargetURL("https://media.example.com")
			if err != nil {
				t.Fatalf("normalize target: %v", err)
			}
			var followedHeaders http.Header
			calls := 0
			transport := &redirectFollowTransport{
				playbackHosts: map[string]bool{redirectHostKey(target): true},
				policy:        UAHeaderPolicy{},
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
			request.Header.Set("User-Agent", "ClientUA/9.9")
			request.Header.Set("X-Emby-Authorization", tc.value)
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatalf("follow redirect: %v", err)
			}
			response.Body.Close()

			if calls != 2 {
				t.Fatalf("calls = %d, want 2", calls)
			}
			if got := followedHeaders.Values("X-Emby-Authorization"); len(got) != 0 {
				t.Fatalf("unsafe X-Emby-Authorization forwarded across origin: %q", got)
			}
			if got := followedHeaders.Get("User-Agent"); got != "ClientUA/9.9" {
				t.Fatalf("User-Agent = %q, want the client value preserved", got)
			}
		})
	}
}

func TestProbeClientRejectsCrossHostRedirect(t *testing.T) {
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/private", http.StatusFound)
	}))
	defer redirected.Close()

	health := probeTargetHealth(diagProbePlan{
		BaseURL:       redirected.URL,
		Kind:          "metadata_api",
		Method:        http.MethodGet,
		CandidateURLs: []string{redirected.URL + "/System/Info/Public"},
		ParseVersion:  true,
	})
	if health.Status != "offline" {
		t.Fatalf("status = %q, want offline", health.Status)
	}
	if !strings.Contains(health.Error, "different host") {
		t.Fatalf("error = %q, want cross-host redirect rejection", health.Error)
	}
}

func TestProbeClientFollowsSameHostRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/System/Info/Public", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"1.2.3"}`))
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/System/Info/Public", http.StatusFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	health := probeTargetHealth(diagProbePlan{
		BaseURL:       server.URL,
		Kind:          "metadata_api",
		Method:        http.MethodGet,
		CandidateURLs: []string{server.URL + "/redirect"},
		ParseVersion:  true,
	})
	if health.Status != "online" {
		t.Fatalf("status = %q error=%q, want online", health.Status, health.Error)
	}
	if health.EmbyVer != "1.2.3" {
		t.Fatalf("emby version = %q, want 1.2.3", health.EmbyVer)
	}
}

func TestConfiguredSetupTokenRejectsShortToken(t *testing.T) {
	if _, err := configuredSetupToken(0, strings.Repeat("x", 31)); !strings.Contains(err.Error(), "at least 32") {
		t.Fatalf("short token error = %v", err)
	}
	token, err := configuredSetupToken(0, strings.Repeat("x", 32))
	if err != nil {
		t.Fatalf("32-byte token rejected: %v", err)
	}
	if token != strings.Repeat("x", 32) {
		t.Fatalf("token = %q", token)
	}
}

func TestSetupIsRateLimited(t *testing.T) {
	app := newTestApp(t)
	app.setupToken = strings.Repeat("x", 32)

	post := func() int {
		body := strings.NewReader(`{"username":"admin","password":"correct horse battery staple","setup_token":"wrong-token"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", body)
		req.RemoteAddr = "192.0.2.10:1234"
		rr := httptest.NewRecorder()
		app.handleSetup(rr, req)
		return rr.Code
	}
	for i := 0; i < maxLoginFailures; i++ {
		if code := post(); code != http.StatusForbidden {
			t.Fatalf("attempt %d status = %d, want 403", i+1, code)
		}
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Fatalf("blocked attempt status = %d, want 429", code)
	}
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
	releasePort(initialPort)
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
	releasePort(initialPort)
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

// setDBReadonly flips the single pooled connection's query_only pragma, making
// every DB write fail while reads keep working. openDB pins SetMaxOpenConns(1),
// so the connection-scoped pragma is deterministic.
func setDBReadonly(t *testing.T, app *App, readonly bool) {
	t.Helper()
	value := "OFF"
	if readonly {
		value = "ON"
	}
	if _, err := app.db.db.Exec("PRAGMA query_only=" + value); err != nil {
		t.Fatalf("PRAGMA query_only=%s: %v", value, err)
	}
}

// execTestSQL runs a one-off statement on the test app's single pooled
// connection, so schema-level failure injection (SQLite triggers) is
// deterministic. Used to make one specific write fail while the flush's own
// writes keep succeeding - the granularity query_only cannot express.
func execTestSQL(t *testing.T, app *App, statement string) {
	t.Helper()
	if _, err := app.db.db.Exec(statement); err != nil {
		t.Fatalf("exec %q: %v", statement, err)
	}
}

func findLiveSite(t *testing.T, snap *TrafficSnapshot, id int64) SiteTraffic {
	t.Helper()
	for _, st := range snap.LiveSites {
		if st.ID == id {
			return st
		}
	}
	t.Fatalf("site %d missing from TrafficSnapshot live sites: %+v", id, snap.LiveSites)
	return SiteTraffic{}
}

// Pending bytes are flushed to the DB exactly once, the authoritative total
// traffic_used = persisted + pending is conserved across flushes, and the
// current-hour log bucket aggregates without double counting.
func TestFlushPersistsPendingExactlyOnceAndConservesTotals(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("conservation", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	inst := &ProxyInstance{Site: *site, server: &http.Server{}}
	inst.bytesIn.Store(120)
	inst.bytesOut.Store(80)
	app.pm.proxies[site.ID] = inst

	// Before any flush the live total already includes the pending bytes.
	snap, err := app.pm.TrafficSnapshot()
	if err != nil {
		t.Fatalf("TrafficSnapshot: %v", err)
	}
	live := findLiveSite(t, snap, site.ID)
	if live.TrafficUsed != 200 || live.PersistedTraffic != 0 || live.BytesIn != 120 || live.BytesOut != 80 {
		t.Fatalf("pre-flush live state = %+v, want used=200 persisted=0 in=120 out=80", live)
	}

	app.pm.FlushTraffic()

	// Pending moved to the baseline exactly once.
	if got := inst.persistedTraffic.Load(); got != 200 {
		t.Fatalf("persistedTraffic after flush = %d, want 200", got)
	}
	if got := inst.bytesIn.Load(); got != 0 {
		t.Fatalf("bytesIn after flush = %d, want 0", got)
	}
	if got := inst.bytesOut.Load(); got != 0 {
		t.Fatalf("bytesOut after flush = %d, want 0", got)
	}
	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.TrafficUsed != 200 {
		t.Fatalf("traffic_used = %d, want 200", reloaded.TrafficUsed)
	}
	logs, err := app.db.GetTrafficLogs(site.ID, 1)
	if err != nil {
		t.Fatalf("GetTrafficLogs: %v", err)
	}
	if len(logs) != 1 || logs[0].BytesIn != 120 || logs[0].BytesOut != 80 {
		t.Fatalf("logs after flush = %+v, want one row with 120/80", logs)
	}

	// A second flush with fresh pending accumulates; nothing is double counted.
	inst.bytesIn.Store(30)
	inst.bytesOut.Store(10)
	app.pm.FlushTraffic()
	if got := inst.persistedTraffic.Load(); got != 240 {
		t.Fatalf("persistedTraffic after second flush = %d, want 240", got)
	}
	logs, err = app.db.GetTrafficLogs(site.ID, 1)
	if err != nil {
		t.Fatalf("GetTrafficLogs: %v", err)
	}
	if len(logs) != 1 || logs[0].BytesIn != 150 || logs[0].BytesOut != 90 {
		t.Fatalf("logs after second flush = %+v, want one aggregated row 150/90", logs)
	}
	snap, err = app.pm.TrafficSnapshot()
	if err != nil {
		t.Fatalf("TrafficSnapshot: %v", err)
	}
	live = findLiveSite(t, snap, site.ID)
	if live.TrafficUsed != 240 || snap.TotalTraffic != 240 {
		t.Fatalf("post-flush total = site:%d snapshot:%d, want 240/240", live.TrafficUsed, snap.TotalTraffic)
	}
}

// A failed flush restores the pending counters verbatim and a later retry
// persists exactly those bytes, so no traffic is lost or double counted.
func TestFlushFailureRestoresPendingAndRetryPersistsExactlyOnce(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("retry", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	inst := &ProxyInstance{Site: *site, server: &http.Server{}}
	inst.bytesIn.Store(120)
	inst.bytesOut.Store(80)
	app.pm.proxies[site.ID] = inst

	setDBReadonly(t, app, true)
	if err := app.pm.flushProxyTraffic(inst); err == nil {
		t.Fatal("flush succeeded against a read-only database")
	}
	// Full refill: pending intact, baseline and DB untouched.
	if got := inst.bytesIn.Load(); got != 120 {
		t.Fatalf("bytesIn after failed flush = %d, want 120 restored", got)
	}
	if got := inst.bytesOut.Load(); got != 80 {
		t.Fatalf("bytesOut after failed flush = %d, want 80 restored", got)
	}
	if got := inst.persistedTraffic.Load(); got != 0 {
		t.Fatalf("persistedTraffic after failed flush = %d, want 0", got)
	}
	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.TrafficUsed != 0 {
		t.Fatalf("traffic_used after failed flush = %d, want 0", reloaded.TrafficUsed)
	}

	// Retry after the DB recovers persists the exact same bytes, once.
	setDBReadonly(t, app, false)
	if err := app.pm.flushProxyTraffic(inst); err != nil {
		t.Fatalf("flush retry: %v", err)
	}
	if got := inst.persistedTraffic.Load(); got != 200 {
		t.Fatalf("persistedTraffic after retry = %d, want 200", got)
	}
	reloaded, err = app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.TrafficUsed != 200 {
		t.Fatalf("traffic_used after retry = %d, want 200", reloaded.TrafficUsed)
	}
	logs, err := app.db.GetTrafficLogs(site.ID, 1)
	if err != nil {
		t.Fatalf("GetTrafficLogs: %v", err)
	}
	if len(logs) != 1 || logs[0].BytesIn != 120 || logs[0].BytesOut != 80 {
		t.Fatalf("logs after retry = %+v, want one row 120/80", logs)
	}
}

// The single-site history snapshot reads DB logs, persisted baseline and
// pending under one lock: pending bytes land in the current-hour bucket of the
// returned copy (synthetic ID=0 bucket when absent, no-op when pending is 0).
func TestSiteTrafficHistoryMergesPendingIntoCurrentHourBucket(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("merge", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	pastHour := time.Now().Add(-2 * time.Hour).Truncate(time.Hour).Format("2006-01-02 15:04:05")
	if _, err := app.db.db.Exec("INSERT INTO traffic_logs (site_id, bytes_in, bytes_out, recorded_at) VALUES (?,?,?,?)", site.ID, 100, 50, pastHour); err != nil {
		t.Fatalf("insert past log: %v", err)
	}
	if _, err := app.db.db.Exec("UPDATE sites SET traffic_used=150 WHERE id=?", site.ID); err != nil {
		t.Fatalf("bump traffic_used: %v", err)
	}

	inst := &ProxyInstance{Site: *site, server: &http.Server{}}
	inst.persistedTraffic.Store(150)
	inst.bytesIn.Store(30)
	inst.bytesOut.Store(20)
	app.pm.proxies[site.ID] = inst

	history, err := app.pm.SiteTrafficHistory(*site, 24)
	if err != nil {
		t.Fatalf("SiteTrafficHistory: %v", err)
	}
	if len(history.Logs) != 2 {
		t.Fatalf("logs = %+v, want past row plus synthetic current-hour bucket", history.Logs)
	}
	if history.Logs[0].ID == 0 || history.Logs[0].BytesIn != 100 || history.Logs[0].BytesOut != 50 {
		t.Fatalf("past bucket mutated = %+v, want 100/50 untouched", history.Logs[0])
	}
	current := history.Logs[1]
	hourBefore := time.Now()
	if _, err := time.Parse(time.RFC3339, current.RecordedAt); err != nil {
		t.Fatalf("synthetic recorded_at %q is not RFC3339: %v", current.RecordedAt, err)
	}
	hourAfter := time.Now()
	if current.ID != 0 || current.BytesIn != 30 || current.BytesOut != 20 || !(sameTrafficHour(current.RecordedAt, hourBefore) || sameTrafficHour(current.RecordedAt, hourAfter)) {
		t.Fatalf("synthetic current bucket = %+v, want ID=0 30/20 at the current hour", current)
	}
	if !history.Snapshot.Running || history.Snapshot.PersistedTraffic != 150 || history.Snapshot.BytesIn != 30 || history.Snapshot.BytesOut != 20 || history.Snapshot.TrafficUsed != 200 {
		t.Fatalf("snapshot = %+v, want running persisted=150 in=30 out=20 used=200", history.Snapshot)
	}

	// pending = 0 is a no-op: no synthetic bucket is appended.
	inst.bytesIn.Store(0)
	inst.bytesOut.Store(0)
	history, err = app.pm.SiteTrafficHistory(*site, 24)
	if err != nil {
		t.Fatalf("SiteTrafficHistory: %v", err)
	}
	if len(history.Logs) != 1 {
		t.Fatalf("logs with zero pending = %+v, want only the past row", history.Logs)
	}

	// When the current hour already has a bucket, pending merges into it.
	// Use the synchronous addTraffic so the bucket is committed before the
	// immediate read below (AddTraffic only logs errors and races the read).
	// The bucket is identified by its bytes and real ID, never by a recorded_at
	// string layout: the SQLite driver re-serializes DATETIME columns as
	// RFC3339, so the persisted value must be matched by time semantics.
	if err := app.db.addTraffic(site.ID, 10, 5); err != nil {
		t.Fatalf("addTraffic: %v", err)
	}
	inst.bytesIn.Store(7)
	inst.bytesOut.Store(3)
	history, err = app.pm.SiteTrafficHistory(*site, 24)
	if err != nil {
		t.Fatalf("SiteTrafficHistory: %v", err)
	}
	if len(history.Logs) != 2 {
		t.Fatalf("logs after merge = %+v, want past row plus one current-hour bucket, no synthetic duplicate", history.Logs)
	}
	var merged *TrafficLog
	for i := range history.Logs {
		l := &history.Logs[i]
		if l.ID == 0 {
			t.Fatalf("synthetic ID=0 bucket present although the real row exists: %+v", l)
		}
		if l.BytesIn == 17 && l.BytesOut == 8 {
			if merged != nil {
				t.Fatalf("two buckets carry 17/8: %+v and %+v", *merged, *l)
			}
			merged = l
		}
	}
	if merged == nil {
		t.Fatalf("no 17/8 bucket in %+v; pending must merge into the real addTraffic row", history.Logs)
	}
}

// The merge identifies the current hour by time semantics, across every
// format persisted rows carry: RFC3339 / RFC3339Nano (what the modernc
// SQLite driver re-serializes DATETIME columns as) and the legacy
// "2006-01-02 15:04:05" SQL layout. Rows from other hours and values that
// parse as neither never absorb pending bytes; zero pending is a no-op.
func TestMergePendingIntoLogsHourRecognition(t *testing.T) {
	tests := []struct {
		name       string
		recordedAt string
		pendingIn  int64
		pendingOut int64
		wantMerge  bool // pending lands in the existing bucket
		wantAppend bool // synthetic ID=0 bucket is appended
	}{
		{"RFC3339 current hour", "", 8, 4, true, false},
		{"RFC3339Nano current hour", "", 8, 4, true, false},
		{"RFC3339Nano current hour with fraction", "", 8, 4, true, false},
		{"legacy SQL layout current hour", "", 8, 4, true, false},
		{"RFC3339 other hour", "", 8, 4, false, true},
		{"legacy SQL layout other hour", "", 8, 4, false, true},
		{"unparseable value", "not-a-timestamp", 8, 4, false, true},
		{"empty value", "", 8, 4, false, true},
		{"zero pending no-op", "", 0, 0, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			nowLocal := now.In(time.Local)
			// wallHour is the current local wall hour stamped as UTC, the exact
			// shape the SQLite driver returns for a stored local-hour row.
			wallHour := func(h int) time.Time {
				return time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day(), h, 0, 0, 0, time.UTC)
			}
			recordedAt := tt.recordedAt
			switch tt.name {
			case "RFC3339 current hour":
				recordedAt = wallHour(nowLocal.Hour()).Format(time.RFC3339)
			case "RFC3339Nano current hour":
				recordedAt = wallHour(nowLocal.Hour()).Format(time.RFC3339Nano)
			case "RFC3339Nano current hour with fraction":
				recordedAt = wallHour(nowLocal.Hour()).Add(250 * time.Millisecond).Format(time.RFC3339Nano)
			case "legacy SQL layout current hour":
				recordedAt = nowLocal.Format("2006-01-02 15:04:05")
			case "RFC3339 other hour":
				recordedAt = wallHour(nowLocal.Hour() - 1).Format(time.RFC3339)
			case "legacy SQL layout other hour":
				recordedAt = nowLocal.Add(-time.Hour).Format("2006-01-02 15:04:05")
			}

			in := []TrafficLog{{ID: 7, SiteID: 3, BytesIn: 10, BytesOut: 5, RecordedAt: recordedAt}}
			out := mergePendingIntoLogs(in, 3, tt.pendingIn, tt.pendingOut)

			if tt.wantMerge {
				if len(out) != 1 {
					t.Fatalf("len(out) = %d, want the existing bucket merged; got %+v", len(out), out)
				}
				if out[0].ID != 7 || out[0].BytesIn != 18 || out[0].BytesOut != 9 {
					t.Fatalf("merged bucket = %+v, want ID=7 18/9", out[0])
				}
				return
			}
			if tt.wantAppend {
				if len(out) != 2 {
					t.Fatalf("len(out) = %d, want original plus synthetic bucket; got %+v", len(out), out)
				}
				if out[0].ID != 7 || out[0].BytesIn != 10 || out[0].BytesOut != 5 {
					t.Fatalf("existing bucket mutated = %+v, want 10/5 untouched", out[0])
				}
				syn := out[1]
				if syn.ID != 0 || syn.SiteID != 3 || syn.BytesIn != 8 || syn.BytesOut != 4 {
					t.Fatalf("synthetic bucket = %+v, want ID=0 site=3 8/4", syn)
				}
				if _, err := time.Parse(time.RFC3339, syn.RecordedAt); err != nil {
					t.Fatalf("synthetic recorded_at %q is not RFC3339: %v", syn.RecordedAt, err)
				}
				if !sameTrafficHour(syn.RecordedAt, time.Now()) {
					t.Fatalf("synthetic recorded_at %q is not the current hour", syn.RecordedAt)
				}
				return
			}
			if len(out) != 1 || out[0] != in[0] {
				t.Fatalf("zero pending must be a no-op, got %+v", out)
			}
		})
	}
}

// mergePendingIntoLogs is only ever allowed to touch the copy it is given
// (GetTrafficLogs always returns a fresh slice): mutating the returned slice
// must never leak into the caller's own data.
func TestMergePendingIntoLogsOnlyMutatesPrivateCopy(t *testing.T) {
	now := time.Now()
	nowLocal := now.In(time.Local)
	wallHour := time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day(), nowLocal.Hour(), 0, 0, 0, time.UTC)
	src := []TrafficLog{
		{ID: 1, SiteID: 3, BytesIn: 10, BytesOut: 5, RecordedAt: wallHour.Format(time.RFC3339)},
		{ID: 2, SiteID: 3, BytesIn: 1, BytesOut: 1, RecordedAt: wallHour.Add(-3 * time.Hour).Format(time.RFC3339)},
	}
	work := append([]TrafficLog(nil), src...)
	out := mergePendingIntoLogs(work, 3, 8, 4)
	// Pending lands in the current-hour element of the returned copy.
	if len(out) != 2 || out[0].BytesIn != 18 || out[0].BytesOut != 9 {
		t.Fatalf("merged result = %+v, want current-hour bucket 18/9", out)
	}
	// Caller-side mutation of the result must not touch the caller's original.
	out[0].BytesIn = 999
	out[0].BytesOut = 999
	if src[0].BytesIn != 10 || src[0].BytesOut != 5 || src[1].BytesIn != 1 {
		t.Fatalf("source slice mutated through the result: %+v", src)
	}
}

// In a non-UTC deployment the DB stores local wall-clock hours and the driver
// stamps them as UTC on read, so matching must compare wall-clock components
// and the synthetic bucket must carry the current local wall hour as Z. This
// pins that behavior with the process zone fixed to UTC+8: an RFC3339 row
// whose hour reads 08:00Z matches a now of 08:30+08, a different wall hour
// does not, and the synthetic bucket is exactly the local 08:00Z row the next
// addTraffic will persist.
func TestMergePendingIntoLogsFixedZoneUTC8(t *testing.T) {
	savedLocal := time.Local
	time.Local = time.FixedZone("UTC+8", 8*3600)
	defer func() { time.Local = savedLocal }()

	now := time.Now().In(time.Local)
	wallHour := func(h int) time.Time {
		return time.Date(now.Year(), now.Month(), now.Day(), h, 0, 0, 0, time.UTC)
	}
	// RFC3339 08:00Z matches a now of 08:30+08: the stored local hour 08 read
	// back as Z is the same wall clock, even though the instants differ.
	if !sameTrafficHour(wallHour(now.Hour()).Format(time.RFC3339), now) {
		t.Fatalf("RFC3339 %q must match local wall hour %s", wallHour(now.Hour()).Format(time.RFC3339), now.Format(time.RFC3339))
	}
	// The legacy local wall-clock row matches by the same wall-clock rule.
	if !sameTrafficHour(now.Format("2006-01-02 15:04:05"), now) {
		t.Fatalf("legacy %q must match local wall hour %s", now.Format("2006-01-02 15:04:05"), now.Format(time.RFC3339))
	}
	// A different wall hour never matches, regardless of instant proximity.
	if sameTrafficHour(wallHour(now.Hour()-1).Format(time.RFC3339), now) {
		t.Fatalf("RFC3339 %q must not match local wall hour %s", wallHour(now.Hour()-1).Format(time.RFC3339), now.Format(time.RFC3339))
	}

	// A real current-hour RFC3339 row absorbs pending bytes.
	in := []TrafficLog{{ID: 5, SiteID: 2, BytesIn: 1, BytesOut: 1, RecordedAt: wallHour(now.Hour()).Format(time.RFC3339)}}
	out := mergePendingIntoLogs(in, 2, 9, 3)
	if len(out) != 1 || out[0].ID != 5 || out[0].BytesIn != 10 || out[0].BytesOut != 4 {
		t.Fatalf("merged bucket = %+v, want ID=5 10/4", out)
	}

	// The synthetic bucket is the current local wall hour stamped as UTC,
	// byte-identical to the row the next addTraffic will persist and read back.
	in = []TrafficLog{{ID: 5, SiteID: 2, BytesIn: 1, BytesOut: 1, RecordedAt: wallHour(now.Hour() - 1).Format(time.RFC3339)}}
	out = mergePendingIntoLogs(in, 2, 9, 3)
	if len(out) != 2 {
		t.Fatalf("len(out) = %d, want original plus synthetic bucket; got %+v", len(out), out)
	}
	want := wallHour(now.Hour()).Format(time.RFC3339)
	if out[1].RecordedAt != want {
		t.Fatalf("synthetic recorded_at = %q, want %q (local wall hour as Z)", out[1].RecordedAt, want)
	}
}

// The global snapshot is one authoritative payload: every DB site overlaid
// with persistedTraffic + pending for running sites, with unified totals.
func TestTrafficSnapshotUnifiedPayloadAndTotals(t *testing.T) {
	app := newTestApp(t)
	siteA, err := app.db.CreateSite("running-a", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 1024, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	siteB, err := app.db.CreateSite("idle-b", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	app.db.AddTraffic(siteB.ID, 40, 0)

	inst := &ProxyInstance{Site: *siteA, server: &http.Server{}}
	inst.persistedTraffic.Store(100)
	inst.bytesIn.Store(30)
	inst.bytesOut.Store(20)
	app.pm.proxies[siteA.ID] = inst

	snap, err := app.pm.TrafficSnapshot()
	if err != nil {
		t.Fatalf("TrafficSnapshot: %v", err)
	}
	if snap.TotalSites != 2 || snap.OnlineSites != 2 || snap.RunningSites != 1 {
		t.Fatalf("counts = total:%d online:%d running:%d, want 2/2/1", snap.TotalSites, snap.OnlineSites, snap.RunningSites)
	}
	if snap.TotalTraffic != 190 {
		t.Fatalf("total_traffic = %d, want 190 (100+30+20 persisted+pending + 40 DB)", snap.TotalTraffic)
	}
	a := findLiveSite(t, snap, siteA.ID)
	if !a.Running || a.TrafficQuota != 1024 || a.PersistedTraffic != 100 || a.BytesIn != 30 || a.BytesOut != 20 || a.TrafficUsed != 150 {
		t.Fatalf("running site entry = %+v, want running quota=1024 persisted=100 in=30 out=20 used=150", a)
	}
	b := findLiveSite(t, snap, siteB.ID)
	if b.Running || b.PersistedTraffic != 40 || b.BytesIn != 0 || b.BytesOut != 0 || b.TrafficUsed != 40 {
		t.Fatalf("idle site entry = %+v, want not running persisted=40 used=40", b)
	}
}

// The legacy endpoint keeps the plain TrafficLog[] shape (with live-merged
// current hour) and returns [] for unknown sites; the /snapshot endpoint
// returns the {snapshot, logs} envelope and 404 for unknown sites.
func TestHandleTrafficLegacyArrayAndSnapshotEnvelope(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("shape", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	inst := &ProxyInstance{Site: *site, server: &http.Server{}}
	inst.bytesIn.Store(40)
	inst.bytesOut.Store(10)
	app.pm.proxies[site.ID] = inst

	// Legacy: plain array, live-merged current hour.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/traffic/"+jsonNumber64(site.ID)+"?hours=24", nil)
	app.handleTraffic(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("legacy status = %d body=%s", rr.Code, rr.Body.String())
	}
	var logs []TrafficLog
	if err := json.Unmarshal(rr.Body.Bytes(), &logs); err != nil {
		t.Fatalf("legacy body is not a TrafficLog array: %v body=%s", err, rr.Body.String())
	}
	if len(logs) != 1 || logs[0].ID != 0 || logs[0].BytesIn != 40 || logs[0].BytesOut != 10 {
		t.Fatalf("legacy logs = %+v, want synthetic current-hour bucket 40/10", logs)
	}

	// Envelope: {snapshot, logs} with the same live state.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/traffic/"+jsonNumber64(site.ID)+"/snapshot?hours=24", nil)
	app.handleTraffic(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("snapshot status = %d body=%s", rr.Code, rr.Body.String())
	}
	body := decodeBody(t, rr)
	snap := mustMapValue(t, body, "snapshot")
	if mustNumberValue(t, snap, "traffic_used") != 50 || mustNumberValue(t, snap, "persisted_traffic") != 0 || mustNumberValue(t, snap, "bytes_in") != 40 || mustNumberValue(t, snap, "bytes_out") != 10 {
		t.Fatalf("envelope snapshot = %v, want used=50 persisted=0 in=40 out=10", snap)
	}
	if !mustBoolValue(t, snap, "running") {
		t.Fatal("envelope snapshot must report the site as running")
	}
	envLogs, ok := body["logs"].([]interface{})
	if !ok || len(envLogs) != 1 {
		t.Fatalf("envelope logs = %v, want one merged bucket", body["logs"])
	}

	// Legacy unknown site: empty array, not an error.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/traffic/999999?hours=24", nil)
	app.handleTraffic(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("legacy missing-site status = %d body=%s", rr.Code, rr.Body.String())
	}
	logs = nil
	if err := json.Unmarshal(rr.Body.Bytes(), &logs); err != nil || len(logs) != 0 {
		t.Fatalf("legacy missing-site body = %q, want []", rr.Body.String())
	}

	// Envelope unknown site: 404.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/traffic/999999/snapshot?hours=24", nil)
	app.handleTraffic(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("snapshot missing-site status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

// StopSite fails closed when the flush cannot persist: the instance stays
// registered, its pending bytes stay intact, and a later retry succeeds.
func TestStopSiteFailClosedOnFlushError(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("stopclosed", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	inst := &ProxyInstance{Site: *site, server: &http.Server{}}
	inst.bytesIn.Store(50)
	inst.bytesOut.Store(25)
	app.pm.proxies[site.ID] = inst

	setDBReadonly(t, app, true)
	if err := app.pm.StopSite(site.ID); err == nil {
		t.Fatal("StopSite succeeded against a read-only database")
	}
	if !app.pm.IsRunning(site.ID) {
		t.Fatal("StopSite dropped the instance despite the failed flush")
	}
	if got := inst.bytesIn.Load(); got != 50 {
		t.Fatalf("bytesIn after failed stop = %d, want 50", got)
	}
	if got := inst.bytesOut.Load(); got != 25 {
		t.Fatalf("bytesOut after failed stop = %d, want 25", got)
	}
	if got := inst.persistedTraffic.Load(); got != 0 {
		t.Fatalf("persistedTraffic after failed stop = %d, want 0", got)
	}
	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.TrafficUsed != 0 {
		t.Fatalf("traffic_used after failed stop = %d, want 0", reloaded.TrafficUsed)
	}

	// Same stop succeeds once the DB recovers and persists exactly once.
	setDBReadonly(t, app, false)
	if err := app.pm.StopSite(site.ID); err != nil {
		t.Fatalf("StopSite retry: %v", err)
	}
	if app.pm.IsRunning(site.ID) {
		t.Fatal("instance still registered after successful stop")
	}
	reloaded, err = app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.TrafficUsed != 75 {
		t.Fatalf("traffic_used after stop retry = %d, want 75", reloaded.TrafficUsed)
	}
}

// DELETE only deletes the DB row when the stop (and its flush) succeeded; a
// failed flush aborts with the instance and the row intact.
func TestDeleteSiteAbortsWhenFlushFails(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("delclosed", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	inst := &ProxyInstance{Site: *site, server: &http.Server{}}
	inst.bytesIn.Store(10)
	inst.bytesOut.Store(5)
	app.pm.proxies[site.ID] = inst

	setDBReadonly(t, app, true)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/sites/"+jsonNumber64(site.ID), nil)
	app.handleSiteByID(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("DELETE status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
	if _, err := app.db.GetSite(site.ID); err != nil {
		t.Fatal("site row was deleted despite the failed flush")
	}
	if !app.pm.IsRunning(site.ID) {
		t.Fatal("instance was stopped despite the failed flush")
	}
	if got := inst.bytesIn.Load(); got != 10 {
		t.Fatalf("bytesIn after failed delete = %d, want 10", got)
	}
	setDBReadonly(t, app, false)
}

// Replacing a running instance fails closed when the flush cannot persist: the
// old instance and its pending bytes stay registered and the new instance's
// freshly bound listener is released.
func TestStartSiteReplaceFailClosedAndReleasesNewListener(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("replaceclosed", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	releasePort(site.ListenPort)
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	t.Cleanup(func() { app.pm.StopSite(site.ID) })

	app.pm.mu.RLock()
	inst := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if inst == nil {
		t.Fatal("site did not register a proxy instance")
	}
	inst.bytesIn.Store(60)
	inst.bytesOut.Store(40)

	moved := *site
	moved.ListenPort = freePort(t)
	releasePort(moved.ListenPort)
	setDBReadonly(t, app, true)
	if err := app.pm.StartSite(moved); err == nil {
		t.Fatal("replace succeeded against a read-only database")
	}
	setDBReadonly(t, app, false)

	// The old instance is still the registered one, with pending intact.
	app.pm.mu.RLock()
	still := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if still != inst {
		t.Fatal("old instance was replaced despite the failed flush")
	}
	if got := inst.bytesIn.Load(); got != 60 {
		t.Fatalf("bytesIn after failed replace = %d, want 60", got)
	}
	if got := inst.bytesOut.Load(); got != 40 {
		t.Fatalf("bytesOut after failed replace = %d, want 40", got)
	}
	if got := inst.persistedTraffic.Load(); got != 0 {
		t.Fatalf("persistedTraffic after failed replace = %d, want 0", got)
	}

	// The new listener was released: the new port binds again immediately.
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", moved.ListenPort))
	if err != nil {
		t.Fatalf("new listener was not released after failed replace: %v", err)
	}
	ln.Close()
}

// Concurrent flush/snapshot/history must never expose a torn per-instance
// view (traffic_used != persisted + pending), and every byte written ends up
// persisted exactly once. Run with -race.
func TestConcurrentFlushSnapshotAndHistoryStayConsistent(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("race", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	inst := &ProxyInstance{Site: *site, server: &http.Server{}}
	app.pm.proxies[site.ID] = inst

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer: accumulates 300 * 10 = 3000 pending bytes.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 300; i++ {
			inst.bytesIn.Add(7)
			inst.bytesOut.Add(3)
			time.Sleep(time.Microsecond)
		}
		close(stop)
	}()

	// Flusher: keeps draining pending into the DB until the writer stops.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				app.pm.FlushTraffic()
				time.Sleep(100 * time.Microsecond)
			}
		}
	}()

	// Snapshotter: every observed per-site view must satisfy the invariant.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			snap, err := app.pm.TrafficSnapshot()
			if err != nil {
				t.Errorf("TrafficSnapshot: %v", err)
				return
			}
			for _, st := range snap.LiveSites {
				if st.ID == site.ID && st.TrafficUsed != st.PersistedTraffic+st.BytesIn+st.BytesOut {
					t.Errorf("torn snapshot view: used=%d persisted=%d in=%d out=%d", st.TrafficUsed, st.PersistedTraffic, st.BytesIn, st.BytesOut)
					return
				}
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()

	// Historian: same invariant on the single-site envelope.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			h, err := app.pm.SiteTrafficHistory(*site, 24)
			if err != nil {
				t.Errorf("SiteTrafficHistory: %v", err)
				return
			}
			if h.Snapshot.TrafficUsed != h.Snapshot.PersistedTraffic+h.Snapshot.BytesIn+h.Snapshot.BytesOut {
				t.Errorf("torn history view: used=%d persisted=%d in=%d out=%d", h.Snapshot.TrafficUsed, h.Snapshot.PersistedTraffic, h.Snapshot.BytesIn, h.Snapshot.BytesOut)
				return
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()

	wg.Wait()

	// Conservation: the final flush persists every written byte exactly once.
	app.pm.FlushTraffic()
	if got := inst.persistedTraffic.Load(); got != 3000 {
		t.Fatalf("persistedTraffic after concurrent run = %d, want 3000", got)
	}
	if got := inst.bytesIn.Load() + inst.bytesOut.Load(); got != 0 {
		t.Fatalf("pending after concurrent run = %d, want 0", got)
	}
	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.TrafficUsed != 3000 {
		t.Fatalf("traffic_used after concurrent run = %d, want 3000", reloaded.TrafficUsed)
	}
}

// The read-only traffic paths (legacy, envelope, dashboard, overview, SSE)
// must never write the database: they all succeed while the DB rejects writes.
func TestTrafficReadsDoNotWriteDatabase(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("readonly", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	inst := &ProxyInstance{Site: *site, server: &http.Server{}}
	inst.bytesIn.Store(11)
	inst.bytesOut.Store(9)
	app.pm.proxies[site.ID] = inst

	setDBReadonly(t, app, true)
	defer setDBReadonly(t, app, false)

	// Legacy array endpoint.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/traffic/"+jsonNumber64(site.ID)+"?hours=24", nil)
	app.handleTraffic(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("legacy status = %d body=%s", rr.Code, rr.Body.String())
	}

	// Envelope endpoint; the live pending shows up in the read-only view.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/traffic/"+jsonNumber64(site.ID)+"/snapshot?hours=24", nil)
	app.handleTraffic(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("envelope status = %d body=%s", rr.Code, rr.Body.String())
	}
	body := decodeBody(t, rr)
	snap := mustMapValue(t, body, "snapshot")
	if mustNumberValue(t, snap, "bytes_in") != 11 || mustNumberValue(t, snap, "traffic_used") != 20 {
		t.Fatalf("read-only envelope snapshot = %v, want in=11 used=20", snap)
	}

	// Dashboard and overview share the unified snapshot payload.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	app.handleDashboard(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d body=%s", rr.Code, rr.Body.String())
	}
	body = decodeBody(t, rr)
	if mustNumberValue(t, body, "total_traffic") != 20 || mustNumberValue(t, body, "running_sites") != 1 {
		t.Fatalf("dashboard payload = %v, want total_traffic=20 running_sites=1", body)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/traffic/overview", nil)
	app.handleTraffic(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("overview status = %d body=%s", rr.Code, rr.Body.String())
	}
	body = decodeBody(t, rr)
	if mustNumberValue(t, body, "total_traffic") != 20 {
		t.Fatalf("overview payload = %v, want total_traffic=20", body)
	}

	// SSE event frame.
	rr = httptest.NewRecorder()
	if err := app.sendSSEEvent(rr, rr); err != nil {
		t.Fatalf("sendSSEEvent against a read-only DB: %v", err)
	}
	if !strings.HasPrefix(rr.Body.String(), "data: ") || !strings.Contains(rr.Body.String(), "\"total_traffic\":20") {
		t.Fatalf("SSE frame = %q, want data: frame with total_traffic 20", rr.Body.String())
	}

	// And the DB really is untouched: no logs, no usage.
	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.TrafficUsed != 0 {
		t.Fatalf("traffic_used = %d, want 0 (reads must not write)", reloaded.TrafficUsed)
	}
	logs, err := app.db.GetTrafficLogs(site.ID, 24)
	if err != nil {
		t.Fatalf("GetTrafficLogs: %v", err)
	}
	if len(logs) != 0 {
		t.Fatalf("traffic_logs = %+v, want empty (reads must not write)", logs)
	}
}

// Toggle-off stops (and flushes) before flipping the flag; a failed flush
// aborts with the flag still on and the instance still running.
func TestToggleOffAbortsWhenFlushFails(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("togglestop", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	inst := &ProxyInstance{Site: *site, server: &http.Server{}}
	inst.bytesIn.Store(20)
	app.pm.proxies[site.ID] = inst

	setDBReadonly(t, app, true)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/sites/"+jsonNumber64(site.ID)+"/toggle", nil)
	app.handleSiteByID(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("toggle status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
	setDBReadonly(t, app, false)

	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if !reloaded.Enabled {
		t.Fatal("toggle-off flipped the flag despite the failed flush")
	}
	if !app.pm.IsRunning(site.ID) {
		t.Fatal("toggle-off stopped the instance despite the failed flush")
	}
	if got := inst.bytesIn.Load(); got != 20 {
		t.Fatalf("bytesIn after failed toggle = %d, want 20", got)
	}
}

// The PUT pre-stop runs before the DB update; a failed flush aborts with the
// old config still in the DB and the old instance still running.
func TestSiteUpdateAbortsWhenPreStopFlushFails(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("prestop", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	releasePort(site.ListenPort)
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	t.Cleanup(func() { app.pm.StopSite(site.ID) })

	app.pm.mu.RLock()
	inst := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if inst == nil {
		t.Fatal("site did not register a proxy instance")
	}
	inst.bytesIn.Store(33)

	// Same listen_port -> the update path pre-stops; the flush fails -> abort.
	body := strings.NewReader(`{"name":"renamed","listen_port":` + jsonNumber(site.ListenPort) + `,"target_url":"http://127.0.0.1:8096","ua_mode":"infuse"}`)
	setDBReadonly(t, app, true)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/sites/"+jsonNumber64(site.ID), body)
	app.handleSiteByID(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("PUT status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
	setDBReadonly(t, app, false)

	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.Name != "prestop" {
		t.Fatalf("name = %q, want the old config preserved", reloaded.Name)
	}
	if !reloaded.Enabled {
		t.Fatal("PUT disabled the site despite the failed flush")
	}
	if reloaded.TrafficUsed != 0 {
		t.Fatalf("traffic_used = %d, want 0", reloaded.TrafficUsed)
	}
	app.pm.mu.RLock()
	still := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if still != inst {
		t.Fatal("pre-stop replaced the instance despite the failed flush")
	}
	if got := inst.bytesIn.Load(); got != 33 {
		t.Fatalf("bytesIn after failed PUT = %d, want 33", got)
	}
}

// GET /api/sites overlays the authoritative live traffic (persisted + pending)
// for running sites while preserving the exact Site JSON shape plus the
// running flag; the read never writes the database, so pending bytes appear
// before any flush.
func TestHandleSitesGETOverlaysLiveTrafficWithoutDBWrite(t *testing.T) {
	app := newTestApp(t)
	running, err := app.db.CreateSite("live", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	stopped, err := app.db.CreateSite("stopped", freePort(t), "http://127.0.0.1:8097", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	inst := &ProxyInstance{Site: *running, server: &http.Server{}}
	inst.persistedTraffic.Store(100)
	inst.bytesIn.Store(11)
	inst.bytesOut.Store(9)
	app.pm.proxies[running.ID] = inst

	// The GET must succeed while the DB rejects every write, proving the live
	// overlay is a pure read.
	setDBReadonly(t, app, true)
	defer setDBReadonly(t, app, false)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/sites", nil)
	app.handleSites(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/sites status = %d; body=%s", rr.Code, rr.Body.String())
	}

	// The response rows keep exactly the Site JSON fields plus "running": the
	// overlay may only change traffic_used, never add per-component fields.
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode /api/sites: %v", err)
	}
	expectedKeys := map[string]bool{
		"id": true, "name": true, "listen_port": true, "target_url": true,
		"playback_target_url": true, "playback_mode": true, "stream_hosts": true,
		"ua_mode": true, "custom_user_agent": true, "custom_client": true,
		"custom_version": true, "enabled": true, "traffic_quota": true,
		"traffic_used": true, "speed_limit": true, "created_at": true,
		"updated_at": true, "running": true,
	}
	if len(raw) != 2 {
		t.Fatalf("GET /api/sites returned %d rows, want 2: %s", len(raw), rr.Body.String())
	}
	for i, row := range raw {
		if len(row) != len(expectedKeys) {
			t.Fatalf("row %d has %d fields, want %d: %v", i, len(row), len(expectedKeys), row)
		}
		for key := range row {
			if !expectedKeys[key] {
				t.Fatalf("row %d has unexpected field %q", i, key)
			}
		}
	}

	var rows []struct {
		ID          int64 `json:"id"`
		Running     bool  `json:"running"`
		Enabled     bool  `json:"enabled"`
		TrafficUsed int64 `json:"traffic_used"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode /api/sites rows: %v", err)
	}
	var liveRow, stoppedRow *struct {
		ID          int64 `json:"id"`
		Running     bool  `json:"running"`
		Enabled     bool  `json:"enabled"`
		TrafficUsed int64 `json:"traffic_used"`
	}
	for i := range rows {
		switch rows[i].ID {
		case running.ID:
			liveRow = &rows[i]
		case stopped.ID:
			stoppedRow = &rows[i]
		}
	}
	if liveRow == nil || stoppedRow == nil {
		t.Fatalf("expected both sites in the response: %+v", rows)
	}
	if liveRow.TrafficUsed != 120 {
		t.Fatalf("live traffic_used = %d, want 120 (100 persisted + 11 + 9 pending)", liveRow.TrafficUsed)
	}
	if !liveRow.Running {
		t.Fatal("running site must be flagged running")
	}
	if !liveRow.Enabled {
		t.Fatal("non-traffic fields must keep their DB values")
	}
	if stoppedRow.TrafficUsed != 0 || stoppedRow.Running {
		t.Fatalf("stopped site row = traffic_used %d running %v, want 0/false", stoppedRow.TrafficUsed, stoppedRow.Running)
	}

	// The read left the DB untouched: no flush, no logs.
	reloaded, err := app.db.GetSite(running.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.TrafficUsed != 0 {
		t.Fatalf("DB traffic_used = %d, want 0 (the read must not flush)", reloaded.TrafficUsed)
	}
	logs, err := app.db.GetTrafficLogs(running.ID, 24)
	if err != nil {
		t.Fatalf("GetTrafficLogs: %v", err)
	}
	if len(logs) != 0 {
		t.Fatalf("traffic_logs = %+v, want empty (the read must not write)", logs)
	}
}

// A PUT whose record update fails after a successful pre-stop must restart the
// old instance: the enabled row is never left without a running proxy. The
// failure is injected with a trigger that aborts name updates only, so the
// pre-stop flush (which updates traffic_used, not name) still succeeds - the
// granularity query_only cannot express.
func TestSiteUpdateRestartsPreStoppedInstanceWhenRecordUpdateFails(t *testing.T) {
	app := newTestApp(t)
	port := freePort(t)
	site, err := app.db.CreateSite("rename-me", port, "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	releasePort(port)
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	t.Cleanup(func() { app.pm.StopSite(site.ID) })

	app.pm.mu.RLock()
	inst := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if inst == nil {
		t.Fatal("site did not register a proxy instance")
	}
	inst.bytesIn.Store(33)

	execTestSQL(t, app, "CREATE TRIGGER block_rename BEFORE UPDATE OF name ON sites BEGIN SELECT RAISE(ABORT, 'rename blocked'); END;")
	defer execTestSQL(t, app, "DROP TRIGGER block_rename")

	// Same listen_port -> the update path pre-stops; the flush succeeds but the
	// record update (which sets name) is aborted.
	body := strings.NewReader(`{"name":"renamed","listen_port":` + jsonNumber(site.ListenPort) + `,"target_url":"http://127.0.0.1:8096","ua_mode":"infuse"}`)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/sites/"+jsonNumber64(site.ID), body)
	app.handleSiteByID(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("PUT status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "rename blocked") {
		t.Fatalf("PUT error must report the record update failure: %s", rr.Body.String())
	}

	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.Name != "rename-me" {
		t.Fatalf("name = %q, want the old config preserved", reloaded.Name)
	}
	if !reloaded.Enabled {
		t.Fatal("PUT disabled the site despite the failed record update")
	}
	if reloaded.TrafficUsed != 33 {
		t.Fatalf("traffic_used = %d, want 33 (the pre-stop flush persisted pending bytes)", reloaded.TrafficUsed)
	}
	if !app.pm.IsRunning(site.ID) {
		t.Fatal("the pre-stopped instance was not restarted after the failed record update")
	}
	app.pm.mu.RLock()
	restarted := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if restarted == nil || restarted == inst {
		t.Fatal("expected a fresh instance for the restored site")
	}
	if got := restarted.persistedTraffic.Load(); got != 33 {
		t.Fatalf("restarted persistedTraffic = %d, want 33", got)
	}
	if got := restarted.bytesIn.Load(); got != 0 {
		t.Fatalf("restarted bytesIn = %d, want 0", got)
	}
}

// DELETE restarts the stopped enabled site when the row deletion fails: the
// instance is never left stopped while the enabled row survives. The failure
// is injected with a trigger that aborts row deletion after the stop flush.
func TestDeleteSiteRestartsInstanceWhenDeleteFails(t *testing.T) {
	app := newTestApp(t)
	port := freePort(t)
	site, err := app.db.CreateSite("del-restore", port, "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	releasePort(port)
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	t.Cleanup(func() { app.pm.StopSite(site.ID) })

	app.pm.mu.RLock()
	inst := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if inst == nil {
		t.Fatal("site did not register a proxy instance")
	}
	inst.bytesIn.Store(10)
	inst.bytesOut.Store(5)

	execTestSQL(t, app, "CREATE TRIGGER block_delete BEFORE DELETE ON sites BEGIN SELECT RAISE(ABORT, 'delete blocked'); END;")
	defer execTestSQL(t, app, "DROP TRIGGER block_delete")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/sites/"+jsonNumber64(site.ID), nil)
	app.handleSiteByID(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("DELETE status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "delete blocked") {
		t.Fatalf("DELETE error must report the delete failure: %s", rr.Body.String())
	}

	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if !reloaded.Enabled {
		t.Fatal("site row was mutated despite the failed delete")
	}
	if reloaded.TrafficUsed != 15 {
		t.Fatalf("traffic_used = %d, want 15 (the stop flush persisted pending bytes)", reloaded.TrafficUsed)
	}
	if !app.pm.IsRunning(site.ID) {
		t.Fatal("the stopped instance was not restarted after the failed delete")
	}
	app.pm.mu.RLock()
	restarted := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if restarted == nil || restarted == inst {
		t.Fatal("expected a fresh instance for the surviving row")
	}
	if got := restarted.persistedTraffic.Load(); got != 15 {
		t.Fatalf("restarted persistedTraffic = %d, want 15", got)
	}
	if in, out := restarted.bytesIn.Load(), restarted.bytesOut.Load(); in != 0 || out != 0 {
		t.Fatalf("restarted pending counters = in:%d out:%d, want 0/0", in, out)
	}
}

func TestHandleSitesCreatePersistsPlaybackTargetURL(t *testing.T) {
	app := newTestApp(t)

	port := freePort(t)
	releasePort(port)
	body := strings.NewReader(`{"name":"split","listen_port":` + jsonNumber(port) + `,"target_url":"http://127.0.0.1:8096","playback_target_url":"https://media.example.com","ua_mode":"infuse"}`)
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
	port := freePort(t)
	releasePort(port)
	createPayload, err := json.Marshal(map[string]interface{}{
		"name":              "custom-identity",
		"listen_port":       port,
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

func TestHandleSitesCreateAndUpdatePassthroughMode(t *testing.T) {
	app := newTestApp(t)
	port := freePort(t)
	releasePort(port)
	createPayload, err := json.Marshal(map[string]interface{}{
		"name":              "passthrough-site",
		"listen_port":       port,
		"target_url":        "http://127.0.0.1:8096",
		"ua_mode":           "passthrough",
		"custom_user_agent": "Stale UA",
		"custom_client":     "Stale Client",
		"custom_version":    "9.9",
	})
	if err != nil {
		t.Fatalf("marshal create payload: %v", err)
	}
	rr := httptest.NewRecorder()
	app.handleSites(rr, httptest.NewRequest(http.MethodPost, "/api/sites", bytes.NewReader(createPayload)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", rr.Code, rr.Body.String())
	}
	var created Site
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created site: %v", err)
	}
	t.Cleanup(func() { app.pm.StopSite(created.ID) })
	if created.UAMode != passthroughUAMode || created.CustomUserAgent != "" || created.CustomClient != "" || created.CustomVersion != "" {
		t.Fatalf("created passthrough site = %#v, want cleared custom triplet", created)
	}

	// PUT switching passthrough -> custom stores the triplet.
	customPayload, err := json.Marshal(map[string]interface{}{
		"name":              created.Name,
		"listen_port":       created.ListenPort,
		"target_url":        created.TargetURL,
		"ua_mode":           "custom",
		"custom_user_agent": "New UA",
		"custom_client":     "New Client",
		"custom_version":    "2.0",
	})
	if err != nil {
		t.Fatalf("marshal custom payload: %v", err)
	}
	rr = httptest.NewRecorder()
	app.handleSiteByID(rr, httptest.NewRequest(http.MethodPut, "/api/sites/"+jsonNumber64(created.ID), bytes.NewReader(customPayload)))
	if rr.Code != http.StatusOK {
		t.Fatalf("custom update status = %d body=%s", rr.Code, rr.Body.String())
	}
	reloaded, err := app.db.GetSite(created.ID)
	if err != nil {
		t.Fatalf("load custom site: %v", err)
	}
	if reloaded.UAMode != customUAMode || reloaded.CustomUserAgent != "New UA" || reloaded.CustomClient != "New Client" || reloaded.CustomVersion != "2.0" {
		t.Fatalf("custom update = %#v", reloaded)
	}

	// PUT switching custom -> passthrough clears the triplet again.
	passPayload, err := json.Marshal(map[string]interface{}{
		"name":        reloaded.Name,
		"listen_port": reloaded.ListenPort,
		"target_url":  reloaded.TargetURL,
		"ua_mode":     "passthrough",
	})
	if err != nil {
		t.Fatalf("marshal passthrough payload: %v", err)
	}
	rr = httptest.NewRecorder()
	app.handleSiteByID(rr, httptest.NewRequest(http.MethodPut, "/api/sites/"+jsonNumber64(created.ID), bytes.NewReader(passPayload)))
	if rr.Code != http.StatusOK {
		t.Fatalf("passthrough update status = %d body=%s", rr.Code, rr.Body.String())
	}
	reloaded, err = app.db.GetSite(created.ID)
	if err != nil {
		t.Fatalf("load passthrough site: %v", err)
	}
	if reloaded.UAMode != passthroughUAMode || reloaded.CustomUserAgent != "" || reloaded.CustomClient != "" || reloaded.CustomVersion != "" {
		t.Fatalf("passthrough update = %#v, want cleared custom triplet", reloaded)
	}
}

func TestHandleSitesRejectsUnknownUAMode(t *testing.T) {
	app := newTestApp(t)
	payload, err := json.Marshal(map[string]interface{}{
		"name":        "bogus-mode",
		"listen_port": freePort(t),
		"target_url":  "http://127.0.0.1:8096",
		"ua_mode":     "bogus",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	rr := httptest.NewRecorder()
	app.handleSites(rr, httptest.NewRequest(http.MethodPost, "/api/sites", bytes.NewReader(payload)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if sites, err := app.db.ListSites(); err != nil || len(sites) != 0 {
		t.Fatalf("unknown-mode site was persisted: sites=%#v err=%v", sites, err)
	}
}

func TestHandleSiteDiagMarksPassthroughWithoutExposingIdentity(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/System/Info/Public" {
			w.Write([]byte("{\"Version\":\"4.9.0\"}"))
			return
		}
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	app := newTestApp(t)
	site, err := app.db.CreateSite("diag-passthrough", freePort(t), upstream.URL, "", "direct", "[]", passthroughUAMode, 0, 0)
	if err != nil {
		t.Fatalf("create passthrough site: %v", err)
	}
	rr := httptest.NewRecorder()
	app.handleSiteByID(rr, httptest.NewRequest(http.MethodGet, "/api/sites/"+jsonNumber64(site.ID)+"/diag", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("diag status=%d body=%s", rr.Code, rr.Body.String())
	}
	headers := mustMapValue(t, decodeBody(t, rr), "headers")
	if got := mustBoolValue(t, headers, "passthrough"); !got {
		t.Fatalf("passthrough = %v, want true", got)
	}
	if got := mustBoolValue(t, headers, "ua_applied"); got {
		t.Fatalf("ua_applied = %v, want false", got)
	}
	// Diagnostics must not render identity values for passthrough: there is no
	// configured profile, and the real request headers are never shown.
	if got := mustStringValue(t, headers, "current_ua"); got != "" {
		t.Fatalf("current_ua = %q, want empty", got)
	}
	if got := mustStringValue(t, headers, "client_field"); got != "" {
		t.Fatalf("client_field = %q, want empty", got)
	}
	if got := mustStringValue(t, headers, "version_field"); got != "" {
		t.Fatalf("version_field = %q, want empty", got)
	}
}

func TestHandleUAProfilesReturnsThreePresetsWithoutPassthrough(t *testing.T) {
	app := newTestApp(t)
	rr := httptest.NewRecorder()
	app.handleUAProfiles(rr, httptest.NewRequest(http.MethodGet, "/api/ua-profiles", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var profiles []UAProfile
	if err := json.Unmarshal(rr.Body.Bytes(), &profiles); err != nil {
		t.Fatalf("decode profiles: %v body=%s", err, rr.Body.String())
	}
	if len(profiles) != 3 {
		t.Fatalf("profiles = %#v, want exactly the three presets", profiles)
	}
	names := make(map[string]bool, len(profiles))
	for _, p := range profiles {
		names[p.Name] = true
		if p.Name == "" || p.UserAgent == "" || p.Client == "" || p.Version == "" {
			t.Fatalf("preset with empty identity fields: %#v", p)
		}
	}
	for _, want := range []string{"Infuse", "Web", "Client"} {
		if !names[want] {
			t.Fatalf("presets missing %q: %#v", want, profiles)
		}
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
	releasePort(site.ListenPort)
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
	releasePort(site.ListenPort)
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
	releasePort(site.ListenPort)
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
