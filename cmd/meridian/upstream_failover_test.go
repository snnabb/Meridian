package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func mustFailoverURL(t *testing.T, value string) *url.URL {
	t.Helper()
	target, err := normalizeTargetURL(value)
	if err != nil {
		t.Fatalf("normalize target %q: %v", value, err)
	}
	return target
}

func failoverRequest(t *testing.T, method, path string, primary *url.URL, targets []*url.URL) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, "http://meridian.test"+path, nil)
	original := *req.URL
	applyUpstreamURL(req.URL, primary)
	req.Host = primary.Host
	return withFailoverRequestPlan(req, &original, targets, primary, 4<<20)
}

func TestFailoverTransportRetriesOnlyRetryableReadFailures(t *testing.T) {
	var primaryCalls, backupCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer primary.Close()
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backupCalls.Add(1)
		if r.URL.Path != "/emby/System/Info" {
			t.Fatalf("backup path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backup"))
	}))
	defer backup.Close()

	primaryTarget := mustFailoverURL(t, primary.URL+"/emby")
	backupTarget := mustFailoverURL(t, backup.URL+"/emby")
	transport := &failoverTransport{base: http.DefaultTransport, state: newUpstreamFailoverState()}
	resp, err := transport.RoundTrip(failoverRequest(t, http.MethodGet, "/System/Info", primaryTarget, []*url.URL{primaryTarget, backupTarget}))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "backup" {
		t.Fatalf("response = %d %q", resp.StatusCode, body)
	}
	if primaryCalls.Load() != 1 || backupCalls.Load() != 1 {
		t.Fatalf("calls primary=%d backup=%d", primaryCalls.Load(), backupCalls.Load())
	}

	// The working backup is preferred while its five-minute preference remains.
	resp, err = transport.RoundTrip(failoverRequest(t, http.MethodGet, "/System/Info", primaryTarget, []*url.URL{primaryTarget, backupTarget}))
	if err != nil {
		t.Fatalf("preferred RoundTrip: %v", err)
	}
	resp.Body.Close()
	if primaryCalls.Load() != 1 || backupCalls.Load() != 2 {
		t.Fatalf("preference calls primary=%d backup=%d", primaryCalls.Load(), backupCalls.Load())
	}
}

func TestFailoverTransportDoesNotRetryNonRetryableOrWrites(t *testing.T) {
	var primaryCalls, backupCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer primary.Close()
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backupCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer backup.Close()
	primaryTarget := mustFailoverURL(t, primary.URL)
	backupTarget := mustFailoverURL(t, backup.URL)
	transport := &failoverTransport{base: http.DefaultTransport, state: newUpstreamFailoverState()}
	targets := []*url.URL{primaryTarget, backupTarget}

	resp, err := transport.RoundTrip(failoverRequest(t, http.MethodGet, "/missing", primaryTarget, targets))
	if err != nil {
		t.Fatalf("GET RoundTrip: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || primaryCalls.Load() != 1 || backupCalls.Load() != 0 {
		t.Fatalf("GET calls/status primary=%d backup=%d status=%d", primaryCalls.Load(), backupCalls.Load(), resp.StatusCode)
	}

	resp, err = transport.RoundTrip(failoverRequest(t, http.MethodPost, "/write", primaryTarget, targets))
	if err != nil {
		t.Fatalf("POST RoundTrip: %v", err)
	}
	resp.Body.Close()
	if primaryCalls.Load() != 2 || backupCalls.Load() != 0 {
		t.Fatalf("POST unexpectedly retried primary=%d backup=%d", primaryCalls.Load(), backupCalls.Load())
	}
}

func TestFailoverTransportRoutesWritesToEstablishedActiveLineWithoutRetry(t *testing.T) {
	const payload = `{"PositionTicks":12345}`
	var primaryCalls, backupCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer primary.Close()
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backupCalls.Add(1)
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if r.URL.Path != "/emby/Sessions/Playing/Progress" || string(body) != payload {
				t.Fatalf("active write path=%q body=%q", r.URL.Path, body)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backup.Close()

	primaryTarget := mustFailoverURL(t, primary.URL+"/emby")
	backupTarget := mustFailoverURL(t, backup.URL+"/emby")
	targets := []*url.URL{primaryTarget, backupTarget}
	transport := &failoverTransport{base: http.DefaultTransport, state: newUpstreamFailoverState()}
	readResp, err := transport.RoundTrip(failoverRequest(t, http.MethodGet, "/System/Info", primaryTarget, targets))
	if err != nil {
		t.Fatalf("establish active line: %v", err)
	}
	readResp.Body.Close()

	writeReq := httptest.NewRequest(http.MethodPost, "http://meridian.test/Sessions/Playing/Progress", strings.NewReader(payload))
	original := *writeReq.URL
	applyUpstreamURL(writeReq.URL, primaryTarget)
	writeReq.Host = primaryTarget.Host
	writeReq = withFailoverRequestPlan(writeReq, &original, targets, primaryTarget, 4<<20)
	writeResp, err := transport.RoundTrip(writeReq)
	if err != nil {
		t.Fatalf("active write: %v", err)
	}
	writeResp.Body.Close()
	if writeResp.StatusCode != http.StatusNoContent || primaryCalls.Load() != 1 || backupCalls.Load() != 2 {
		t.Fatalf("status=%d primary=%d backup=%d", writeResp.StatusCode, primaryCalls.Load(), backupCalls.Load())
	}
}

func TestFailoverTransportRetriesReplayablePlaybackInfoPost(t *testing.T) {
	const payload = `{"DeviceProfile":{"MaxStreamingBitrate":120000000}}`
	var primaryCalls, backupCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls.Add(1)
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer primary.Close()
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backupCalls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/emby/Items/1/PlaybackInfo" || string(body) != payload {
			t.Fatalf("backup request method=%q path=%q body=%q", r.Method, r.URL.Path, body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"MediaSources":[]}`))
	}))
	defer backup.Close()

	primaryTarget := mustFailoverURL(t, primary.URL+"/emby")
	backupTarget := mustFailoverURL(t, backup.URL+"/emby")
	req := httptest.NewRequest(http.MethodPost, "http://meridian.test/Items/1/PlaybackInfo", strings.NewReader(payload))
	if err := prepareFailoverPlaybackInfoBody(req, 4<<20); err != nil {
		t.Fatalf("prepare body: %v", err)
	}
	original := *req.URL
	applyUpstreamURL(req.URL, primaryTarget)
	req.Host = primaryTarget.Host
	req = withFailoverRequestPlan(req, &original, []*url.URL{primaryTarget, backupTarget}, primaryTarget, 4<<20)

	transport := &failoverTransport{base: http.DefaultTransport, state: newUpstreamFailoverState()}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || primaryCalls.Load() != 1 || backupCalls.Load() != 1 {
		t.Fatalf("status=%d primary=%d backup=%d", resp.StatusCode, primaryCalls.Load(), backupCalls.Load())
	}
}

func TestFailoverTransportDoesNotRetryUnreplayablePlaybackInfoPost(t *testing.T) {
	var calls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer primary.Close()
	primaryTarget := mustFailoverURL(t, primary.URL)
	backupTarget := mustFailoverURL(t, "https://backup.example")
	req := failoverRequest(t, http.MethodPost, "/emby/Items/1/PlaybackInfo", primaryTarget, []*url.URL{primaryTarget, backupTarget})
	req.Body = io.NopCloser(strings.NewReader("{}"))
	req.ContentLength = 2
	req.GetBody = nil
	transport := &failoverTransport{base: http.DefaultTransport, state: newUpstreamFailoverState()}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	resp.Body.Close()
	if calls.Load() != 1 || resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("calls=%d status=%d", calls.Load(), resp.StatusCode)
	}
}

func TestParseFailoverTargetsRejectsDuplicatesAndLimits(t *testing.T) {
	if _, err := parseFailoverTargets("https://primary.example", []string{"https://primary.example"}); err == nil {
		t.Fatal("duplicate primary accepted")
	}
	tooMany := make([]string, maxFailoverTargets)
	for i := range tooMany {
		tooMany[i] = "https://backup" + string(rune('a'+i)) + ".example"
	}
	if _, err := parseFailoverTargets("https://primary.example", tooMany); err == nil {
		t.Fatal("too many backups accepted")
	}

	state := newUpstreamFailoverState()
	primary := mustFailoverURL(t, "https://primary.example")
	backup := mustFailoverURL(t, "https://backup.example")
	now := time.Now()
	state.markFailure(primary, now)
	ordered := state.ordered([]*url.URL{primary, backup}, now)
	if upstreamTargetKey(ordered[0]) != upstreamTargetKey(backup) {
		t.Fatalf("cooled primary remained first: %s", ordered[0])
	}
}

func TestNormalizeFailoverLinesKeepsDisabledMetadataOutOfRuntimeTargets(t *testing.T) {
	lines, targets, err := normalizeFailoverLines("https://primary.example", []FailoverLine{
		{Name: "备用一", URL: "https://backup-one.example", Enabled: true},
		{Name: "停用线路", URL: "https://backup-two.example", Enabled: false},
	}, nil)
	if err != nil {
		t.Fatalf("normalizeFailoverLines: %v", err)
	}
	if len(lines) != 2 || len(targets) != 1 || targets[0] != "https://backup-one.example" {
		t.Fatalf("lines=%+v targets=%+v", lines, targets)
	}
	if lines[1].Name != "停用线路" || lines[1].Enabled {
		t.Fatalf("disabled metadata changed: %+v", lines[1])
	}
}

func TestNormalizeFailoverLinesConvertsLegacyTargets(t *testing.T) {
	lines, targets, err := normalizeFailoverLines("https://primary.example", nil, []string{"https://backup.example"})
	if err != nil {
		t.Fatalf("normalizeFailoverLines legacy: %v", err)
	}
	if len(lines) != 1 || lines[0].Name != "线路2" || !lines[0].Enabled || len(targets) != 1 {
		t.Fatalf("legacy conversion lines=%+v targets=%+v", lines, targets)
	}
}

func TestFailoverStateProbesRecoveredPrimaryAndRestoresPriority(t *testing.T) {
	state := newUpstreamFailoverState()
	primary := mustFailoverURL(t, "https://primary.example")
	backup := mustFailoverURL(t, "https://backup.example")
	targets := []*url.URL{primary, backup}
	now := time.Now()
	state.markFailure(primary, now)
	state.markSuccess(backup, now)

	duringCooldown := state.ordered(targets, now.Add(failoverCooldown-time.Second))
	if upstreamTargetKey(duringCooldown[0]) != upstreamTargetKey(backup) {
		t.Fatalf("backup not preferred during primary cooldown: %s", duringCooldown[0])
	}
	probe := state.ordered(targets, now.Add(failoverCooldown+time.Second))
	if upstreamTargetKey(probe[0]) != upstreamTargetKey(primary) {
		t.Fatalf("primary was not selected for recovery probe: %s", probe[0])
	}
	concurrent := state.ordered(targets, now.Add(failoverCooldown+2*time.Second))
	if upstreamTargetKey(concurrent[0]) != upstreamTargetKey(backup) {
		t.Fatalf("concurrent request did not stay on backup: %s", concurrent[0])
	}
	state.markSuccess(primary, now.Add(failoverCooldown+3*time.Second))
	restored := state.ordered(targets, now.Add(failoverCooldown+4*time.Second))
	if upstreamTargetKey(restored[0]) != upstreamTargetKey(primary) {
		t.Fatalf("recovered primary did not regain priority: %s", restored[0])
	}
}
