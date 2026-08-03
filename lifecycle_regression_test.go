package main

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"modernc.org/sqlite"
)

var (
	registerLifecycleFailOnce sync.Once
	registerLifecycleFailErr  error
	failNextTrafficUpdate     atomic.Bool
)

// registerLifecycleFailureFunction installs a process-wide SQLite scalar
// function whose failure is controlled outside the transaction. Unlike a
// control row updated by a trigger, the one-shot state is therefore not rolled
// back with the failed traffic transaction.
func registerLifecycleFailureFunction(t *testing.T) {
	t.Helper()
	registerLifecycleFailOnce.Do(func() {
		registerLifecycleFailErr = sqlite.RegisterScalarFunction(
			"meridian_lifecycle_fail_traffic_once",
			0,
			func(_ *sqlite.FunctionContext, _ []driver.Value) (driver.Value, error) {
				if failNextTrafficUpdate.Swap(false) {
					return nil, errors.New("injected final traffic flush failure")
				}
				return int64(0), nil
			},
		)
	})
	if registerLifecycleFailErr != nil {
		t.Fatalf("register SQLite failure function: %v", registerLifecycleFailErr)
	}
}

type finalFlushFailureFixture struct {
	app         *App
	site        *Site
	requestDone <-chan struct{}
}

// newFinalFlushFailureFixture keeps one proxied request active until StopSite
// cancels the instance. The upstream then adds a small amount of tail traffic,
// so StopSite's pre-close checkpoint is a no-op while its post-close checkpoint
// reaches the injected SQLite failure. This deterministically exercises the
// irreversible-close error path rather than the retryable pre-close path.
func newFinalFlushFailureFixture(t *testing.T, name string) finalFlushFailureFixture {
	t.Helper()
	registerLifecycleFailureFunction(t)
	failNextTrafficUpdate.Store(false)

	app := newTestApp(t)
	started := make(chan struct{})
	requestDone := make(chan struct{})
	var inst *ProxyInstance

	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		inst.bytesOut.Add(23)
	}))
	t.Cleanup(upstream.Close)

	port := freePort(t)
	site, err := app.db.CreateSite(name, port, upstream.URL, "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	releasePort(port)
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	app.pm.mu.RLock()
	inst = app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if inst == nil {
		t.Fatal("proxy instance was not installed")
	}
	t.Cleanup(func() {
		failNextTrafficUpdate.Store(false)
		_ = app.pm.StopSite(site.ID)
	})

	go func() {
		defer close(requestDone)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, requestErr := client.Get(fmt.Sprintf("http://127.0.0.1:%d/stream", port))
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request did not reach upstream")
	}

	if _, err := app.db.db.Exec(`
		CREATE TRIGGER fail_one_final_lifecycle_traffic_update
		BEFORE UPDATE OF traffic_used ON sites
		BEGIN
			SELECT meridian_lifecycle_fail_traffic_once();
		END;
	`); err != nil {
		t.Fatalf("create final traffic trigger: %v", err)
	}
	failNextTrafficUpdate.Store(true)
	return finalFlushFailureFixture{app: app, site: site, requestDone: requestDone}
}

func waitForFinalFlushFixtureRequest(t *testing.T, requestDone <-chan struct{}) {
	t.Helper()
	select {
	case <-requestDone:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request did not finish after ingress closed")
	}
}

func TestToggleOffAfterFinalFlushFailureDisablesSiteAndReportsCleanupPending(t *testing.T) {
	fixture := newFinalFlushFailureFixture(t, "toggle-final-flush")
	rr := httptest.NewRecorder()
	fixture.app.handleSiteByID(
		rr,
		httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/sites/%d/toggle", fixture.site.ID), nil),
	)
	if rr.Code != http.StatusOK {
		t.Fatalf("toggle status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	waitForFinalFlushFixtureRequest(t, fixture.requestDone)
	if failNextTrafficUpdate.Load() {
		t.Fatal("toggle never reached the injected final traffic flush failure")
	}
	body := decodeBody(t, rr)
	if enabled, ok := body["enabled"].(bool); !ok || enabled {
		t.Fatalf("toggle enabled=%#v, want false", body["enabled"])
	}
	if cleanupPending, ok := body["cleanup_pending"].(bool); !ok || !cleanupPending {
		t.Fatalf("toggle cleanup_pending=%#v, want true", body["cleanup_pending"])
	}
	restored, err := fixture.app.db.GetSite(fixture.site.ID)
	if err != nil {
		t.Fatalf("GetSite after toggle: %v", err)
	}
	if restored.Enabled {
		t.Fatal("site record remained enabled after irreversible toggle shutdown")
	}
}

func TestSamePortPutAfterFinalFlushFailureReturnsUnavailableAndDisablesOldRecord(t *testing.T) {
	fixture := newFinalFlushFailureFixture(t, "put-final-flush")
	payload := fmt.Sprintf(
		`{"name":"put-should-not-commit","listen_port":%d,"target_url":%q,"ua_mode":"infuse"}`,
		fixture.site.ListenPort,
		fixture.site.TargetURL,
	)
	rr := httptest.NewRecorder()
	fixture.app.handleSiteByID(
		rr,
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/sites/%d", fixture.site.ID), strings.NewReader(payload)),
	)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("PUT status=%d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	waitForFinalFlushFixtureRequest(t, fixture.requestDone)
	if failNextTrafficUpdate.Load() {
		t.Fatal("PUT never reached the injected final traffic flush failure")
	}
	restored, err := fixture.app.db.GetSite(fixture.site.ID)
	if err != nil {
		t.Fatalf("GetSite after PUT: %v", err)
	}
	if restored.Enabled {
		t.Fatal("old site record remained enabled after irreversible PUT shutdown")
	}
	if restored.Name != fixture.site.Name || restored.ListenPort != fixture.site.ListenPort || restored.TargetURL != fixture.site.TargetURL {
		t.Fatalf("PUT changed old record despite aborted update: got name=%q port=%d target=%q", restored.Name, restored.ListenPort, restored.TargetURL)
	}
}

func TestDeleteAfterFinalFlushFailureReturnsUnavailableAndRetainsDisabledRecord(t *testing.T) {
	fixture := newFinalFlushFailureFixture(t, "delete-final-flush")
	rr := httptest.NewRecorder()
	fixture.app.handleSiteByID(
		rr,
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/sites/%d", fixture.site.ID), nil),
	)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("DELETE status=%d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	waitForFinalFlushFixtureRequest(t, fixture.requestDone)
	if failNextTrafficUpdate.Load() {
		t.Fatal("DELETE never reached the injected final traffic flush failure")
	}
	restored, err := fixture.app.db.GetSite(fixture.site.ID)
	if err != nil {
		t.Fatalf("site record was deleted instead of retained: %v", err)
	}
	if restored.Enabled {
		t.Fatal("retained site record remained enabled after irreversible DELETE shutdown")
	}
	if restored.Name != fixture.site.Name || restored.ListenPort != fixture.site.ListenPort || restored.TargetURL != fixture.site.TargetURL {
		t.Fatalf("DELETE changed retained record: got name=%q port=%d target=%q", restored.Name, restored.ListenPort, restored.TargetURL)
	}
}

// A different-port PUT does not pre-stop the old proxy. StartSite itself may
// nevertheless close that proxy before a later step (here, its final traffic
// flush) fails. Rolling the database row back must also restore a fresh runtime;
// leaving the old closing instance in the manager makes an enabled site stay
// offline until an operator intervenes.
func TestDifferentPortUpdateRestartsOldSiteAfterPostShutdownReplaceFailure(t *testing.T) {
	registerLifecycleFailureFunction(t)
	failNextTrafficUpdate.Store(false)

	app := newTestApp(t)
	started := make(chan struct{})
	requestDone := make(chan struct{})
	var firstRequest sync.Once
	var oldInst *ProxyInstance

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isFirst := false
		firstRequest.Do(func() {
			isFirst = true
			close(started)
		})
		if isFirst {
			<-r.Context().Done()
			// Produce traffic after StartSite's pre-stop flush. The replacement's
			// final flush is therefore the first traffic_used update and the one
			// deliberately failed by the trigger below.
			oldInst.bytesOut.Add(17)
			return
		}
		_, _ = io.WriteString(w, "restored")
	}))
	defer upstream.Close()

	oldPort := freePort(t)
	site, err := app.db.CreateSite("replace-rollback", oldPort, upstream.URL, "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	releasePort(oldPort)
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	t.Cleanup(func() { _ = app.pm.StopSite(site.ID) })

	app.pm.mu.RLock()
	oldInst = app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if oldInst == nil {
		t.Fatal("old proxy instance was not installed")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	go func() {
		defer close(requestDone)
		resp, requestErr := client.Get(fmt.Sprintf("http://127.0.0.1:%d/stream", oldPort))
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request did not reach the old upstream")
	}

	if _, err := app.db.db.Exec(`
		CREATE TRIGGER fail_one_lifecycle_traffic_update
		BEFORE UPDATE OF traffic_used ON sites
		BEGIN
			SELECT meridian_lifecycle_fail_traffic_once();
		END;
	`); err != nil {
		t.Fatalf("create one-shot traffic trigger: %v", err)
	}
	failNextTrafficUpdate.Store(true)

	newPort := freePort(t)
	releasePort(newPort)
	payload := fmt.Sprintf(
		`{"name":"replace-rollback","listen_port":%d,"target_url":%q,"ua_mode":"infuse"}`,
		newPort,
		upstream.URL,
	)
	rr := httptest.NewRecorder()
	app.handleSiteByID(
		rr,
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/sites/%d", site.ID), strings.NewReader(payload)),
	)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("PUT status=%d, want 500 from injected replacement failure; body=%s", rr.Code, rr.Body.String())
	}
	if failNextTrafficUpdate.Load() {
		t.Fatal("replacement never reached the injected final traffic flush failure")
	}
	select {
	case <-requestDone:
	case <-time.After(2 * time.Second):
		t.Fatal("old in-flight request did not finish during replacement shutdown")
	}

	restored, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite after rollback: %v", err)
	}
	if !restored.Enabled || restored.ListenPort != oldPort {
		t.Fatalf("rolled-back row = enabled:%v port:%d, want enabled:true port:%d", restored.Enabled, restored.ListenPort, oldPort)
	}
	if !app.pm.IsRunning(site.ID) {
		t.Fatal("enabled site remained offline after replacement failed post-shutdown")
	}
	app.pm.mu.RLock()
	recoveredInst := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if recoveredInst == nil || recoveredInst == oldInst {
		t.Fatal("rollback did not install a fresh accepting proxy instance")
	}
	if restored.TrafficUsed < 17 {
		t.Fatalf("tail traffic was not conserved during rollback: traffic_used=%d", restored.TrafficUsed)
	}

	verifyClient := &http.Client{Timeout: 2 * time.Second}
	resp, err := verifyClient.Get(fmt.Sprintf("http://127.0.0.1:%d/health", oldPort))
	if err != nil {
		t.Fatalf("rolled-back listener is unavailable: %v", err)
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read rolled-back proxy response: %v", readErr)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "restored" {
		t.Fatalf("rolled-back proxy response status=%d body=%q", resp.StatusCode, body)
	}
}

func waitForLifecyclePortState(t *testing.T, port int, wantListening bool) {
	t.Helper()
	address := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		listening := err == nil
		if conn != nil {
			_ = conn.Close()
		}
		if listening == wantListening {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("port %s listening=%v, want %v (last dial error: %v)", address, listening, wantListening, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEnabledSiteIngressModeTransitionMatrix(t *testing.T) {
	tests := []struct {
		from       string
		to         string
		changePort bool
	}{
		{from: ingressModePort, to: ingressModePort, changePort: true},
		{from: ingressModePort, to: ingressModeHost},
		{from: ingressModePort, to: ingressModeBoth},
		{from: ingressModeHost, to: ingressModePort},
		{from: ingressModeHost, to: ingressModeHost, changePort: true},
		{from: ingressModeHost, to: ingressModeBoth, changePort: true},
		{from: ingressModeBoth, to: ingressModePort},
		{from: ingressModeBoth, to: ingressModeHost},
		{from: ingressModeBoth, to: ingressModeBoth, changePort: true},
	}

	for _, tt := range tests {
		portKind := "same-port"
		if tt.changePort {
			portKind = "different-port"
		}
		t.Run(tt.from+"-to-"+tt.to+"-"+portKind, func(t *testing.T) {
			app := newTestApp(t)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "matrix-ok")
			}))
			defer upstream.Close()

			startPort := freePort(t)
			oldHost := ""
			if ingressUsesHost(tt.from) {
				oldHost = fmt.Sprintf("%s-%s-old.example.test", tt.from, tt.to)
			}
			if ingressUsesPort(tt.from) {
				releasePort(startPort)
			}
			site, err := app.db.CreateSiteRecord(Site{
				Name:         "ingress-" + tt.from + "-to-" + tt.to,
				ListenPort:   startPort,
				PublicHost:   oldHost,
				IngressMode:  tt.from,
				TargetURL:    upstream.URL,
				PlaybackMode: "direct",
				StreamHosts:  "[]",
				UAMode:       "infuse",
			})
			if err != nil {
				t.Fatalf("CreateSiteRecord: %v", err)
			}
			if err := app.pm.StartSite(*site); err != nil {
				t.Fatalf("start %s ingress: %v", tt.from, err)
			}
			t.Cleanup(func() { _ = app.pm.StopSite(site.ID) })
			// Host-only start deliberately kept the reservation open to prove that
			// it did not bind the dedicated port. Release it before the PUT so the
			// destination state, rather than the test reservation, owns the port.
			if !ingressUsesPort(tt.from) {
				releasePort(startPort)
			}

			destinationPort := startPort
			if tt.changePort {
				destinationPort = freePort(t)
				releasePort(destinationPort)
			}
			newHost := ""
			if ingressUsesHost(tt.to) {
				newHost = fmt.Sprintf("%s-%s-new.example.test", tt.from, tt.to)
			}
			payload, err := json.Marshal(map[string]interface{}{
				"name":          site.Name,
				"listen_port":   destinationPort,
				"public_host":   newHost,
				"ingress_mode":  tt.to,
				"target_url":    upstream.URL,
				"playback_mode": "direct",
				"ua_mode":       "infuse",
			})
			if err != nil {
				t.Fatalf("marshal PUT payload: %v", err)
			}
			rr := httptest.NewRecorder()
			app.handleSiteByID(
				rr,
				httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/sites/%d", site.ID), strings.NewReader(string(payload))),
			)
			if rr.Code != http.StatusOK {
				t.Fatalf("PUT %s -> %s status=%d body=%s", tt.from, tt.to, rr.Code, rr.Body.String())
			}

			updated, err := app.db.GetSite(site.ID)
			if err != nil {
				t.Fatalf("GetSite after PUT: %v", err)
			}
			if !updated.Enabled || updated.IngressMode != tt.to || updated.PublicHost != newHost || updated.ListenPort != destinationPort {
				t.Fatalf(
					"updated row = enabled:%v mode:%q host:%q port:%d, want true/%q/%q/%d",
					updated.Enabled,
					updated.IngressMode,
					updated.PublicHost,
					updated.ListenPort,
					tt.to,
					newHost,
					destinationPort,
				)
			}
			if !app.pm.IsRunning(site.ID) {
				t.Fatalf("enabled %s ingress is not operational after %s -> %s", tt.to, tt.from, tt.to)
			}
			_, _, runtimeRunning, portListening := app.pm.GetSiteRuntime(site.ID)
			if !runtimeRunning || portListening != ingressUsesPort(tt.to) {
				t.Fatalf(
					"runtime = running:%v port_listening:%v, want true/%v",
					runtimeRunning,
					portListening,
					ingressUsesPort(tt.to),
				)
			}

			if oldHost != "" {
				if oldID, exists := app.pm.PublicHostSiteID(oldHost); exists {
					t.Fatalf("old public_host %q still maps to site %d", oldHost, oldID)
				}
			}
			if ingressUsesHost(tt.to) {
				mappedID, exists := app.pm.PublicHostSiteID(newHost)
				if !exists || mappedID != site.ID {
					t.Fatalf("new public_host %q mapping = %d/%v, want %d/true", newHost, mappedID, exists, site.ID)
				}
				handler, configured := app.pm.PublicHostHandler(newHost)
				if !configured || handler == nil {
					t.Fatalf("new public_host %q has no active handler", newHost)
				}
				hostResponse := httptest.NewRecorder()
				handler.ServeHTTP(hostResponse, httptest.NewRequest(http.MethodGet, "http://"+newHost+"/matrix", nil))
				if hostResponse.Code != http.StatusOK || hostResponse.Body.String() != "matrix-ok" {
					t.Fatalf("host ingress status=%d body=%q", hostResponse.Code, hostResponse.Body.String())
				}
			}

			waitForLifecyclePortState(t, destinationPort, ingressUsesPort(tt.to))
			if ingressUsesPort(tt.to) {
				portClient := &http.Client{Timeout: 2 * time.Second}
				response, err := portClient.Get(fmt.Sprintf("http://127.0.0.1:%d/matrix", destinationPort))
				if err != nil {
					t.Fatalf("dedicated port request: %v", err)
				}
				body, readErr := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if readErr != nil || response.StatusCode != http.StatusOK || string(body) != "matrix-ok" {
					t.Fatalf("port ingress status=%d body=%q readErr=%v", response.StatusCode, body, readErr)
				}
			}
			if tt.changePort && ingressUsesPort(tt.from) {
				waitForLifecyclePortState(t, startPort, false)
			}
		})
	}
}
