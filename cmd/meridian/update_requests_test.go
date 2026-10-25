package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStableUpdateRequestBoundaries(t *testing.T) {
	for _, row := range []struct {
		request systemUpdateRequest
		valid   bool
	}{
		{systemUpdateRequest{Version: "v1.15.0"}, true},
		{systemUpdateRequest{Version: "v1.15.0", Channel: "stable"}, true},
		{systemUpdateRequest{Version: "v1.15.0-beta.1"}, false},
		{systemUpdateRequest{Version: "v1.15.0", Channel: "beta"}, false},
		{systemUpdateRequest{Version: "v1.15.0", Channel: "unknown"}, false},
		{systemUpdateRequest{Version: "1.15.0"}, false},
		{systemUpdateRequest{Version: "v01.15.0"}, false},
		{systemUpdateRequest{Action: "rollback"}, true},
		{systemUpdateRequest{Action: "rollback", Version: "v1.14.2"}, false},
		{systemUpdateRequest{Version: "../../bad"}, false},
	} {
		if got := row.request.normalize(); got != row.valid {
			t.Errorf("%+v: got %v, want %v", row.request, got, row.valid)
		}
	}
}

func TestSystemUpdateRejectsTestChannelBeforeNetwork(t *testing.T) {
	app := &App{}
	for _, row := range []struct{ method, path, body string }{
		{"GET", "/api/system/update/check?channel=beta", ""},
		{"POST", "/api/system/update", `{"version":"v99.0.0","channel":"beta"}`},
		{"POST", "/api/system/update", `{"version":"v99.0.0-beta.1"}`},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(row.method, row.path, strings.NewReader(row.body))
		if row.method == "GET" {
			app.handleSystemUpdateCheck(w, r)
		} else {
			app.handleSystemUpdate(w, r)
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s %s: %d %s", row.method, row.path, w.Code, w.Body.String())
		}
	}
}

func TestStableUpdateWorksWithProtocolOneAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("deployed updater uses a Unix socket on Linux")
	}
	directory, err := os.MkdirTemp("", "meridian-agent-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	socket := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var legacy struct {
			Version string `json:"version"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&legacy); err != nil {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(updateJob{Message: err.Error()})
			return
		}
		received <- legacy.Version
		_ = json.NewEncoder(w).Encode(updateJob{State: "running", Version: legacy.Version})
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	t.Setenv("MERIDIAN_UPDATER_SOCKET", socket)
	previous := appVersion
	appVersion = "v1.14.2"
	t.Cleanup(func() { appVersion = previous })
	w := httptest.NewRecorder()
	(&App{}).handleSystemUpdate(w, httptest.NewRequest("POST", "/api/system/update", strings.NewReader(`{"version":"v1.15.0","channel":"stable"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("legacy agent rejected update: %d %s", w.Code, w.Body.String())
	}
	select {
	case got := <-received:
		if got != "v1.15.0" {
			t.Fatalf("version = %s", got)
		}
	default:
		t.Fatal("legacy agent received no update")
	}
}

func TestRollbackAdvertisesOnlyCompleteSnapshot(t *testing.T) {
	directory := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write("version", "v1.14.2\n")
	if got := rollbackSnapshotVersion(directory); got != "" {
		t.Fatalf("marker-only snapshot advertised: %s", got)
	}
	if err := os.Mkdir(filepath.Join(directory, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	write("meridian", "binary")
	write("service", "service")
	if got := rollbackSnapshotVersion(directory); got != "v1.14.2" {
		t.Fatalf("complete snapshot: %q", got)
	}
	write("version", "../../untrusted")
	if got := rollbackSnapshotVersion(directory); got != "" {
		t.Fatal("invalid version advertised")
	}
	write("version", "v1.14.2-beta.abc1234")
	if got := rollbackSnapshotVersion(directory); got != "v1.14.2-beta.abc1234" {
		t.Fatal("existing development snapshot cannot be restored")
	}
	write("service", "")
	if got := rollbackSnapshotVersion(directory); got != "" {
		t.Fatal("empty service advertised")
	}
	if runtime.GOOS != "windows" {
		if err := os.Remove(filepath.Join(directory, "service")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(directory, "meridian"), filepath.Join(directory, "service")); err != nil {
			t.Fatal(err)
		}
		if got := rollbackSnapshotVersion(directory); got != "" {
			t.Fatal("symlink advertised")
		}
	}
}
