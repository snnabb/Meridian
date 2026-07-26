package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSetupTokenFilePath(t *testing.T) {
	if got := setupTokenFilePath(":memory:"); got != "" {
		t.Fatalf("in-memory path = %q, want empty", got)
	}
	if got := setupTokenFilePath("file:test.db?mode=memory"); got != "" {
		t.Fatalf("DSN path = %q, want empty", got)
	}
	want := filepath.Join("data", "setup-token")
	if got := setupTokenFilePath(filepath.Join("data", "meridian.db")); got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

func TestWriteSetupTokenFileIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "setup-token")
	if err := writeSetupTokenFile(path, "bootstrap-token-value"); err != nil {
		t.Fatalf("writeSetupTokenFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.TrimSpace(string(data)) != "bootstrap-token-value" {
		t.Fatalf("contents = %q", string(data))
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Fatalf("mode = %04o, want 0600", perm)
		}
	}
	// No configured path must be a no-op rather than an error, so an in-memory
	// database still starts.
	if err := writeSetupTokenFile("", "bootstrap-token-value"); err != nil {
		t.Fatalf("empty path should be a no-op: %v", err)
	}
}

func TestHandleSetupRemovesParkedTokenFileOnSuccess(t *testing.T) {
	app := newTestApp(t)
	app.setupToken = "bootstrap-token-value"
	app.setupTokenPath = filepath.Join(t.TempDir(), "setup-token")
	if err := writeSetupTokenFile(app.setupTokenPath, app.setupToken); err != nil {
		t.Fatalf("writeSetupTokenFile: %v", err)
	}

	body := strings.NewReader(`{"username":"admin","password":"correct-horse-battery","setup_token":"bootstrap-token-value"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", body)
	rr := httptest.NewRecorder()
	app.handleSetup(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(app.setupTokenPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("setup token file survived a completed setup: %v", err)
	}
}

func TestHandleSetupKeepsTokenFileWhenTokenIsWrong(t *testing.T) {
	// A rejected attempt must not destroy the operator's only copy of the token,
	// otherwise one typo locks them out of their own panel.
	app := newTestApp(t)
	app.setupToken = "bootstrap-token-value"
	app.setupTokenPath = filepath.Join(t.TempDir(), "setup-token")
	if err := writeSetupTokenFile(app.setupTokenPath, app.setupToken); err != nil {
		t.Fatalf("writeSetupTokenFile: %v", err)
	}

	body := strings.NewReader(`{"username":"admin","password":"correct-horse-battery","setup_token":"wrong-token"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", body)
	rr := httptest.NewRecorder()
	app.handleSetup(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s, want 403", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(app.setupTokenPath); err != nil {
		t.Fatalf("setup token file must survive a rejected attempt: %v", err)
	}
}

func TestClearSetupTokenFileToleratesMissingAndUnsetPaths(t *testing.T) {
	app := newTestApp(t)

	// Unset path: nothing to do, and must not panic.
	app.setupTokenPath = ""
	app.clearSetupTokenFile()

	// Already-removed file: idempotent, so a second setup attempt is harmless.
	app.setupTokenPath = filepath.Join(t.TempDir(), "setup-token")
	app.clearSetupTokenFile()
	app.clearSetupTokenFile()
}
