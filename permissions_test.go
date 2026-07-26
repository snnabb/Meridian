package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// permissions_unix_test.go asserts the 0600 outcome, but it is build-tagged unix
// and every CI job runs on ubuntu, so nothing ever exercised the other branch.
// These run everywhere and pin the contract itself.

func TestHardenDatabaseFilePermissionsHonoursPlatformCapability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "modes.db")
	db, err := openDB(path)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat database: %v", err)
	}
	if fileModesEnforced() {
		if perm := info.Mode().Perm(); perm&0077 != 0 {
			t.Fatalf("modes are enforced on %s but the database is %04o, want owner-only", runtime.GOOS, perm)
		}
		return
	}
	// Where modes are not enforced the gap is a documented warning, never a
	// startup failure: the panel still has to come up.
	t.Logf("file modes are not enforced on %s; database left at %04o", runtime.GOOS, info.Mode().Perm())
}

func TestHardenDatabaseFilePermissionsIgnoresNonFilePaths(t *testing.T) {
	for _, path := range []string{":memory:", "file:test.db?mode=memory"} {
		if err := hardenDatabaseFilePermissions(path); err != nil {
			t.Fatalf("hardenDatabaseFilePermissions(%q) = %v, want nil", path, err)
		}
	}
}

func TestHardenDatabaseFilePermissionsToleratesMissingSidecars(t *testing.T) {
	// A database with no -wal/-shm beside it must not be treated as an error,
	// which is what lets openDB run before SQLite creates them.
	path := filepath.Join(t.TempDir(), "absent.db")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatalf("seed database file: %v", err)
	}
	if err := hardenDatabaseFilePermissions(path); err != nil {
		t.Fatalf("hardenDatabaseFilePermissions = %v, want nil", err)
	}
}
