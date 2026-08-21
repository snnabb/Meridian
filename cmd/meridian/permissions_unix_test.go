//go:build unix

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDatabaseFilesAreOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "permissions.db")
	db, err := openDB(path)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()

	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(candidate)
		if errors.Is(err, os.ErrNotExist) && candidate != path {
			continue
		}
		if err != nil {
			t.Fatalf("stat %s: %v", filepath.Base(candidate), err)
		}
		if got := info.Mode().Perm(); got&0077 != 0 {
			t.Errorf("%s permissions = %04o, want owner-only", filepath.Base(candidate), got)
		}
	}
}
