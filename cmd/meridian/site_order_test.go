package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func createSiteForOrderTest(t *testing.T, app *App, name string, port int) *Site {
	t.Helper()
	site, err := app.db.CreateSiteRecord(Site{
		Name:       name,
		ListenPort: port,
		TargetURL:  "https://" + name + ".example.com",
	})
	if err != nil {
		t.Fatalf("create site %s: %v", name, err)
	}
	return site
}

func TestSiteReorderPersistsAndDrivesListOrder(t *testing.T) {
	app := newTestApp(t)
	alpha := createSiteForOrderTest(t, app, "alpha", 19001)
	beta := createSiteForOrderTest(t, app, "beta", 19002)
	gamma := createSiteForOrderTest(t, app, "gamma", 19003)

	payload, err := json.Marshal(map[string]interface{}{
		"site_ids": []int64{gamma.ID, alpha.ID, beta.ID},
	})
	if err != nil {
		t.Fatalf("marshal reorder payload: %v", err)
	}
	rr := httptest.NewRecorder()
	app.handleSiteReorder(rr, httptest.NewRequest(http.MethodPut, "/api/sites/reorder", bytes.NewReader(payload)))
	if rr.Code != http.StatusOK {
		t.Fatalf("reorder status=%d body=%s", rr.Code, rr.Body.String())
	}

	sites, err := app.db.ListSites()
	if err != nil {
		t.Fatalf("list reordered sites: %v", err)
	}
	want := []int64{gamma.ID, alpha.ID, beta.ID}
	if len(sites) != len(want) {
		t.Fatalf("site count=%d want=%d", len(sites), len(want))
	}
	for i, id := range want {
		if sites[i].ID != id || sites[i].SortOrder != int64(i) {
			t.Fatalf("site[%d]=id:%d order:%d want id:%d order:%d", i, sites[i].ID, sites[i].SortOrder, id, i)
		}
	}

	listResponse := httptest.NewRecorder()
	app.handleSites(listResponse, httptest.NewRequest(http.MethodGet, "/api/sites", nil))
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list API status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	var listed []struct {
		ID        int64 `json:"id"`
		SortOrder int64 `json:"sort_order"`
	}
	if err := json.Unmarshal(listResponse.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list API: %v", err)
	}
	for i, id := range want {
		if listed[i].ID != id || listed[i].SortOrder != int64(i) {
			t.Fatalf("API site[%d]=%+v want id:%d order:%d", i, listed[i], id, i)
		}
	}
}

func TestSiteReorderRejectsIncompleteOrDuplicateOrder(t *testing.T) {
	app := newTestApp(t)
	alpha := createSiteForOrderTest(t, app, "alpha", 19101)
	beta := createSiteForOrderTest(t, app, "beta", 19102)

	for _, ids := range [][]int64{{alpha.ID}, {alpha.ID, alpha.ID}, {alpha.ID, beta.ID + 1000}} {
		payload, err := json.Marshal(map[string]interface{}{"site_ids": ids})
		if err != nil {
			t.Fatalf("marshal invalid reorder payload: %v", err)
		}
		rr := httptest.NewRecorder()
		app.handleSiteReorder(rr, httptest.NewRequest(http.MethodPut, "/api/sites/reorder", bytes.NewReader(payload)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("ids=%v status=%d body=%s", ids, rr.Code, rr.Body.String())
		}
	}
}

func TestSiteOrderMigrationBackfillsLegacyIDOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-site-order.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := legacy.Exec(`CREATE TABLE sites (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		listen_port INTEGER NOT NULL UNIQUE,
		target_url TEXT NOT NULL,
		ua_mode TEXT DEFAULT 'passthrough',
		enabled INTEGER DEFAULT 1,
		traffic_quota BIGINT DEFAULT 0,
		traffic_used BIGINT DEFAULT 0,
		speed_limit INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		legacy.Close()
		t.Fatalf("create legacy sites: %v", err)
	}
	if _, err := legacy.Exec(`INSERT INTO sites (name, listen_port, target_url) VALUES
		('first', 19201, 'https://first.example.com'),
		('second', 19202, 'https://second.example.com')`); err != nil {
		legacy.Close()
		t.Fatalf("insert legacy sites: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	db, err := openDB(path)
	if err != nil {
		t.Fatalf("migrate legacy database: %v", err)
	}
	defer db.Close()
	sites, err := db.ListSites()
	if err != nil {
		t.Fatalf("list migrated sites: %v", err)
	}
	if len(sites) != 2 || sites[0].Name != "first" || sites[1].Name != "second" {
		t.Fatalf("migrated site order=%+v", sites)
	}
	if sites[0].SortOrder != sites[0].ID || sites[1].SortOrder != sites[1].ID {
		t.Fatalf("legacy sort order not backfilled from IDs: %+v", sites)
	}
}
