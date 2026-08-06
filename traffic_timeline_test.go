package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTrafficMinuteMigrationIsRepeatableAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "timeline.db")
	for attempt := range 2 {
		db, err := openDB(path)
		if err != nil {
			t.Fatalf("openDB attempt %d: %v", attempt, err)
		}
		rows, err := db.db.Query("SELECT name, pk FROM pragma_table_info('traffic_minute_logs') ORDER BY cid")
		if err != nil {
			db.Close()
			t.Fatalf("inspect minute schema: %v", err)
		}
		var names []string
		var primary []int
		for rows.Next() {
			var name string
			var pk int
			if err := rows.Scan(&name, &pk); err != nil {
				rows.Close()
				db.Close()
				t.Fatalf("scan minute schema: %v", err)
			}
			names = append(names, name)
			primary = append(primary, pk)
		}
		rows.Close()
		db.Close()
		want := []string{"site_id", "minute_start_unix", "bytes_in", "bytes_out", "requests"}
		if strings.Join(names, ",") != strings.Join(want, ",") {
			t.Fatalf("minute columns = %v, want %v", names, want)
		}
		if len(primary) != 5 || primary[0] != 1 || primary[1] != 2 {
			t.Fatalf("minute primary key positions = %v", primary)
		}
	}
}

func TestTrafficMinuteCompletionBoundaryFlushAndDenseTimeline(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("minutes", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	inst := &ProxyInstance{Site: *site, server: &http.Server{}}
	app.pm.proxies[site.ID] = inst

	startMinute := trafficMinuteStart(time.Now().Add(-2 * time.Minute))
	completionMinute := startMinute + trafficMinuteSeconds
	meter := newRequestTrafficMeterAt(inst, time.Unix(startMinute+59, 0))
	meter.add(12, 8, time.Unix(startMinute+59, 0))
	meter.finish(time.Unix(completionMinute, 0))
	if got := inst.reqCount.Load(); got != 1 {
		t.Fatalf("completed request count = %d, want 1", got)
	}
	if _, exists := inst.pendingMinuteTraffic[completionMinute]; !exists {
		t.Fatalf("request was not attributed to completion minute: %+v", inst.pendingMinuteTraffic)
	}
	if err := app.pm.flushProxyTraffic(inst); err != nil {
		t.Fatalf("flushProxyTraffic: %v", err)
	}

	var in, out, requests int64
	if err := app.db.db.QueryRow("SELECT bytes_in, bytes_out, requests FROM traffic_minute_logs WHERE site_id=? AND minute_start_unix=?", site.ID, completionMinute).Scan(&in, &out, &requests); err != nil {
		t.Fatalf("read minute row: %v", err)
	}
	if in != 12 || out != 8 || requests != 1 {
		t.Fatalf("minute row = in:%d out:%d requests:%d", in, out, requests)
	}
	reloaded, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if reloaded.TrafficUsed != 20 || inst.persistedTraffic.Load() != 20 || inst.bytesIn.Load() != 0 || inst.bytesOut.Load() != 0 {
		t.Fatalf("totals after transactional flush = site:%d persisted:%d pending:%d/%d", reloaded.TrafficUsed, inst.persistedTraffic.Load(), inst.bytesIn.Load(), inst.bytesOut.Load())
	}

	timelineNow := time.Unix(completionMinute+trafficMinuteSeconds, 0)
	timeline, err := app.db.GetTrafficTimeline(site.ID, 60, timelineNow)
	if err != nil {
		t.Fatalf("GetTrafficTimeline: %v", err)
	}
	wantLast := trafficMinuteStart(timelineNow)
	if len(timeline) != 60 || timeline[0].MinuteStartUnix != wantLast-59*trafficMinuteSeconds || timeline[59].MinuteStartUnix != wantLast {
		t.Fatalf("dense timeline bounds = len:%d first:%d last:%d", len(timeline), timeline[0].MinuteStartUnix, timeline[len(timeline)-1].MinuteStartUnix)
	}
	index := int((completionMinute - timeline[0].MinuteStartUnix) / trafficMinuteSeconds)
	if timeline[index].BytesIn != 12 || timeline[index].Requests != 1 {
		t.Fatalf("persisted dense bucket = %+v", timeline[index])
	}
	if timeline[index-1].BytesIn != 0 || timeline[index-1].BytesOut != 0 || timeline[index-1].Requests != 0 {
		t.Fatalf("missing minute was not zero-filled: %+v", timeline[index-1])
	}
}

func TestTrafficTimelineRangeAllowlist(t *testing.T) {
	for _, minutes := range []int{60, 360, 1440, 10080} {
		if !validTrafficTimelineMinutes(minutes) {
			t.Errorf("allowed range %d rejected", minutes)
		}
	}
	for _, minutes := range []int{0, 59, 61, 10081} {
		if validTrafficTimelineMinutes(minutes) {
			t.Errorf("invalid range %d accepted", minutes)
		}
	}
}

func TestTrafficMinuteRetentionDeletesOneBoundedBatch(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("retention", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	now := time.Unix(2_000_000, 0).UTC()
	cutoff := trafficMinuteStart(now.Add(-trafficMinuteRetention))
	for i := range trafficMinutePruneBatchSize + 44 {
		if _, err := app.db.db.Exec("INSERT INTO traffic_minute_logs(site_id, minute_start_unix, bytes_in, bytes_out, requests) VALUES(?,?,?,?,?)", site.ID, cutoff-int64(i+1)*60, 1, 0, 1); err != nil {
			t.Fatalf("insert stale minute %d: %v", i, err)
		}
	}
	current := trafficMinuteStart(now)
	if err := app.db.addTrafficMinuteBuckets(site.ID, 0, 0, map[int64]trafficMinuteDelta{current: {Requests: 1}}, now); err != nil {
		t.Fatalf("maintenance flush: %v", err)
	}
	var stale int
	if err := app.db.db.QueryRow("SELECT COUNT(*) FROM traffic_minute_logs WHERE minute_start_unix<?", cutoff).Scan(&stale); err != nil {
		t.Fatalf("count stale rows: %v", err)
	}
	if stale != 44 {
		t.Fatalf("stale rows after one bounded prune = %d, want 44", stale)
	}
}

func TestConcurrentTrafficFlushPersistsMinuteAndTotalExactlyOnce(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("concurrent", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	inst := &ProxyInstance{Site: *site, server: &http.Server{}}
	app.pm.proxies[site.ID] = inst
	now := time.Now()
	meter := newRequestTrafficMeterAt(inst, now)
	meter.add(21, 34, now)
	meter.finish(now)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- app.pm.flushProxyTraffic(inst) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent flush: %v", err)
		}
	}
	var total, minuteBytes, requests int64
	if err := app.db.db.QueryRow("SELECT traffic_used FROM sites WHERE id=?", site.ID).Scan(&total); err != nil {
		t.Fatalf("read total: %v", err)
	}
	if err := app.db.db.QueryRow("SELECT bytes_in+bytes_out, requests FROM traffic_minute_logs WHERE site_id=?", site.ID).Scan(&minuteBytes, &requests); err != nil {
		t.Fatalf("read minute: %v", err)
	}
	if total != 55 || minuteBytes != 55 || requests != 1 {
		t.Fatalf("concurrent result = total:%d minute:%d requests:%d", total, minuteBytes, requests)
	}
}
func TestRequestMeterStartupSerializesWithLegacyFallback(t *testing.T) {
	inst := &ProxyInstance{server: &http.Server{}}
	inst.trafficMu.Lock()
	started := make(chan struct{})
	created := make(chan *requestTrafficMeter, 1)
	go func() {
		close(started)
		created <- newRequestTrafficMeterAt(inst, time.Now())
	}()
	<-started
	select {
	case meter := <-created:
		inst.trafficMu.Unlock()
		meter.finish(time.Now())
		t.Fatal("request meter startup did not serialize with a traffic flush")
	case <-time.After(25 * time.Millisecond):
	}
	inst.trafficMu.Unlock()
	select {
	case meter := <-created:
		meter.finish(time.Now())
	case <-time.After(time.Second):
		t.Fatal("request meter startup remained blocked after traffic flush released")
	}
}

func TestRequestCompletionDoesNotInsertSQLiteAndFailedFlushRetainsBucket(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("memory-only", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if _, err := app.db.db.Exec(`CREATE TRIGGER reject_minute_insert BEFORE INSERT ON traffic_minute_logs BEGIN SELECT RAISE(ABORT, 'flush only'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	inst := &ProxyInstance{Site: *site, server: &http.Server{}}
	now := time.Now()
	meter := newRequestTrafficMeterAt(inst, now)
	meter.add(3, 4, now)
	meter.finish(now) // must remain purely in-memory despite the rejecting trigger
	var rows int
	if err := app.db.db.QueryRow("SELECT COUNT(*) FROM traffic_minute_logs").Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("per-request minute rows=%d err=%v", rows, err)
	}
	if err := app.pm.flushProxyTraffic(inst); err == nil {
		t.Fatal("flush unexpectedly bypassed rejecting SQLite trigger")
	}
	if len(inst.pendingMinuteTraffic) != 1 || inst.bytesIn.Load() != 3 || inst.bytesOut.Load() != 4 {
		t.Fatalf("failed flush did not retain counters: buckets=%+v pending=%d/%d", inst.pendingMinuteTraffic, inst.bytesIn.Load(), inst.bytesOut.Load())
	}
}

func TestTrafficTimelineAPIAuthErrorsAndPrivacy(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("api", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	now := time.Now()
	minute := trafficMinuteStart(now)
	if err := app.db.addTrafficMinuteBuckets(site.ID, 5, 7, map[int64]trafficMinuteDelta{minute: {BytesIn: 5, BytesOut: 7, Requests: 2}}, now); err != nil {
		t.Fatalf("seed timeline: %v", err)
	}

	for _, tc := range []struct {
		method, target string
		status         int
	}{
		{http.MethodGet, "/api/traffic/" + jsonNumber64(site.ID) + "/timeline?minutes=61", http.StatusBadRequest},
		{http.MethodGet, "/api/traffic/999999/timeline?minutes=60", http.StatusNotFound},
		{http.MethodPost, "/api/traffic/" + jsonNumber64(site.ID) + "/timeline?minutes=60", http.StatusMethodNotAllowed},
	} {
		rr := httptest.NewRecorder()
		app.handleTraffic(rr, httptest.NewRequest(tc.method, tc.target, nil))
		if rr.Code != tc.status {
			t.Errorf("%s %s status=%d body=%s", tc.method, tc.target, rr.Code, rr.Body.String())
		}
	}

	rr := httptest.NewRecorder()
	app.handleTraffic(rr, httptest.NewRequest(http.MethodGet, "/api/traffic/"+jsonNumber64(site.ID)+"/timeline?minutes=60", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("timeline status=%d body=%s", rr.Code, rr.Body.String())
	}
	var payload []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode timeline: %v", err)
	}
	if len(payload) != 60 {
		t.Fatalf("timeline buckets=%d, want 60", len(payload))
	}
	for key := range payload[len(payload)-1] {
		switch key {
		case "minute_start_unix", "bytes_in", "bytes_out", "requests":
		default:
			t.Fatalf("timeline leaked identity/extra field %q", key)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/traffic/", app.authMiddleware(app.handleTraffic))
	unauthenticated := httptest.NewRecorder()
	mux.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/api/traffic/"+jsonNumber64(site.ID)+"/timeline?minutes=60", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated timeline status=%d, want 401", unauthenticated.Code)
	}
}
