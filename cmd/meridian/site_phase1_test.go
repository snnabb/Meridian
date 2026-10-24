package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLiveSiteEditKeepsActiveStreamAndPersistsLimits(t *testing.T) {
	app := newTestApp(t)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = io.WriteString(w, "last")
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()
	site, err := app.db.CreateSite("live", freePort(t), upstream.URL, "", "direct", "[]", "passthrough", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	releasePort(site.ListenPort)
	if err = app.pm.StartSite(*site); err != nil {
		t.Fatal(err)
	}
	defer app.pm.StopSite(site.ID)
	inst := app.pm.proxies[site.ID]
	server := httptest.NewServer(inst.handler)
	defer server.Close()
	resp, err := server.Client().Get(server.URL + "/large.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	first := make([]byte, 5)
	if _, err = io.ReadFull(resp.Body, first); err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"name": "renamed", "target_url": site.TargetURL, "listen_port": site.ListenPort, "traffic_quota": 1000000, "speed_limit": 2, "total_speed_limit": 4}
	body, _ := json.Marshal(payload)
	rr := httptest.NewRecorder()
	app.handleSiteByID(rr, httptest.NewRequest(http.MethodPut, "/api/sites/"+strconv.FormatInt(site.ID, 10), bytes.NewReader(body)))
	close(release)
	if rr.Code != 200 {
		t.Fatalf("update %d %s", rr.Code, rr.Body.String())
	}
	if app.pm.proxies[site.ID] != inst {
		t.Fatal("live edit replaced active instance")
	}
	rest, err := io.ReadAll(resp.Body)
	if err != nil || string(first)+string(rest) != "firstlast" {
		t.Fatalf("stream interrupted: %q %q %v", first, rest, err)
	}
	stored, err := app.db.GetSite(site.ID)
	if err != nil || stored.TotalSpeedLimit != 4 || inst.runtimeSite().TrafficQuota != 1000000 {
		t.Fatalf("limits not stored/applied: %+v %v", stored, err)
	}
}
func TestSiteRateSharedBudgetAndCancellation(t *testing.T) {
	l := newSiteRateLimiter(256 * 1024)
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := &sitePacedWriter{dst: io.Discard, limiter: l, ctx: context.Background()}
			if _, err := w.Write(make([]byte, 128*1024)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if time.Since(start) < 900*time.Millisecond {
		t.Fatal("concurrent streams bypassed aggregate limit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.wait(ctx, 1); err != context.Canceled {
		t.Fatalf("cancel = %v", err)
	}
	slow := newSiteRateLimiter(1)
	done := make(chan error, 1)
	go func() { done <- slow.wait(context.Background(), siteRateChunk) }()
	slow.setRate(0)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("rate edit did not release wait")
	}
}
func TestLiveQuotaIncludesUnlimitedTraffic(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("quota", freePort(t), "http://127.0.0.1:1", "", "direct", "[]", "passthrough", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	inst := &ProxyInstance{Site: *site}
	q := &trafficQuotaState{pm: app.pm, inst: inst}
	n, res, err := q.reserve(true, 100, time.Now())
	if err != nil || n != 100 {
		t.Fatal(n, err)
	}
	res.settle(100)
	limited := *site
	limited.TrafficQuota = 120
	inst.liveSite.Store(&limited)
	n, _, err = q.reserve(true, 40, time.Now())
	if n != 20 || err != errTrafficQuotaExceeded {
		t.Fatalf("prior unlimited usage lost: %d %v", n, err)
	}
}
func TestSiteTemplatesAndBulkStalePreview(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("workflow", freePort(t), "http://example.com", "", "direct", "[]", "passthrough", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	policy := siteTemplateConfig(*site)
	if err := app.db.SetSiteEnabled(site.ID, false); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"target_url", "public_host", "listen_port", "accounts", "upstream_headers"} {
		if _, ok := policy[key]; ok {
			t.Fatal("template contains", key)
		}
	}
	payload := map[string]any{"site_ids": []int64{site.ID}, "action": "limits", "total_speed_limit": 7, "preview": true}
	call := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(payload)
		rr := httptest.NewRecorder()
		app.handleSiteBulk(rr, httptest.NewRequest("POST", "/api/sites/bulk", bytes.NewReader(body)))
		return rr
	}
	rr := call()
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	var preview struct {
		Token string `json:"preview_token"`
		Valid bool   `json:"valid"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &preview)
	if !preview.Valid {
		t.Fatal(rr.Body.String())
	}
	payload["preview"] = false
	payload["preview_token"] = preview.Token
	if _, err = app.db.db.Exec("UPDATE sites SET name='changed' WHERE id=?", site.ID); err != nil {
		t.Fatal(err)
	}
	if rr = call(); rr.Code != 409 {
		t.Fatal("stale batch accepted")
	}
	payload["preview"] = true
	rr = call()
	_ = json.Unmarshal(rr.Body.Bytes(), &preview)
	payload["preview"] = false
	payload["preview_token"] = preview.Token
	if rr = call(); rr.Code != 200 || !strings.Contains(rr.Body.String(), "completed") {
		t.Fatal(rr.Body.String())
	}
	stored, _ := app.db.GetSite(site.ID)
	if stored.TotalSpeedLimit != 7 {
		t.Fatal("limit not applied")
	}
}
