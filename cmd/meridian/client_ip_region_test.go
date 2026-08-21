package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientIPRegionResolverClassifiesLocalAddresses(t *testing.T) {
	resolver, err := newClientIPRegionResolver("off", nil)
	if err != nil || resolver != nil {
		t.Fatalf("disabled resolver=%#v err=%v", resolver, err)
	}
	if _, got := clientIPRegionStatic("127.0.0.1"); got != clientIPRegionLocal {
		t.Fatalf("loopback region=%q", got)
	}
	if _, got := clientIPRegionStatic("203.0.113.10"); got != clientIPRegionLocal {
		t.Fatalf("documentation region=%q", got)
	}
	if _, got := clientIPRegionStatic("not-an-ip"); got != clientIPRegionUnknown {
		t.Fatalf("invalid region=%q", got)
	}
}

func TestClientIPRegionResolverFetchesAndCaches(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/8.8.8.8" {
			t.Errorf("path=%q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"country":"美国","region":"加利福尼亚州","city":"圣何塞"}`)
	}))
	defer server.Close()
	resolver, err := newClientIPRegionResolver(server.URL+"/{ip}", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if got := resolver.lookup("8.8.8.8"); got != clientIPRegionPending {
		t.Fatalf("first lookup=%q", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := resolver.lookup("8.8.8.8"); got == "美国 · 加利福尼亚州 · 圣何塞" {
			if requests.Load() != 1 {
				t.Fatalf("requests=%d, want 1", requests.Load())
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("region lookup did not complete; requests=%d", requests.Load())
}
