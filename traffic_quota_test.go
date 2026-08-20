package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrafficQuotaReservationIsAtomicAcrossConcurrentWriters(t *testing.T) {
	app := newTestApp(t)
	inst := &ProxyInstance{Site: Site{ID: 999, TrafficQuota: 100}}
	quota := &trafficQuotaState{pm: app.pm, inst: inst}

	var total atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, _ := quota.allow(true, 20, time.Now())
			total.Add(allowed)
		}()
	}
	wg.Wait()
	if got := total.Load(); got != 100 {
		t.Fatalf("reserved bytes = %d, want exactly 100", got)
	}
}
