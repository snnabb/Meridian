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
			allowed, _, _ := quota.reserve(true, 20, time.Now())
			total.Add(allowed)
		}()
	}
	wg.Wait()
	if got := total.Load(); got != 100 {
		t.Fatalf("reserved bytes = %d, want exactly 100", got)
	}
}

func TestTrafficQuotaSettlementRefundsUnusedReservation(t *testing.T) {
	app := newTestApp(t)
	inst := &ProxyInstance{Site: Site{ID: 999, TrafficQuota: 100}}
	quota := &trafficQuotaState{pm: app.pm, inst: inst}

	allowed, reservation, err := quota.reserve(true, 20, time.Now())
	if allowed != 20 || err != nil {
		t.Fatalf("reserve = (%d, %v), want (20, nil)", allowed, err)
	}
	reservation.settle(3)

	quota.mu.Lock()
	usage := quota.usage
	quota.mu.Unlock()
	if usage != 3 {
		t.Fatalf("settled quota usage = %d, want 3", usage)
	}
}

func TestTrafficQuotaSettlementTracksActualBytesAcrossCycleChange(t *testing.T) {
	app := newTestApp(t)
	inst := &ProxyInstance{Site: Site{ID: 999, TrafficQuota: 100}}
	quota := &trafficQuotaState{pm: app.pm, inst: inst}

	_, reservation, err := quota.reserve(true, 20, time.Now())
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	quota.mu.Lock()
	quota.generation++
	quota.usage = 10
	quota.cycleMode = trafficBillingModeBidirectional
	quota.mu.Unlock()

	reservation.settle(3)
	quota.mu.Lock()
	usage := quota.usage
	quota.mu.Unlock()
	if usage != 13 {
		t.Fatalf("new-cycle quota usage = %d, want 13", usage)
	}
}
