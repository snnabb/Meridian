package main

import (
	"errors"
	"sync"
	"time"
)

var errTrafficQuotaExceeded = errors.New("traffic quota exceeded")

type trafficQuotaState struct {
	mu          sync.Mutex
	pm          *ProxyManager
	inst        *ProxyInstance
	cycleStart  time.Time
	cycleMode   string
	usage       int64
	generation  uint64
	initialized bool
}

type trafficQuotaReservation struct {
	state      *trafficQuotaState
	generation uint64
	reserved   int64
	outbound   bool
	charged    bool
}

func (reservation trafficQuotaReservation) settle(actual int64) {
	if reservation.state == nil || reservation.reserved <= 0 {
		return
	}
	if actual < 0 {
		actual = 0
	}
	if actual > reservation.reserved {
		actual = reservation.reserved
	}
	reservation.state.mu.Lock()
	defer reservation.state.mu.Unlock()
	if reservation.state.generation != reservation.generation {
		if actual > 0 && (reservation.outbound || reservation.state.cycleMode != trafficBillingModeOutbound) {
			const maxInt64Value = int64(^uint64(0) >> 1)
			if reservation.state.usage > maxInt64Value-actual {
				reservation.state.usage = maxInt64Value
			} else {
				reservation.state.usage += actual
			}
		}
		return
	}
	if !reservation.charged {
		return
	}
	refund := reservation.reserved - actual
	if refund <= 0 {
		return
	}
	if refund >= reservation.state.usage {
		reservation.state.usage = 0
		return
	}
	reservation.state.usage -= refund
}

func (q *trafficQuotaState) reserve(outbound bool, requested int64, now time.Time) (int64, trafficQuotaReservation, error) {
	if q == nil || q.inst == nil || q.pm == nil || q.pm.database == nil || q.inst.Site.TrafficQuota <= 0 || requested <= 0 {
		return requested, trafficQuotaReservation{}, nil
	}
	settings := q.pm.database.currentSystemSettings()
	cycleStart := trafficCycleStart(now, settings.TrafficResetDay)
	cycleMode := trafficBillingModeLabel(settings.TrafficBillingMode)
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.initialized || !q.cycleStart.Equal(cycleStart) || q.cycleMode != cycleMode {
		currentUsed, err := q.pm.currentTrafficCycleUsage(q.inst, now)
		if err != nil {
			return 0, trafficQuotaReservation{}, err
		}
		q.cycleStart, q.cycleMode, q.usage, q.initialized = cycleStart, cycleMode, currentUsed, true
		q.generation++
	}
	if !outbound && cycleMode == trafficBillingModeOutbound {
		reservation := trafficQuotaReservation{state: q, generation: q.generation, reserved: requested}
		return requested, reservation, nil
	}
	remaining := q.inst.Site.TrafficQuota - q.usage
	if remaining <= 0 {
		return 0, trafficQuotaReservation{}, errTrafficQuotaExceeded
	}
	allowed := requested
	if allowed > remaining {
		allowed = remaining
	}
	q.usage += allowed
	reservation := trafficQuotaReservation{state: q, generation: q.generation, reserved: allowed, outbound: outbound, charged: true}
	if allowed < requested {
		return allowed, reservation, errTrafficQuotaExceeded
	}
	return allowed, reservation, nil
}
