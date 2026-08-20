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
	initialized bool
}

func (q *trafficQuotaState) allow(outbound bool, requested int64, now time.Time) (int64, error) {
	if q == nil || q.inst == nil || q.pm == nil || q.pm.database == nil || q.inst.Site.TrafficQuota <= 0 || requested <= 0 {
		return requested, nil
	}
	settings := q.pm.database.currentSystemSettings()
	cycleStart := trafficCycleStart(now, settings.TrafficResetDay)
	cycleMode := trafficBillingModeLabel(settings.TrafficBillingMode)
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.initialized || !q.cycleStart.Equal(cycleStart) || q.cycleMode != cycleMode {
		currentUsed, err := q.pm.currentTrafficCycleUsage(q.inst, now)
		if err != nil {
			return 0, err
		}
		q.cycleStart, q.cycleMode, q.usage, q.initialized = cycleStart, cycleMode, currentUsed, true
	}
	if !outbound && cycleMode == trafficBillingModeOutbound {
		return requested, nil
	}
	remaining := q.inst.Site.TrafficQuota - q.usage
	if remaining <= 0 {
		return 0, errTrafficQuotaExceeded
	}
	allowed := requested
	if int64(allowed) > remaining {
		allowed = remaining
	}
	q.usage += allowed
	if allowed < requested {
		return allowed, errTrafficQuotaExceeded
	}
	return allowed, nil
}
