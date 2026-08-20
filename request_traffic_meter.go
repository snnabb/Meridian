package main

import (
	"context"
	"sync"
	"time"
)

type requestTrafficMeterContextKey struct{}

func requestTrafficMeterFromContext(ctx context.Context) *requestTrafficMeter {
	if ctx == nil {
		return nil
	}
	meter, _ := ctx.Value(requestTrafficMeterContextKey{}).(*requestTrafficMeter)
	return meter
}

type requestTrafficMeter struct {
	inst          *ProxyInstance
	mu            sync.Mutex
	startedMinute int64
	localIn       int64
	localOut      int64
	streaming     bool
	finished      bool
}

func newRequestTrafficMeter(inst *ProxyInstance) *requestTrafficMeter {
	return newRequestTrafficMeterAt(inst, time.Now())
}

func newRequestTrafficMeterAt(inst *ProxyInstance, at time.Time) *requestTrafficMeter {
	if inst == nil {
		return nil
	}
	inst.trafficMu.Lock()
	inst.activeTrafficMeters.Add(1)
	inst.trafficMu.Unlock()
	return &requestTrafficMeter{inst: inst, startedMinute: trafficMinuteStart(at)}
}

func (inst *ProxyInstance) addMinuteTraffic(minuteStart, bytesIn, bytesOut, requests int64, addGlobal bool) {
	if inst == nil || bytesIn == 0 && bytesOut == 0 && requests == 0 {
		return
	}
	inst.trafficMu.Lock()
	defer inst.trafficMu.Unlock()
	if addGlobal {
		inst.bytesIn.Add(bytesIn)
		inst.bytesOut.Add(bytesOut)
	}
	if inst.pendingMinuteTraffic == nil {
		inst.pendingMinuteTraffic = make(map[int64]trafficMinuteDelta)
	}
	delta := inst.pendingMinuteTraffic[minuteStart]
	delta.BytesIn += bytesIn
	delta.BytesOut += bytesOut
	delta.Requests += requests
	inst.pendingMinuteTraffic[minuteStart] = delta
	inst.flushBytesIn += bytesIn
	inst.flushBytesOut += bytesOut
}

func (m *requestTrafficMeter) promoteLocked() {
	if m == nil || m.streaming {
		return
	}
	m.streaming = true
	if m.localIn != 0 || m.localOut != 0 {
		m.inst.addMinuteTraffic(m.startedMinute, m.localIn, m.localOut, 0, false)
		m.localIn, m.localOut = 0, 0
	}
}

func (m *requestTrafficMeter) promote() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.promoteLocked()
}

func (m *requestTrafficMeter) add(bytesIn, bytesOut int64, at time.Time) {
	if m == nil || bytesIn == 0 && bytesOut == 0 {
		return
	}
	minute := trafficMinuteStart(at)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.finished {
		return
	}
	if !m.streaming && minute == m.startedMinute {
		m.inst.bytesIn.Add(bytesIn)
		m.inst.bytesOut.Add(bytesOut)
		m.localIn += bytesIn
		m.localOut += bytesOut
		return
	}
	if !m.streaming {
		m.promoteLocked()
	}
	m.inst.addMinuteTraffic(minute, bytesIn, bytesOut, 0, true)
}

func (m *requestTrafficMeter) addIn(n int64)  { m.add(n, 0, time.Now()) }
func (m *requestTrafficMeter) addOut(n int64) { m.add(0, n, time.Now()) }

func (m *requestTrafficMeter) finish(at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.finished {
		m.mu.Unlock()
		return
	}
	m.finished = true
	minute := trafficMinuteStart(at)
	if m.streaming {
		m.inst.addMinuteTraffic(minute, 0, 0, 1, false)
	} else {
		m.inst.addMinuteTraffic(minute, m.localIn, m.localOut, 1, false)
		m.localIn, m.localOut = 0, 0
	}
	m.inst.reqCount.Add(1)
	m.inst.pendingRequests.Add(1)
	m.mu.Unlock()
	m.inst.activeTrafficMeters.Add(-1)
}
