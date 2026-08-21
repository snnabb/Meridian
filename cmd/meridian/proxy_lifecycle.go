package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

func (pm *ProxyManager) StopSite(id int64) error {
	pm.lifecycleMu.Lock()
	defer pm.lifecycleMu.Unlock()
	pm.mu.RLock()
	inst, ok := pm.proxies[id]
	pm.mu.RUnlock()
	if !ok {
		return nil
	}
	// Check persistence before closing any listener or request context. A DB
	// failure therefore leaves a fully usable instance that can be retried.
	// lifecycleMu pins inst, and trafficMu protects its counters without blocking
	// shared-host routing on pm.mu.
	ingressAlreadyClosed := !inst.isAccepting()
	if err := pm.flushProxyTraffic(inst); err != nil {
		if ingressAlreadyClosed {
			return &siteIngressClosedError{siteID: id, flushErr: err}
		}
		return err
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	shutdownErr := inst.shutdown(shutdownCtx)
	shutdownCancel()
	finalFlushErr := pm.flushProxyTraffic(inst)
	if shutdownErr != nil || finalFlushErr != nil {
		// Keep the stopped instance and its pending counters addressable so a
		// subsequent StopSite/GracefulShutdown can retry the final persistence.
		return &siteIngressClosedError{siteID: id, drainErr: shutdownErr, flushErr: finalFlushErr}
	}
	nextSelfTargets, snapshotErr := pm.buildDynamicSelfTargetPolicy()
	pm.mu.Lock()
	if pm.proxies[id] == inst {
		delete(pm.proxies, id)
	}
	if snapshotErr != nil {
		pm.dynamicRuntime.selfTargets.Store(nil)
	} else {
		pm.dynamicRuntime.selfTargets.Store(nextSelfTargets)
	}
	pm.mu.Unlock()
	if snapshotErr != nil {
		log.Printf("dynamic discovery disabled until the next lifecycle refresh: %v", snapshotErr)
	}
	return nil
}

func (pm *ProxyManager) IsRunning(id int64) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	inst, ok := pm.proxies[id]
	return ok && inst.isOperational()
}

func (pm *ProxyManager) StartAllEnabled() (int, error) {
	sites, err := pm.database.ListSites()
	if err != nil {
		return 0, err
	}
	for _, site := range sites {
		if err := pm.RegisterSiteHost(site); err != nil {
			return 0, err
		}
	}
	for _, s := range sites {
		if s.Enabled {
			if err := pm.StartSite(s); err != nil {
				if errors.Is(err, errUnsafeHostOnlyIngress) {
					return len(sites), fmt.Errorf("site %q: %w", s.Name, err)
				}
				log.Printf("[%s] failed to start: %v", s.Name, err)
			}
		}
	}
	return len(sites), nil
}

// FlushTraffic flushes every running instance's pending traffic and request
// count to the DB. It is driven by the periodic ticker: a failed flush restores
// the pending counters and is logged here, so the next tick retries the same
// values.
func (pm *ProxyManager) FlushTraffic() {
	pm.mu.RLock()
	instances := make([]*ProxyInstance, 0, len(pm.proxies))
	for _, inst := range pm.proxies {
		instances = append(instances, inst)
	}
	pm.mu.RUnlock()
	for _, inst := range instances {
		if err := pm.flushProxyTraffic(inst); err != nil {
			log.Printf("[%s] failed to flush traffic: %v", inst.Site.Name, err)
		}
	}
}

// flushProxyTraffic persists inst's pending bytes and requests into the DB and
// moves the bytes into the persisted baseline. The caller must pin inst through
// lifecycleMu, a pm.mu snapshot, or another stable reference; inst.trafficMu is
// acquired here. On failure the pending counters are fully restored so the next
// flush retries the same values. Never call this while already holding
// inst.trafficMu.
func (pm *ProxyManager) flushProxyTraffic(inst *ProxyInstance) error {
	inst.trafficMu.Lock()
	defer inst.trafficMu.Unlock()
	return pm.flushProxyTrafficLocked(inst)
}

// flushProxyTrafficLocked is the body of flushProxyTraffic and assumes
// inst.trafficMu is held. Order is swap -> DB -> persisted baseline: the
// pending counters are zeroed first, the baseline moves only after the DB
// transaction commits, and all counters are restored verbatim on any error.
func (pm *ProxyManager) flushProxyTrafficLocked(inst *ProxyInstance) error {
	in := inst.bytesIn.Swap(0)
	out := inst.bytesOut.Swap(0)
	requests := inst.pendingRequests.Swap(0)
	buckets := make(map[int64]trafficMinuteDelta, len(inst.pendingMinuteTraffic))
	for minute, delta := range inst.pendingMinuteTraffic {
		buckets[minute] = delta
	}
	inst.pendingMinuteTraffic = make(map[int64]trafficMinuteDelta)
	inst.flushBytesIn = 0
	inst.flushBytesOut = 0
	var bucketRequests int64
	for _, delta := range buckets {
		bucketRequests += delta.Requests
	}
	if requests > bucketRequests {
		minute := trafficMinuteStart(time.Now())
		delta := buckets[minute]
		delta.Requests += requests - bucketRequests
		buckets[minute] = delta
	}
	if in == 0 && out == 0 && requests == 0 && len(buckets) == 0 {
		return nil
	}
	if pm.database == nil {
		inst.bytesIn.Add(in)
		inst.bytesOut.Add(out)
		inst.pendingRequests.Add(requests)
		for minute, delta := range buckets {
			current := inst.pendingMinuteTraffic[minute]
			current.BytesIn += delta.BytesIn
			current.BytesOut += delta.BytesOut
			current.Requests += delta.Requests
			inst.pendingMinuteTraffic[minute] = current
		}
		inst.flushBytesIn = in
		inst.flushBytesOut = out
		return fmt.Errorf("traffic database is unavailable")
	}
	if err := pm.database.addTrafficMinuteBuckets(inst.Site.ID, in, out, buckets, time.Now()); err != nil {
		inst.bytesIn.Add(in)
		inst.bytesOut.Add(out)
		inst.pendingRequests.Add(requests)
		for minute, delta := range buckets {
			current := inst.pendingMinuteTraffic[minute]
			current.BytesIn += delta.BytesIn
			current.BytesOut += delta.BytesOut
			current.Requests += delta.Requests
			inst.pendingMinuteTraffic[minute] = current
		}
		inst.flushBytesIn = in
		inst.flushBytesOut = out
		return err
	}
	delta := in + out
	inst.persistedTraffic.Add(delta)
	inst.persistedBytesIn.Add(in)
	inst.persistedBytesOut.Add(out)
	inst.Site.TrafficUsed += delta
	inst.Site.TrafficUsedIn += in
	inst.Site.TrafficUsedOut += out
	settings := pm.database.currentSystemSettings()
	cycleStart := trafficCycleStart(time.Now(), settings.TrafficResetDay)
	cycleMode := trafficBillingModeLabel(settings.TrafficBillingMode)
	if inst.trafficCycleMode == cycleMode && inst.trafficCycleStart.Equal(cycleStart) {
		inst.trafficCycleUsage += trafficBillableBytes(cycleMode, in, out)
	}
	return nil
}

// currentTrafficCycleUsage returns one consistent view of the persisted and
// pending usage for the active billing cycle. The persisted portion is loaded
// once per reset boundary or billing-mode change, then advanced by successful
// traffic flushes while trafficMu prevents a swap/query race.
func (pm *ProxyManager) currentTrafficCycleUsage(inst *ProxyInstance, now time.Time) (int64, error) {
	settings := pm.database.currentSystemSettings()
	cycleStart := trafficCycleStart(now, settings.TrafficResetDay)
	cycleMode := trafficBillingModeLabel(settings.TrafficBillingMode)

	inst.trafficMu.Lock()
	defer inst.trafficMu.Unlock()
	if inst.trafficCycleMode != cycleMode || !inst.trafficCycleStart.Equal(cycleStart) {
		persisted, err := pm.database.SumTrafficSinceForSite(inst.Site.ID, cycleStart, cycleMode)
		if err != nil {
			return 0, err
		}
		inst.trafficCycleStart = cycleStart
		inst.trafficCycleMode = cycleMode
		inst.trafficCycleUsage = persisted
	}
	return inst.trafficCycleUsage + trafficBillableBytes(cycleMode, inst.bytesIn.Load(), inst.bytesOut.Load()), nil
}

func (inst *ProxyInstance) persistedDirections() (int64, int64) {
	in, out := inst.persistedBytesIn.Load(), inst.persistedBytesOut.Load()
	if in == 0 && out == 0 && inst.persistedTraffic.Load() > 0 {
		return legacyTrafficDirections(inst.persistedTraffic.Load())
	}
	return in, out
}

// sameTrafficMinute reports whether a persisted recorded_at value falls in the
// same wall-clock minute as now. Stored rows are wall-clock values: legacy
// "2006-01-02 15:04:05" rows carry the writer's local time, and the modernc
// SQLite driver re-serializes DATETIME columns as RFC3339 with the stored
// wall clock in UTC (it attaches Z to whatever text was written). The
// year/month/day/hour/minute components of the stored value are therefore compared
// against the current local wall clock, never the instants: an instant-based
// comparison would shift the bucket by the zone offset in non-UTC
// deployments. Values that parse as neither format never match, so a corrupt
// or foreign string cannot swallow pending bytes.
func sameTrafficMinute(recordedAt string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, recordedAt)
	if err != nil {
		if t, err = time.ParseInLocation("2006-01-02 15:04:05", recordedAt, time.Local); err != nil {
			return false
		}
	}
	nowLocal := now.In(time.Local)
	y, m, d := t.Date()
	ny, nm, nd := nowLocal.Date()
	return y == ny && m == nm && d == nd && t.Hour() == nowLocal.Hour() && t.Minute() == nowLocal.Minute()
}

// mergePendingIntoLogs merges live pending bytes and requests into the current-
// minute bucket of the returned log copy: it adds to the existing bucket when
// present, or appends a synthetic bucket with ID 0 when the minute has no bucket
// yet and any pending value is non-zero. All-zero pending values are a no-op.
// The input slice must be a private copy (GetTrafficLogs always returns one).
// The current minute is matched by wall-clock semantics via sameTrafficMinute, so rows
// persisted in either the RFC3339 form the SQLite driver returns or the
// legacy SQL layout merge correctly. The synthetic bucket is built from the
// current local wall minute stamped as UTC, exactly the representation the next
// addTraffic row will carry after the driver re-serializes it, with ID 0.
func mergePendingIntoLogs(logs []TrafficLog, siteID, pendingIn, pendingOut, pendingRequests int64) []TrafficLog {
	return mergePendingIntoLogsAt(logs, siteID, pendingIn, pendingOut, pendingRequests, time.Now())
}

func mergePendingIntoLogsAt(logs []TrafficLog, siteID, pendingIn, pendingOut, pendingRequests int64, now time.Time) []TrafficLog {
	if pendingIn == 0 && pendingOut == 0 && pendingRequests == 0 {
		return logs
	}
	for i := range logs {
		if sameTrafficMinute(logs[i].RecordedAt, now) {
			logs[i].BytesIn += pendingIn
			logs[i].BytesOut += pendingOut
			logs[i].Requests += pendingRequests
			if logs[i].RecordedAtMS <= 0 {
				logs[i].RecordedAtMS = trafficWallClockMillis(logs[i].RecordedAt)
			}
			return logs
		}
	}
	nowLocal := now.In(time.Local)
	return append(logs, TrafficLog{
		ID:           0,
		SiteID:       siteID,
		BytesIn:      pendingIn,
		BytesOut:     pendingOut,
		Requests:     pendingRequests,
		RecordedAt:   time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day(), nowLocal.Hour(), nowLocal.Minute(), 0, 0, time.UTC).Format(time.RFC3339),
		RecordedAtMS: time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day(), nowLocal.Hour(), nowLocal.Minute(), 0, 0, time.Local).UnixMilli(),
	})
}

// SiteTrafficHistory captures a single site's traffic history as a consistent
// point-in-time view: the DB log window plus live pending bytes and requests
// merged into the returned copy's current-minute bucket, alongside the authoritative live
// state. For a running site the DB read and the live counters happen under
// inst.trafficMu (with pm.mu held read-only to pin the instance), so the view
// never interleaves with a concurrent flush.
func (pm *ProxyManager) SiteTrafficHistory(site Site, hours int) (*TrafficHistory, error) {
	billingMode := pm.database.currentSystemSettings().TrafficBillingMode
	persistedIn, persistedOut := siteTrafficDirections(site)
	snap := SiteTraffic{
		ID:               site.ID,
		Name:             site.Name,
		TrafficQuota:     site.TrafficQuota,
		PersistedTraffic: trafficBillableBytes(billingMode, persistedIn, persistedOut),
		TrafficUsed:      trafficBillableBytes(billingMode, persistedIn, persistedOut),
	}

	pm.mu.RLock()
	inst, present := pm.proxies[site.ID]
	if !present {
		pm.mu.RUnlock()
		logs, err := pm.database.GetTrafficLogs(site.ID, hours)
		if err != nil {
			return nil, err
		}
		return &TrafficHistory{Snapshot: snap, Logs: logs, BillingMode: billingMode}, nil
	}
	// pm.mu -> trafficMu lock order. trafficMu stays held across the DB read
	// so the logs and the live counters describe the same instant.
	inst.trafficMu.Lock()
	defer inst.trafficMu.Unlock()
	defer pm.mu.RUnlock()

	logs, err := pm.database.GetTrafficLogs(site.ID, hours)
	if err != nil {
		return nil, err
	}
	snap.Running = inst.isOperational()
	persistedIn, persistedOut = inst.persistedDirections()
	snap.PersistedTraffic = trafficBillableBytes(billingMode, persistedIn, persistedOut)
	snap.BytesIn = inst.bytesIn.Load()
	snap.BytesOut = inst.bytesOut.Load()
	snap.CumulativeBytesIn = inst.cumulativeBytesIn.Load()
	snap.CumulativeBytesOut = inst.cumulativeBytesOut.Load()
	snap.TrafficUsed = snap.PersistedTraffic + trafficBillableBytes(billingMode, snap.BytesIn, snap.BytesOut)
	snap.Requests = inst.reqCount.Load()
	logs = mergePendingIntoLogs(logs, site.ID, snap.BytesIn, snap.BytesOut, inst.pendingRequests.Load())
	return &TrafficHistory{Snapshot: snap, Logs: logs, BillingMode: billingMode}, nil
}

// overlaySiteTrafficLocked fills st with the authoritative live per-instance
// state for a running site: persistedTraffic + pending bytes, exactly the same
// merge every traffic view renders. The caller must hold pm.mu (read or
// write); inst.trafficMu is acquired here following the pm.mu -> trafficMu
// lock order, so the overlay never interleaves with a concurrent flush. This
// is the single per-site merge algorithm for all live traffic payloads.
func (pm *ProxyManager) overlaySiteTrafficLocked(s Site, st *SiteTraffic) {
	if inst, ok := pm.proxies[s.ID]; ok {
		inst.trafficMu.Lock()
		st.Running = inst.isOperational()
		persistedIn, persistedOut := inst.persistedDirections()
		billingMode := pm.database.currentSystemSettings().TrafficBillingMode
		st.PersistedTraffic = trafficBillableBytes(billingMode, persistedIn, persistedOut)
		st.BytesIn = inst.bytesIn.Load()
		st.BytesOut = inst.bytesOut.Load()
		st.CumulativeBytesIn = inst.cumulativeBytesIn.Load()
		st.CumulativeBytesOut = inst.cumulativeBytesOut.Load()
		st.TrafficUsed = st.PersistedTraffic + trafficBillableBytes(billingMode, st.BytesIn, st.BytesOut)
		st.Requests = inst.reqCount.Load()
		inst.trafficMu.Unlock()
	}
}

// LiveSiteTraffic overlays the authoritative live traffic state (persisted
// baseline plus pending bytes, under each instance's trafficMu) onto the given
// DB sites and returns it as a map keyed by site ID. One pm.mu read lock is
// taken for the whole map, so the view is consistent and there is no N+1 lock
// churn; the lock order is pm.mu -> trafficMu.
func (pm *ProxyManager) LiveSiteTraffic(sites []Site) map[int64]SiteTraffic {
	live := make(map[int64]SiteTraffic, len(sites))
	settings := pm.database.currentSystemSettings()
	billingMode := settings.TrafficBillingMode
	monthlyBySite, err := pm.database.SumTrafficSinceBySite(trafficCycleStart(time.Now(), settings.TrafficResetDay), billingMode)
	if err != nil {
		log.Printf("[traffic] failed to load monthly site totals: %v", err)
		monthlyBySite = map[int64]int64{}
	}
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for _, s := range sites {
		persistedIn, persistedOut := siteTrafficDirections(s)
		st := SiteTraffic{
			ID:               s.ID,
			Name:             s.Name,
			TrafficQuota:     s.TrafficQuota,
			MonthlyTraffic:   monthlyBySite[s.ID],
			PersistedTraffic: trafficBillableBytes(billingMode, persistedIn, persistedOut),
			TrafficUsed:      trafficBillableBytes(billingMode, persistedIn, persistedOut),
		}
		pm.overlaySiteTrafficLocked(s, &st)
		st.MonthlyTraffic += trafficBillableBytes(billingMode, st.BytesIn, st.BytesOut)
		live[s.ID] = st
	}
	return live
}

// TrafficSnapshot builds the authoritative global traffic payload: every DB
// site, overlaid with live per-instance state for running sites. Dashboard,
// traffic overview and SSE events all render this single payload.
func (pm *ProxyManager) TrafficSnapshot() (*TrafficSnapshot, error) {
	sites, err := pm.database.ListSites()
	if err != nil {
		return nil, err
	}
	settings := pm.database.currentSystemSettings()
	billingMode := settings.TrafficBillingMode
	monthlyBySite, err := pm.database.SumTrafficSinceBySite(trafficCycleStart(time.Now(), settings.TrafficResetDay), billingMode)
	if err != nil {
		return nil, err
	}
	var monthlyTraffic int64
	for _, value := range monthlyBySite {
		monthlyTraffic += value
	}
	snap := &TrafficSnapshot{
		TotalSites:      len(sites),
		LiveSites:       make([]SiteTraffic, 0, len(sites)),
		MonthlyTraffic:  monthlyTraffic,
		BillingMode:     trafficBillingModeLabel(billingMode),
		TrafficResetDay: settings.TrafficResetDay,
	}
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for _, inst := range pm.proxies {
		if inst.isOperational() {
			snap.RunningSites++
		}
	}
	for _, s := range sites {
		persistedIn, persistedOut := siteTrafficDirections(s)
		st := SiteTraffic{
			ID:               s.ID,
			Name:             s.Name,
			TrafficQuota:     s.TrafficQuota,
			MonthlyTraffic:   monthlyBySite[s.ID],
			PersistedTraffic: trafficBillableBytes(billingMode, persistedIn, persistedOut),
			TrafficUsed:      trafficBillableBytes(billingMode, persistedIn, persistedOut),
		}
		if s.Enabled {
			snap.OnlineSites++
		}
		pm.overlaySiteTrafficLocked(s, &st)
		st.MonthlyTraffic += trafficBillableBytes(billingMode, st.BytesIn, st.BytesOut)
		snap.TotalTraffic += st.TrafficUsed
		snap.MonthlyTraffic += trafficBillableBytes(billingMode, st.BytesIn, st.BytesOut)
		snap.TotalRequests += st.Requests
		snap.LiveSites = append(snap.LiveSites, st)
	}
	snap.UptimeSeconds = int64(time.Since(startTime).Seconds())
	return snap, nil
}

func (pm *ProxyManager) GetRunningCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	running := 0
	for _, inst := range pm.proxies {
		if inst.isOperational() {
			running++
		}
	}
	return running
}

func (pm *ProxyManager) GetSiteRuntime(id int64) (requests int64, startedAt time.Time, running, portListening bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	inst, ok := pm.proxies[id]
	if !ok {
		return 0, time.Time{}, false, false
	}
	return inst.reqCount.Load(), inst.startedAt, inst.isOperational(), inst.portServing.Load()
}

// GracefulShutdown stops all proxies gracefully
func (pm *ProxyManager) GracefulShutdown(ctx context.Context) {
	pm.lifecycleMu.Lock()
	defer pm.lifecycleMu.Unlock()
	pm.shutdownStarted.Store(true)
	pm.mu.RLock()
	instances := make(map[int64]*ProxyInstance, len(pm.proxies))
	for id, inst := range pm.proxies {
		instances[id] = inst
	}
	pm.mu.RUnlock()

	type shutdownResult struct {
		id   int64
		inst *ProxyInstance
		err  error
	}
	results := make(chan shutdownResult, len(instances))
	for id, inst := range instances {
		log.Printf("[%s] shutting down...", inst.Site.Name)
		go func(id int64, inst *ProxyInstance) {
			// shutdown closes the request gate and every listener/connection before
			// waiting, so launching all instances in parallel stops every ingress
			// promptly instead of spending the shared deadline site by site.
			results <- shutdownResult{id: id, inst: inst, err: inst.shutdown(ctx)}
		}(id, inst)
	}

	// Capture an early best-effort checkpoint after all shutdowns have started.
	// The final pass below always runs, even when one or more drains time out.
	for _, inst := range instances {
		if err := pm.flushProxyTraffic(inst); err != nil {
			log.Printf("[%s] pre-shutdown traffic flush failed: %v", inst.Site.Name, err)
		}
	}

	drainErrors := make(map[int64]error, len(instances))
	for range instances {
		result := <-results
		drainErrors[result.id] = result.err
		if result.err != nil {
			log.Printf("[%s] shutdown drain failed: %v", result.inst.Site.Name, result.err)
		}
	}

	for id, inst := range instances {
		if err := pm.flushProxyTraffic(inst); err != nil {
			log.Printf("[%s] final shutdown traffic flush failed: %v", inst.Site.Name, err)
			continue
		}
		if drainErrors[id] != nil {
			// Keep a timed-out instance addressable: a caller that does not exit the
			// process may retry and persist counters produced by a late request.
			continue
		}
		pm.mu.Lock()
		if pm.proxies[id] == inst {
			delete(pm.proxies, id)
		}
		pm.mu.Unlock()
	}
}
