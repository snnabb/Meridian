package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	progressRequestBodyLimit     = 64 << 10
	progressResponseBodyLimit    = 64 << 10
	progressMaxKeyComponentBytes = 256
	progressDebounceWindow       = time.Second
	progressMaxDispatchDelay     = 5 * time.Second
	progressIdleExpiry           = 5 * time.Minute
	progressCleanupInterval      = time.Minute
	progressMaxSiteKeys          = 1024
	progressMaxGlobalKeys        = 4096
	progressMaxWaitersPerKey     = 16
	progressMaxGlobalWaiters     = 1024
)

var (
	errProgressResponseTooLarge = errors.New("progress upstream response exceeds the coalescing limit")
	errProgressDispatchPanicked = errors.New("progress upstream dispatch panicked")
)

type progressRequestKind uint8

const (
	progressRequestNone progressRequestKind = iota
	progressRequestUpdate
	progressRequestStopped
)

// progressIdentity is deliberately limited to the three protocol identifiers
// needed for ordering. It is never logged or persisted.
type progressIdentity struct {
	SessionID     string
	PlaySessionID string
	ItemID        string
}

// progressInternalKey binds a protocol identity to an in-memory, process-keyed
// credential digest. Responses can therefore never be shared across distinct
// authenticated callers even if they submit the same protocol identifiers.
type progressInternalKey struct {
	Identity   progressIdentity
	Credential [sha256.Size]byte
}

type progressGlobalRuntime struct {
	mu                sync.Mutex
	activeKeys        int
	waiters           int
	maxActiveKeys     int
	maxWaiters        int
	credentialKey     [sha256.Size]byte
	credentialKeyGood bool
}

func newProgressGlobalRuntime(maxActiveKeys, maxWaiters int) *progressGlobalRuntime {
	runtime := &progressGlobalRuntime{maxActiveKeys: maxActiveKeys, maxWaiters: maxWaiters}
	_, runtimeErr := rand.Read(runtime.credentialKey[:])
	runtime.credentialKeyGood = runtimeErr == nil
	return runtime
}

func (r *progressGlobalRuntime) reserveKey() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maxActiveKeys <= 0 || r.activeKeys >= r.maxActiveKeys {
		return false
	}
	r.activeKeys++
	return true
}

func (r *progressGlobalRuntime) releaseKey() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.activeKeys > 0 {
		r.activeKeys--
	}
	r.mu.Unlock()
}

func (r *progressGlobalRuntime) reserveWaiter() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maxWaiters <= 0 || r.waiters >= r.maxWaiters {
		return false
	}
	r.waiters++
	return true
}

func (r *progressGlobalRuntime) releaseWaiter() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.waiters > 0 {
		r.waiters--
	}
	r.mu.Unlock()
}

func progressPathKind(r *http.Request) progressRequestKind {
	if r == nil || r.Method != http.MethodPost || r.URL == nil {
		return progressRequestNone
	}
	switch r.URL.Path {
	case "/Sessions/Playing/Progress", "/emby/Sessions/Playing/Progress":
		return progressRequestUpdate
	case "/Sessions/Playing/Stopped", "/emby/Sessions/Playing/Stopped":
		return progressRequestStopped
	default:
		return progressRequestNone
	}
}

type progressReplayBody struct {
	io.Reader
	closer io.Closer
}

func (b *progressReplayBody) Close() error {
	if b == nil || b.closer == nil {
		return nil
	}
	return b.closer.Close()
}

// readProgressRequestBody consumes no more than 64 KiB. Whenever completeness
// cannot be proven, it restores the consumed prefix in front of the original
// reader so the ordinary proxy path can fail open without changing the body.
func readProgressRequestBody(r *http.Request) ([]byte, bool) {
	if r == nil || r.Body == nil || r.ContentLength > progressRequestBodyLimit {
		return nil, false
	}
	original := r.Body
	limited := &io.LimitedReader{R: original, N: progressRequestBodyLimit}
	payload, err := io.ReadAll(limited)
	complete := err == nil
	if complete {
		switch {
		case r.ContentLength >= 0:
			complete = int64(len(payload)) == r.ContentLength
		case len(payload) == progressRequestBodyLimit:
			// With an unknown length, filling the entire allowance cannot prove EOF
			// without reading a forbidden extra byte. Conservatively fail open.
			complete = false
		}
	}
	if !complete {
		r.Body = &progressReplayBody{
			Reader: io.MultiReader(bytes.NewReader(payload), original),
			closer: original,
		}
		return nil, false
	}
	_ = original.Close()
	r.Body = io.NopCloser(bytes.NewReader(payload))
	return payload, true
}

func parseProgressIdentity(payload []byte) (progressIdentity, bool) {
	var decoded struct {
		SessionID     string `json:"SessionId"`
		PlaySessionID string `json:"PlaySessionId"`
		ItemID        string `json:"ItemId"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &decoded) != nil {
		return progressIdentity{}, false
	}
	identity := progressIdentity{
		SessionID:     decoded.SessionID,
		PlaySessionID: decoded.PlaySessionID,
		ItemID:        decoded.ItemID,
	}
	for _, component := range []string{identity.SessionID, identity.PlaySessionID, identity.ItemID} {
		if component == "" || len(component) > progressMaxKeyComponentBytes {
			return progressIdentity{}, false
		}
	}
	return identity, true
}

var progressCredentialHeaders = []string{
	"Authorization",
	"Cookie",
	"Proxy-Authorization",
	"X-Api-Key",
	"X-Emby-Authorization",
	"X-Emby-Token",
	"X-MediaBrowser-Token",
}

func progressCredentialDigest(runtime *progressGlobalRuntime, r *http.Request) ([sha256.Size]byte, bool) {
	var digest [sha256.Size]byte
	if runtime == nil || r == nil || !runtime.credentialKeyGood {
		return digest, false
	}
	mac := hmac.New(sha256.New, runtime.credentialKey[:])
	for index, name := range progressCredentialHeaders {
		_, _ = mac.Write([]byte{byte(index + 1)})
		for _, value := range r.Header.Values(name) {
			valueDigest := sha256.Sum256([]byte(value))
			_, _ = mac.Write([]byte{1})
			_, _ = mac.Write(valueDigest[:])
		}
		_, _ = mac.Write([]byte{0})
	}
	if r.URL != nil {
		queryDigest := sha256.Sum256([]byte(r.URL.RawQuery))
		_, _ = mac.Write(queryDigest[:])
		if r.URL.User != nil {
			userDigest := sha256.Sum256([]byte(r.URL.User.String()))
			_, _ = mac.Write(userDigest[:])
		}
	}
	if r.TLS != nil {
		for _, certificate := range r.TLS.PeerCertificates {
			certificateDigest := sha256.Sum256(certificate.Raw)
			_, _ = mac.Write(certificateDigest[:])
		}
	}
	copy(digest[:], mac.Sum(nil))
	return digest, true
}

type progressResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

type progressOutcome struct {
	Response progressResponse
	Err      error
}

type progressCaptureWriter struct {
	header        http.Header
	writtenHeader http.Header
	status        int
	body          bytes.Buffer
	overflow      bool
}

func newProgressCaptureWriter() *progressCaptureWriter {
	return &progressCaptureWriter{header: make(http.Header)}
}

func (w *progressCaptureWriter) Header() http.Header {
	return w.header
}

func (w *progressCaptureWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		return
	}
	if w.status != 0 {
		return
	}
	w.status = status
	w.writtenHeader = w.header.Clone()
}

func (w *progressCaptureWriter) Write(payload []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	remaining := progressResponseBodyLimit - w.body.Len()
	if remaining > 0 {
		amount := len(payload)
		if amount > remaining {
			amount = remaining
		}
		_, _ = w.body.Write(payload[:amount])
	}
	if len(payload) > remaining {
		w.overflow = true
	}
	return len(payload), nil
}

func (w *progressCaptureWriter) Flush() {}

func (w *progressCaptureWriter) response() (progressResponse, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.overflow {
		return progressBadGatewayResponse(), errProgressResponseTooLarge
	}
	return progressResponse{
		Status: w.status,
		Header: w.writtenHeader.Clone(),
		Body:   append([]byte(nil), w.body.Bytes()...),
	}, nil
}

func progressBadGatewayResponse() progressResponse {
	return progressResponse{
		Status: http.StatusBadGateway,
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   []byte(`{"error":"upstream unavailable"}`),
	}
}

func progressServiceUnavailableResponse() progressResponse {
	return progressResponse{
		Status: http.StatusServiceUnavailable,
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   []byte(`{"error":"site is stopping"}`),
	}
}

func progressDispatchPanicError(recovered any) error {
	if recoveredErr, ok := recovered.(error); ok && errors.Is(recoveredErr, http.ErrAbortHandler) {
		return http.ErrAbortHandler
	}
	return errProgressDispatchPanicked
}

func writeProgressResponse(w http.ResponseWriter, response progressResponse) {
	for name, values := range response.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	status := response.Status
	if status == 0 {
		status = http.StatusBadGateway
	}
	w.WriteHeader(status)
	if len(response.Body) > 0 {
		_, _ = w.Write(response.Body)
	}
}

type progressDispatchErrorContextKey struct{}

type progressDispatchErrorState struct {
	mu  sync.Mutex
	err error
}

func (s *progressDispatchErrorState) record(err error) {
	if s == nil || err == nil {
		return
	}
	s.mu.Lock()
	s.err = errors.Join(s.err, err)
	s.mu.Unlock()
}

func (s *progressDispatchErrorState) load() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func recordProgressDispatchError(r *http.Request, err error) {
	if r == nil || err == nil {
		return
	}
	if state, ok := r.Context().Value(progressDispatchErrorContextKey{}).(*progressDispatchErrorState); ok {
		state.record(err)
	}
}

type progressBufferedRequest struct {
	request *http.Request
	release func()
}

func newProgressBufferedRequest(runtimeCtx context.Context, r *http.Request, payload []byte) *progressBufferedRequest {
	valueCtx := context.WithoutCancel(r.Context())
	dispatchCtx, dispatchCancel := context.WithCancel(valueCtx)
	stopRuntimeCancel := context.AfterFunc(runtimeCtx, dispatchCancel)
	request := r.Clone(dispatchCtx)
	request.Body = io.NopCloser(bytes.NewReader(payload))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(payload)), nil
	}
	request.ContentLength = int64(len(payload))
	request.TransferEncoding = nil
	request.Trailer = nil
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			stopRuntimeCancel()
			dispatchCancel()
			if request.Body != nil {
				_ = request.Body.Close()
			}
		})
	}
	return &progressBufferedRequest{request: request, release: release}
}

type progressDispatchFunc func(*http.Request) (progressResponse, error)

type progressCoalescerConfig struct {
	debounce         time.Duration
	maxDispatchDelay time.Duration
	idleExpiry       time.Duration
	cleanupInterval  time.Duration
	maxSiteKeys      int
	maxWaitersPerKey int
}

func defaultProgressCoalescerConfig() progressCoalescerConfig {
	return progressCoalescerConfig{
		debounce:         progressDebounceWindow,
		maxDispatchDelay: progressMaxDispatchDelay,
		idleExpiry:       progressIdleExpiry,
		cleanupInterval:  progressCleanupInterval,
		maxSiteKeys:      progressMaxSiteKeys,
		maxWaitersPerKey: progressMaxWaitersPerKey,
	}
}

type progressWaiter struct {
	result chan progressOutcome
	batch  *progressBatch
	entry  *progressEntry
	active bool
}

type progressBatch struct {
	request         *progressBufferedRequest
	waiters         map[*progressWaiter]struct{}
	firstArrival    time.Time
	lastArrival     time.Time
	ready           bool
	timer           *time.Timer
	timerGeneration uint64
}

type progressBarrier struct {
	granted  chan struct{}
	active   bool
	canceled bool
	released bool
}

type progressWork struct {
	batch   *progressBatch
	barrier *progressBarrier
}

type progressEntry struct {
	queue         []*progressWork
	activeBatch   *progressBatch
	activeBarrier *progressBarrier
	waiters       int
	lastActivity  time.Time
}

type progressDrainCycle struct {
	done chan struct{}
	err  error
}

type progressCoalescerState uint8

const (
	progressCoalescerOpen progressCoalescerState = iota
	progressCoalescerQuiescing
	progressCoalescerDraining
	progressCoalescerDrained
	progressCoalescerClosed
)

type progressCoalescer struct {
	mu              sync.Mutex
	global          *progressGlobalRuntime
	config          progressCoalescerConfig
	dispatch        progressDispatchFunc
	entries         map[progressInternalKey]*progressEntry
	state           progressCoalescerState
	drain           *progressDrainCycle
	admissions      int
	ctx             context.Context
	cancel          context.CancelFunc
	maintenanceDone chan struct{}
}

func newProgressCoalescer(global *progressGlobalRuntime, config progressCoalescerConfig, dispatch progressDispatchFunc) *progressCoalescer {
	ctx, cancel := context.WithCancel(context.Background())
	coalescer := &progressCoalescer{
		global:          global,
		config:          config,
		dispatch:        dispatch,
		entries:         make(map[progressInternalKey]*progressEntry),
		ctx:             ctx,
		cancel:          cancel,
		maintenanceDone: make(chan struct{}),
	}
	if config.cleanupInterval <= 0 {
		close(coalescer.maintenanceDone)
	} else {
		go coalescer.runMaintenance()
	}
	return coalescer
}

func (c *progressCoalescer) beginProgressIngress() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != progressCoalescerOpen {
		return false
	}
	c.admissions++
	return true
}

func (c *progressCoalescer) endProgressIngress() {
	c.mu.Lock()
	if c.admissions > 0 {
		c.admissions--
	}
	c.advanceDrainLocked()
	c.mu.Unlock()
}

func (c *progressCoalescer) runMaintenance() {
	defer close(c.maintenanceDone)
	ticker := time.NewTicker(c.config.cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			c.cleanupIdle(now)
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *progressCoalescer) cleanupIdle(now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.config.idleExpiry <= 0 {
		return
	}
	for key, entry := range c.entries {
		if entry.activeBatch != nil || entry.activeBarrier != nil || len(entry.queue) != 0 || entry.waiters != 0 {
			continue
		}
		if now.Sub(entry.lastActivity) < c.config.idleExpiry {
			continue
		}
		delete(c.entries, key)
		c.global.releaseKey()
	}
}

func (c *progressCoalescer) getOrCreateEntryLocked(key progressInternalKey, now time.Time) (*progressEntry, bool) {
	if entry := c.entries[key]; entry != nil {
		return entry, false
	}
	if c.config.maxSiteKeys <= 0 || len(c.entries) >= c.config.maxSiteKeys || !c.global.reserveKey() {
		return nil, false
	}
	entry := &progressEntry{lastActivity: now}
	c.entries[key] = entry
	return entry, true
}

func (c *progressCoalescer) releaseEmptyNewEntryLocked(key progressInternalKey, entry *progressEntry, created bool) {
	if !created || entry == nil || entry.activeBatch != nil || entry.activeBarrier != nil || len(entry.queue) != 0 || entry.waiters != 0 {
		return
	}
	if c.entries[key] == entry {
		delete(c.entries, key)
		c.global.releaseKey()
	}
}

func (c *progressCoalescer) reserveWaiterLocked(entry *progressEntry) bool {
	if entry == nil || c.config.maxWaitersPerKey <= 0 || entry.waiters >= c.config.maxWaitersPerKey || !c.global.reserveWaiter() {
		return false
	}
	entry.waiters++
	return true
}

func (c *progressCoalescer) releaseWaiterLocked(entry *progressEntry) {
	if entry != nil && entry.waiters > 0 {
		entry.waiters--
		c.global.releaseWaiter()
	}
}

func (c *progressCoalescer) scheduleBatchLocked(key progressInternalKey, entry *progressEntry, batch *progressBatch, now time.Time) {
	if batch.ready {
		return
	}
	deadline := now.Add(c.config.debounce)
	maxDeadline := batch.firstArrival.Add(c.config.maxDispatchDelay)
	if deadline.After(maxDeadline) {
		deadline = maxDeadline
	}
	if !deadline.After(now) {
		batch.ready = true
		if batch.timer != nil {
			batch.timer.Stop()
			batch.timer = nil
		}
		return
	}
	if batch.timer != nil {
		batch.timer.Stop()
	}
	batch.timerGeneration++
	generation := batch.timerGeneration
	batch.timer = time.AfterFunc(deadline.Sub(now), func() {
		c.markBatchReady(key, entry, batch, generation)
	})
}

func (c *progressCoalescer) markBatchReady(key progressInternalKey, entry *progressEntry, batch *progressBatch, generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries[key] != entry || batch.timerGeneration != generation || batch.ready || c.state == progressCoalescerClosed {
		return
	}
	batch.ready = true
	batch.timer = nil
	c.advanceEntryLocked(key, entry)
}

func (c *progressCoalescer) forceQueuedBatchesLocked(entry *progressEntry) {
	for _, work := range entry.queue {
		if work.batch == nil {
			continue
		}
		work.batch.ready = true
		work.batch.timerGeneration++
		if work.batch.timer != nil {
			work.batch.timer.Stop()
			work.batch.timer = nil
		}
	}
}

func (c *progressCoalescer) advanceEntryLocked(key progressInternalKey, entry *progressEntry) {
	if entry == nil || entry.activeBatch != nil || entry.activeBarrier != nil || len(entry.queue) == 0 {
		return
	}
	work := entry.queue[0]
	if work.batch != nil && !work.batch.ready {
		return
	}
	entry.queue = entry.queue[1:]
	if work.batch != nil {
		entry.activeBatch = work.batch
		go c.dispatchBatch(key, entry, work.batch)
		return
	}
	entry.activeBarrier = work.barrier
	work.barrier.active = true
	close(work.barrier.granted)
}

func (c *progressCoalescer) dispatchBufferedRequest(buffered *progressBufferedRequest) (response progressResponse, dispatchErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			response = progressBadGatewayResponse()
			dispatchErr = progressDispatchPanicError(recovered)
		}
	}()
	defer func() {
		if buffered != nil && buffered.release != nil {
			buffered.release()
		}
	}()
	if buffered == nil || buffered.request == nil || c.dispatch == nil {
		return progressBadGatewayResponse(), errProgressDispatchPanicked
	}
	return c.dispatch(buffered.request)
}

func (c *progressCoalescer) dispatchBatch(key progressInternalKey, entry *progressEntry, batch *progressBatch) {
	response, dispatchErr := c.dispatchBufferedRequest(batch.request)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries[key] != entry || entry.activeBatch != batch {
		return
	}
	entry.activeBatch = nil
	entry.lastActivity = time.Now()
	if dispatchErr != nil && c.drain != nil && (c.state == progressCoalescerQuiescing || c.state == progressCoalescerDraining) {
		c.drain.err = errors.Join(c.drain.err, dispatchErr)
	}
	outcome := progressOutcome{Response: response, Err: dispatchErr}
	for waiter := range batch.waiters {
		if !waiter.active {
			continue
		}
		waiter.active = false
		c.releaseWaiterLocked(entry)
		waiter.result <- outcome
	}
	if c.state == progressCoalescerDraining {
		c.forceQueuedBatchesLocked(entry)
	}
	c.advanceEntryLocked(key, entry)
	c.completeDrainLocked()
}

func (c *progressCoalescer) enqueueUpdate(key progressInternalKey, request *progressBufferedRequest, now time.Time) (*progressWaiter, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != progressCoalescerOpen && c.state != progressCoalescerQuiescing {
		return nil, false
	}
	entry, created := c.getOrCreateEntryLocked(key, now)
	if entry == nil {
		return nil, false
	}
	if !c.reserveWaiterLocked(entry) {
		c.releaseEmptyNewEntryLocked(key, entry, created)
		return nil, false
	}
	waiter := &progressWaiter{result: make(chan progressOutcome, 1), entry: entry, active: true}
	var batch *progressBatch
	if len(entry.queue) > 0 {
		batch = entry.queue[len(entry.queue)-1].batch
	}
	if batch == nil {
		batch = &progressBatch{
			request:      request,
			waiters:      make(map[*progressWaiter]struct{}),
			firstArrival: now,
			lastArrival:  now,
		}
		entry.queue = append(entry.queue, &progressWork{batch: batch})
	} else {
		batch.request.release()
		batch.request = request
		batch.lastArrival = now
	}
	waiter.batch = batch
	batch.waiters[waiter] = struct{}{}
	entry.lastActivity = now
	c.scheduleBatchLocked(key, entry, batch, now)
	c.advanceEntryLocked(key, entry)
	return waiter, true
}

func (c *progressCoalescer) resolveCanceledWaiter(key progressInternalKey, entry *progressEntry, waiter *progressWaiter) (progressOutcome, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if waiter == nil {
		return progressOutcome{}, false
	}
	if !waiter.active {
		select {
		case outcome := <-waiter.result:
			return outcome, true
		default:
			return progressOutcome{}, false
		}
	}
	if c.entries[key] != entry {
		return progressOutcome{}, false
	}
	waiter.active = false
	delete(waiter.batch.waiters, waiter)
	c.releaseWaiterLocked(entry)
	entry.lastActivity = time.Now()
	return progressOutcome{}, false
}

func (c *progressCoalescer) waitForProgressOutcome(ctx context.Context, key progressInternalKey, waiter *progressWaiter) (progressOutcome, bool) {
	select {
	case outcome := <-waiter.result:
		return outcome, true
	default:
	}
	select {
	case outcome := <-waiter.result:
		return outcome, true
	case <-ctx.Done():
		return c.resolveCanceledWaiter(key, waiter.entry, waiter)
	}
}

func (c *progressCoalescer) enqueueBarrier(key progressInternalKey, now time.Time) (*progressEntry, *progressBarrier, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != progressCoalescerOpen && c.state != progressCoalescerQuiescing {
		return nil, nil, false
	}
	entry, created := c.getOrCreateEntryLocked(key, now)
	if entry == nil {
		return nil, nil, false
	}
	if !c.reserveWaiterLocked(entry) {
		c.releaseEmptyNewEntryLocked(key, entry, created)
		return nil, nil, false
	}
	barrier := &progressBarrier{granted: make(chan struct{})}
	c.forceQueuedBatchesLocked(entry)
	entry.queue = append(entry.queue, &progressWork{barrier: barrier})
	entry.lastActivity = now
	c.advanceEntryLocked(key, entry)
	return entry, barrier, true
}

func (c *progressCoalescer) removeBarrierLocked(entry *progressEntry, barrier *progressBarrier) bool {
	for index, work := range entry.queue {
		if work.barrier != barrier {
			continue
		}
		entry.queue = append(entry.queue[:index], entry.queue[index+1:]...)
		return true
	}
	return false
}

func (c *progressCoalescer) waitForBarrier(ctx context.Context, key progressInternalKey, entry *progressEntry, barrier *progressBarrier) bool {
	select {
	case <-barrier.granted:
		return true
	case <-ctx.Done():
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.entries[key] != entry || barrier.released {
			return false
		}
		if barrier.active {
			return true
		}
		if c.removeBarrierLocked(entry, barrier) {
			barrier.canceled = true
			c.releaseWaiterLocked(entry)
			entry.lastActivity = time.Now()
			c.advanceEntryLocked(key, entry)
			c.completeDrainLocked()
		}
		return false
	}
}

func (c *progressCoalescer) releaseBarrier(key progressInternalKey, entry *progressEntry, barrier *progressBarrier) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries[key] != entry || entry.activeBarrier != barrier || barrier.released {
		return
	}
	barrier.released = true
	barrier.active = false
	entry.activeBarrier = nil
	c.releaseWaiterLocked(entry)
	entry.lastActivity = time.Now()
	if c.state == progressCoalescerDraining {
		c.forceQueuedBatchesLocked(entry)
	}
	c.advanceEntryLocked(key, entry)
	c.completeDrainLocked()
}

func (c *progressCoalescer) serveProgressFallback(w http.ResponseWriter, r *http.Request, ordinary http.Handler) {
	c.mu.Lock()
	failOpen := c.state == progressCoalescerOpen
	c.mu.Unlock()
	if failOpen {
		ordinary.ServeHTTP(w, r)
		return
	}
	writeProgressResponse(w, progressServiceUnavailableResponse())
}

func (c *progressCoalescer) ServeHTTP(w http.ResponseWriter, r *http.Request, ordinary http.Handler) bool {
	if c == nil || ordinary == nil {
		return false
	}
	kind := progressPathKind(r)
	if kind == progressRequestNone {
		return false
	}
	if !c.beginProgressIngress() {
		writeProgressResponse(w, progressServiceUnavailableResponse())
		return true
	}
	admissionActive := true
	releaseAdmission := func() {
		if admissionActive {
			admissionActive = false
			c.endProgressIngress()
		}
	}
	defer releaseAdmission()

	payload, complete := readProgressRequestBody(r)
	if !complete {
		c.serveProgressFallback(w, r, ordinary)
		return true
	}
	identity, valid := parseProgressIdentity(payload)
	if !valid {
		c.serveProgressFallback(w, r, ordinary)
		return true
	}
	credential, valid := progressCredentialDigest(c.global, r)
	if !valid {
		c.serveProgressFallback(w, r, ordinary)
		return true
	}
	key := progressInternalKey{Identity: identity, Credential: credential}
	now := time.Now()

	if kind == progressRequestStopped {
		entry, barrier, accepted := c.enqueueBarrier(key, now)
		if !accepted {
			c.serveProgressFallback(w, r, ordinary)
			return true
		}
		releaseAdmission()
		if !c.waitForBarrier(r.Context(), key, entry, barrier) {
			return true
		}
		defer c.releaseBarrier(key, entry, barrier)
		if r.Context().Err() != nil {
			return true
		}
		ordinary.ServeHTTP(w, r)
		return true
	}

	request := newProgressBufferedRequest(c.ctx, r, payload)
	waiter, accepted := c.enqueueUpdate(key, request, now)
	if !accepted {
		request.release()
		c.serveProgressFallback(w, r, ordinary)
		return true
	}
	releaseAdmission()
	outcome, published := c.waitForProgressOutcome(r.Context(), key, waiter)
	if published {
		writeProgressResponse(w, outcome.Response)
	}
	return true
}

func (c *progressCoalescer) advanceDrainLocked() {
	if c.state != progressCoalescerQuiescing || c.drain == nil || c.admissions != 0 {
		return
	}
	c.state = progressCoalescerDraining
	for key, entry := range c.entries {
		c.forceQueuedBatchesLocked(entry)
		c.advanceEntryLocked(key, entry)
	}
	c.completeDrainLocked()
}

func (c *progressCoalescer) completeDrainLocked() {
	if c.state != progressCoalescerDraining || c.drain == nil || c.admissions != 0 {
		return
	}
	for _, entry := range c.entries {
		if entry.activeBatch != nil || entry.activeBarrier != nil || len(entry.queue) != 0 {
			return
		}
	}
	cycle := c.drain
	c.drain = nil
	if cycle.err == nil {
		c.state = progressCoalescerDrained
	} else {
		c.state = progressCoalescerOpen
	}
	close(cycle.done)
}

func (c *progressCoalescer) Drain(ctx context.Context) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	switch c.state {
	case progressCoalescerClosed, progressCoalescerDrained:
		c.mu.Unlock()
		return nil
	case progressCoalescerQuiescing, progressCoalescerDraining:
		cycle := c.drain
		c.mu.Unlock()
		select {
		case <-cycle.done:
			return cycle.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	cycle := &progressDrainCycle{done: make(chan struct{})}
	c.state = progressCoalescerQuiescing
	c.drain = cycle
	c.advanceDrainLocked()
	c.mu.Unlock()

	select {
	case <-cycle.done:
		return cycle.err
	case <-ctx.Done():
		c.mu.Lock()
		if (c.state == progressCoalescerQuiescing || c.state == progressCoalescerDraining) && c.drain == cycle {
			c.state = progressCoalescerOpen
			c.drain = nil
		}
		c.mu.Unlock()
		return ctx.Err()
	}
}

func (c *progressCoalescer) Close() {
	if c == nil {
		return
	}
	c.cancel()
	c.mu.Lock()
	if c.state == progressCoalescerClosed {
		done := c.maintenanceDone
		c.mu.Unlock()
		<-done
		return
	}
	c.state = progressCoalescerClosed
	for key, entry := range c.entries {
		for _, work := range entry.queue {
			if work.batch != nil {
				work.batch.timerGeneration++
				if work.batch.timer != nil {
					work.batch.timer.Stop()
				}
				work.batch.request.release()
			}
		}
		delete(c.entries, key)
		c.global.releaseKey()
	}
	c.mu.Unlock()
	<-c.maintenanceDone
}

func (c *progressCoalescer) activeCounts() (keys, waiters int) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, entry := range c.entries {
		waiters += entry.waiters
	}
	return len(c.entries), waiters
}
