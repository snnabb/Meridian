package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type progressTestResult struct {
	recorder *httptest.ResponseRecorder
	handled  bool
}

func progressTestConfig() progressCoalescerConfig {
	return progressCoalescerConfig{
		debounce:         40 * time.Millisecond,
		maxDispatchDelay: 120 * time.Millisecond,
		idleExpiry:       time.Minute,
		cleanupInterval:  0,
		maxSiteKeys:      32,
		maxWaitersPerKey: 16,
	}
}

func progressTestPayload(session, playSession, item string, position int) string {
	return fmt.Sprintf(`{"SessionId":%q,"PlaySessionId":%q,"ItemId":%q,"PositionTicks":%d}`, session, playSession, item, position)
}

func progressTestRequest(ctx context.Context, requestPath, session, playSession, item string, position int) *http.Request {
	request := httptest.NewRequest(http.MethodPost, requestPath, strings.NewReader(progressTestPayload(session, playSession, item, position)))
	if ctx != nil {
		request = request.WithContext(ctx)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "MediaBrowser Token=shared-test-token")
	return request
}

func progressTestStart(coalescer *progressCoalescer, request *http.Request, ordinary http.Handler) <-chan progressTestResult {
	result := make(chan progressTestResult, 1)
	go func() {
		recorder := httptest.NewRecorder()
		handled := coalescer.ServeHTTP(recorder, request, ordinary)
		if !handled {
			ordinary.ServeHTTP(recorder, request)
		}
		result <- progressTestResult{recorder: recorder, handled: handled}
	}()
	return result
}

func progressTestAwait(t *testing.T, result <-chan progressTestResult) progressTestResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for progress request")
		return progressTestResult{}
	}
}

func progressTestWaitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for progress runtime state")
		}
		time.Sleep(time.Millisecond)
	}
}

func progressTestPosition(t *testing.T, request *http.Request) int {
	t.Helper()
	payload, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatalf("read dispatched body: %v", err)
	}
	var decoded struct {
		Position int `json:"PositionTicks"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode dispatched body: %v", err)
	}
	return decoded.Position
}

func progressTestOrdinary(status int, body string, calls *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls != nil {
			calls.Add(1)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

type progressTestCloseNotifier struct {
	io.ReadCloser
	once   sync.Once
	closed chan struct{}
}

func (body *progressTestCloseNotifier) Close() error {
	err := body.ReadCloser.Close()
	body.once.Do(func() { close(body.closed) })
	return err
}

func TestProgressCoalescerLatestWriteWinsAndFansOutExactResult(t *testing.T) {
	global := newProgressGlobalRuntime(32, 32)
	var dispatches atomic.Int64
	var capturedPosition atomic.Int64
	var capturedHeader atomic.Value
	coalescer := newProgressCoalescer(global, progressTestConfig(), func(request *http.Request) (progressResponse, error) {
		dispatches.Add(1)
		capturedPosition.Store(int64(progressTestPosition(t, request)))
		capturedHeader.Store(request.Header.Get("X-Progress-Version"))
		return progressResponse{
			Status: http.StatusAlreadyReported,
			Header: http.Header{"Content-Type": []string{"application/json"}, "X-Upstream": []string{"latest"}},
			Body:   []byte(`{"accepted":"latest"}`),
		}, nil
	})
	t.Cleanup(coalescer.Close)
	ordinaryCalls := &atomic.Int64{}
	ordinary := progressTestOrdinary(http.StatusTeapot, "ordinary", ordinaryCalls)

	firstRequest := progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "session", "play", "item", 10)
	firstRequest.Header.Set("X-Progress-Version", "first")
	first := progressTestStart(coalescer, firstRequest, ordinary)
	progressTestWaitFor(t, func() bool {
		_, waiters := coalescer.activeCounts()
		return waiters == 1
	})
	secondRequest := progressTestRequest(context.Background(), "/emby/Sessions/Playing/Progress", "session", "play", "item", 20)
	secondRequest.Header.Set("X-Progress-Version", "latest")
	second := progressTestStart(coalescer, secondRequest, ordinary)

	firstResult := progressTestAwait(t, first)
	secondResult := progressTestAwait(t, second)
	for index, result := range []progressTestResult{firstResult, secondResult} {
		if !result.handled || result.recorder.Code != http.StatusAlreadyReported || result.recorder.Body.String() != `{"accepted":"latest"}` {
			t.Fatalf("result %d handled=%t status=%d body=%q", index, result.handled, result.recorder.Code, result.recorder.Body.String())
		}
		if result.recorder.Header().Get("X-Upstream") != "latest" {
			t.Fatalf("result %d lost exact upstream header", index)
		}
	}
	if dispatches.Load() != 1 || capturedPosition.Load() != 20 || capturedHeader.Load() != "latest" || ordinaryCalls.Load() != 0 {
		t.Fatalf("dispatches=%d position=%d header=%v ordinary=%d", dispatches.Load(), capturedPosition.Load(), capturedHeader.Load(), ordinaryCalls.Load())
	}
}

func TestProgressCoalescerHonorsMaximumDispatchLatency(t *testing.T) {
	config := progressTestConfig()
	config.debounce = 200 * time.Millisecond
	config.maxDispatchDelay = 90 * time.Millisecond
	global := newProgressGlobalRuntime(32, 32)
	dispatched := make(chan struct{}, 1)
	var latest atomic.Int64
	coalescer := newProgressCoalescer(global, config, func(request *http.Request) (progressResponse, error) {
		latest.Store(int64(progressTestPosition(t, request)))
		dispatched <- struct{}{}
		return progressResponse{Status: http.StatusNoContent, Header: make(http.Header)}, nil
	})
	t.Cleanup(coalescer.Close)
	ordinary := progressTestOrdinary(http.StatusTeapot, "ordinary", nil)

	startedAt := time.Now()
	results := make([]<-chan progressTestResult, 0, 5)
	for position := 1; position <= 5; position++ {
		results = append(results, progressTestStart(coalescer, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "latency", "play", "item", position), ordinary))
		progressTestWaitFor(t, func() bool {
			_, waiters := coalescer.activeCounts()
			return waiters >= position
		})
	}
	select {
	case <-dispatched:
		if elapsed := time.Since(startedAt); elapsed > config.maxDispatchDelay+150*time.Millisecond {
			t.Fatalf("dispatch latency %s exceeded bounded allowance", elapsed)
		}
	case <-time.After(config.maxDispatchDelay + 300*time.Millisecond):
		t.Fatal("maximum dispatch latency was not enforced")
	}
	if latest.Load() != 5 {
		t.Fatalf("dispatched position=%d, want latest 5", latest.Load())
	}
	for _, result := range results {
		if got := progressTestAwait(t, result); !got.handled || got.recorder.Code != http.StatusNoContent {
			t.Fatalf("fanout handled=%t status=%d", got.handled, got.recorder.Code)
		}
	}
}

func TestProgressCoalescerSeparatesKeysSitesAndCredentials(t *testing.T) {
	config := progressTestConfig()
	config.debounce = 10 * time.Millisecond
	global := newProgressGlobalRuntime(32, 32)
	var mu sync.Mutex
	dispatched := make([]string, 0, 4)
	makeCoalescer := func(site string) *progressCoalescer {
		return newProgressCoalescer(global, config, func(request *http.Request) (progressResponse, error) {
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			var decoded struct {
				ItemID string `json:"ItemId"`
			}
			if err := json.Unmarshal(payload, &decoded); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			dispatched = append(dispatched, site+":"+decoded.ItemID+":"+request.Header.Get("Authorization"))
			mu.Unlock()
			return progressResponse{Status: http.StatusOK, Header: make(http.Header), Body: []byte(site)}, nil
		})
	}
	firstSite := makeCoalescer("one")
	secondSite := makeCoalescer("two")
	t.Cleanup(firstSite.Close)
	t.Cleanup(secondSite.Close)
	ordinary := progressTestOrdinary(http.StatusTeapot, "ordinary", nil)

	requests := []struct {
		coalescer *progressCoalescer
		request   *http.Request
	}{
		{firstSite, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "s", "p", "item-a", 1)},
		{firstSite, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "s", "p", "item-b", 2)},
		{secondSite, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "s", "p", "item-a", 3)},
		{firstSite, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "s", "p", "item-a", 4)},
	}
	requests[3].request.Header.Set("Authorization", "MediaBrowser Token=other-test-token")
	results := make([]<-chan progressTestResult, 0, len(requests))
	for _, request := range requests {
		results = append(results, progressTestStart(request.coalescer, request.request, ordinary))
	}
	for _, result := range results {
		if got := progressTestAwait(t, result); !got.handled || got.recorder.Code != http.StatusOK {
			t.Fatalf("separated request handled=%t status=%d", got.handled, got.recorder.Code)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dispatched) != 4 {
		t.Fatalf("dispatches=%v, want four separate key/site/credential groups", dispatched)
	}
}

func TestProgressCoalescerFailsOpenUnsafeRequestsAndLimits(t *testing.T) {
	config := progressTestConfig()
	config.debounce = time.Second
	config.maxDispatchDelay = time.Second
	config.maxSiteKeys = 1
	config.maxWaitersPerKey = 1
	global := newProgressGlobalRuntime(1, 1)
	coalescer := newProgressCoalescer(global, config, func(request *http.Request) (progressResponse, error) {
		_ = progressTestPosition(t, request)
		return progressResponse{Status: http.StatusNoContent, Header: make(http.Header)}, nil
	})
	t.Cleanup(coalescer.Close)
	var ordinaryCalls atomic.Int64
	ordinary := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		ordinaryCalls.Add(1)
		payload, _ := io.ReadAll(request.Body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(payload)
	})

	ctx, cancel := context.WithCancel(context.Background())
	first := progressTestStart(coalescer, progressTestRequest(ctx, "/Sessions/Playing/Progress", "s", "p", "one", 1), ordinary)
	progressTestWaitFor(t, func() bool {
		keys, waiters := coalescer.activeCounts()
		return keys == 1 && waiters == 1
	})

	waiterLimit := progressTestAwait(t, progressTestStart(coalescer, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "s", "p", "one", 2), ordinary))
	keyLimit := progressTestAwait(t, progressTestStart(coalescer, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "s", "p", "two", 3), ordinary))
	for name, result := range map[string]progressTestResult{"waiter": waiterLimit, "key": keyLimit} {
		if !result.handled || result.recorder.Code != http.StatusAccepted {
			t.Fatalf("%s limit handled=%t status=%d", name, result.handled, result.recorder.Code)
		}
	}

	invalid := httptest.NewRequest(http.MethodPost, "/Sessions/Playing/Progress", strings.NewReader(`{"SessionId":`))
	invalidResult := progressTestAwait(t, progressTestStart(coalescer, invalid, ordinary))
	if !invalidResult.handled || invalidResult.recorder.Body.String() != `{"SessionId":` {
		t.Fatalf("invalid JSON did not fail open byte-identically: handled=%t body=%q", invalidResult.handled, invalidResult.recorder.Body.String())
	}
	oversizedPayload := bytes.Repeat([]byte("x"), progressRequestBodyLimit+1)
	oversized := httptest.NewRequest(http.MethodPost, "/emby/Sessions/Playing/Progress", bytes.NewReader(oversizedPayload))
	oversizedResult := progressTestAwait(t, progressTestStart(coalescer, oversized, ordinary))
	if !oversizedResult.handled || !bytes.Equal(oversizedResult.recorder.Body.Bytes(), oversizedPayload) {
		t.Fatalf("oversized body was not preserved on fail-open")
	}
	getRequest := httptest.NewRequest(http.MethodGet, "/Sessions/Playing/Progress", nil)
	if got := progressTestAwait(t, progressTestStart(coalescer, getRequest, ordinary)); got.handled {
		t.Fatal("non-POST progress request was intercepted")
	}

	cancel()
	_ = progressTestAwait(t, first)
	if ordinaryCalls.Load() != 5 {
		t.Fatalf("ordinary fail-open calls=%d, want 5", ordinaryCalls.Load())
	}
}

func TestProgressStoppedPathFlushesAndOrdersLaterUpdates(t *testing.T) {
	config := progressTestConfig()
	config.debounce = 30 * time.Millisecond
	config.maxDispatchDelay = 80 * time.Millisecond
	global := newProgressGlobalRuntime(32, 32)
	firstDispatchStarted := make(chan struct{})
	releaseFirstDispatch := make(chan struct{})
	stoppedStarted := make(chan struct{})
	releaseStopped := make(chan struct{})
	var orderMu sync.Mutex
	order := make([]string, 0, 3)
	coalescer := newProgressCoalescer(global, config, func(request *http.Request) (progressResponse, error) {
		position := progressTestPosition(t, request)
		orderMu.Lock()
		order = append(order, fmt.Sprintf("progress-%d", position))
		orderMu.Unlock()
		if position == 1 {
			close(firstDispatchStarted)
			<-releaseFirstDispatch
		}
		return progressResponse{Status: http.StatusOK, Header: make(http.Header), Body: []byte("progress-ok")}, nil
	})
	t.Cleanup(coalescer.Close)
	ordinary := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if progressPathKind(request) != progressRequestStopped {
			t.Fatalf("unexpected ordinary request path %s", request.URL.Path)
		}
		orderMu.Lock()
		order = append(order, "stopped")
		orderMu.Unlock()
		close(stoppedStarted)
		<-releaseStopped
		w.WriteHeader(http.StatusNoContent)
	})

	before := progressTestStart(coalescer, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "s", "p", "i", 1), ordinary)
	progressTestWaitFor(t, func() bool {
		_, waiters := coalescer.activeCounts()
		return waiters == 1
	})
	stopped := progressTestStart(coalescer, progressTestRequest(context.Background(), "/emby/Sessions/Playing/Stopped", "s", "p", "i", 0), ordinary)
	select {
	case <-firstDispatchStarted:
	case <-time.After(time.Second):
		t.Fatal("Stopped did not immediately flush pending progress")
	}
	after := progressTestStart(coalescer, progressTestRequest(context.Background(), "/emby/Sessions/Playing/Progress", "s", "p", "i", 2), ordinary)
	select {
	case <-stoppedStarted:
		t.Fatal("Stopped overtook the pending latest update")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseFirstDispatch)
	select {
	case <-stoppedStarted:
	case <-time.After(time.Second):
		t.Fatal("Stopped was not forwarded after pending progress")
	}
	time.Sleep(40 * time.Millisecond)
	orderMu.Lock()
	if len(order) != 2 {
		orderMu.Unlock()
		t.Fatalf("later progress overtook active Stopped: order=%v", order)
	}
	orderMu.Unlock()
	close(releaseStopped)

	for _, result := range []<-chan progressTestResult{before, stopped, after} {
		_ = progressTestAwait(t, result)
	}
	orderMu.Lock()
	defer orderMu.Unlock()
	want := []string{"progress-1", "stopped", "progress-2"}
	if fmt.Sprint(order) != fmt.Sprint(want) {
		t.Fatalf("upstream order=%v, want %v", order, want)
	}
}

func TestProgressCanceledWaiterDoesNotDropPendingUpdate(t *testing.T) {
	config := progressTestConfig()
	config.debounce = 30 * time.Millisecond
	global := newProgressGlobalRuntime(32, 32)
	dispatched := make(chan int, 1)
	coalescer := newProgressCoalescer(global, config, func(request *http.Request) (progressResponse, error) {
		dispatched <- progressTestPosition(t, request)
		return progressResponse{Status: http.StatusNoContent, Header: make(http.Header)}, nil
	})
	t.Cleanup(coalescer.Close)
	ctx, cancel := context.WithCancel(context.Background())
	result := progressTestStart(coalescer, progressTestRequest(ctx, "/Sessions/Playing/Progress", "cancel", "p", "i", 7), progressTestOrdinary(http.StatusTeapot, "ordinary", nil))
	progressTestWaitFor(t, func() bool {
		_, waiters := coalescer.activeCounts()
		return waiters == 1
	})
	cancel()
	if got := progressTestAwait(t, result); !got.handled {
		t.Fatal("canceled accepted waiter fell through to ordinary proxy")
	}
	progressTestWaitFor(t, func() bool {
		_, waiters := coalescer.activeCounts()
		return waiters == 0
	})
	select {
	case position := <-dispatched:
		if position != 7 {
			t.Fatalf("dispatched canceled waiter position=%d", position)
		}
	case <-time.After(time.Second):
		t.Fatal("pending update was dropped when its waiter canceled")
	}
}

func TestProgressUpstreamErrorResultPropagatesExactly(t *testing.T) {
	config := progressTestConfig()
	config.debounce = 5 * time.Millisecond
	global := newProgressGlobalRuntime(32, 32)
	upstreamErr := errors.New("upstream reset")
	coalescer := newProgressCoalescer(global, config, func(*http.Request) (progressResponse, error) {
		return progressResponse{
			Status: http.StatusBadGateway,
			Header: http.Header{"Content-Type": []string{"application/json"}, "Retry-After": []string{"3"}},
			Body:   []byte(`{"error":"upstream unavailable"}`),
		}, upstreamErr
	})
	t.Cleanup(coalescer.Close)
	result := progressTestAwait(t, progressTestStart(coalescer, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "error", "p", "i", 1), progressTestOrdinary(http.StatusTeapot, "ordinary", nil)))
	if !result.handled || result.recorder.Code != http.StatusBadGateway || result.recorder.Body.String() != `{"error":"upstream unavailable"}` || result.recorder.Header().Get("Retry-After") != "3" {
		t.Fatalf("upstream error result changed: handled=%t status=%d headers=%v body=%q", result.handled, result.recorder.Code, result.recorder.Header(), result.recorder.Body.String())
	}
}

func TestProgressDispatchRecoversPanicsAndReleasesResources(t *testing.T) {
	testCases := []struct {
		name       string
		panicValue any
	}{
		{name: "abort handler", panicValue: http.ErrAbortHandler},
		{name: "arbitrary value", panicValue: []string{"private upstream detail"}},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			global := newProgressGlobalRuntime(32, 32)
			closed := make(chan struct{})
			var dispatches atomic.Int64
			coalescer := newProgressCoalescer(global, progressTestConfig(), func(request *http.Request) (progressResponse, error) {
				if dispatches.Add(1) == 1 {
					request.Body = &progressTestCloseNotifier{ReadCloser: request.Body, closed: closed}
					panic(testCase.panicValue)
				}
				return progressResponse{Status: http.StatusNoContent, Header: make(http.Header)}, nil
			})
			t.Cleanup(coalescer.Close)
			ordinary := progressTestOrdinary(http.StatusTeapot, "ordinary", nil)

			first := progressTestAwait(t, progressTestStart(coalescer, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "panic", "p", "i", 1), ordinary))
			if !first.handled || first.recorder.Code != http.StatusBadGateway || first.recorder.Header().Get("Content-Type") != "application/json" || first.recorder.Body.String() != `{"error":"upstream unavailable"}` {
				t.Fatalf("panic outcome handled=%t status=%d headers=%v body=%q", first.handled, first.recorder.Code, first.recorder.Header(), first.recorder.Body.String())
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("panicking dispatch did not close its detached request body")
			}
			progressTestWaitFor(t, func() bool {
				_, waiters := coalescer.activeCounts()
				return waiters == 0
			})

			second := progressTestAwait(t, progressTestStart(coalescer, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "panic", "p", "i", 2), ordinary))
			if !second.handled || second.recorder.Code != http.StatusNoContent || dispatches.Load() != 2 {
				t.Fatalf("post-panic dispatch handled=%t status=%d dispatches=%d", second.handled, second.recorder.Code, dispatches.Load())
			}
		})
	}
}

func TestProgressCaptureOverflowReturnsCompleteBoundedGatewayError(t *testing.T) {
	capture := newProgressCaptureWriter()
	capture.Header().Set("Content-Type", "application/octet-stream")
	capture.Header().Set("X-Upstream-Detail", "must-not-leak")
	capture.WriteHeader(http.StatusCreated)
	payload := bytes.Repeat([]byte("x"), progressResponseBodyLimit+1)
	if written, err := capture.Write(payload); err != nil || written != len(payload) {
		t.Fatalf("capture write=%d/%d error=%v", written, len(payload), err)
	}
	response, err := capture.response()
	if !errors.Is(err, errProgressResponseTooLarge) {
		t.Fatalf("capture error=%v, want response-too-large", err)
	}
	if response.Status != http.StatusBadGateway || response.Header.Get("Content-Type") != "application/json" || len(response.Header) != 1 || string(response.Body) != `{"error":"upstream unavailable"}` {
		t.Fatalf("overflow response status=%d headers=%v body=%q", response.Status, response.Header, response.Body)
	}
	if len(response.Body) >= progressResponseBodyLimit {
		t.Fatalf("overflow error body=%d bytes, want a bounded replacement", len(response.Body))
	}
	recorder := httptest.NewRecorder()
	writeProgressResponse(recorder, response)
	if recorder.Code != http.StatusBadGateway || recorder.Header().Get("X-Upstream-Detail") != "" || recorder.Body.String() != `{"error":"upstream unavailable"}` {
		t.Fatalf("replayed overflow status=%d headers=%v body=%q", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

func TestProgressPublishedOutcomeWinsReadyCancellation(t *testing.T) {
	coalescer := newProgressCoalescer(newProgressGlobalRuntime(4, 4), progressTestConfig(), func(*http.Request) (progressResponse, error) {
		return progressResponse{}, nil
	})
	t.Cleanup(coalescer.Close)
	outcome := progressOutcome{Response: progressResponse{
		Status: http.StatusAccepted,
		Header: http.Header{"X-Published": []string{"yes"}},
		Body:   []byte("published"),
	}}
	waiter := &progressWaiter{result: make(chan progressOutcome, 1), active: false}
	waiter.result <- outcome
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, published := coalescer.waitForProgressOutcome(ctx, progressInternalKey{}, waiter)
	if !published || got.Response.Status != http.StatusAccepted || got.Response.Header.Get("X-Published") != "yes" || string(got.Response.Body) != "published" {
		t.Fatalf("published=%t outcome=%+v", published, got)
	}
}

func TestProgressDrainAdoptsRacingIngressAndRejectsLateRequests(t *testing.T) {
	config := progressTestConfig()
	config.debounce = time.Hour
	config.maxDispatchDelay = time.Hour
	coalescer := newProgressCoalescer(newProgressGlobalRuntime(32, 32), config, func(request *http.Request) (progressResponse, error) {
		if position := progressTestPosition(t, request); position != 8 {
			t.Fatalf("dispatched position=%d, want admitted position 8", position)
		}
		return progressResponse{Status: http.StatusNoContent, Header: make(http.Header)}, nil
	})
	t.Cleanup(coalescer.Close)
	var ordinaryCalls atomic.Int64
	ordinary := progressTestOrdinary(http.StatusTeapot, "ordinary", &ordinaryCalls)
	payload := progressTestPayload("admitted", "p", "i", 8)
	reader, writer := io.Pipe()
	request := httptest.NewRequest(http.MethodPost, "/Sessions/Playing/Progress", reader)
	request.ContentLength = int64(len(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "MediaBrowser Token=shared-test-token")
	admittedResult := progressTestStart(coalescer, request, ordinary)
	progressTestWaitFor(t, func() bool {
		coalescer.mu.Lock()
		defer coalescer.mu.Unlock()
		return coalescer.admissions == 1
	})

	drainResult := make(chan error, 1)
	go func() { drainResult <- coalescer.Drain(context.Background()) }()
	progressTestWaitFor(t, func() bool {
		coalescer.mu.Lock()
		defer coalescer.mu.Unlock()
		return coalescer.state == progressCoalescerQuiescing
	})
	for _, requestPath := range []string{"/Sessions/Playing/Progress", "/emby/Sessions/Playing/Stopped"} {
		late := progressTestAwait(t, progressTestStart(coalescer, progressTestRequest(context.Background(), requestPath, "late", "p", "i", 9), ordinary))
		if !late.handled || late.recorder.Code != http.StatusServiceUnavailable || late.recorder.Header().Get("Content-Type") != "application/json" || late.recorder.Body.String() != `{"error":"site is stopping"}` {
			t.Fatalf("late %s handled=%t status=%d headers=%v body=%q", requestPath, late.handled, late.recorder.Code, late.recorder.Header(), late.recorder.Body.String())
		}
	}
	select {
	case err := <-drainResult:
		t.Fatalf("drain returned before its admitted parser was adopted: %v", err)
	default:
	}
	if _, err := io.WriteString(writer, payload); err != nil {
		t.Fatalf("release admitted body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close admitted body: %v", err)
	}
	if got := progressTestAwait(t, admittedResult); !got.handled || got.recorder.Code != http.StatusNoContent {
		t.Fatalf("admitted request handled=%t status=%d", got.handled, got.recorder.Code)
	}
	select {
	case err := <-drainResult:
		if err != nil {
			t.Fatalf("drain admitted request: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("drain did not finish after the admitted request was adopted")
	}
	if ordinaryCalls.Load() != 0 {
		t.Fatalf("late progress reached the ordinary proxy %d times", ordinaryCalls.Load())
	}
}

func TestProgressQuiescingLimitFailureCannotFailOpen(t *testing.T) {
	testCases := []struct {
		name        string
		requestPath string
	}{
		{name: "update", requestPath: "/Sessions/Playing/Progress"},
		{name: "stopped", requestPath: "/emby/Sessions/Playing/Stopped"},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			config := progressTestConfig()
			config.debounce = time.Hour
			config.maxDispatchDelay = time.Hour
			config.maxWaitersPerKey = 1
			dispatchStarted := make(chan struct{})
			releaseDispatch := make(chan struct{})
			coalescer := newProgressCoalescer(newProgressGlobalRuntime(32, 1), config, func(request *http.Request) (progressResponse, error) {
				_ = progressTestPosition(t, request)
				close(dispatchStarted)
				<-releaseDispatch
				return progressResponse{Status: http.StatusNoContent, Header: make(http.Header)}, nil
			})
			t.Cleanup(coalescer.Close)
			var ordinaryCalls atomic.Int64
			ordinary := progressTestOrdinary(http.StatusAccepted, "ordinary", &ordinaryCalls)
			first := progressTestStart(coalescer, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "limit-race", "p", "i", 1), ordinary)
			progressTestWaitFor(t, func() bool {
				_, waiters := coalescer.activeCounts()
				return waiters == 1
			})

			payload := progressTestPayload("limit-race", "p", "i", 2)
			reader, writer := io.Pipe()
			racingRequest := httptest.NewRequest(http.MethodPost, testCase.requestPath, reader)
			racingRequest.ContentLength = int64(len(payload))
			racingRequest.Header.Set("Content-Type", "application/json")
			racingRequest.Header.Set("Authorization", "MediaBrowser Token=shared-test-token")
			racingResult := progressTestStart(coalescer, racingRequest, ordinary)
			progressTestWaitFor(t, func() bool {
				coalescer.mu.Lock()
				defer coalescer.mu.Unlock()
				return coalescer.admissions == 1
			})
			drainResult := make(chan error, 1)
			go func() { drainResult <- coalescer.Drain(context.Background()) }()
			progressTestWaitFor(t, func() bool {
				coalescer.mu.Lock()
				defer coalescer.mu.Unlock()
				return coalescer.state == progressCoalescerQuiescing
			})

			if _, err := io.WriteString(writer, payload); err != nil {
				t.Fatalf("release racing body: %v", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("close racing body: %v", err)
			}
			rejected := progressTestAwait(t, racingResult)
			if !rejected.handled || rejected.recorder.Code != http.StatusServiceUnavailable || rejected.recorder.Header().Get("Content-Type") != "application/json" || rejected.recorder.Body.String() != `{"error":"site is stopping"}` {
				t.Fatalf("quiescing %s handled=%t status=%d headers=%v body=%q", testCase.name, rejected.handled, rejected.recorder.Code, rejected.recorder.Header(), rejected.recorder.Body.String())
			}
			if ordinaryCalls.Load() != 0 {
				t.Fatalf("quiescing %s bypassed through %d ordinary dispatches", testCase.name, ordinaryCalls.Load())
			}
			select {
			case <-dispatchStarted:
			case <-time.After(time.Second):
				t.Fatal("drain did not force the older batch after rejecting the racing request")
			}
			close(releaseDispatch)
			if got := progressTestAwait(t, first); !got.handled || got.recorder.Code != http.StatusNoContent {
				t.Fatalf("older batch handled=%t status=%d", got.handled, got.recorder.Code)
			}
			select {
			case err := <-drainResult:
				if err != nil {
					t.Fatalf("drain older batch: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("drain did not finish after the older batch")
			}
		})
	}
}

func TestProgressDrainRejectsLateStoppedWithoutOvertakingForcedUpdate(t *testing.T) {
	config := progressTestConfig()
	config.debounce = time.Hour
	config.maxDispatchDelay = time.Hour
	dispatchStarted := make(chan struct{})
	releaseDispatch := make(chan struct{})
	coalescer := newProgressCoalescer(newProgressGlobalRuntime(32, 32), config, func(request *http.Request) (progressResponse, error) {
		_ = progressTestPosition(t, request)
		close(dispatchStarted)
		<-releaseDispatch
		return progressResponse{Status: http.StatusNoContent, Header: make(http.Header)}, nil
	})
	t.Cleanup(coalescer.Close)
	var ordinaryCalls atomic.Int64
	ordinary := progressTestOrdinary(http.StatusAccepted, "ordinary-stopped", &ordinaryCalls)
	update := progressTestStart(coalescer, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "order", "p", "i", 1), ordinary)
	progressTestWaitFor(t, func() bool {
		_, waiters := coalescer.activeCounts()
		return waiters == 1
	})
	drainResult := make(chan error, 1)
	go func() { drainResult <- coalescer.Drain(context.Background()) }()
	select {
	case <-dispatchStarted:
	case <-time.After(time.Second):
		t.Fatal("drain did not force the queued update")
	}

	stopped := progressTestAwait(t, progressTestStart(coalescer, progressTestRequest(context.Background(), "/emby/Sessions/Playing/Stopped", "order", "p", "i", 0), ordinary))
	if !stopped.handled || stopped.recorder.Code != http.StatusServiceUnavailable || stopped.recorder.Body.String() != `{"error":"site is stopping"}` {
		t.Fatalf("late Stopped handled=%t status=%d body=%q", stopped.handled, stopped.recorder.Code, stopped.recorder.Body.String())
	}
	if ordinaryCalls.Load() != 0 {
		t.Fatalf("late Stopped overtook the forced update through %d ordinary dispatches", ordinaryCalls.Load())
	}
	close(releaseDispatch)
	if got := progressTestAwait(t, update); !got.handled || got.recorder.Code != http.StatusNoContent {
		t.Fatalf("forced update handled=%t status=%d", got.handled, got.recorder.Code)
	}
	select {
	case err := <-drainResult:
		if err != nil {
			t.Fatalf("drain forced update: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("drain did not finish after the forced update")
	}
}

func TestStopSiteFailsBeforeClosingIngressWhenProgressFlushFails(t *testing.T) {
	config := progressTestConfig()
	config.debounce = time.Hour
	config.maxDispatchDelay = time.Hour
	global := newProgressGlobalRuntime(32, 32)
	flushErr := errors.New("forced progress flush failure")
	coalescer := newProgressCoalescer(global, config, func(*http.Request) (progressResponse, error) {
		return progressResponse{Status: http.StatusBadGateway, Header: make(http.Header), Body: []byte("failed")}, flushErr
	})
	t.Cleanup(coalescer.Close)
	instanceCtx, cancelInstance := context.WithCancel(context.Background())
	t.Cleanup(cancelInstance)
	instance := &ProxyInstance{Site: Site{ID: 77}, ctx: instanceCtx, cancel: cancelInstance, progress: coalescer, hijackedConns: make(map[net.Conn]struct{})}
	manager := &ProxyManager{proxies: map[int64]*ProxyInstance{77: instance}}

	requestResult := progressTestStart(coalescer, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "lifecycle", "p", "i", 1), progressTestOrdinary(http.StatusTeapot, "ordinary", nil))
	progressTestWaitFor(t, func() bool {
		_, waiters := coalescer.activeCounts()
		return waiters == 1
	})
	stopErr := manager.StopSite(77)
	if !errors.Is(stopErr, flushErr) {
		t.Fatalf("StopSite error=%v, want progress flush failure", stopErr)
	}
	if instance.closing || !instance.isAccepting() || manager.proxies[77] != instance {
		t.Fatal("failed progress flush crossed the irreversible ingress-close boundary")
	}
	result := progressTestAwait(t, requestResult)
	if result.recorder.Code != http.StatusBadGateway || result.recorder.Body.String() != "failed" {
		t.Fatalf("flush waiter status=%d body=%q", result.recorder.Code, result.recorder.Body.String())
	}
}

func TestProgressIdleCleanupIsRaceSafeAndReleasesLimits(t *testing.T) {
	config := progressTestConfig()
	config.debounce = 5 * time.Millisecond
	config.idleExpiry = 20 * time.Millisecond
	global := newProgressGlobalRuntime(1, 4)
	coalescer := newProgressCoalescer(global, config, func(*http.Request) (progressResponse, error) {
		return progressResponse{Status: http.StatusNoContent, Header: make(http.Header)}, nil
	})
	t.Cleanup(coalescer.Close)
	result := progressTestStart(coalescer, progressTestRequest(context.Background(), "/Sessions/Playing/Progress", "cleanup", "p", "i", 1), progressTestOrdinary(http.StatusTeapot, "ordinary", nil))
	progressTestWaitFor(t, func() bool {
		keys, waiters := coalescer.activeCounts()
		return keys == 1 && waiters == 1
	})
	coalescer.cleanupIdle(time.Now().Add(time.Hour))
	if keys, _ := coalescer.activeCounts(); keys != 1 {
		t.Fatal("cleanup removed an active progress key")
	}
	_ = progressTestAwait(t, result)

	var cleaners sync.WaitGroup
	for range 8 {
		cleaners.Add(1)
		go func() {
			defer cleaners.Done()
			coalescer.cleanupIdle(time.Now().Add(time.Hour))
		}()
	}
	cleaners.Wait()
	if keys, waiters := coalescer.activeCounts(); keys != 0 || waiters != 0 {
		t.Fatalf("post-cleanup keys=%d waiters=%d", keys, waiters)
	}
	global.mu.Lock()
	activeKeys, globalWaiters := global.activeKeys, global.waiters
	global.mu.Unlock()
	if activeKeys != 0 || globalWaiters != 0 {
		t.Fatalf("global limits leaked keys=%d waiters=%d", activeKeys, globalWaiters)
	}
}

func TestProgressToggleOffLeavesOrdinaryProxyBehavior(t *testing.T) {
	app := newTestApp(t)
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		payload, _ := io.ReadAll(request.Body)
		w.Header().Set("X-Upstream", "ordinary")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(payload)
	}))
	defer upstream.Close()

	port := freePort(t)
	site, err := app.db.CreateSiteRecord(Site{
		Name:                      "progress-off",
		ListenPort:                port,
		IngressMode:               ingressModePort,
		TargetURL:                 upstream.URL,
		PlaybackMode:              "direct",
		StreamHosts:               "[]",
		UAMode:                    "infuse",
		ProgressCoalescingEnabled: false,
		Enabled:                   true,
	})
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	releasePort(port)
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("start site: %v", err)
	}
	t.Cleanup(func() { _ = app.pm.StopSite(site.ID) })
	app.pm.mu.RLock()
	instance := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if instance == nil || instance.progress != nil {
		t.Fatal("disabled progress toggle created a coalescing runtime")
	}

	client := &http.Client{Timeout: 2 * time.Second}
	for position := 1; position <= 2; position++ {
		request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/Sessions/Playing/Progress", port), strings.NewReader(progressTestPayload("off", "p", "i", position)))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("ordinary progress request: %v", err)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusAccepted || !bytes.Contains(body, []byte(fmt.Sprintf(`"PositionTicks":%d`, position))) || response.Header.Get("X-Upstream") != "ordinary" {
			t.Fatalf("position %d status=%d body=%q header=%q read=%v", position, response.StatusCode, body, response.Header.Get("X-Upstream"), readErr)
		}
	}
	if upstreamCalls.Load() != 2 {
		t.Fatalf("toggle-off upstream calls=%d, want 2", upstreamCalls.Load())
	}
}
