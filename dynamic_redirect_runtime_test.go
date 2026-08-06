package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type redirectRuntimeCloseSpy struct {
	io.Reader
	closed atomic.Bool
}

func (b *redirectRuntimeCloseSpy) Close() error {
	b.closed.Store(true)
	return nil
}

type redirectRuntimeDialCapture struct {
	request *http.Request
	network string
	address string
	err     error
}

type redirectRuntimeResolveResult struct {
	ips    []net.IP
	reason string
}

type redirectRuntimeSignalWriter struct {
	header  http.Header
	started chan struct{}
	once    sync.Once
	mu      sync.Mutex
	status  int
}

func newRedirectRuntimeSignalWriter() *redirectRuntimeSignalWriter {
	return &redirectRuntimeSignalWriter{
		header:  make(http.Header),
		started: make(chan struct{}),
	}
}

func (w *redirectRuntimeSignalWriter) Header() http.Header {
	return w.header
}

func (w *redirectRuntimeSignalWriter) WriteHeader(status int) {
	w.mu.Lock()
	if w.status == 0 {
		w.status = status
	}
	w.mu.Unlock()
	w.once.Do(func() { close(w.started) })
}

func (w *redirectRuntimeSignalWriter) Write(payload []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return len(payload), nil
}

func redirectRuntimePolicy(profile string, available bool) dynamicRedirectPolicy {
	limits, ok := dynamicLimitsForProfile(profile)
	if !ok {
		panic("unknown test dynamic profile")
	}
	return dynamicRedirectPolicy{
		configured: true,
		available:  available,
		profile:    profile,
		limits:     limits,
		sources:    []string{dynamicDiscoverySourceRedirect},
		domainRules: []DynamicDomainRule{
			{Type: "suffix", Value: "example.com"},
		},
	}
}

func redirectRuntimeEligibleRequest(method, rawURL string) *http.Request {
	req := httptest.NewRequest(method, rawURL, nil)
	ctx := context.WithValue(req.Context(), dynamicRequestEligibleContextKey{}, true)
	return req.WithContext(ctx)
}

func redirectRuntimeResponse(req *http.Request, status int, locations []string, body io.ReadCloser) *http.Response {
	header := make(http.Header)
	for _, location := range locations {
		header.Add("Location", location)
	}
	if body == nil {
		body = http.NoBody
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       body,
		Request:    req,
	}
}

func redirectRuntimePipeDial(captures chan<- redirectRuntimeDialCapture, response func(*http.Request) string) dynamicDialContextFunc {
	return func(_ context.Context, network, address string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			req, err := http.ReadRequest(bufio.NewReader(server))
			captures <- redirectRuntimeDialCapture{
				request: req,
				network: network,
				address: address,
				err:     err,
			}
			if err != nil {
				return
			}
			_, _ = io.WriteString(server, response(req))
		}()
		return client, nil
	}
}

func redirectRuntimeFactory(captures chan<- redirectRuntimeDialCapture, response func(*http.Request) string) dynamicTransportFactory {
	return func(target *url.URL, pinnedIPs []net.IP, selfTargets *dynamicSelfTargetPolicy) (*http.Transport, error) {
		transport, err := newDynamicTransportWithDialer(target, pinnedIPs, redirectRuntimePipeDial(captures, response), selfTargets)
		if err != nil {
			return nil, err
		}
		if target.Scheme == "https" {
			// The pipe represents a connection after a verified TLS handshake. The
			// production factory remains responsible for real TLS verification.
			transport.DialTLSContext = transport.DialContext
		}
		return transport, nil
	}
}

func redirectRuntimeAssertError(t *testing.T, err error, wantReason string) *dynamicProxyError {
	t.Helper()
	var dynamicErr *dynamicProxyError
	if !errors.As(err, &dynamicErr) {
		t.Fatalf("error = %T %v, want *dynamicProxyError", err, err)
	}
	if dynamicErr.reasonCode != wantReason {
		t.Fatalf("dynamic reason = %q, want %q", dynamicErr.reasonCode, wantReason)
	}
	return dynamicErr
}

func redirectRuntimeState(t *testing.T, limits DynamicProfileLimits, resolver dynamicIPResolver) (*dynamicRuntime, *dynamicSiteState) {
	t.Helper()
	runtime := newDynamicRuntime()
	runtime.resolver = resolver
	runtime.selfTargets.Store(newTestDynamicSelfTargetPolicy(t))
	return runtime, newDynamicSiteState(runtime, limits)
}

func TestDynamicRedirectRuntimeEligibilityIsNarrow(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		path      string
		websocket bool
		want      bool
	}{
		{name: "video GET", method: http.MethodGet, path: "/Videos/42/stream.mkv", want: true},
		{name: "audio HEAD", method: http.MethodHead, path: "/emby/Audio/42/file.mp3", want: true},
		{name: "live TV GET", method: http.MethodGet, path: "/LiveTv/LiveStreamFiles/42/stream.ts", want: true},
		{name: "item download", method: http.MethodGet, path: "/Items/42/Download", want: true},
		{name: "exact PlaybackInfo", method: http.MethodGet, path: "/Items/42/PlaybackInfo?UserId=7", want: true},
		{name: "exact emby PlaybackInfo", method: http.MethodHead, path: "/emby/Items/42/PlaybackInfo", want: true},
		{name: "HLS manifest", method: http.MethodGet, path: "/custom/live.m3u8", want: true},
		{name: "DASH manifest", method: http.MethodHead, path: "/custom/manifest.mpd", want: true},
		{name: "ordinary API", method: http.MethodGet, path: "/Users/AuthenticateByName", want: false},
		{name: "POST media", method: http.MethodPost, path: "/Videos/42/stream", want: false},
		{name: "PlaybackInfo POST", method: http.MethodPost, path: "/Items/42/PlaybackInfo", want: false},
		{name: "empty item id", method: http.MethodGet, path: "/Items//PlaybackInfo", want: false},
		{name: "PlaybackInfo trailing slash", method: http.MethodGet, path: "/Items/42/PlaybackInfo/", want: false},
		{name: "PlaybackInfo extra segment", method: http.MethodGet, path: "/emby/Items/42/PlaybackInfo/extra", want: false},
		{name: "media websocket", method: http.MethodGet, path: "/Videos/42/stream", websocket: true, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, "https://origin.example.com"+test.path, nil)
			if test.websocket {
				req.Header.Set("Connection", "keep-alive, Upgrade")
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			}
			if got := isDynamicRedirectEligibleRequest(req); got != test.want {
				t.Fatalf("eligibility for %s %s = %t, want %t", test.method, test.path, got, test.want)
			}
		})
	}
	if isDynamicRedirectEligibleRequest(nil) {
		t.Fatal("nil request was eligible")
	}
}

func TestDynamicRedirectRuntimeExtremeEligibilityIsBroadButReserved(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		path        string
		upgrade     bool
		wantExtreme bool
		wantStrict  bool
	}{
		{name: "ordinary API GET", method: http.MethodGet, path: "/Users/AuthenticateByName", wantExtreme: true},
		{name: "ordinary API POST", method: http.MethodPost, path: "/Sessions/Playing", wantExtreme: true},
		{name: "arbitrary PATCH path", method: http.MethodPatch, path: "/plugins/custom/action", wantExtreme: true},
		{name: "arbitrary PUT path", method: http.MethodPut, path: "/plugins/custom/action", wantExtreme: true},
		{name: "arbitrary DELETE path", method: http.MethodDelete, path: "/plugins/custom/action", wantExtreme: true},
		{name: "CONNECT tunnel", method: http.MethodConnect, path: "/proxy"},
		{name: "existing video GET", method: http.MethodGet, path: "/Videos/42/stream.mkv", wantExtreme: true, wantStrict: true},
		{name: "existing PlaybackInfo HEAD", method: http.MethodHead, path: "/Items/42/PlaybackInfo", wantExtreme: true, wantStrict: true},
		{name: "existing media POST remains strict-ineligible", method: http.MethodPost, path: "/Videos/42/stream", wantExtreme: true},
		{name: "upgrade intent", method: http.MethodGet, path: "/Videos/42/stream", upgrade: true},
		{name: "reserved capability root", method: http.MethodGet, path: strings.TrimSuffix(dynamicRoutePrefix, "/")},
		{name: "reserved capability token", method: http.MethodGet, path: dynamicRoutePrefix + "opaque-token"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, "https://origin.example.com"+test.path, nil)
			if test.upgrade {
				req.Header.Set("Connection", "keep-alive, Upgrade")
				req.Header.Set("Upgrade", "websocket")
			}
			if got := isExtremeDynamicRedirectEligibleRequest(req); got != test.wantExtreme {
				t.Fatalf("Extreme eligibility for %s %s = %t, want %t", test.method, test.path, got, test.wantExtreme)
			}
			if got := isDynamicRedirectEligibleRequest(req); got != test.wantStrict {
				t.Fatalf("strict eligibility for %s %s = %t, want %t", test.method, test.path, got, test.wantStrict)
			}
		})
	}
	if isExtremeDynamicRedirectEligibleRequest(nil) || isDynamicRedirectEligibleRequest(nil) {
		t.Fatal("nil request was eligible")
	}
}

func TestDynamicRedirectRuntimePreservesDisabledAndManualRedirects(t *testing.T) {
	const manualTarget = "https://media.example.com/Videos/42/stream"
	manualURL, err := url.Parse(manualTarget)
	if err != nil {
		t.Fatal(err)
	}
	manualAuthority := redirectHostKey(manualURL)

	t.Run("disabled discovery follows configured manual authority", func(t *testing.T) {
		calls := 0
		factoryCalls := 0
		transport := &redirectFollowTransport{
			base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return redirectRuntimeResponse(req, http.StatusFound, []string{manualTarget}, nil), nil
				}
				if req.URL.String() != manualTarget {
					t.Fatalf("manual target = %q", req.URL.String())
				}
				return redirectRuntimeResponse(req, http.StatusOK, nil, io.NopCloser(strings.NewReader("manual"))), nil
			}),
			playbackHosts: map[string]bool{manualAuthority: true},
			dynamicTransportFactory: func(*url.URL, []net.IP, *dynamicSelfTargetPolicy) (*http.Transport, error) {
				factoryCalls++
				return nil, errors.New("dynamic factory must not run")
			},
		}
		resp, err := transport.RoundTrip(httptest.NewRequest(http.MethodGet, "https://origin.example.com/Videos/42/stream", nil))
		if err != nil {
			t.Fatalf("legacy RoundTrip: %v", err)
		}
		defer resp.Body.Close()
		if calls != 2 || factoryCalls != 0 || resp.StatusCode != http.StatusOK {
			t.Fatalf("calls=%d factory=%d status=%d, want 2/0/200", calls, factoryCalls, resp.StatusCode)
		}
	})

	t.Run("disabled discovery leaves unknown authority untouched", func(t *testing.T) {
		body := &redirectRuntimeCloseSpy{Reader: strings.NewReader("legacy redirect")}
		calls := 0
		transport := &redirectFollowTransport{
			base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return redirectRuntimeResponse(req, http.StatusFound, []string{"https://unknown.example.net/media"}, body), nil
			}),
			playbackHosts: map[string]bool{manualAuthority: true},
		}
		resp, err := transport.RoundTrip(httptest.NewRequest(http.MethodGet, "https://origin.example.com/Videos/42/stream", nil))
		if err != nil {
			t.Fatalf("legacy unknown RoundTrip: %v", err)
		}
		if calls != 1 || resp.StatusCode != http.StatusFound || body.closed.Load() {
			t.Fatalf("calls=%d status=%d closed=%t, want untouched redirect", calls, resp.StatusCode, body.closed.Load())
		}
		_ = resp.Body.Close()
	})

	t.Run("configured manual authority does not require dynamic key or DNS", func(t *testing.T) {
		calls := 0
		factoryCalls := 0
		policy := redirectRuntimePolicy(dynamicProfileCompatible, false)
		transport := &redirectFollowTransport{
			base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return redirectRuntimeResponse(req, http.StatusTemporaryRedirect, []string{manualTarget}, nil), nil
				}
				return redirectRuntimeResponse(req, http.StatusOK, nil, io.NopCloser(strings.NewReader("manual"))), nil
			}),
			playbackHosts:         map[string]bool{manualAuthority: true},
			configuredAuthorities: map[string]bool{manualAuthority: true, "https://origin.example.com": true},
			dynamicPolicy:         policy,
			dynamicTransportFactory: func(*url.URL, []net.IP, *dynamicSelfTargetPolicy) (*http.Transport, error) {
				factoryCalls++
				return nil, errors.New("dynamic factory must not run")
			},
		}
		resp, err := transport.RoundTrip(redirectRuntimeEligibleRequest(http.MethodGet, "https://origin.example.com/Videos/42/stream"))
		if err != nil {
			t.Fatalf("manual RoundTrip with unavailable key: %v", err)
		}
		defer resp.Body.Close()
		if calls != 2 || factoryCalls != 0 || resp.StatusCode != http.StatusOK {
			t.Fatalf("calls=%d factory=%d status=%d, want 2/0/200", calls, factoryCalls, resp.StatusCode)
		}
	})

	t.Run("configured dynamic policy leaves ineligible API redirect untouched", func(t *testing.T) {
		calls := 0
		transport := &redirectFollowTransport{
			base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return redirectRuntimeResponse(req, http.StatusMovedPermanently, []string{manualTarget}, nil), nil
			}),
			playbackHosts: map[string]bool{manualAuthority: true},
			dynamicPolicy: redirectRuntimePolicy(dynamicProfileSafe, true),
		}
		resp, err := transport.RoundTrip(httptest.NewRequest(http.MethodGet, "https://origin.example.com/Users/42", nil))
		if err != nil {
			t.Fatalf("ineligible RoundTrip: %v", err)
		}
		defer resp.Body.Close()
		if calls != 1 || resp.StatusCode != http.StatusMovedPermanently {
			t.Fatalf("calls=%d status=%d, want untouched 1/301", calls, resp.StatusCode)
		}
	})

	t.Run("configured dynamic policy leaves source-disabled redirect untouched", func(t *testing.T) {
		calls := 0
		policy := redirectRuntimePolicy(dynamicProfileSafe, true)
		policy.sources = []string{dynamicDiscoverySourceHLS}
		transport := &redirectFollowTransport{
			base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return redirectRuntimeResponse(req, http.StatusFound, []string{manualTarget}, nil), nil
			}),
			playbackHosts: map[string]bool{manualAuthority: true},
			dynamicPolicy: policy,
		}
		resp, err := transport.RoundTrip(redirectRuntimeEligibleRequest(http.MethodGet, "https://origin.example.com/Videos/42/stream"))
		if err != nil {
			t.Fatalf("source-disabled RoundTrip: %v", err)
		}
		defer resp.Body.Close()
		if calls != 1 || resp.StatusCode != http.StatusFound {
			t.Fatalf("calls=%d status=%d, want untouched 1/302", calls, resp.StatusCode)
		}
	})

	t.Run("direct capability follower rejects source-disabled unknown authority", func(t *testing.T) {
		policy := redirectRuntimePolicy(dynamicProfileSafe, true)
		policy.sources = []string{dynamicDiscoverySourceHLS}
		var resolverCalls atomic.Int32
		_, state := redirectRuntimeState(t, policy.limits, dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
			resolverCalls.Add(1)
			return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
		}))
		body := &redirectRuntimeCloseSpy{Reader: strings.NewReader("redirect")}
		request := redirectRuntimeEligibleRequest(http.MethodGet, "https://origin.example.com/Videos/42/stream")
		response := redirectRuntimeResponse(request, http.StatusFound, []string{"https://unknown.example.net/media"}, body)
		transport := &redirectFollowTransport{
			configuredAuthorities: map[string]bool{"https://origin.example.com": true},
			dynamicPolicy:         policy,
			dynamicState:          state,
		}
		got, err := transport.roundTripDynamic(request, response)
		var denied *dynamicProxyError
		if got != nil || !errors.As(err, &denied) || denied.reasonCode != dynamicObservationReasonUnsupportedStatus || !body.closed.Load() || resolverCalls.Load() != 0 {
			t.Fatalf("source-disabled direct follower response=%#v err=%v bodyClosed=%t resolverCalls=%d", got, err, body.closed.Load(), resolverCalls.Load())
		}
	})
}

func TestDynamicRedirectRuntimeFollowsAllAllowedUnknownStatuses(t *testing.T) {
	for _, status := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			method := http.MethodGet
			if status == http.StatusPermanentRedirect {
				method = http.MethodHead
			}
			policy := redirectRuntimePolicy(dynamicProfileSafe, true)
			var resolverCalls atomic.Int32
			resolver := dynamicIPResolverFunc(func(_ context.Context, host string) ([]net.IPAddr, error) {
				resolverCalls.Add(1)
				if host != "cdn.example.com" {
					return nil, fmt.Errorf("unexpected DNS host %q", host)
				}
				return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
			})
			runtime, state := redirectRuntimeState(t, policy.limits, resolver)
			captures := make(chan redirectRuntimeDialCapture, 1)
			initialBody := &redirectRuntimeCloseSpy{Reader: strings.NewReader("redirect body")}
			transport := &redirectFollowTransport{
				base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					return redirectRuntimeResponse(req, status, []string{"https://cdn.example.com/media/segment"}, initialBody), nil
				}),
				configuredAuthorities: map[string]bool{"https://origin.example.net": true},
				dynamicPolicy:         policy,
				dynamicState:          state,
				dynamicTransportFactory: redirectRuntimeFactory(captures, func(req *http.Request) string {
					if req.Method == http.MethodHead {
						return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"
					}
					return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
				}),
			}
			resp, err := transport.RoundTrip(redirectRuntimeEligibleRequest(method, "https://origin.example.net/Videos/42/stream"))
			if err != nil {
				t.Fatalf("RoundTrip status %d: %v", status, err)
			}
			if !responseIsDynamic(resp) || !initialBody.closed.Load() || resolverCalls.Load() != 1 {
				t.Fatalf("dynamic=%t initialClosed=%t resolverCalls=%d", responseIsDynamic(resp), initialBody.closed.Load(), resolverCalls.Load())
			}
			capture := <-captures
			if capture.err != nil || capture.address != "1.1.1.1:443" || capture.request.Method != method || capture.request.URL.Path != "/media/segment" {
				t.Fatalf("capture=%#v", capture)
			}
			if len(runtime.streams) != 1 || len(state.streams) != 1 {
				t.Fatalf("stream permits global/site=%d/%d, want 1/1", len(runtime.streams), len(state.streams))
			}
			authorityEntry := state.authorities["https://cdn.example.com:443"]
			if authorityEntry == nil || authorityEntry.committed || authorityEntry.inFlight != 1 {
				t.Fatalf("provisional authority before response acceptance = %#v", authorityEntry)
			}
			_ = resp.Body.Close()
			if len(runtime.streams) != 0 || len(state.streams) != 0 {
				t.Fatalf("stream permits after close global/site=%d/%d", len(runtime.streams), len(state.streams))
			}
			if len(state.authorities) != 0 || len(runtime.authorities) != 0 {
				t.Fatalf("unaccepted response retained authorities site=%d global=%d", len(state.authorities), len(runtime.authorities))
			}
		})
	}
}

func TestDynamicRedirectRuntimeAcceptsPercentEncodedSpaces(t *testing.T) {
	policy := redirectRuntimePolicy(dynamicProfileExtreme, true)
	var resolverCalls atomic.Int32
	resolver := dynamicIPResolverFunc(func(_ context.Context, host string) ([]net.IPAddr, error) {
		resolverCalls.Add(1)
		if host != "cdn.example.com" {
			return nil, fmt.Errorf("unexpected DNS host %q", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	})
	_, state := redirectRuntimeState(t, policy.limits, resolver)
	captures := make(chan redirectRuntimeDialCapture, 1)
	initialBody := &redirectRuntimeCloseSpy{Reader: strings.NewReader("redirect body")}
	transport := &redirectFollowTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return redirectRuntimeResponse(req, http.StatusFound, []string{"https://cdn.example.com/media/My%20Movie.mkv?label=Director%20Cut&signature=a+b"}, initialBody), nil
		}),
		configuredAuthorities: map[string]bool{"https://origin.example.net": true},
		dynamicPolicy:         policy,
		dynamicState:          state,
		dynamicTransportFactory: redirectRuntimeFactory(captures, func(*http.Request) string {
			return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
		}),
	}
	resp, err := transport.RoundTrip(redirectRuntimeEligibleRequest(http.MethodGet, "https://origin.example.net/Videos/42/stream"))
	if err != nil {
		t.Fatalf("follow encoded-space redirect: %v", err)
	}
	defer resp.Body.Close()
	capture := <-captures
	if capture.err != nil || capture.address != "1.1.1.1:443" || capture.request.RequestURI != "/media/My%20Movie.mkv?label=Director%20Cut&signature=a+b" {
		t.Fatalf("capture=%#v", capture)
	}
	if !responseIsDynamic(resp) || !initialBody.closed.Load() || resolverCalls.Load() != 1 {
		t.Fatalf("dynamic=%t initialClosed=%t resolverCalls=%d", responseIsDynamic(resp), initialBody.closed.Load(), resolverCalls.Load())
	}
}

func TestDynamicRedirectRuntimeSeeOtherIsExtremeOnly(t *testing.T) {
	for _, test := range []struct {
		profile     string
		wantHandled bool
	}{
		{profile: dynamicProfileSafe},
		{profile: dynamicProfileCompatible},
		{profile: dynamicProfileExtreme, wantHandled: true},
	} {
		t.Run(test.profile, func(t *testing.T) {
			calls := 0
			redirectBody := &redirectRuntimeCloseSpy{Reader: strings.NewReader("redirect")}
			transport := &redirectFollowTransport{
				base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					if calls == 1 {
						return redirectRuntimeResponse(req, http.StatusSeeOther, []string{"/Videos/42/next"}, redirectBody), nil
					}
					return redirectRuntimeResponse(req, http.StatusOK, nil, io.NopCloser(strings.NewReader("ok"))), nil
				}),
				dynamicPolicy: redirectRuntimePolicy(test.profile, true),
			}
			resp, err := transport.RoundTrip(redirectRuntimeEligibleRequest(http.MethodGet, "https://origin.example.com/Videos/42/stream"))
			if test.wantHandled {
				if err != nil {
					t.Fatalf("Extreme 303 RoundTrip: %v", err)
				}
				if resp == nil || resp.StatusCode != http.StatusOK || calls != 2 {
					t.Fatalf("Extreme 303 response=%#v calls=%d, want 200 after two calls", resp, calls)
				}
				_ = resp.Body.Close()
			} else {
				if resp != nil || calls != 1 {
					t.Fatalf("%s 303 response=%#v calls=%d, want rejection after one call", test.profile, resp, calls)
				}
				redirectRuntimeAssertError(t, err, dynamicObservationReasonUnsupportedStatus)
			}
			if !redirectBody.closed.Load() {
				t.Fatal("303 response body was not closed")
			}
		})
	}
}

func TestDynamicRedirectRuntimeExtremeMethodAndBodySemantics(t *testing.T) {
	const payload = `{"operation":"transcode"}`
	tests := []struct {
		name       string
		status     int
		method     string
		wantMethod string
		keepBody   bool
	}{
		{name: "301 GET", status: http.StatusMovedPermanently, method: http.MethodGet, wantMethod: http.MethodGet},
		{name: "301 HEAD", status: http.StatusMovedPermanently, method: http.MethodHead, wantMethod: http.MethodHead},
		{name: "301 POST", status: http.StatusMovedPermanently, method: http.MethodPost, wantMethod: http.MethodGet},
		{name: "301 PATCH", status: http.StatusMovedPermanently, method: http.MethodPatch, wantMethod: http.MethodPatch, keepBody: true},
		{name: "302 GET", status: http.StatusFound, method: http.MethodGet, wantMethod: http.MethodGet},
		{name: "302 HEAD", status: http.StatusFound, method: http.MethodHead, wantMethod: http.MethodHead},
		{name: "302 POST", status: http.StatusFound, method: http.MethodPost, wantMethod: http.MethodGet},
		{name: "302 PATCH", status: http.StatusFound, method: http.MethodPatch, wantMethod: http.MethodPatch, keepBody: true},
		{name: "303 GET", status: http.StatusSeeOther, method: http.MethodGet, wantMethod: http.MethodGet},
		{name: "303 HEAD", status: http.StatusSeeOther, method: http.MethodHead, wantMethod: http.MethodHead},
		{name: "303 POST", status: http.StatusSeeOther, method: http.MethodPost, wantMethod: http.MethodGet},
		{name: "303 PATCH", status: http.StatusSeeOther, method: http.MethodPatch, wantMethod: http.MethodGet},
		{name: "307 GET", status: http.StatusTemporaryRedirect, method: http.MethodGet, wantMethod: http.MethodGet, keepBody: true},
		{name: "307 HEAD", status: http.StatusTemporaryRedirect, method: http.MethodHead, wantMethod: http.MethodHead, keepBody: true},
		{name: "307 POST", status: http.StatusTemporaryRedirect, method: http.MethodPost, wantMethod: http.MethodPost, keepBody: true},
		{name: "307 PATCH", status: http.StatusTemporaryRedirect, method: http.MethodPatch, wantMethod: http.MethodPatch, keepBody: true},
		{name: "308 GET", status: http.StatusPermanentRedirect, method: http.MethodGet, wantMethod: http.MethodGet, keepBody: true},
		{name: "308 HEAD", status: http.StatusPermanentRedirect, method: http.MethodHead, wantMethod: http.MethodHead, keepBody: true},
		{name: "308 POST", status: http.StatusPermanentRedirect, method: http.MethodPost, wantMethod: http.MethodPost, keepBody: true},
		{name: "308 PATCH", status: http.StatusPermanentRedirect, method: http.MethodPatch, wantMethod: http.MethodPatch, keepBody: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			redirectBody := &redirectRuntimeCloseSpy{Reader: strings.NewReader("redirect")}
			var followedMethod, followedBody, replayedBody, followedContentType, followedContentEncoding string
			var followedLength int64
			var followedHadBody, followedHadGetBody bool
			transport := &redirectFollowTransport{
				base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					if calls == 1 {
						return redirectRuntimeResponse(req, test.status, []string{"/redirected"}, redirectBody), nil
					}
					followedMethod = req.Method
					followedLength = req.ContentLength
					followedContentType = req.Header.Get("Content-Type")
					followedContentEncoding = req.Header.Get("Content-Encoding")
					followedHadBody = req.Body != nil && req.Body != http.NoBody
					if followedHadBody {
						body, readErr := io.ReadAll(req.Body)
						if readErr != nil {
							t.Fatalf("read followed body: %v", readErr)
						}
						followedBody = string(body)
					}
					followedHadGetBody = req.GetBody != nil
					if followedHadGetBody {
						replay, replayErr := req.GetBody()
						if replayErr != nil {
							t.Fatalf("GetBody after redirect: %v", replayErr)
						}
						body, readErr := io.ReadAll(replay)
						_ = replay.Close()
						if readErr != nil {
							t.Fatalf("read GetBody after redirect: %v", readErr)
						}
						replayedBody = string(body)
					}
					return redirectRuntimeResponse(req, http.StatusOK, nil, io.NopCloser(strings.NewReader("ok"))), nil
				}),
				dynamicPolicy: redirectRuntimePolicy(dynamicProfileExtreme, true),
			}
			request := redirectRuntimeEligibleRequest(test.method, "https://origin.example.com/original")
			request.Body = io.NopCloser(strings.NewReader(payload))
			request.ContentLength = int64(len(payload))
			if test.keepBody {
				request.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(payload)), nil
				}
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Content-Encoding", "identity")

			resp, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatalf("Extreme redirect: %v", err)
			}
			if resp == nil || resp.StatusCode != http.StatusOK || calls != 2 {
				t.Fatalf("response=%#v calls=%d, want 200 after two calls", resp, calls)
			}
			_ = resp.Body.Close()
			_ = request.Body.Close()
			if !redirectBody.closed.Load() {
				t.Fatal("redirect response body was not closed")
			}
			if followedMethod != test.wantMethod {
				t.Fatalf("followed method=%q, want %q", followedMethod, test.wantMethod)
			}
			if test.keepBody {
				if !followedHadBody || followedBody != payload || !followedHadGetBody || replayedBody != payload {
					t.Fatalf("preserved body present=%t body=%q GetBody=%t replay=%q", followedHadBody, followedBody, followedHadGetBody, replayedBody)
				}
				if followedLength != int64(len(payload)) || followedContentType != "application/json" || followedContentEncoding != "identity" {
					t.Fatalf("preserved body metadata length=%d type=%q encoding=%q", followedLength, followedContentType, followedContentEncoding)
				}
			} else {
				if followedHadBody || followedBody != "" || followedHadGetBody || replayedBody != "" || followedLength != 0 {
					t.Fatalf("dropped body present=%t body=%q GetBody=%t replay=%q length=%d", followedHadBody, followedBody, followedHadGetBody, replayedBody, followedLength)
				}
				if followedContentType != "" || followedContentEncoding != "" {
					t.Fatalf("dropped body leaked metadata type=%q encoding=%q", followedContentType, followedContentEncoding)
				}
			}
		})
	}
}

func TestDynamicRedirectRuntimeExtremeReplayDenials(t *testing.T) {
	policy := redirectRuntimePolicy(dynamicProfileExtreme, true)
	tests := []struct {
		name      string
		configure func(*http.Request, int64)
	}{
		{
			name: "missing GetBody",
			configure: func(req *http.Request, _ int64) {
				req.GetBody = nil
			},
		},
		{
			name: "unknown length",
			configure: func(req *http.Request, _ int64) {
				req.ContentLength = -1
			},
		},
		{
			name: "over profile body limit",
			configure: func(req *http.Request, maxBodyBytes int64) {
				req.ContentLength = maxBodyBytes + 1
			},
		},
		{
			name: "transfer encoding",
			configure: func(req *http.Request, _ int64) {
				req.TransferEncoding = []string{"chunked"}
			},
		},
		{
			name: "trailers",
			configure: func(req *http.Request, _ int64) {
				req.Trailer = http.Header{"X-Body-Digest": []string{"secret"}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const payload = "request-body"
			calls := 0
			redirectBody := &redirectRuntimeCloseSpy{Reader: strings.NewReader("redirect")}
			transport := &redirectFollowTransport{
				base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					if calls == 1 {
						return redirectRuntimeResponse(req, http.StatusTemporaryRedirect, []string{"/redirected"}, redirectBody), nil
					}
					return redirectRuntimeResponse(req, http.StatusOK, nil, io.NopCloser(strings.NewReader("unexpected"))), nil
				}),
				dynamicPolicy: policy,
			}
			request := redirectRuntimeEligibleRequest(http.MethodPatch, "https://origin.example.com/original")
			request.Body = io.NopCloser(strings.NewReader(payload))
			request.ContentLength = int64(len(payload))
			request.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(payload)), nil
			}
			test.configure(request, policy.limits.MaxBodyBytes)

			resp, err := transport.RoundTrip(request)
			if resp != nil {
				_ = resp.Body.Close()
				t.Fatalf("response=%#v, want nil", resp)
			}
			redirectRuntimeAssertError(t, err, dynamicObservationReasonRedirectBodyReplayDenied)
			if calls != 1 {
				t.Fatalf("upstream calls=%d, want one before replay denial", calls)
			}
			if !redirectBody.closed.Load() {
				t.Fatal("denied redirect response body was not closed")
			}
			_ = request.Body.Close()
		})
	}
}

func TestDynamicRedirectRuntimePreparesRepeatableExtremeBody(t *testing.T) {
	const payload = `{"MediaSourceId":"source-1"}`
	limits, ok := dynamicLimitsForProfile(dynamicProfileExtreme)
	if !ok {
		t.Fatal("Extreme profile limits missing")
	}
	_, state := redirectRuntimeState(t, limits, nil)
	t.Cleanup(state.close)
	request := httptest.NewRequest(http.MethodPatch, "https://origin.example.com/original", strings.NewReader(payload))
	request.ContentLength = int64(len(payload))
	request.GetBody = nil
	release, err := prepareExtremeRedirectReplayBody(request, state, int64(len(payload)))
	if err != nil {
		t.Fatalf("prepare bounded replay body: %v", err)
	}
	if release == nil || request.GetBody == nil {
		t.Fatalf("release_non_nil=%t GetBody_non_nil=%t, want both true", release != nil, request.GetBody != nil)
	}
	t.Cleanup(release)

	initialBody, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatalf("read prepared initial body: %v", err)
	}
	_ = request.Body.Close()
	if string(initialBody) != payload {
		t.Fatalf("prepared initial body=%q, want %q", initialBody, payload)
	}

	transport := &redirectFollowTransport{dynamicPolicy: redirectRuntimePolicy(dynamicProfileExtreme, true)}
	current := request
	for index, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		target := redirectRuntimeMustParseURL(t, fmt.Sprintf("https://origin.example.com/hop-%d", index+1))
		next, stripBodyHeaders, reasonCode := transport.newExtremeCompatibleDynamicRedirectRequest(current.Context(), current, status, target)
		if reasonCode != "" || next == nil || stripBodyHeaders {
			t.Fatalf("hop %d request=%#v strip=%t reason=%q", index+1, next, stripBodyHeaders, reasonCode)
		}
		body, readErr := io.ReadAll(next.Body)
		if readErr != nil {
			t.Fatalf("read hop %d body: %v", index+1, readErr)
		}
		_ = next.Body.Close()
		if string(body) != payload || next.Method != http.MethodPatch || next.ContentLength != int64(len(payload)) || next.GetBody == nil {
			t.Fatalf("hop %d method=%q length=%d GetBody=%t body=%q", index+1, next.Method, next.ContentLength, next.GetBody != nil, body)
		}
		extra, replayErr := next.GetBody()
		if replayErr != nil {
			t.Fatalf("hop %d GetBody: %v", index+1, replayErr)
		}
		replayed, readErr := io.ReadAll(extra)
		_ = extra.Close()
		if readErr != nil || string(replayed) != payload {
			t.Fatalf("hop %d repeated body=%q err=%v", index+1, replayed, readErr)
		}
		current = next
	}
	release()
}

func TestDynamicRedirectRuntimeExtremeCrossAuthorityBodyHeaders(t *testing.T) {
	const payload = `{"operation":"probe"}`
	target := redirectRuntimeMustParseURL(t, "https://cdn.example.com/jobs/42")
	targetAuthority := redirectHostKey(target)
	redirectBody := &redirectRuntimeCloseSpy{Reader: strings.NewReader("redirect")}
	var followed *http.Request
	var followedBody string
	calls := 0
	transport := &redirectFollowTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return redirectRuntimeResponse(req, http.StatusTemporaryRedirect, []string{target.String()}, redirectBody), nil
			}
			followed = req
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read cross-authority body: %v", err)
			}
			followedBody = string(body)
			return redirectRuntimeResponse(req, http.StatusOK, nil, io.NopCloser(strings.NewReader("ok"))), nil
		}),
		playbackHosts:         map[string]bool{targetAuthority: true},
		configuredAuthorities: map[string]bool{targetAuthority: true},
		dynamicPolicy:         redirectRuntimePolicy(dynamicProfileExtreme, true),
	}
	request := redirectRuntimeEligibleRequest(http.MethodPatch, "https://origin.example.com/jobs/42")
	request.Body = io.NopCloser(strings.NewReader(payload))
	request.ContentLength = int64(len(payload))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(payload)), nil
	}
	wantHeaders := map[string]string{
		"Accept":           "application/json",
		"Accept-Encoding":  "identity",
		"Range":            "bytes=0-4095",
		"If-Range":         `"safe-etag"`,
		"User-Agent":       "safe-client/1",
		"Content-Type":     "application/json",
		"Content-Encoding": "gzip",
		"Content-Language": "en-US",
		"Content-MD5":      "safe-content-md5",
		"Digest":           "sha-256=safe-digest",
	}
	for name, value := range wantHeaders {
		request.Header.Set(name, value)
	}
	for name, value := range map[string]string{
		"Authorization":        "Bearer origin-secret",
		"Cookie":               "session=origin-secret",
		"Proxy-Authorization":  "Basic proxy-secret",
		"X-Emby-Authorization": `MediaBrowser Client="client", Token="emby-secret"`,
		"X-Emby-Token":         "emby-secret",
		"X-MediaBrowser-Token": "media-secret",
		"Forwarded":            "for=203.0.113.9;proto=https",
		"X-Forwarded-For":      "203.0.113.9",
		"X-Forwarded-Host":     "private.example.net",
		"X-Forwarded-Proto":    "https",
		"X-Real-IP":            "203.0.113.9",
		"Connection":           "keep-alive, X-Hop-Secret",
		"X-Hop-Secret":         "hop-secret",
		"Keep-Alive":           "timeout=5",
		"Proxy-Connection":     "keep-alive",
		"TE":                   "trailers",
		"Trailer":              "X-Trailer-Secret",
		"Transfer-Encoding":    "chunked",
		"Upgrade":              "websocket",
		"Expect":               "100-continue",
		"Content-Length":       "999999",
		"X-Arbitrary-Secret":   "unknown-secret",
	} {
		request.Header.Set(name, value)
	}

	resp, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("cross-authority replay: %v", err)
	}
	if resp == nil || resp.StatusCode != http.StatusOK || calls != 2 || followed == nil {
		t.Fatalf("response=%#v calls=%d followed_non_nil=%t", resp, calls, followed != nil)
	}
	_ = resp.Body.Close()
	_ = request.Body.Close()
	if !redirectBody.closed.Load() {
		t.Fatal("cross-authority redirect body was not closed")
	}
	if followed.Method != http.MethodPatch || followedBody != payload || followed.ContentLength != int64(len(payload)) || followed.GetBody == nil {
		t.Fatalf("followed method=%q body=%q length=%d GetBody=%t", followed.Method, followedBody, followed.ContentLength, followed.GetBody != nil)
	}
	for name, want := range wantHeaders {
		if got := followed.Header.Get(name); got != want {
			t.Errorf("safe replay header %s=%q, want %q", name, got, want)
		}
	}
	for _, name := range []string{
		"Authorization", "Cookie", "Proxy-Authorization", "X-Emby-Authorization", "X-Emby-Token", "X-MediaBrowser-Token",
		"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP",
		"Connection", "X-Hop-Secret", "Keep-Alive", "Proxy-Connection", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Expect",
		"Content-Length", "X-Arbitrary-Secret",
	} {
		if values := followed.Header.Values(name); len(values) != 0 {
			t.Errorf("cross-authority replay leaked %s=%q", name, values)
		}
	}
	if len(followed.Header) != len(wantHeaders) {
		t.Errorf("cross-authority replay headers=%v, want only %v", followed.Header, wantHeaders)
	}
}

func TestDynamicRedirectRuntimeReusesCallerStreamLease(t *testing.T) {
	policy := redirectRuntimePolicy(dynamicProfileSafe, true)
	policy.limits.MaxStreams = 1
	runtime, state := redirectRuntimeState(t, policy.limits, dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	}))
	release, acquired := state.acquireStream()
	if !acquired {
		t.Fatal("acquire caller stream lease")
	}
	captures := make(chan redirectRuntimeDialCapture, 1)
	transport := &redirectFollowTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return redirectRuntimeResponse(req, http.StatusFound, []string{"https://cdn.example.com/media.ts"}, http.NoBody), nil
		}),
		configuredAuthorities:   map[string]bool{"https://origin.example.net": true},
		dynamicPolicy:           policy,
		dynamicState:            state,
		streamLeaseHeld:         true,
		dynamicTransportFactory: redirectRuntimeFactory(captures, func(*http.Request) string { return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" }),
	}
	resp, err := transport.RoundTrip(redirectRuntimeEligibleRequest(http.MethodGet, "https://origin.example.net/Videos/42/stream"))
	if err != nil {
		release()
		t.Fatalf("RoundTrip with caller lease: %v", err)
	}
	if capture := <-captures; capture.err != nil {
		release()
		t.Fatalf("dynamic redirect capture: %#v", capture)
	}
	if len(runtime.streams) != 1 || len(state.streams) != 1 {
		release()
		t.Fatalf("caller lease count global/site=%d/%d", len(runtime.streams), len(state.streams))
	}
	_ = resp.Body.Close()
	if len(runtime.streams) != 1 || len(state.streams) != 1 {
		release()
		t.Fatalf("response close released caller-owned lease global/site=%d/%d", len(runtime.streams), len(state.streams))
	}
	release()
	if len(runtime.streams) != 0 || len(state.streams) != 0 {
		t.Fatalf("caller release left permits global/site=%d/%d", len(runtime.streams), len(state.streams))
	}
}

func TestDynamicRedirectRuntimeRetainsAuthorityThroughStructuredRewrite(t *testing.T) {
	policy := redirectRuntimePolicy(dynamicProfileCompatible, true)
	policy.sources = []string{dynamicDiscoverySourceRedirect, dynamicDiscoverySourceHLS}
	runtime, state := redirectRuntimeState(t, policy.limits, dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	}))
	body := "#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXT-X-ENDLIST\n"
	captures := make(chan redirectRuntimeDialCapture, 1)
	transport := &redirectFollowTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return redirectRuntimeResponse(req, http.StatusFound, []string{"https://cdn.example.com/master.m3u8"}, http.NoBody), nil
		}),
		configuredAuthorities: map[string]bool{"https://origin.example.net": true},
		dynamicPolicy:         policy,
		dynamicState:          state,
		dynamicTransportFactory: redirectRuntimeFactory(captures, func(*http.Request) string {
			return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apple.mpegurl\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		}),
	}
	resp, err := transport.RoundTrip(redirectRuntimeEligibleRequest(http.MethodGet, "https://origin.example.net/Videos/42/stream"))
	if err != nil {
		t.Fatalf("dynamic manifest RoundTrip: %v", err)
	}
	if capture := <-captures; capture.err != nil {
		t.Fatalf("dynamic manifest capture: %#v", capture)
	}
	issuer := &dynamicCapabilityIssuer{key: make([]byte, 32), siteID: 1, policyRevision: 1, policy: policy, state: state}
	if err := rewriteDynamicStructuredResponse(resp, issuer, true); err != nil {
		t.Fatalf("rewrite dynamic manifest: %v", err)
	}
	authority := "https://cdn.example.com:443"
	entry := state.authorities[authority]
	if entry == nil || entry.committed || entry.inFlight != 1 {
		t.Fatalf("authority after body rewrite = %#v", entry)
	}
	commitDynamicResponseAuthorities(resp)
	entry = state.authorities[authority]
	if entry == nil || !entry.committed || entry.inFlight != 0 || runtime.authorities[authority] != 1 {
		t.Fatalf("authority after response acceptance = %#v global=%d", entry, runtime.authorities[authority])
	}
	_ = resp.Body.Close()
}

func TestDynamicRedirectRuntimeCarriesPlaybackInfoSourceAcrossRenamedTarget(t *testing.T) {
	policy := redirectRuntimePolicy(dynamicProfileCompatible, true)
	policy.sources = []string{dynamicDiscoverySourceRedirect, dynamicDiscoverySourcePlaybackInfo, dynamicDiscoverySourceHLS}
	_, state := redirectRuntimeState(t, policy.limits, dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	}))
	body := `{"MediaSources":[{"TranscodingUrl":"/Videos/1/master.m3u8?api_key=relative-secret"}]}`
	captures := make(chan redirectRuntimeDialCapture, 1)
	transport := &redirectFollowTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return redirectRuntimeResponse(req, http.StatusFound, []string{"https://cdn.example.com/renamed-response"}, http.NoBody), nil
		}),
		configuredAuthorities: map[string]bool{"https://origin.example.net": true},
		dynamicPolicy:         policy,
		dynamicState:          state,
		dynamicTransportFactory: redirectRuntimeFactory(captures, func(*http.Request) string {
			return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		}),
	}
	request := redirectRuntimeEligibleRequest(http.MethodGet, "https://origin.example.net/Items/1/PlaybackInfo")
	request = request.WithContext(context.WithValue(request.Context(), dynamicExpectedStructuredSourceContextKey{}, dynamicDiscoverySourcePlaybackInfo))
	resp, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("redirected PlaybackInfo RoundTrip: %v", err)
	}
	if capture := <-captures; capture.err != nil {
		t.Fatalf("redirected PlaybackInfo capture: %#v", capture)
	}
	if got := dynamicResponseExpectedStructuredSource(resp); got != dynamicDiscoverySourcePlaybackInfo {
		t.Fatalf("carried structured source = %q", got)
	}
	issuer := &dynamicCapabilityIssuer{key: make([]byte, 32), siteID: 1, policyRevision: 1, policy: policy, state: state}
	if err := rewriteDynamicStructuredResponseExpected(resp, issuer, true, dynamicResponseExpectedStructuredSource(resp), 0, false); err != nil {
		t.Fatalf("rewrite redirected PlaybackInfo: %v", err)
	}
	rewritten, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read redirected PlaybackInfo: %v", err)
	}
	text := string(rewritten)
	if strings.Contains(text, "relative-secret") {
		t.Fatalf("redirected PlaybackInfo leaked relative target: %s", text)
	}
	start := strings.Index(text, dynamicRoutePrefix)
	if start < 0 {
		t.Fatalf("redirected PlaybackInfo has no capability: %s", text)
	}
	end := strings.IndexByte(text[start:], '"')
	if end < 0 {
		t.Fatalf("redirected PlaybackInfo capability is unterminated: %s", text)
	}
	claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, text[start:start+end]))
	if err != nil {
		t.Fatalf("open redirected PlaybackInfo capability: %v", err)
	}
	if claims.Source != dynamicDiscoverySourceHLS || claims.Kind != dynamicCapabilityKindManifest || claims.Target != "https://cdn.example.com:443/Videos/1/master.m3u8?api_key=relative-secret" {
		t.Fatalf("redirected relative claims = %#v", claims)
	}
	commitDynamicResponseAuthorities(resp)
	_ = resp.Body.Close()

	requiredBody := `{"MediaSources":[{"TranscodingUrl":"/Videos/1/master.m3u8","RequiredHttpHeaders":{"X-Required":"secret"}}]}`
	requiredRequest := httptest.NewRequest(http.MethodGet, "https://cdn.example.com/renamed-response", nil)
	requiredHeader := make(http.Header)
	requiredHeader.Set("Content-Type", "application/json")
	requiredResponse := &http.Response{StatusCode: http.StatusOK, Header: requiredHeader, Body: io.NopCloser(strings.NewReader(requiredBody)), ContentLength: int64(len(requiredBody)), Request: requiredRequest}
	if err := rewriteDynamicStructuredResponseExpected(requiredResponse, issuer, true, dynamicDiscoverySourcePlaybackInfo, 0, false); err == nil {
		t.Fatal("redirected relative URL with required headers was accepted")
	}
}

func TestDynamicRedirectRuntimePassesDisabledPlaybackInfoThrough(t *testing.T) {
	policy := redirectRuntimePolicy(dynamicProfileSafe, true)
	policy.sources = []string{dynamicDiscoverySourceRedirect}
	_, state := redirectRuntimeState(t, policy.limits, dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	}))
	body := `{"MediaSources":[{"DirectStreamUrl":"https://media.example.com/video.mp4?token=secret"}]}`
	captures := make(chan redirectRuntimeDialCapture, 1)
	transport := &redirectFollowTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return redirectRuntimeResponse(req, http.StatusFound, []string{"https://cdn.example.com/session/renamed"}, http.NoBody), nil
		}),
		configuredAuthorities: map[string]bool{"https://origin.example.net": true},
		dynamicPolicy:         policy,
		dynamicState:          state,
		dynamicTransportFactory: redirectRuntimeFactory(captures, func(*http.Request) string {
			return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nETag: upstream-validator\r\n\r\n%s", len(body), body)
		}),
	}
	request := redirectRuntimeEligibleRequest(http.MethodGet, "https://origin.example.net/Items/1/PlaybackInfo")
	source := dynamicStructuredRequestIdentity(request)
	if source != dynamicDiscoverySourcePlaybackInfo || policy.sourceEnabled(source) || !policy.sourceEnabled(dynamicDiscoverySourceRedirect) {
		t.Fatalf("PlaybackInfo-off request identity = %q playback_enabled=%t redirect_enabled=%t", source, policy.sourceEnabled(source), policy.sourceEnabled(dynamicDiscoverySourceRedirect))
	}
	request = request.WithContext(context.WithValue(request.Context(), dynamicExpectedStructuredSourceContextKey{}, source))
	resp, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("PlaybackInfo-off redirect RoundTrip: %v", err)
	}
	if capture := <-captures; capture.err != nil {
		t.Fatalf("PlaybackInfo-off redirect capture: %#v", capture)
	}
	if !responseIsDynamic(resp) || dynamicResponseExpectedStructuredSource(resp) != dynamicDiscoverySourcePlaybackInfo {
		t.Fatalf("redirected response identity: dynamic=%t source=%q", responseIsDynamic(resp), dynamicResponseExpectedStructuredSource(resp))
	}
	issuer := &dynamicCapabilityIssuer{key: make([]byte, 32), siteID: 1, policyRevision: 1, policy: policy, state: state}
	if err := rewriteDynamicStructuredResponseExpected(resp, issuer, true, dynamicResponseExpectedStructuredSource(resp), 0, false); err != nil {
		t.Fatalf("PlaybackInfo-off redirected response was rejected: %v", err)
	}
	unchanged, err := io.ReadAll(resp.Body)
	if err != nil || string(unchanged) != body {
		t.Fatalf("PlaybackInfo-off redirected body=%q err=%v, want unchanged", unchanged, err)
	}
	if resp.Header.Get("ETag") != "upstream-validator" || len(issuer.state.capabilities) != 0 {
		t.Fatalf("PlaybackInfo-off redirected response changed: headers=%#v capabilities=%d", resp.Header, len(issuer.state.capabilities))
	}
	commitDynamicResponseAuthorities(resp)
	_ = resp.Body.Close()

	configuredRequest := httptest.NewRequest(http.MethodGet, "https://origin.example.net/session/renamed", nil)
	configuredRequest = configuredRequest.WithContext(context.WithValue(configuredRequest.Context(), dynamicExpectedStructuredSourceContextKey{}, source))
	configuredHeader := make(http.Header)
	configuredHeader.Set("Content-Type", "application/json")
	configuredResponse := &http.Response{StatusCode: http.StatusOK, Header: configuredHeader, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: configuredRequest}
	if err := rewriteDynamicStructuredResponseExpected(configuredResponse, issuer, false, source, 0, false); err != nil {
		t.Fatalf("configured response with PlaybackInfo off did not pass through: %v", err)
	}
	unchanged, err = io.ReadAll(configuredResponse.Body)
	if err != nil || string(unchanged) != body {
		t.Fatalf("configured PlaybackInfo-off body=%q err=%v, want unchanged", unchanged, err)
	}

	opaqueBody := `<html><body>opaque upstream response</body></html>`
	opaqueHeader := make(http.Header)
	opaqueHeader.Set("Content-Type", "text/html")
	opaqueResponse := &http.Response{StatusCode: http.StatusOK, Header: opaqueHeader, Body: io.NopCloser(strings.NewReader(opaqueBody)), ContentLength: int64(len(opaqueBody)), Request: configuredRequest}
	if err := rewriteDynamicStructuredResponseExpected(opaqueResponse, issuer, true, source, 0, false); err != nil {
		t.Fatalf("PlaybackInfo-off opaque redirected response was rejected: %v", err)
	}
	unchanged, err = io.ReadAll(opaqueResponse.Body)
	if err != nil || string(unchanged) != opaqueBody || len(issuer.state.capabilities) != 0 {
		t.Fatalf("PlaybackInfo-off opaque body=%q err=%v capabilities=%d", unchanged, err, len(issuer.state.capabilities))
	}
}

func TestDynamicRedirectRuntimeRebuildsHeadersAndCleansResponse(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:65535")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:65535")
	t.Setenv("ALL_PROXY", "http://proxy.invalid:65535")
	t.Setenv("NO_PROXY", "")

	policy := redirectRuntimePolicy(dynamicProfileSafe, true)
	var resolverHost string
	resolver := dynamicIPResolverFunc(func(_ context.Context, host string) ([]net.IPAddr, error) {
		resolverHost = host
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	})
	runtime, state := redirectRuntimeState(t, policy.limits, resolver)
	captures := make(chan redirectRuntimeDialCapture, 1)
	var createdTransport *http.Transport
	var factoryTarget string
	var factoryPins []string
	factory := func(target *url.URL, pinnedIPs []net.IP, selfTargets *dynamicSelfTargetPolicy) (*http.Transport, error) {
		factoryTarget = target.String()
		for _, pin := range pinnedIPs {
			factoryPins = append(factoryPins, pin.String())
		}
		transport, err := newDynamicTransportWithDialer(target, pinnedIPs, redirectRuntimePipeDial(captures, func(*http.Request) string {
			return "HTTP/1.1 206 Partial Content\r\n" +
				"Accept-Ranges: bytes\r\n" +
				"Content-Disposition: inline\r\n" +
				"Content-Length: 7\r\n" +
				"Content-Range: bytes 100-106/1000\r\n" +
				"Content-Type: video/mp4\r\n" +
				"ETag: strong-etag\r\n" +
				"Location: https://leak.example.net/private?token=secret\r\n" +
				"Set-Cookie: upstream_secret=yes\r\n" +
				"Server: secret-origin\r\n" +
				"X-Upstream-Secret: hidden\r\n" +
				"Cache-Control: public, max-age=3600\r\n" +
				"Referrer-Policy: unsafe-url\r\n" +
				"X-Content-Type-Options: none\r\n" +
				"Connection: keep-alive\r\n\r\n" +
				"payload"
		}), selfTargets)
		if err != nil {
			return nil, err
		}
		transport.DialTLSContext = transport.DialContext
		createdTransport = transport
		return transport, nil
	}
	initialBody := &redirectRuntimeCloseSpy{Reader: strings.NewReader("must be discarded")}
	transport := &redirectFollowTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return redirectRuntimeResponse(req, http.StatusFound, []string{"https://cdn.example.com/media/file.mp4?opaque=1"}, initialBody), nil
		}),
		configuredAuthorities:   map[string]bool{"https://origin.example.net": true},
		dynamicPolicy:           policy,
		dynamicState:            state,
		dynamicTransportFactory: factory,
	}
	req := redirectRuntimeEligibleRequest(http.MethodGet, "https://origin.example.net/Videos/42/stream")
	req.Header.Add("Accept", "video/mp4")
	req.Header.Add("Accept", "application/octet-stream")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Range", "bytes=100-199")
	req.Header.Set("If-Range", "strong-etag")
	req.Header.Set("User-Agent", "untrusted-client/9")
	req.Header.Set("Authorization", "Bearer origin-secret")
	req.Header.Set("Cookie", "session=origin-secret")
	req.Header.Set("X-Emby-Token", "emby-secret")
	req.Header.Set("X-Emby-Authorization", `MediaBrowser Token="embedded-secret"`)
	req.Header.Set("X-MediaBrowser-Token", "media-secret")
	req.Header.Set("Proxy-Authorization", "Basic secret")
	req.Header.Set("Forwarded", "for=203.0.113.1")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("If-None-Match", "origin-etag")
	req.Header.Set("Origin", "https://origin.example.net")
	req.Header.Set("Referer", "https://origin.example.net/private")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("X-Arbitrary-Secret", "secret")
	req.Header.Set("Connection", "keep-alive, X-Arbitrary-Secret")

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("dynamic RoundTrip: %v", err)
	}
	if !initialBody.closed.Load() {
		t.Fatal("initial redirect body was not closed")
	}
	if resolverHost != "cdn.example.com" || factoryTarget != "https://cdn.example.com:443/media/file.mp4?opaque=1" {
		t.Fatalf("resolver=%q target=%q", resolverHost, factoryTarget)
	}
	if len(factoryPins) != 1 || factoryPins[0] != "1.1.1.1" {
		t.Fatalf("factory pins=%v, want [1.1.1.1]", factoryPins)
	}
	if createdTransport == nil || createdTransport.Proxy != nil || !createdTransport.DisableKeepAlives || !createdTransport.DisableCompression || createdTransport.ForceAttemptHTTP2 || createdTransport.MaxConnsPerHost != 1 {
		t.Fatalf("unsafe dynamic transport settings: %#v", createdTransport)
	}
	if createdTransport.TLSClientConfig == nil || createdTransport.TLSClientConfig.InsecureSkipVerify || createdTransport.TLSClientConfig.ServerName != "cdn.example.com" {
		t.Fatalf("dynamic TLS config=%#v", createdTransport.TLSClientConfig)
	}

	capture := <-captures
	if capture.err != nil {
		t.Fatalf("read pinned request: %v", capture.err)
	}
	if capture.network != "tcp" || capture.address != "1.1.1.1:443" {
		t.Fatalf("dial network/address=%q/%q, want tcp/1.1.1.1:443", capture.network, capture.address)
	}
	if capture.request.Host != "cdn.example.com:443" || capture.request.URL.RequestURI() != "/media/file.mp4?opaque=1" {
		t.Fatalf("pinned request host/URI=%q/%q", capture.request.Host, capture.request.URL.RequestURI())
	}
	if !capture.request.Close || strings.Contains(strings.ToLower(capture.request.Header.Get("Connection")), "keep-alive") {
		t.Fatalf("pinned request allowed connection reuse: close=%t Connection=%q", capture.request.Close, capture.request.Header.Get("Connection"))
	}
	for name, want := range map[string][]string{
		"Accept":          {"video/mp4", "application/octet-stream"},
		"Accept-Encoding": {"identity"},
		"Range":           {"bytes=100-199"},
		"If-Range":        {"strong-etag"},
		"User-Agent":      {dynamicRedirectUserAgent},
	} {
		got := capture.request.Header.Values(name)
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("dynamic request %s=%q, want %q", name, got, want)
		}
	}
	for _, name := range []string{
		"Authorization", "Cache-Control", "Cookie", "Forwarded", "If-None-Match", "Origin", "Referer",
		"Proxy-Authorization", "X-Arbitrary-Secret", "X-Emby-Authorization", "X-Emby-Token",
		"X-Forwarded-For", "X-MediaBrowser-Token",
	} {
		if got := capture.request.Header.Values(name); len(got) != 0 {
			t.Errorf("dynamic request leaked %s=%q", name, got)
		}
	}
	if req.Header.Get("Authorization") != "Bearer origin-secret" || req.Header.Get("X-Arbitrary-Secret") != "secret" {
		t.Fatal("dynamic header rebuilding mutated the original request")
	}

	if !responseIsDynamic(resp) {
		t.Fatal("followed response was not marked dynamic")
	}
	resp.Trailer = http.Header{"X-Upstream-Trailer": []string{"secret"}}
	rebuildDynamicResponseHeaders(resp)
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("dynamic response status=%d, want 206", resp.StatusCode)
	}
	for name, want := range map[string]string{
		"Accept-Ranges":          "bytes",
		"Content-Disposition":    "inline",
		"Content-Length":         "7",
		"Content-Range":          "bytes 100-106/1000",
		"Content-Type":           "video/mp4",
		"ETag":                   "strong-etag",
		"Cache-Control":          "private, no-store",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := resp.Header.Get(name); got != want {
			t.Errorf("clean response %s=%q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"Location", "Set-Cookie", "Server", "X-Upstream-Secret", "Connection"} {
		if got := resp.Header.Values(name); len(got) != 0 {
			t.Errorf("clean response leaked %s=%q", name, got)
		}
	}
	if resp.Trailer != nil {
		t.Fatalf("dynamic response trailers=%v, want nil", resp.Trailer)
	}
	payload, err := io.ReadAll(resp.Body)
	if err != nil || string(payload) != "payload" {
		t.Fatalf("dynamic body=%q err=%v", payload, err)
	}
	if len(runtime.streams) != 1 || len(state.streams) != 1 {
		t.Fatalf("stream permits before close global/site=%d/%d", len(runtime.streams), len(state.streams))
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close dynamic response: %v", err)
	}
	if len(runtime.streams) != 0 || len(state.streams) != 0 {
		t.Fatalf("stream permits after close global/site=%d/%d", len(runtime.streams), len(state.streams))
	}
}

func TestDynamicRedirectRuntimeBlocksInformationalAndTrailerHeaders(t *testing.T) {
	policy := redirectRuntimePolicy(dynamicProfileCompatible, true)
	resolver := dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	})
	_, state := redirectRuntimeState(t, policy.limits, resolver)
	captures := make(chan redirectRuntimeDialCapture, 1)
	follow := &redirectFollowTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return redirectRuntimeResponse(req, http.StatusFound, []string{"http://cdn.example.com/media"}, http.NoBody), nil
		}),
		dynamicPolicy: policy,
		dynamicState:  state,
		dynamicTransportFactory: redirectRuntimeFactory(captures, func(*http.Request) string {
			return "HTTP/1.1 103 Early Hints\r\n" +
				"Link: </private?token=early-secret>; rel=preload\r\n" +
				"X-Early-Secret: early-secret\r\n\r\n" +
				"HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/octet-stream\r\n" +
				"X-Upstream-Secret: response-secret\r\n" +
				"Transfer-Encoding: chunked\r\n" +
				"Trailer: X-Upstream-Trailer\r\n\r\n" +
				"7\r\npayload\r\n" +
				"0\r\nX-Upstream-Trailer: trailer-secret\r\n\r\n"
		}),
	}
	proxy := &httputil.ReverseProxy{
		Transport: follow,
		Rewrite: func(proxyReq *httputil.ProxyRequest) {
			ctx := context.WithValue(proxyReq.Out.Context(), dynamicRequestEligibleContextKey{}, true)
			proxyReq.Out = proxyReq.Out.WithContext(ctx)
		},
		ModifyResponse: func(resp *http.Response) error {
			if responseIsDynamic(resp) {
				rebuildDynamicResponseHeaders(resp)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadGateway)
		},
	}
	server := httptest.NewServer(proxy)
	defer server.Close()

	var informationalResponses atomic.Int32
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(_ int, _ textproto.MIMEHeader) error {
			informationalResponses.Add(1)
			return nil
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, server.URL+"/Videos/42/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("proxy dynamic response: %v", err)
	}
	payload, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil || string(payload) != "payload" || resp.StatusCode != http.StatusOK {
		t.Fatalf("dynamic response status=%d body=%q read=%v close=%v", resp.StatusCode, payload, readErr, closeErr)
	}
	if informationalResponses.Load() != 0 {
		t.Fatalf("forwarded %d informational responses from unknown authority", informationalResponses.Load())
	}
	for _, name := range []string{"Link", "X-Early-Secret", "X-Upstream-Secret", "X-Upstream-Trailer"} {
		if headerValues, trailerValues := resp.Header.Values(name), resp.Trailer.Values(name); len(headerValues) != 0 || len(trailerValues) != 0 {
			t.Errorf("dynamic response leaked %s header=%q trailer=%q", name, headerValues, trailerValues)
		}
	}
	capture := <-captures
	if capture.err != nil || capture.address != "1.1.1.1:80" {
		t.Fatalf("dynamic capture=%#v", capture)
	}
}

func TestDynamicRedirectRuntimePreservesNotModified(t *testing.T) {
	policy := redirectRuntimePolicy(dynamicProfileCompatible, true)
	body := &redirectRuntimeCloseSpy{Reader: strings.NewReader("unexpected")}
	calls := 0
	transport := &redirectFollowTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			response := redirectRuntimeResponse(req, http.StatusNotModified, nil, body)
			response.Header.Set("ETag", `"current"`)
			return response, nil
		}),
		dynamicPolicy: policy,
	}
	request := redirectRuntimeEligibleRequest(http.MethodGet, "https://origin.example.com/Videos/42/stream")
	request.Header.Set("If-None-Match", `"current"`)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("304 RoundTrip: %v", err)
	}
	if response == nil || response.StatusCode != http.StatusNotModified || response.Header.Get("ETag") != `"current"` || calls != 1 || body.closed.Load() {
		t.Fatalf("304 response=%#v calls=%d closed=%t", response, calls, body.closed.Load())
	}
	if err := response.Body.Close(); err != nil || !body.closed.Load() {
		t.Fatalf("close 304 body err=%v closed=%t", err, body.closed.Load())
	}
}

func TestDynamicRedirectRuntimeRejectsMalformedRedirectChains(t *testing.T) {
	policy := redirectRuntimePolicy(dynamicProfileCompatible, true)
	for _, test := range []struct {
		name      string
		status    int
		locations []string
		reason    string
	}{
		{name: "unsupported 300", status: http.StatusMultipleChoices, locations: []string{"http://cdn.example.com/media"}, reason: dynamicObservationReasonUnsupportedStatus},
		{name: "unsupported 303", status: http.StatusSeeOther, locations: []string{"http://cdn.example.com/media"}, reason: dynamicObservationReasonUnsupportedStatus},
		{name: "missing Location", status: http.StatusFound, reason: dynamicObservationReasonInvalidLocation},
		{name: "empty Location", status: http.StatusFound, locations: []string{""}, reason: dynamicObservationReasonInvalidLocation},
		{name: "whitespace Location", status: http.StatusFound, locations: []string{" http://cdn.example.com/media"}, reason: dynamicObservationReasonInvalidLocation},
		{name: "duplicate Location", status: http.StatusFound, locations: []string{"http://one.example.com/media", "http://two.example.com/media"}, reason: dynamicObservationReasonInvalidLocation},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &redirectRuntimeCloseSpy{Reader: strings.NewReader("private upstream body")}
			transport := &redirectFollowTransport{
				base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					return redirectRuntimeResponse(req, test.status, test.locations, body), nil
				}),
				dynamicPolicy: policy,
			}
			resp, err := transport.RoundTrip(redirectRuntimeEligibleRequest(http.MethodGet, "http://origin.example.com/Videos/42/stream"))
			if resp != nil {
				t.Fatalf("response=%#v, want nil", resp)
			}
			redirectRuntimeAssertError(t, err, test.reason)
			if !body.closed.Load() {
				t.Fatal("rejected redirect body was not closed")
			}
		})
	}

	t.Run("same authority loop", func(t *testing.T) {
		calls := 0
		var bodies []*redirectRuntimeCloseSpy
		transport := &redirectFollowTransport{
			base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				body := &redirectRuntimeCloseSpy{Reader: strings.NewReader("redirect")}
				bodies = append(bodies, body)
				if calls == 1 {
					return redirectRuntimeResponse(req, http.StatusFound, []string{"/Videos/42/next"}, body), nil
				}
				return redirectRuntimeResponse(req, http.StatusFound, []string{"/Videos/42/stream"}, body), nil
			}),
			dynamicPolicy: policy,
		}
		resp, err := transport.RoundTrip(redirectRuntimeEligibleRequest(http.MethodGet, "http://origin.example.com/Videos/42/stream"))
		if resp != nil || calls != 2 {
			t.Fatalf("response=%#v calls=%d, want nil/2", resp, calls)
		}
		redirectRuntimeAssertError(t, err, dynamicObservationReasonRedirectLoop)
		for index, body := range bodies {
			if !body.closed.Load() {
				t.Errorf("redirect body %d was not closed", index)
			}
		}
	})

	t.Run("same authority hop exhaustion", func(t *testing.T) {
		limited := policy
		limited.limits.MaxRedirects = 1
		calls := 0
		transport := &redirectFollowTransport{
			base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return redirectRuntimeResponse(req, http.StatusPermanentRedirect, []string{fmt.Sprintf("/Videos/42/hop-%d", calls)}, nil), nil
			}),
			dynamicPolicy: limited,
		}
		resp, err := transport.RoundTrip(redirectRuntimeEligibleRequest(http.MethodHead, "http://origin.example.com/Videos/42/stream"))
		if resp != nil || calls != 2 {
			t.Fatalf("response=%#v calls=%d, want nil/2", resp, calls)
		}
		redirectRuntimeAssertError(t, err, dynamicObservationReasonHopLimit)
	})
}

func TestDynamicSafeEmptyRulesKeepHTTPS443PublicDNSBoundary(t *testing.T) {
	policy := redirectRuntimePolicy(dynamicProfileSafe, true)
	policy.domainRules = nil
	selfTargets := newTestDynamicSelfTargetPolicy(t)
	parse := func(raw string) *url.URL {
		t.Helper()
		target, err := normalizeDynamicURL(raw)
		if err != nil {
			t.Fatalf("normalize %q: %v", raw, err)
		}
		return target
	}

	publicTarget := parse("https://cdn.example.net/media")
	if reason := policy.validateTarget(nil, publicTarget, selfTargets); reason != "" {
		t.Fatalf("public DNS HTTPS:443 reason=%q, want allowed", reason)
	}
	publicResolver := dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	})
	if pinned, err := resolveDynamicURLIPs(context.Background(), publicResolver, publicTarget, policy.limits.MaxDNSIPs, selfTargets); err != nil || len(pinned) != 1 || !pinned[0].Equal(net.ParseIP("1.1.1.1")) {
		t.Fatalf("public DNS resolution pins=%v err=%v", pinned, err)
	}

	for name, test := range map[string]struct {
		raw    string
		reason string
	}{
		"IP literal": {raw: "https://8.8.8.8/media", reason: dynamicObservationReasonDomainDenied},
		"HTTP":       {raw: "http://cdn.example.net/media", reason: dynamicObservationReasonSchemeDenied},
		"non-443":    {raw: "https://cdn.example.net:444/media", reason: dynamicObservationReasonPortDenied},
		"self":       {raw: "https://panel.example.com/media", reason: dynamicObservationReasonSelfTarget},
	} {
		t.Run(name, func(t *testing.T) {
			if reason := policy.validateTarget(nil, parse(test.raw), selfTargets); reason != test.reason {
				t.Fatalf("reason=%q, want %q", reason, test.reason)
			}
		})
	}

	privateTarget := parse("https://private.example.net/media")
	if reason := policy.validateTarget(nil, privateTarget, selfTargets); reason != "" {
		t.Fatalf("private DNS name was rejected before DNS pinning: %q", reason)
	}
	privateResolver := dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.8")}}, nil
	})
	if _, err := resolveDynamicURLIPs(context.Background(), privateResolver, privateTarget, policy.limits.MaxDNSIPs, selfTargets); err == nil {
		t.Fatal("Safe empty rules allowed a private DNS answer")
	}
}

func TestDynamicRedirectRuntimeRefusesUnsafeUnknownTargets(t *testing.T) {
	tests := []struct {
		name           string
		profile        string
		origin         string
		location       string
		answers        []net.IPAddr
		wantReason     string
		wantDNSCalls   int32
		denyTargetHost bool
	}{
		{
			name:       "safe profile scheme",
			profile:    dynamicProfileSafe,
			origin:     "https://origin.example.net/Videos/42/stream",
			location:   "http://cdn.example.com/media",
			wantReason: dynamicObservationReasonSchemeDenied,
		},
		{
			name:       "safe profile port",
			profile:    dynamicProfileSafe,
			origin:     "https://origin.example.net/Videos/42/stream",
			location:   "https://cdn.example.com:444/media",
			wantReason: dynamicObservationReasonPortDenied,
		},
		{
			name:       "safe profile domain",
			profile:    dynamicProfileSafe,
			origin:     "https://origin.example.net/Videos/42/stream",
			location:   "https://cdn.example.net/media",
			wantReason: dynamicObservationReasonDomainDenied,
		},
		{
			name:       "HTTPS downgrade",
			profile:    dynamicProfileCompatible,
			origin:     "https://origin.example.net/Videos/42/stream",
			location:   "http://cdn.example.com/media",
			wantReason: dynamicObservationReasonHTTPSDowngradeDenied,
		},
		{
			name:           "Meridian self authority",
			profile:        dynamicProfileCompatible,
			origin:         "http://origin.example.net/Videos/42/stream",
			location:       "http://panel.example.com/media",
			wantReason:     dynamicObservationReasonSelfTarget,
			denyTargetHost: true,
		},
		{
			name:     "mixed public and private DNS",
			profile:  dynamicProfileCompatible,
			origin:   "http://origin.example.net/Videos/42/stream",
			location: "http://cdn.example.com/media",
			answers: []net.IPAddr{
				{IP: net.ParseIP("1.1.1.1")},
				{IP: net.ParseIP("127.0.0.1")},
			},
			wantReason:   dynamicObservationReasonAddressDenied,
			wantDNSCalls: 1,
		},
		{
			name:       "private IP literal",
			profile:    dynamicProfileCompatible,
			origin:     "http://origin.example.net/Videos/42/stream",
			location:   "http://127.0.0.1/media",
			wantReason: dynamicObservationReasonInvalidLocation,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := redirectRuntimePolicy(test.profile, true)
			var resolverCalls atomic.Int32
			resolver := dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
				resolverCalls.Add(1)
				return test.answers, nil
			})
			runtime := newDynamicRuntime()
			runtime.resolver = resolver
			selfTargets := newTestDynamicSelfTargetPolicy(t)
			if test.denyTargetHost {
				selfTargets.deniedHosts["panel.example.com"] = struct{}{}
			}
			runtime.selfTargets.Store(selfTargets)
			state := newDynamicSiteState(runtime, policy.limits)
			body := &redirectRuntimeCloseSpy{Reader: strings.NewReader("private redirect body")}
			factoryCalls := 0
			transport := &redirectFollowTransport{
				base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					return redirectRuntimeResponse(req, http.StatusFound, []string{test.location}, body), nil
				}),
				configuredAuthorities: map[string]bool{redirectHostKey(redirectRuntimeMustParseURL(t, test.origin)): true},
				dynamicPolicy:         policy,
				dynamicState:          state,
				dynamicTransportFactory: func(*url.URL, []net.IP, *dynamicSelfTargetPolicy) (*http.Transport, error) {
					factoryCalls++
					return nil, errors.New("unsafe target reached transport factory")
				},
			}
			resp, err := transport.RoundTrip(redirectRuntimeEligibleRequest(http.MethodGet, test.origin))
			if resp != nil {
				t.Fatalf("response=%#v, want nil", resp)
			}
			redirectRuntimeAssertError(t, err, test.wantReason)
			if resolverCalls.Load() != test.wantDNSCalls || factoryCalls != 0 {
				t.Fatalf("DNS/factory calls=%d/%d, want %d/0", resolverCalls.Load(), factoryCalls, test.wantDNSCalls)
			}
			if !body.closed.Load() {
				t.Fatal("unsafe redirect body was not closed")
			}
		})
	}
}

func redirectRuntimeMustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL %q: %v", raw, err)
	}
	return parsed
}

func TestDynamicRedirectRuntimeMissingKeyFailsClosedAndSanitizesHTTPError(t *testing.T) {
	policy := redirectRuntimePolicy(dynamicProfileSafe, false)
	var resolverCalls atomic.Int32
	_, state := redirectRuntimeState(t, policy.limits, dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		resolverCalls.Add(1)
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	}))
	body := &redirectRuntimeCloseSpy{Reader: strings.NewReader("private-upstream-body")}
	const privateLocation = "https://cdn.example.com/media?access_token=private-token"
	transport := &redirectFollowTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return redirectRuntimeResponse(req, http.StatusFound, []string{privateLocation}, body), nil
		}),
		configuredAuthorities: map[string]bool{"https://origin.example.net": true},
		dynamicPolicy:         policy,
		dynamicState:          state,
	}
	resp, err := transport.RoundTrip(redirectRuntimeEligibleRequest(http.MethodGet, "https://origin.example.net/Videos/42/stream"))
	if resp != nil {
		t.Fatalf("response=%#v, want nil", resp)
	}
	dynamicErr := redirectRuntimeAssertError(t, err, dynamicObservationReasonRuntimeUnavailable)
	if resolverCalls.Load() != 0 || !body.closed.Load() {
		t.Fatalf("resolverCalls=%d bodyClosed=%t, want 0/true", resolverCalls.Load(), body.closed.Load())
	}

	recorder := httptest.NewRecorder()
	recorder.Header().Set("Location", privateLocation)
	dynamicErr.writeResponse(recorder)
	result := recorder.Result()
	defer result.Body.Close()
	payload, readErr := io.ReadAll(result.Body)
	if readErr != nil {
		t.Fatalf("read sanitized response: %v", readErr)
	}
	if result.StatusCode != http.StatusBadGateway || result.Header.Get("Location") != "" || result.Header.Get("Retry-After") != "" {
		t.Fatalf("sanitized status/Location/Retry-After=%d/%q/%q", result.StatusCode, result.Header.Get("Location"), result.Header.Get("Retry-After"))
	}
	if string(payload) != `{"error":"dynamic discovery unavailable"}` || strings.Contains(string(payload), "private-token") || strings.Contains(string(payload), dynamicErr.reasonCode) {
		t.Fatalf("sanitized body=%q", payload)
	}
	for name, want := range map[string]string{
		"Content-Type":           "application/json",
		"Cache-Control":          "no-store",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := result.Header.Get(name); got != want {
			t.Errorf("sanitized response %s=%q, want %q", name, got, want)
		}
	}
}

func TestDynamicRedirectRuntimeHTTPErrorClassification(t *testing.T) {
	for _, test := range []struct {
		name       string
		reason     string
		wantStatus int
		wantRetry  string
	}{
		{name: "policy denial is bad gateway", reason: dynamicObservationReasonDomainDenied, wantStatus: http.StatusBadGateway},
		{name: "capacity is retryable", reason: dynamicObservationReasonCapacityLimit, wantStatus: http.StatusServiceUnavailable, wantRetry: "1"},
		{name: "rate is retryable", reason: dynamicObservationReasonRateLimit, wantStatus: http.StatusServiceUnavailable, wantRetry: "60"},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			recorder.Header().Set("Location", "https://private.example.com/path?token=secret")
			newDynamicProxyError(test.reason).writeResponse(recorder)
			result := recorder.Result()
			defer result.Body.Close()
			payload, err := io.ReadAll(result.Body)
			if err != nil {
				t.Fatal(err)
			}
			if result.StatusCode != test.wantStatus || result.Header.Get("Retry-After") != test.wantRetry || result.Header.Get("Location") != "" {
				t.Fatalf("status/retry/Location=%d/%q/%q, want %d/%q/empty", result.StatusCode, result.Header.Get("Retry-After"), result.Header.Get("Location"), test.wantStatus, test.wantRetry)
			}
			if string(payload) != `{"error":"dynamic discovery unavailable"}` || strings.Contains(string(payload), test.reason) || strings.Contains(string(payload), "private.example.com") {
				t.Fatalf("error body=%q", payload)
			}
		})
	}
}

func TestDynamicRedirectRuntimeAuthorityAndRateBudgets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	baseLimits, ok := dynamicLimitsForProfile(dynamicProfileCompatible)
	if !ok {
		t.Fatal("compatible profile missing")
	}

	t.Run("per-site authority capacity", func(t *testing.T) {
		limits := baseLimits
		limits.MaxAuthorities = 1
		limits.MaxNewAuthoritiesPerMinute = 10
		runtime := newDynamicRuntime()
		state := newDynamicSiteState(runtime, limits)
		first, reason := state.reserveAuthority("https://one.example.com:443", now)
		if reason != "" || first == nil {
			t.Fatalf("first reservation=%v reason=%q", first, reason)
		}
		first.commit()
		if reservation, reason := state.reserveAuthority("https://two.example.com:443", now); reservation != nil || reason != dynamicObservationReasonCapacityLimit {
			t.Fatalf("second reservation=%v reason=%q", reservation, reason)
		}
		if len(state.authorities) != 1 || runtime.authorities["https://one.example.com:443"] != 1 {
			t.Fatalf("site/runtime authorities=%v/%v", state.authorities, runtime.authorities)
		}
		state.close()
		if len(runtime.authorities) != 0 {
			t.Fatalf("runtime authorities after site close=%v", runtime.authorities)
		}
	})

	t.Run("global authority capacity", func(t *testing.T) {
		limits := baseLimits
		limits.MaxAuthorities = globalDynamicMaxAuthorities + 1
		limits.MaxNewAuthoritiesPerMinute = globalDynamicMaxNewAuthoritiesMinute + 1
		runtime := newDynamicRuntime()
		for index := range globalDynamicMaxAuthorities {
			runtime.authorities[fmt.Sprintf("https://occupied-%d.example.com:443", index)] = 1
		}
		state := newDynamicSiteState(runtime, limits)
		if reservation, reason := state.reserveAuthority("https://new.example.com:443", now); reservation != nil || reason != dynamicObservationReasonCapacityLimit {
			t.Fatalf("global capacity reservation=%v reason=%q", reservation, reason)
		}
	})

	t.Run("per-site new-authority rate", func(t *testing.T) {
		limits := baseLimits
		limits.MaxAuthorities = 10
		limits.MaxNewAuthoritiesPerMinute = 1
		runtime := newDynamicRuntime()
		state := newDynamicSiteState(runtime, limits)
		first, reason := state.reserveAuthority("https://one.example.com:443", now)
		if reason != "" || first == nil {
			t.Fatalf("first reservation=%v reason=%q", first, reason)
		}
		first.rollback()
		if reservation, reason := state.reserveAuthority("https://two.example.com:443", now.Add(time.Second)); reservation != nil || reason != dynamicObservationReasonRateLimit {
			t.Fatalf("site rate reservation=%v reason=%q", reservation, reason)
		}
	})

	t.Run("global new-authority rate", func(t *testing.T) {
		limits := baseLimits
		limits.MaxAuthorities = globalDynamicMaxAuthorities + 1
		limits.MaxNewAuthoritiesPerMinute = globalDynamicMaxNewAuthoritiesMinute + 1
		runtime := newDynamicRuntime()
		runtime.newAuthorities = make([]time.Time, globalDynamicMaxNewAuthoritiesMinute)
		for index := range runtime.newAuthorities {
			runtime.newAuthorities[index] = now
		}
		state := newDynamicSiteState(runtime, limits)
		if reservation, reason := state.reserveAuthority("https://new.example.com:443", now.Add(time.Second)); reservation != nil || reason != dynamicObservationReasonRateLimit {
			t.Fatalf("global rate reservation=%v reason=%q", reservation, reason)
		}
	})

	t.Run("known authority bypasses new-authority budgets", func(t *testing.T) {
		limits := baseLimits
		limits.MaxAuthorities = 1
		limits.MaxNewAuthoritiesPerMinute = 1
		runtime := newDynamicRuntime()
		state := newDynamicSiteState(runtime, limits)
		const authority = "https://known.example.com:443"
		first, reason := state.reserveAuthority(authority, now)
		if reason != "" || first == nil {
			t.Fatalf("first reservation=%v reason=%q", first, reason)
		}
		first.commit()
		second, reason := state.reserveAuthority(authority, now.Add(time.Second))
		if reason != "" || second == nil {
			t.Fatalf("known authority reservation=%v reason=%q", second, reason)
		}
		second.rollback()
	})
}

func TestDynamicRedirectRuntimeProfileOperationalBoundaries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, profile := range []string{dynamicProfileSafe, dynamicProfileCompatible, dynamicProfileExtreme} {
		limits, ok := dynamicLimitsForProfile(profile)
		if !ok {
			t.Fatalf("profile %q missing", profile)
		}
		t.Run(profile+" authority limit", func(t *testing.T) {
			runtime := newDynamicRuntime()
			state := newDynamicSiteState(runtime, limits)
			for index := range limits.MaxAuthorities - 1 {
				authority := fmt.Sprintf("https://seed-%d.example.com:443", index)
				state.authorities[authority] = &dynamicAuthorityEntry{committed: true}
				runtime.authorities[authority] = 1
			}
			if len(state.authorities) != limits.MaxAuthorities-1 {
				t.Fatalf("limit-1 authorities=%d, want %d", len(state.authorities), limits.MaxAuthorities-1)
			}
			atLimit, reasonCode := state.reserveAuthority("https://at-limit.example.com:443", now)
			if reasonCode != "" || atLimit == nil {
				t.Fatalf("at-limit reservation=%v reason=%q", atLimit, reasonCode)
			}
			atLimit.commit()
			if len(state.authorities) != limits.MaxAuthorities {
				t.Fatalf("at-limit authorities=%d, want %d", len(state.authorities), limits.MaxAuthorities)
			}
			if beyond, reasonCode := state.reserveAuthority("https://beyond-limit.example.com:443", now); beyond != nil || reasonCode != dynamicObservationReasonCapacityLimit {
				t.Fatalf("limit+1 reservation=%v reason=%q", beyond, reasonCode)
			}
			state.close()
		})

		t.Run(profile+" discovery rate", func(t *testing.T) {
			runtime := newDynamicRuntime()
			state := newDynamicSiteState(runtime, limits)
			for range limits.MaxNewAuthoritiesPerMinute - 1 {
				state.newAuthorities = append(state.newAuthorities, now)
				runtime.newAuthorities = append(runtime.newAuthorities, now)
			}
			if len(state.newAuthorities) != limits.MaxNewAuthoritiesPerMinute-1 {
				t.Fatalf("limit-1 rate=%d, want %d", len(state.newAuthorities), limits.MaxNewAuthoritiesPerMinute-1)
			}
			atLimit, reasonCode := state.reserveAuthority("https://rate-at-limit.example.com:443", now)
			if reasonCode != "" || atLimit == nil {
				t.Fatalf("at-limit rate reservation=%v reason=%q", atLimit, reasonCode)
			}
			atLimit.rollback()
			if len(state.newAuthorities) != limits.MaxNewAuthoritiesPerMinute {
				t.Fatalf("at-limit rate=%d, want %d", len(state.newAuthorities), limits.MaxNewAuthoritiesPerMinute)
			}
			if beyond, reasonCode := state.reserveAuthority("https://rate-beyond-limit.example.com:443", now); beyond != nil || reasonCode != dynamicObservationReasonRateLimit {
				t.Fatalf("limit+1 rate reservation=%v reason=%q", beyond, reasonCode)
			}
		})

		t.Run(profile+" stream limit", func(t *testing.T) {
			runtime := newDynamicRuntime()
			state := newDynamicSiteState(runtime, limits)
			releases := make([]func(), 0, limits.MaxStreams)
			for range limits.MaxStreams - 1 {
				release, acquired := state.acquireStream()
				if !acquired {
					t.Fatalf("stream acquisition failed before limit at %d", len(releases))
				}
				releases = append(releases, release)
			}
			if len(state.streams) != limits.MaxStreams-1 {
				t.Fatalf("limit-1 streams=%d, want %d", len(state.streams), limits.MaxStreams-1)
			}
			release, acquired := state.acquireStream()
			if !acquired {
				t.Fatal("at-limit stream acquisition failed")
			}
			releases = append(releases, release)
			if len(state.streams) != limits.MaxStreams {
				t.Fatalf("at-limit streams=%d, want %d", len(state.streams), limits.MaxStreams)
			}
			if beyondRelease, acquired := state.acquireStream(); acquired || beyondRelease != nil {
				t.Fatalf("limit+1 stream acquired: release_non_nil=%t acquired=%t", beyondRelease != nil, acquired)
			}
			for _, release := range releases {
				release()
			}
			if len(state.streams) != 0 || len(runtime.streams) != 0 {
				t.Fatalf("stream permits leaked: site=%d runtime=%d", len(state.streams), len(runtime.streams))
			}
		})
	}
}

func TestDynamicRedirectRuntimeDeduplicatesConcurrentAuthorityResolution(t *testing.T) {
	const concurrentDiscoveries = 200
	limits, ok := dynamicLimitsForProfile(dynamicProfileCompatible)
	if !ok {
		t.Fatal("compatible profile missing")
	}
	target, err := normalizeDynamicURL("https://cdn.example.com/media")
	if err != nil {
		t.Fatal(err)
	}
	resolverStarted := make(chan struct{})
	allowResolution := make(chan struct{})
	var resolverCalls atomic.Int32
	resolver := dynamicIPResolverFunc(func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		if resolverCalls.Add(1) == 1 {
			close(resolverStarted)
		}
		select {
		case <-allowResolution:
			return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	runtime, state := redirectRuntimeState(t, limits, resolver)
	selfTargets := runtime.selfTargets.Load()

	start := make(chan struct{})
	allReserved := make(chan struct{})
	results := make(chan error, concurrentDiscoveries)
	var reserved sync.WaitGroup
	var finished sync.WaitGroup
	reserved.Add(concurrentDiscoveries)
	finished.Add(concurrentDiscoveries)
	for range concurrentDiscoveries {
		go func() {
			defer finished.Done()
			<-start
			reservation, reasonCode := state.reserveAuthority("https://cdn.example.com:443", time.Now())
			if reasonCode != "" || reservation == nil {
				reserved.Done()
				results <- fmt.Errorf("reserve authority: reservation=%v reason=%q", reservation, reasonCode)
				return
			}
			reserved.Done()
			ips, reasonCode := reservation.resolve(context.Background(), target, selfTargets)
			if reasonCode != "" || len(ips) != 1 || !ips[0].Equal(net.ParseIP("1.1.1.1")) {
				reservation.rollback()
				results <- fmt.Errorf("resolve authority: ips=%v reason=%q", ips, reasonCode)
				return
			}
			reservation.commit()
			results <- nil
		}()
	}
	close(start)
	go func() {
		reserved.Wait()
		close(allReserved)
	}()
	select {
	case <-allReserved:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent authority reservations did not complete")
	}
	select {
	case <-resolverStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("shared authority resolution did not start")
	}
	if resolverCalls.Load() != 1 {
		t.Fatalf("resolver calls before release=%d, want 1", resolverCalls.Load())
	}
	runtime.mu.Lock()
	state.mu.Lock()
	entry := state.authorities["https://cdn.example.com:443"]
	entryPresent := entry != nil
	entryInFlight := 0
	if entryPresent {
		entryInFlight = entry.inFlight
	}
	siteAuthorityCount := len(state.authorities)
	runtimeAuthorityCount := runtime.authorities["https://cdn.example.com:443"]
	state.mu.Unlock()
	runtime.mu.Unlock()
	if !entryPresent || entryInFlight != concurrentDiscoveries || siteAuthorityCount != 1 || runtimeAuthorityCount != 1 {
		t.Fatalf("deduplicated authority state: present=%t in_flight=%d site=%d runtime=%d", entryPresent, entryInFlight, siteAuthorityCount, runtimeAuthorityCount)
	}

	close(allowResolution)
	allFinished := make(chan struct{})
	go func() {
		finished.Wait()
		close(allFinished)
	}()
	select {
	case <-allFinished:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent authority resolutions did not finish")
	}
	close(results)
	for result := range results {
		if result != nil {
			t.Error(result)
		}
	}
	if resolverCalls.Load() != 1 {
		t.Fatalf("resolver calls=%d, want one shared lookup", resolverCalls.Load())
	}

	next, reasonCode := state.reserveAuthority("https://cdn.example.com:443", time.Now())
	if reasonCode != "" || next == nil {
		t.Fatalf("later reservation=%v reason=%q", next, reasonCode)
	}
	if _, reasonCode := next.resolve(context.Background(), target, selfTargets); reasonCode != "" {
		next.rollback()
		t.Fatalf("later resolution reason=%q", reasonCode)
	}
	next.commit()
	if resolverCalls.Load() != 2 {
		t.Fatalf("later use resolver calls=%d, want 2", resolverCalls.Load())
	}
}

func TestDynamicRedirectRuntimeDNSWorkerAndAnswerBudgets(t *testing.T) {
	policy := redirectRuntimePolicy(dynamicProfileCompatible, true)
	target, err := normalizeDynamicURL("http://cdn.example.com/media")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("global DNS worker releases after cancellation", func(t *testing.T) {
		started := make(chan struct{})
		var calls atomic.Int32
		resolver := dynamicIPResolverFunc(func(ctx context.Context, _ string) ([]net.IPAddr, error) {
			call := calls.Add(1)
			if call == 1 {
				close(started)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
		})
		runtime, state := redirectRuntimeState(t, policy.limits, resolver)
		runtime.dnsWorkers = make(chan struct{}, 1)
		ctx, cancel := context.WithCancel(context.Background())
		firstResult := make(chan redirectRuntimeResolveResult, 1)
		go func() {
			ips, reason := state.resolve(ctx, target, runtime.selfTargets.Load())
			firstResult <- redirectRuntimeResolveResult{ips: ips, reason: reason}
		}()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("first resolver did not start")
		}
		if ips, reason := state.resolve(context.Background(), target, runtime.selfTargets.Load()); ips != nil || reason != dynamicObservationReasonCapacityLimit {
			t.Fatalf("second resolution=%v reason=%q", ips, reason)
		}
		if calls.Load() != 1 || len(runtime.dnsWorkers) != 1 {
			t.Fatalf("DNS calls/workers=%d/%d, want 1/1", calls.Load(), len(runtime.dnsWorkers))
		}
		cancel()
		select {
		case result := <-firstResult:
			if result.ips != nil || result.reason != dynamicObservationReasonDNSFailure {
				t.Fatalf("canceled resolution=%v reason=%q", result.ips, result.reason)
			}
		case <-time.After(time.Second):
			t.Fatal("canceled resolution did not return")
		}
		if len(runtime.dnsWorkers) != 0 {
			t.Fatalf("DNS workers after cancel=%d", len(runtime.dnsWorkers))
		}
		ips, reason := state.resolve(context.Background(), target, runtime.selfTargets.Load())
		if reason != "" || len(ips) != 1 || !ips[0].Equal(net.ParseIP("1.1.1.1")) || calls.Load() != 2 {
			t.Fatalf("post-cancel resolution=%v reason=%q calls=%d", ips, reason, calls.Load())
		}
	})

	t.Run("per-site DNS answer limit", func(t *testing.T) {
		limits := policy.limits
		limits.MaxDNSIPs = 1
		resolver := dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("1.1.1.1")},
				{IP: net.ParseIP("8.8.8.8")},
			}, nil
		})
		runtime, state := redirectRuntimeState(t, limits, resolver)
		if ips, reason := state.resolve(context.Background(), target, runtime.selfTargets.Load()); ips != nil || reason != dynamicObservationReasonCapacityLimit {
			t.Fatalf("oversized DNS result=%v reason=%q", ips, reason)
		}
		if len(runtime.dnsWorkers) != 0 {
			t.Fatalf("DNS worker leaked after oversized answer: %d", len(runtime.dnsWorkers))
		}
	})
}

func TestDynamicRedirectRuntimePerSiteAndGlobalStreamPermits(t *testing.T) {
	limits, ok := dynamicLimitsForProfile(dynamicProfileCompatible)
	if !ok {
		t.Fatal("compatible profile missing")
	}
	limits.MaxStreams = 1

	t.Run("per-site limit", func(t *testing.T) {
		runtime := newDynamicRuntime()
		runtime.streams = make(chan struct{}, 2)
		firstSite := newDynamicSiteState(runtime, limits)
		secondSite := newDynamicSiteState(runtime, limits)
		firstRelease, acquired := firstSite.acquireStream()
		if !acquired {
			t.Fatal("first site did not acquire stream")
		}
		if release, acquired := firstSite.acquireStream(); acquired || release != nil {
			t.Fatalf("same site acquired beyond limit: release_non_nil=%t acquired=%t", release != nil, acquired)
		}
		secondRelease, acquired := secondSite.acquireStream()
		if !acquired {
			t.Fatal("second site could not use remaining global permit")
		}
		if len(runtime.streams) != 2 || len(firstSite.streams) != 1 || len(secondSite.streams) != 1 {
			t.Fatalf("global/first/second permits=%d/%d/%d", len(runtime.streams), len(firstSite.streams), len(secondSite.streams))
		}
		firstRelease()
		firstRelease()
		secondRelease()
		if len(runtime.streams) != 0 || len(firstSite.streams) != 0 || len(secondSite.streams) != 0 {
			t.Fatalf("permits leaked after release: %d/%d/%d", len(runtime.streams), len(firstSite.streams), len(secondSite.streams))
		}
	})

	t.Run("global limit", func(t *testing.T) {
		runtime := newDynamicRuntime()
		runtime.streams = make(chan struct{}, 1)
		firstSite := newDynamicSiteState(runtime, limits)
		secondSite := newDynamicSiteState(runtime, limits)
		firstRelease, acquired := firstSite.acquireStream()
		if !acquired {
			t.Fatal("first site did not acquire global stream")
		}
		if release, acquired := secondSite.acquireStream(); acquired || release != nil {
			t.Fatalf("second site acquired beyond global limit: release_non_nil=%t acquired=%t", release != nil, acquired)
		}
		firstRelease()
		secondRelease, acquired := secondSite.acquireStream()
		if !acquired {
			t.Fatal("released global permit was not reusable")
		}
		secondRelease()
		if len(runtime.streams) != 0 {
			t.Fatalf("global stream permits=%d after releases", len(runtime.streams))
		}
	})
}

func TestDynamicRedirectRuntimeRequestCancellationReleasesStream(t *testing.T) {
	policy := redirectRuntimePolicy(dynamicProfileSafe, true)
	policy.limits.MaxStreams = 1
	runtime, state := redirectRuntimeState(t, policy.limits, dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	}))
	runtime.streams = make(chan struct{}, 1)
	initialBody := &redirectRuntimeCloseSpy{Reader: strings.NewReader("redirect")}
	serverDone := make(chan struct{})
	factory := func(target *url.URL, pinnedIPs []net.IP, selfTargets *dynamicSelfTargetPolicy) (*http.Transport, error) {
		dial := func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "1.1.1.1:443" {
				return nil, fmt.Errorf("unexpected pinned dial %s %s", network, address)
			}
			client, server := net.Pipe()
			go func() {
				defer close(serverDone)
				defer server.Close()
				if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
					return
				}
				if _, err := io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nContent-Type: application/octet-stream\r\n\r\n"); err != nil {
					return
				}
				buffer := make([]byte, 1)
				_, _ = server.Read(buffer)
			}()
			return client, nil
		}
		transport, err := newDynamicTransportWithDialer(target, pinnedIPs, dial, selfTargets)
		if err != nil {
			return nil, err
		}
		transport.DialTLSContext = transport.DialContext
		return transport, nil
	}
	follow := &redirectFollowTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return redirectRuntimeResponse(req, http.StatusFound, []string{"https://cdn.example.com/media"}, initialBody), nil
		}),
		configuredAuthorities:   map[string]bool{"https://origin.example.net": true},
		dynamicPolicy:           policy,
		dynamicState:            state,
		dynamicTransportFactory: factory,
	}
	proxy := &httputil.ReverseProxy{
		Director:  func(*http.Request) {},
		Transport: follow,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	baseReq := httptest.NewRequest(http.MethodGet, "https://origin.example.net/Videos/42/stream", nil)
	ctx := context.WithValue(baseReq.Context(), dynamicRequestEligibleContextKey{}, true)
	ctx, cancel := context.WithCancel(ctx)
	req := baseReq.WithContext(ctx)
	writer := newRedirectRuntimeSignalWriter()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				if recoveredErr, ok := recovered.(error); ok {
					done <- recoveredErr
				} else {
					done <- fmt.Errorf("reverse proxy panic: %v", recovered)
				}
				return
			}
			done <- nil
		}()
		proxy.ServeHTTP(writer, req)
	}()
	select {
	case <-writer.started:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("proxy did not start the dynamic response")
	}
	if !initialBody.closed.Load() || len(runtime.streams) != 1 || len(state.streams) != 1 {
		cancel()
		t.Fatalf("initialClosed=%t stream permits global/site=%d/%d", initialBody.closed.Load(), len(runtime.streams), len(state.streams))
	}
	cancel()
	select {
	case proxyErr := <-done:
		if proxyErr != nil && !errors.Is(proxyErr, http.ErrAbortHandler) {
			t.Fatalf("reverse proxy after cancellation: %v", proxyErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reverse proxy did not stop after request cancellation")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("pinned server connection remained open after cancellation")
	}
	if len(runtime.streams) != 0 || len(state.streams) != 0 {
		t.Fatalf("stream permits after cancellation global/site=%d/%d", len(runtime.streams), len(state.streams))
	}
}
