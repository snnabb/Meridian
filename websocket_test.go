package main

import (
	"bufio"
	"bytes"
	"errors"
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

// handleWebSocket hijacks the connection and speaks HTTP by hand, so it needs a
// real listener on both sides; httptest.NewRecorder cannot hijack. fakeWSUpstream
// stands in for an Emby instance: it replies with a canned handshake answer and
// records everything the proxy sends it, which is what lets a test prove that
// particular client bytes never reached the upstream.

const wsClientHandshake = "GET /embywebsocket HTTP/1.1\r\n" +
	"Host: proxy.test\r\n" +
	"Upgrade: websocket\r\n" +
	"Connection: Upgrade\r\n" +
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
	"Sec-WebSocket-Version: 13\r\n\r\n"

type fakeWSUpstream struct {
	ln   net.Listener
	mu   sync.Mutex
	got  []byte
	done chan struct{}
}

func startFakeWSUpstream(t *testing.T, reply string) *fakeWSUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	u := &fakeWSUpstream{ln: ln, done: make(chan struct{})}
	go func() {
		defer close(u.done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := io.WriteString(conn, reply); err != nil {
			return
		}
		buf := make([]byte, 4096)
		for {
			if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				return
			}
			n, err := conn.Read(buf)
			if n > 0 {
				u.mu.Lock()
				u.got = append(u.got, buf[:n]...)
				u.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return u
}

func (u *fakeWSUpstream) received() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return string(u.got)
}

func (u *fakeWSUpstream) waitFor(t *testing.T, marker string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(u.received(), marker) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("upstream never received %q; got %q", marker, u.received())
}

// waitForRequest blocks until a complete HTTP request header block has arrived
// and parses it with http.ReadRequest. Header names are case-insensitive on the
// wire and net/http writes its canonical spelling (e.g. "Sec-Websocket-Key"), so
// callers must look headers up by name rather than match literal header text.
func (u *fakeWSUpstream) waitForRequest(t *testing.T) *http.Request {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(u.received())))
		if err == nil {
			return req
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("upstream never received a complete request; got %q", u.received())
	return nil
}

func newWSProxyServer(t *testing.T, upstreamAddr string, inst *ProxyInstance, speedLimitBytes int64, policy UAHeaderPolicy) *httptest.Server {
	t.Helper()
	target, err := normalizeTargetURL("http://" + upstreamAddr)
	if err != nil {
		t.Fatalf("normalizeTargetURL: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleWebSocket(w, r, target, policy, inst, speedLimitBytes)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Metering happens once the underlying write returns, so a reader can observe the
// bytes a moment before the counter moves.
func waitForTunnelCounter(t *testing.T, counter *atomic.Int64, min int64, label string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if counter.Load() >= min {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s = %d, want >= %d", label, counter.Load(), min)
}

func TestHandleWebSocketRefusesTunnelWhenUpstreamDoesNotSwitchProtocols(t *testing.T) {
	// An upstream that ignores the upgrade and answers normally must not get a raw
	// tunnel. Otherwise bytes the client pipelined behind the handshake reach it as
	// requests that skipped every forwarding-header sanitizer.
	upstream := startFakeWSUpstream(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	inst := &ProxyInstance{server: &http.Server{}}
	srv := newWSProxyServer(t, upstream.ln.Addr().String(), inst, 0, UAHeaderPolicy{Rewrite: true, Profile: getUAProfile("infuse")})

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	const smuggled = "GET /SMUGGLED-MUST-NOT-ARRIVE HTTP/1.1\r\n" +
		"Host: internal-emby\r\n" +
		"X-Forwarded-For: 10.0.0.1\r\n\r\n"
	if _, err := io.WriteString(conn, wsClientHandshake+smuggled); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Logf("client read ended with: %v", err)
	}
	// Closing a socket that still holds our unread pipelined bytes can reset the
	// connection and discard the queued response, so this half is best-effort.
	// The security properties asserted below are not.
	if got := string(raw); got != "" {
		if !strings.Contains(got, "502 Bad Gateway") {
			t.Fatalf("client response = %q, want 502 Bad Gateway", got)
		}
		if strings.Contains(got, "200 OK") {
			t.Fatalf("client response relayed the upstream answer: %q", got)
		}
	}

	<-upstream.done
	if strings.Contains(upstream.received(), "SMUGGLED-MUST-NOT-ARRIVE") {
		t.Fatalf("pipelined request reached the upstream: %q", upstream.received())
	}
	if n := inst.bytesOut.Load(); n != 0 {
		t.Fatalf("bytesOut = %d, want 0 when the upgrade was refused", n)
	}
}

func TestHandleWebSocketRelaysSwitchAndMetersBothDirections(t *testing.T) {
	const serverPayload = "UPSTREAM-FRAMES"
	upstream := startFakeWSUpstream(t, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"+
		serverPayload)
	inst := &ProxyInstance{server: &http.Server{}}
	srv := newWSProxyServer(t, upstream.ln.Addr().String(), inst, 0, UAHeaderPolicy{Rewrite: true, Profile: getUAProfile("infuse")})

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, wsClientHandshake); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	buf := make([]byte, 1024)
	seen := ""
	for !strings.Contains(seen, serverPayload) {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read from tunnel: %v (so far %q)", err, seen)
		}
		seen += string(buf[:n])
	}
	if !strings.Contains(seen, "101 Switching Protocols") {
		t.Fatalf("client response = %q, want a relayed 101", seen)
	}
	// Case-insensitive on purpose: http.ReadResponse canonicalises the key to
	// "Sec-Websocket-Accept", header names are case-insensitive on the wire, and
	// this is exactly what httputil.ReverseProxy relays too.
	if !strings.Contains(strings.ToLower(seen), "sec-websocket-accept:") {
		t.Fatalf("handshake response dropped Sec-WebSocket-Accept: %q", seen)
	}

	const clientPayload = "CLIENT-FRAMES"
	if _, err := io.WriteString(conn, clientPayload); err != nil {
		t.Fatalf("write into tunnel: %v", err)
	}
	upstream.waitFor(t, clientPayload)

	waitForTunnelCounter(t, &inst.bytesOut, int64(len(serverPayload)), "bytesOut")
	waitForTunnelCounter(t, &inst.bytesIn, int64(len(clientPayload)), "bytesIn")
}

func TestHandleWebSocketRejectsUpgradeCarryingBody(t *testing.T) {
	// Nothing on the upgrade path reads r.Body, so a body would be left in the
	// hijacked buffer and relayed to the upstream verbatim.
	inst := &ProxyInstance{server: &http.Server{}}
	srv := newWSProxyServer(t, "127.0.0.1:9", inst, 0, UAHeaderPolicy{Rewrite: true, Profile: getUAProfile("infuse")})

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	request := "GET /embywebsocket HTTP/1.1\r\n" +
		"Host: proxy.test\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Content-Length: 5\r\n\r\nhello"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	// A single read: the rejection is not hijacked, so the connection stays in
	// keep-alive and io.ReadAll would block until the deadline.
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read rejection: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "400 Bad Request") {
		t.Fatalf("client response = %q, want 400 Bad Request", string(buf[:n]))
	}
}

func TestHandleWebSocketPassthroughPreservesClientIdentity(t *testing.T) {
	const clientUA = "ClientUA/9.9"
	const clientAuth = `MediaBrowser Client="Client", Device="TV", Version="1"`

	for _, tc := range []struct {
		name     string
		policy   UAHeaderPolicy
		wantUA   string
		wantAuth string
		absent   []string
	}{
		{
			name:     "passthrough keeps client identity",
			policy:   UAHeaderPolicy{},
			wantUA:   clientUA,
			wantAuth: clientAuth,
			absent:   []string{"Infuse/7.8.1", `Client="Infuse"`},
		},
		{
			name:     "rewrite applies configured identity",
			policy:   UAHeaderPolicy{Rewrite: true, Profile: getUAProfile("infuse")},
			wantUA:   "Infuse/7.8.1",
			wantAuth: `MediaBrowser Client="Infuse", Device="TV", Version="7.8.1"`,
			absent:   []string{clientUA, `Client="Client"`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := startFakeWSUpstream(t, "HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
			inst := &ProxyInstance{server: &http.Server{}}
			srv := newWSProxyServer(t, upstream.ln.Addr().String(), inst, 0, tc.policy)

			conn, err := net.Dial("tcp", srv.Listener.Addr().String())
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			handshake := "GET /embywebsocket HTTP/1.1\r\n" +
				"Host: proxy.test\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
				"Sec-WebSocket-Version: 13\r\n" +
				"User-Agent: " + clientUA + "\r\n" +
				"X-Emby-Authorization: " + clientAuth + "\r\n\r\n"
			if _, err := io.WriteString(conn, handshake); err != nil {
				conn.Close()
				t.Fatalf("write handshake: %v", err)
			}
			// Drain until the relayed 101 arrives, then close our side.
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				conn.Close()
				t.Fatalf("set client deadline: %v", err)
			}
			buf := make([]byte, 1024)
			seen := ""
			for !strings.Contains(seen, "101 Switching Protocols") {
				n, err := conn.Read(buf)
				if err != nil {
					break
				}
				seen += string(buf[:n])
			}
			conn.Close()

			req := upstream.waitForRequest(t)
			received := upstream.received()
			if got := req.Header.Get("Sec-WebSocket-Key"); got != "dGhlIHNhbXBsZSBub25jZQ==" {
				t.Fatalf("upstream handshake Sec-WebSocket-Key = %q, want the client key; got: %q", got, received)
			}
			if got := req.Header.Get("User-Agent"); got != tc.wantUA {
				t.Fatalf("upstream handshake User-Agent = %q, want %q; got: %q", got, tc.wantUA, received)
			}
			if got := req.Header.Get("X-Emby-Authorization"); got != tc.wantAuth {
				t.Fatalf("upstream handshake X-Emby-Authorization = %q, want %q; got: %q", got, tc.wantAuth, received)
			}
			for _, marker := range tc.absent {
				if strings.Contains(received, marker) {
					t.Fatalf("upstream handshake carried %q: %q", marker, received)
				}
			}
		})
	}
}

func TestIsWebSocketUpgradeRequiresCompleteHandshake(t *testing.T) {
	full := map[string]string{
		"Upgrade":           "websocket",
		"Connection":        "Upgrade",
		"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
	}
	cases := []struct {
		name    string
		method  string
		headers map[string]string
		want    bool
	}{
		{"complete handshake", http.MethodGet, full, true},
		{"connection list carrying other tokens", http.MethodGet, map[string]string{
			"Upgrade": "websocket", "Connection": "keep-alive, Upgrade", "Sec-WebSocket-Key": "k",
		}, true},
		{"bare upgrade header only", http.MethodGet, map[string]string{"Upgrade": "websocket"}, false},
		{"missing sec-websocket-key", http.MethodGet, map[string]string{
			"Upgrade": "websocket", "Connection": "Upgrade",
		}, false},
		{"connection token absent", http.MethodGet, map[string]string{
			"Upgrade": "websocket", "Connection": "keep-alive", "Sec-WebSocket-Key": "k",
		}, false},
		{"not a GET", http.MethodPost, full, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/embywebsocket", nil)
			for name, value := range tc.headers {
				req.Header.Set(name, value)
			}
			if got := isWebSocketUpgrade(req); got != tc.want {
				t.Fatalf("isWebSocketUpgrade = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPrepareWebSocketUpstreamHeadersDropsContentLength(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/embywebsocket", nil)
	req.Header.Set("Content-Length", "42")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	target, err := normalizeTargetURL("http://127.0.0.1:8096")
	if err != nil {
		t.Fatalf("normalizeTargetURL: %v", err)
	}
	header := prepareWebSocketUpstreamHeaders(req, target, UAHeaderPolicy{Rewrite: true, Profile: getUAProfile("infuse")})
	if got := header.Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length = %q, want it dropped before the upstream handshake", got)
	}
	if header.Get("Sec-WebSocket-Key") == "" {
		t.Fatal("Sec-WebSocket-Key must survive to the upstream")
	}
}

func TestHeaderHasToken(t *testing.T) {
	header := http.Header{}
	header.Add("Connection", "keep-alive, Upgrade")
	header.Add("Connection", "close")
	if !headerHasToken(header, "Connection", "upgrade") {
		t.Fatal("upgrade token in a comma list must be found, case-insensitively")
	}
	if !headerHasToken(header, "Connection", "CLOSE") {
		t.Fatal("token in a second header line must be found")
	}
	if headerHasToken(header, "Connection", "upgrad") {
		t.Fatal("partial token must not match")
	}
	if headerHasToken(http.Header{}, "Connection", "upgrade") {
		t.Fatal("absent header must not match")
	}
}

func TestTunnelWriterMetersAndPaces(t *testing.T) {
	var counter atomic.Int64
	var sink bytes.Buffer
	w := &tunnelWriter{dst: &sink, counter: &counter, start: time.Now()}
	if _, err := w.Write([]byte("0123456789")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := counter.Load(); got != 10 {
		t.Fatalf("counter = %d, want 10", got)
	}
	if sink.String() != "0123456789" {
		t.Fatalf("sink = %q", sink.String())
	}

	// At 1000 bytes/sec, 200 bytes cannot complete in much under 200ms.
	sink.Reset()
	counter.Store(0)
	paced := &tunnelWriter{dst: &sink, counter: &counter, bytesPerSec: 1000, start: time.Now()}
	began := time.Now()
	if _, err := paced.Write(make([]byte, 200)); err != nil {
		t.Fatalf("paced Write: %v", err)
	}
	if elapsed := time.Since(began); elapsed < 100*time.Millisecond {
		t.Fatalf("paced write took %v, want the speed limit to slow it down", elapsed)
	}
	if got := counter.Load(); got != 200 {
		t.Fatalf("paced counter = %d, want 200", got)
	}
}
