package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func writeWebSocketGatewayError(conn net.Conn) {
	const body = `{"error":"upstream refused websocket upgrade"}`
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request, target, primaryTarget *url.URL, policy UAHeaderPolicy, inst *ProxyInstance, speedLimitBytes int64, meter *requestTrafficMeter, upstreamPolicies ...upstreamHeaderPolicy) {
	// Nothing on this path reads r.Body, so a body would be left sitting in the
	// hijacked buffer and relayed verbatim to the upstream.
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		http.Error(w, "websocket upgrade must not carry a body", http.StatusBadRequest)
		return
	}
	scheme := "ws"
	if target.Scheme == "https" {
		scheme = "wss"
	}
	// Hijack client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported", 500)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		log.Printf("[WS] hijack error: %v", err)
		return
	}
	defer clientConn.Close()
	if !inst.trackHijackedConn(clientConn) {
		return
	}
	defer inst.untrackHijackedConn(clientConn)

	// Connect to upstream
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var upstreamConn net.Conn
	port := target.Port()
	if port == "" {
		if scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}
	host := net.JoinHostPort(target.Hostname(), port)
	if scheme == "wss" {
		upstreamConn, err = tls.DialWithDialer(dialer, "tcp", host, secureTLSConfig(target.Hostname()))
	} else {
		upstreamConn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		log.Printf("[WS] upstream dial error: %v", err)
		writeWebSocketGatewayError(clientConn)
		return
	}
	defer upstreamConn.Close()

	// Send upgrade request to upstream
	if err := upstreamConn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("[WS] set handshake deadline: %v", err)
		return
	}
	upstreamURL := *r.URL
	applyUpstreamURL(&upstreamURL, target)
	reqLine := fmt.Sprintf("%s %s HTTP/1.1\r\n", r.Method, upstreamURL.RequestURI())
	if _, err := io.WriteString(upstreamConn, reqLine); err != nil { // #nosec G705 -- net/http rejects control characters in the parsed method and RequestURI.
		log.Printf("[WS] write request line: %v", err)
		return
	}
	upstreamHeader := prepareWebSocketUpstreamHeadersWithClientIPMode(r, target, policy, inst.trustedProxies, inst.Site.ClientIPMode, upstreamPolicies...)
	if primaryTarget != nil && !sameRedirectAuthority(primaryTarget, target) {
		// A separately configured playback/CDN authority is a different trust
		// domain. Preserve only WebSocket negotiation fields and normalized client
		// identity; browser/API credentials must stay with the main origin.
		upstreamHeader = crossAuthorityWebSocketHeadersWithClientIPMode(upstreamHeader, inst.Site.ClientIPMode)
		upstreamHeader.Set("Host", target.Host)
	}
	applySiteForwardedHost(upstreamHeader, r, inst.Site)
	if err := upstreamHeader.Write(upstreamConn); err != nil {
		log.Printf("[WS] write request headers: %v", err)
		return
	}
	if _, err := io.WriteString(upstreamConn, "\r\n"); err != nil {
		log.Printf("[WS] finish request headers: %v", err)
		return
	}
	if err := upstreamConn.SetWriteDeadline(time.Time{}); err != nil {
		log.Printf("[WS] clear handshake deadline: %v", err)
		return
	}

	// Require a real protocol switch before relaying any raw bytes. Without this
	// check the tunnel starts regardless of what the upstream answered, so if the
	// upstream ignored the upgrade and stayed in HTTP keep-alive mode, whatever
	// the client sends next reaches it as requests that never passed through
	// removeClientForwardingHeaders/setTrustedForwardingHeaders/applyUAProfileHeaders.
	if err := upstreamConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("[WS] set handshake read deadline: %v", err)
		return
	}
	// Read through a buffered reader and keep using it below: ReadResponse may
	// consume bytes past the headers, and those belong to the tunnel.
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, r)
	if err != nil {
		log.Printf("[WS] read upstream handshake: %v", err)
		writeWebSocketGatewayError(clientConn)
		return
	}
	defer resp.Body.Close()
	if err := upstreamConn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("[WS] clear handshake read deadline: %v", err)
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		!headerHasToken(resp.Header, "Connection", "upgrade") {
		// The body is deliberately not relayed. An upstream that answers a
		// handshake with a normal response must not turn this path into an
		// unmetered, unthrottled transfer channel.
		log.Printf("[WS] upstream refused upgrade: status %d", resp.StatusCode)
		writeWebSocketGatewayError(clientConn)
		return
	}
	stripPanelSessionSetCookies(resp.Header)
	prefixPathIngressSetCookies(resp.Header, inst.Site.PathPrefix, target.Path)

	// Relay the switch verbatim; the client needs Sec-WebSocket-Accept.
	if _, err := io.WriteString(clientConn, "HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		log.Printf("[WS] write handshake response: %v", err)
		return
	}
	if err := resp.Header.Write(clientConn); err != nil {
		log.Printf("[WS] write handshake headers: %v", err)
		return
	}
	if _, err := io.WriteString(clientConn, "\r\n"); err != nil {
		log.Printf("[WS] finish handshake response: %v", err)
		return
	}

	log.Printf("[WS] tunnel established: client <-> %s", target.Host)

	// Bidirectional copy. Both directions are metered per chunk; only the
	// download direction is paced, matching rateLimitedWriter on the HTTP path.
	if meter == nil {
		meter = requestTrafficMeterFromContext(r.Context())
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(&tunnelWriter{dst: upstreamConn, counter: &inst.bytesIn, cumulative: &inst.cumulativeBytesIn, meter: meter, inbound: true, quota: inst.quota, start: time.Now()}, clientBuf)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(&tunnelWriter{dst: clientConn, counter: &inst.bytesOut, cumulative: &inst.cumulativeBytesOut, meter: meter, bytesPerSec: speedLimitBytes, quota: inst.quota, start: time.Now()}, upstreamReader)
		done <- struct{}{}
	}()
	// The first closed direction must tear down its counterpart, then both copy
	// goroutines must finish before the request leaves activeRequests. Otherwise
	// shutdown can perform its final traffic flush while the second goroutine is
	// still incrementing the old instance's counters.
	<-done
	_ = clientConn.Close()
	_ = upstreamConn.Close()
	<-done
}
