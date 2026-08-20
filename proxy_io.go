package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type originalRequestContextKey struct{}

// isClientRequestCancellation distinguishes a browser/player abandoning an
// in-flight request from Meridian stopping the site. The proxy receives a
// derived context which is canceled for both cases, so the original HTTP
// request context is carried separately and must be canceled as well.
func isClientRequestCancellation(ctx context.Context, err error) bool {
	return errors.Is(err, context.Canceled) && ctx != nil && errors.Is(ctx.Err(), context.Canceled)
}

func originalRequestContext(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	if original, ok := ctx.Value(originalRequestContextKey{}).(context.Context); ok {
		return original
	}
	return ctx
}

// metered response writer
type meteredWriter struct {
	http.ResponseWriter
	written    *atomic.Int64
	cumulative *atomic.Int64
	meter      *requestTrafficMeter
	quota      *trafficQuotaState
}

func addMeteredBytes(primary, cumulative *atomic.Int64, n int) {
	if n <= 0 {
		return
	}
	if primary != nil {
		primary.Add(int64(n))
	}
	if cumulative != nil {
		cumulative.Add(int64(n))
	}
}

func addMeteredBytesWithMeter(primary, cumulative *atomic.Int64, meter *requestTrafficMeter, inbound bool, n int) {
	if n <= 0 {
		return
	}
	if meter != nil {
		if inbound {
			meter.addIn(int64(n))
		} else {
			meter.addOut(int64(n))
		}
		if cumulative != nil {
			cumulative.Add(int64(n))
		}
		return
	}
	addMeteredBytes(primary, cumulative, n)
}

func (m *meteredWriter) Write(b []byte) (int, error) {
	if m.quota != nil {
		allowed, quotaErr := m.quota.allow(true, int64(len(b)), time.Now())
		if allowed == 0 {
			return 0, quotaErr
		}
		if allowed < int64(len(b)) {
			b = b[:allowed]
		}
	}
	n, err := m.ResponseWriter.Write(b)
	addMeteredBytesWithMeter(m.written, m.cumulative, m.meter, false, n)
	if m.quota != nil && int64(n) < int64(len(b)) {
		return n, errTrafficQuotaExceeded
	}
	return n, err
}

// Flush support for streaming
func (m *meteredWriter) Flush() {
	if f, ok := m.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack support for WebSocket upgrade
func (m *meteredWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := m.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}

// metered request body reader
type meteredReader struct {
	io.ReadCloser
	read       *atomic.Int64
	cumulative *atomic.Int64
	meter      *requestTrafficMeter
	quota      *trafficQuotaState
}

func (m *meteredReader) Read(p []byte) (int, error) {
	if m.quota != nil {
		allowed, quotaErr := m.quota.allow(false, int64(len(p)), time.Now())
		if allowed == 0 {
			return 0, quotaErr
		}
		if allowed < int64(len(p)) {
			p = p[:allowed]
		}
	}
	n, err := m.ReadCloser.Read(p)
	addMeteredBytesWithMeter(m.read, m.cumulative, m.meter, true, n)
	if m.quota != nil && int64(n) < int64(len(p)) && err == nil {
		return n, errTrafficQuotaExceeded
	}
	return n, err
}

type rateLimitedWriter struct {
	http.ResponseWriter
	bytesPerSec    int64
	written        *atomic.Int64
	cumulative     *atomic.Int64
	meter          *requestTrafficMeter
	quota          *trafficQuotaState
	requestWritten int64
	start          time.Time
	ctx            context.Context
}

func (w *rateLimitedWriter) Write(b []byte) (int, error) {
	if w.bytesPerSec <= 0 {
		if w.quota != nil {
			allowed, quotaErr := w.quota.allow(true, int64(len(b)), time.Now())
			if allowed == 0 {
				return 0, quotaErr
			}
			if allowed < int64(len(b)) {
				b = b[:allowed]
			}
		}
		n, err := w.ResponseWriter.Write(b)
		addMeteredBytesWithMeter(w.written, w.cumulative, w.meter, false, n)
		if w.quota != nil && int64(n) < int64(len(b)) {
			return n, errTrafficQuotaExceeded
		}
		return n, err
	}
	totalWritten := 0
	for len(b) > 0 {
		elapsed := time.Since(w.start).Seconds()
		if elapsed < 0.001 {
			elapsed = 0.001
		}
		allowed := int64(elapsed*float64(w.bytesPerSec)) - w.requestWritten
		if allowed <= 0 {
			if w.ctx == nil {
				time.Sleep(10 * time.Millisecond)
			} else {
				select {
				case <-w.ctx.Done():
					return totalWritten, w.ctx.Err()
				case <-time.After(10 * time.Millisecond):
				}
			}
			continue
		}
		chunk := b
		if int64(len(chunk)) > allowed {
			chunk = b[:allowed]
		}
		if w.quota != nil {
			quotaAllowed, quotaErr := w.quota.allow(true, int64(len(chunk)), time.Now())
			if quotaAllowed == 0 {
				return totalWritten, quotaErr
			}
			if quotaAllowed < int64(len(chunk)) {
				chunk = chunk[:quotaAllowed]
			}
		}
		n, err := w.ResponseWriter.Write(chunk)
		addMeteredBytesWithMeter(w.written, w.cumulative, w.meter, false, n)
		w.requestWritten += int64(n)
		totalWritten += n
		b = b[n:]
		if w.quota != nil && int64(n) < int64(len(chunk)) {
			return totalWritten, errTrafficQuotaExceeded
		}
		if err != nil {
			return totalWritten, err
		}
		if n == 0 {
			return totalWritten, io.ErrNoProgress
		}
	}
	return totalWritten, nil
}

func (w *rateLimitedWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *rateLimitedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}

// tunnelWriter meters, and optionally paces, bytes copied through a hijacked
// WebSocket tunnel. Accounting has to happen per chunk rather than once the copy
// returns, otherwise a long-lived tunnel stays invisible to the quota gate and
// exempt from the site's speed limit for as long as it is open.
type tunnelWriter struct {
	dst         io.Writer
	counter     *atomic.Int64
	cumulative  *atomic.Int64
	meter       *requestTrafficMeter
	inbound     bool
	quota       *trafficQuotaState
	bytesPerSec int64
	written     int64
	start       time.Time
}

func (t *tunnelWriter) Write(b []byte) (int, error) {
	if t.bytesPerSec <= 0 {
		if t.quota != nil {
			allowed, quotaErr := t.quota.allow(!t.inbound, int64(len(b)), time.Now())
			if allowed == 0 {
				return 0, quotaErr
			}
			if allowed < int64(len(b)) {
				b = b[:allowed]
			}
		}
		n, err := t.dst.Write(b)
		addMeteredBytesWithMeter(t.counter, t.cumulative, t.meter, t.inbound, n)
		if t.quota != nil && int64(n) < int64(len(b)) {
			return n, errTrafficQuotaExceeded
		}
		return n, err
	}
	total := 0
	for len(b) > 0 {
		elapsed := time.Since(t.start).Seconds()
		if elapsed < 0.001 {
			elapsed = 0.001
		}
		allowed := int64(elapsed*float64(t.bytesPerSec)) - t.written
		if allowed <= 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		chunk := b
		if int64(len(chunk)) > allowed {
			chunk = b[:allowed]
		}
		if t.quota != nil {
			quotaAllowed, quotaErr := t.quota.allow(!t.inbound, int64(len(chunk)), time.Now())
			if quotaAllowed == 0 {
				return total, quotaErr
			}
			if quotaAllowed < int64(len(chunk)) {
				chunk = chunk[:quotaAllowed]
			}
		}
		n, err := t.dst.Write(chunk)
		addMeteredBytesWithMeter(t.counter, t.cumulative, t.meter, t.inbound, n)
		t.written += int64(n)
		total += n
		b = b[n:]
		if t.quota != nil && int64(n) < int64(len(chunk)) {
			return total, errTrafficQuotaExceeded
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

// headerHasToken reports whether a comma-separated header such as Connection
// carries the given token, which is how RFC 9110 requires these be compared.
func headerHasToken(header http.Header, name, token string) bool {
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// isWebSocketUpgrade reports whether the request is a real RFC 6455 handshake.
// A bare "Upgrade: websocket" header is not enough to qualify: routing an
// ordinary request into the hijacked tunnel would skip the metering and
// speed-limit wrappers that the normal proxy path installs, and would relay raw
// bytes to an upstream that never agreed to switch protocols. Any request with
// upgrade intent that fails this check is rejected before ReverseProxy, because
// its generic 101 tunnel would bypass Meridian's traffic accounting and limits.
func isWebSocketUpgrade(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		headerHasToken(r.Header, "Connection", "upgrade") &&
		r.Header.Get("Sec-WebSocket-Key") != ""
}

func hasUpgradeIntent(r *http.Request) bool {
	return strings.TrimSpace(r.Header.Get("Upgrade")) != "" ||
		headerHasToken(r.Header, "Connection", "upgrade")
}
