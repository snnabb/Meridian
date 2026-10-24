package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"reflect"
	"sync"
	"time"
)

// Runtime policy is published as an immutable snapshot. ProxyInstance.Site and
// the transport's captured routing configuration are never mutated by an edit.
func siteCanUpdateLive(before, after Site) bool {
	normalize := func(s Site) Site {
		s.Name = ""
		s.TrafficQuota, s.SpeedLimit, s.TotalSpeedLimit = 0, 0, 0
		s.TrafficUsed, s.TrafficUsedIn, s.TrafficUsedOut = 0, 0, 0
		s.SortOrder, s.AccountCount = 0, 0
		s.CreatedAt, s.UpdatedAt = "", ""
		// Derived views do not change routing; compare canonical stored values.
		s.StreamHostList, s.FailoverTargetList, s.FailoverLines, s.UpstreamHeaders = nil, nil, nil, nil
		return s
	}
	return reflect.DeepEqual(normalize(before), normalize(after))
}

func (inst *ProxyInstance) runtimeSite() *Site {
	if current := inst.liveSite.Load(); current != nil {
		return current
	}
	return &inst.Site // Test/legacy instances without a published snapshot.
}

func (pm *ProxyManager) UpdateSiteLive(site Site) bool {
	pm.lifecycleMu.Lock()
	defer pm.lifecycleMu.Unlock()
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	inst := pm.proxies[site.ID]
	if inst == nil || !inst.isOperational() || !siteCanUpdateLive(*inst.runtimeSite(), site) {
		return false
	}
	inst.liveSite.Store(&site)
	inst.totalRate.setRate(int64(site.TotalSpeedLimit) * 125000)
	return true
}

const siteRateChunk = 32 * 1024

// A single bucket is shared by all responses from one running site, including
// cached/dynamic responses and WebSocket downloads. Idle credit is bounded to
// one copy chunk; it cannot accumulate into an unbounded burst.
type siteRateLimiter struct {
	mu      sync.Mutex
	rate    int64
	tokens  float64
	updated time.Time
	changed chan struct{}
}

func newSiteRateLimiter(rate int64) *siteRateLimiter {
	return &siteRateLimiter{rate: rate, updated: time.Now(), changed: make(chan struct{})}
}

func (l *siteRateLimiter) accrue(now time.Time) {
	l.tokens = min(float64(siteRateChunk), l.tokens+now.Sub(l.updated).Seconds()*float64(l.rate))
	l.updated = now
}

func (l *siteRateLimiter) setRate(rate int64) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.accrue(time.Now())
	if l.rate == 0 {
		l.tokens = 0
	}
	l.rate = rate
	close(l.changed)
	l.changed = make(chan struct{})
}

func (l *siteRateLimiter) wait(ctx context.Context, size int) error {
	if l == nil || size <= 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		l.mu.Lock()
		if l.rate <= 0 {
			l.mu.Unlock()
			return nil
		}
		if err := ctx.Err(); err != nil {
			l.mu.Unlock()
			return err
		}
		l.accrue(time.Now())
		if l.tokens >= float64(size) {
			l.tokens -= float64(size)
			l.mu.Unlock()
			return nil
		}
		delay := time.Duration((float64(size) - l.tokens) / float64(l.rate) * float64(time.Second))
		changed := l.changed
		l.mu.Unlock()
		timer := time.NewTimer(max(delay, time.Microsecond))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

type sitePacedWriter struct {
	dst     io.Writer
	limiter *siteRateLimiter
	ctx     context.Context
}

func (w *sitePacedWriter) Write(data []byte) (int, error) {
	total := 0
	for len(data) > 0 {
		size := min(len(data), siteRateChunk)
		if err := w.limiter.wait(w.ctx, size); err != nil {
			return total, err
		}
		n, err := w.dst.Write(data[:size])
		total += n
		data = data[n:]
		if err != nil {
			return total, err
		}
		if n != size {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

type sitePacedResponseWriter struct {
	http.ResponseWriter
	limiter *siteRateLimiter
	ctx     context.Context
}

func (w *sitePacedResponseWriter) Write(data []byte) (int, error) {
	return (&sitePacedWriter{dst: w.ResponseWriter, limiter: w.limiter, ctx: w.ctx}).Write(data)
}
func (w *sitePacedResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *sitePacedResponseWriter) FlushError() error {
	return http.NewResponseController(w.ResponseWriter).Flush()
}
func (w *sitePacedResponseWriter) Flush() { _ = w.FlushError() }
func (w *sitePacedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}
