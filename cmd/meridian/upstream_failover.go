package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	maxFailoverTargets        = 8
	failoverCooldown          = 30 * time.Second
	failoverPreferredLifetime = 5 * time.Minute
)

// upstreamFailoverState is deliberately process-local. A transient network
// failure must not rewrite a site's configured priority in the database.
type upstreamFailoverState struct {
	mu             sync.Mutex
	preferred      string
	preferredUntil time.Time
	failedUntil    map[string]time.Time
	primaryProbeAt time.Time
}

func newUpstreamFailoverState() *upstreamFailoverState {
	return &upstreamFailoverState{failedUntil: make(map[string]time.Time)}
}

func upstreamTargetKey(target *url.URL) string {
	if target == nil {
		return ""
	}
	return canonicalTargetKey(target) + target.EscapedPath()
}

func (s *upstreamFailoverState) ordered(targets []*url.URL, now time.Time) []*url.URL {
	if len(targets) < 2 || s == nil {
		return append([]*url.URL(nil), targets...)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, until := range s.failedUntil {
		if !until.After(now) {
			delete(s.failedUntil, key)
		}
	}
	if !s.preferredUntil.After(now) {
		s.preferred = ""
	}
	primaryKey := upstreamTargetKey(targets[0])
	probePrimary := s.preferred != "" && s.preferred != primaryKey && !s.failedUntil[primaryKey].After(now) && !s.primaryProbeAt.After(now)
	if probePrimary {
		// Reserve one request as the recovery probe. Concurrent requests keep
		// using the active backup until this attempt succeeds or cools down.
		s.primaryProbeAt = now.Add(failoverCooldown)
	}
	preferred, healthy, cooling := make([]*url.URL, 0, 1), make([]*url.URL, 0, len(targets)), make([]*url.URL, 0, len(targets))
	for _, target := range targets {
		key := upstreamTargetKey(target)
		if probePrimary && key == primaryKey {
			preferred = append(preferred, target)
		} else if key == s.preferred && !s.failedUntil[key].After(now) {
			preferred = append(preferred, target)
		} else if s.failedUntil[key].After(now) {
			cooling = append(cooling, target)
		} else {
			healthy = append(healthy, target)
		}
	}
	return append(append(preferred, healthy...), cooling...)
}

func (s *upstreamFailoverState) markFailure(target *url.URL, now time.Time) {
	if s == nil || target == nil {
		return
	}
	key := upstreamTargetKey(target)
	if key == "" {
		return
	}
	s.mu.Lock()
	s.failedUntil[key] = now.Add(failoverCooldown)
	s.primaryProbeAt = now.Add(failoverCooldown)
	if s.preferred == key {
		s.preferred = ""
		s.preferredUntil = time.Time{}
	}
	s.mu.Unlock()
}

func (s *upstreamFailoverState) markSuccess(target *url.URL, now time.Time) {
	if s == nil || target == nil {
		return
	}
	key := upstreamTargetKey(target)
	if key == "" {
		return
	}
	s.mu.Lock()
	delete(s.failedUntil, key)
	s.preferred = key
	s.preferredUntil = now.Add(failoverPreferredLifetime)
	s.primaryProbeAt = time.Time{}
	s.mu.Unlock()
}

func (s *upstreamFailoverState) preferredTarget(targets []*url.URL, now time.Time) *url.URL {
	if s == nil || len(targets) < 2 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.preferred == "" || !s.preferredUntil.After(now) || s.failedUntil[s.preferred].After(now) {
		if !s.preferredUntil.After(now) {
			s.preferred = ""
			s.preferredUntil = time.Time{}
		}
		return nil
	}
	for _, target := range targets {
		if upstreamTargetKey(target) == s.preferred {
			return target
		}
	}
	return nil
}

func isRetryableUpstreamStatus(status int) bool {
	return status == http.StatusInternalServerError || status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

type failoverRequestContextKey struct{}

type failoverRequestPlan struct {
	originalURL      *url.URL
	targets          []*url.URL
	active           *url.URL
	maxBodyBytes     int64
	playbackInfoPost bool
}

func withFailoverRequestPlan(req *http.Request, originalURL *url.URL, targets []*url.URL, active *url.URL, maxBodyBytes int64) *http.Request {
	if req == nil || originalURL == nil || len(targets) < 2 {
		return req
	}
	copyURL := *originalURL
	plan := failoverRequestPlan{
		originalURL:      &copyURL,
		targets:          append([]*url.URL(nil), targets...),
		active:           active,
		maxBodyBytes:     maxBodyBytes,
		playbackInfoPost: req.Method == http.MethodPost && isPlaybackInfoRequest(copyURL.Path),
	}
	return req.WithContext(context.WithValue(req.Context(), failoverRequestContextKey{}, plan))
}

func isFailoverRequestEligible(req *http.Request, plan failoverRequestPlan) bool {
	if req == nil || hasUpgradeIntent(req) {
		return false
	}
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		return true
	}
	if req.Method != http.MethodPost || !plan.playbackInfoPost {
		return false
	}
	hasBody := req.Body != nil && req.Body != http.NoBody || req.ContentLength != 0 || len(req.TransferEncoding) != 0 || len(req.Trailer) != 0
	if !hasBody {
		return true
	}
	return req.GetBody != nil && req.ContentLength > 0 && plan.maxBodyBytes > 0 && req.ContentLength <= plan.maxBodyBytes &&
		len(req.TransferEncoding) == 0 && len(req.Trailer) == 0
}

func failoverPlanFromRequest(req *http.Request) (failoverRequestPlan, bool) {
	if req == nil {
		return failoverRequestPlan{}, false
	}
	plan, ok := req.Context().Value(failoverRequestContextKey{}).(failoverRequestPlan)
	return plan, ok && plan.originalURL != nil && len(plan.targets) > 1
}

type failoverTransport struct {
	base  http.RoundTripper
	state *upstreamFailoverState
}

func (t *failoverTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	plan, enabled := failoverPlanFromRequest(req)
	if !enabled {
		return t.base.RoundTrip(req)
	}
	if !isFailoverRequestEligible(req, plan) {
		preferred := t.state.preferredTarget(plan.targets, time.Now())
		if preferred == nil || upstreamTargetKey(preferred) == upstreamTargetKey(plan.active) {
			return t.base.RoundTrip(req)
		}
		attempt := cloneFailoverInitialAttempt(req, plan, preferred)
		if tracker := backendAddressTrackerFromContext(attempt.Context()); tracker != nil {
			tracker.SetURL(preferred)
		}
		resp, err := t.base.RoundTrip(attempt)
		if err != nil {
			if !isClientRequestCancellation(originalRequestContext(req.Context()), err) {
				t.state.markFailure(preferred, time.Now())
			}
			return nil, err
		}
		if isRetryableUpstreamStatus(resp.StatusCode) {
			t.state.markFailure(preferred, time.Now())
		} else if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusBadRequest {
			t.state.markSuccess(preferred, time.Now())
		}
		return resp, nil
	}
	targets := t.state.ordered(plan.targets, time.Now())
	var lastErr error
	for index, target := range targets {
		attempt := req
		if index > 0 || upstreamTargetKey(target) != upstreamTargetKey(plan.active) {
			var cloneErr error
			attempt, cloneErr = cloneFailoverAttempt(req, plan, target)
			if cloneErr != nil {
				return nil, cloneErr
			}
		}
		if tracker := backendAddressTrackerFromContext(attempt.Context()); tracker != nil {
			tracker.SetURL(target)
		}
		resp, err := t.base.RoundTrip(attempt)
		if err != nil {
			if isClientRequestCancellation(originalRequestContext(req.Context()), err) {
				return nil, err
			}
			t.state.markFailure(target, time.Now())
			lastErr = err
			continue
		}
		if isRetryableUpstreamStatus(resp.StatusCode) {
			t.state.markFailure(target, time.Now())
			if index+1 < len(targets) {
				resp.Body.Close()
				continue
			}
		}
		if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusBadRequest {
			t.state.markSuccess(target, time.Now())
		}
		return resp, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("all upstream failover attempts failed")
}

func cloneFailoverInitialAttempt(req *http.Request, plan failoverRequestPlan, target *url.URL) *http.Request {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	// This request has not been sent yet, so its original body can move to the
	// selected active line without requiring a replay contract.
	clone.Body = req.Body
	cloneURL := *plan.originalURL
	applyUpstreamURL(&cloneURL, target)
	clone.URL = &cloneURL
	clone.Host = target.Host
	return clone
}

func cloneFailoverAttempt(req *http.Request, plan failoverRequestPlan, target *url.URL) (*http.Request, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return nil, errors.New("failover request body is not replayable")
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("replay failover request body: %w", err)
		}
		clone.Body = body
	}
	cloneURL := *plan.originalURL
	applyUpstreamURL(&cloneURL, target)
	clone.URL = &cloneURL
	clone.Host = target.Host
	return clone, nil
}

func prepareFailoverPlaybackInfoBody(r *http.Request, maxBodyBytes int64) error {
	if r == nil || r.Method != http.MethodPost || r.URL == nil || !isPlaybackInfoRequest(r.URL.Path) ||
		r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 || r.GetBody != nil {
		return nil
	}
	if r.ContentLength < 0 || maxBodyBytes <= 0 || r.ContentLength > maxBodyBytes ||
		len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		return nil
	}
	body := make([]byte, int(r.ContentLength))
	if _, err := io.ReadFull(r.Body, body); err != nil {
		_ = r.Body.Close()
		return fmt.Errorf("read replayable PlaybackInfo body: %w", err)
	}
	var extra [1]byte
	if count, err := r.Body.Read(extra[:]); count != 0 || !errors.Is(err, io.EOF) {
		_ = r.Body.Close()
		if err == nil {
			err = errors.New("request body exceeds its declared length")
		}
		return fmt.Errorf("validate replayable PlaybackInfo body: %w", err)
	}
	if err := r.Body.Close(); err != nil {
		return fmt.Errorf("close replayable PlaybackInfo body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return nil
}

func parseFailoverTargets(primary string, raw []string) ([]*url.URL, error) {
	primaryTarget, err := normalizeTargetURL(primary)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxFailoverTargets-1 {
		return nil, errors.New("failover_targets must contain at most 7 backup targets")
	}
	targets := []*url.URL{primaryTarget}
	seen := map[string]bool{upstreamTargetKey(primaryTarget): true}
	for _, value := range raw {
		target, targetErr := normalizeTargetURL(value)
		if targetErr != nil {
			return nil, targetErr
		}
		key := upstreamTargetKey(target)
		if seen[key] {
			return nil, errors.New("failover_targets must not repeat the primary or another backup target")
		}
		seen[key] = true
		targets = append(targets, target)
	}
	return targets, nil
}

func failoverTargetStrings(targets []*url.URL) []string {
	if len(targets) <= 1 {
		return []string{}
	}
	values := make([]string, 0, len(targets)-1)
	for _, target := range targets[1:] {
		if target != nil {
			values = append(values, target.String())
		}
	}
	return values
}
