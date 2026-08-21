package main

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

func pruneDynamicRateWindow(values []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-time.Minute)
	first := 0
	for first < len(values) && !values[first].After(cutoff) {
		first++
	}
	return values[first:]
}

type dynamicAuthorityReservation struct {
	state      *dynamicSiteState
	authority  string
	entry      *dynamicAuthorityEntry
	resolution *dynamicAuthorityResolution
	once       sync.Once
}

type dynamicAuthorityLease struct {
	mu           sync.Mutex
	retained     bool
	once         sync.Once
	reservations []*dynamicAuthorityReservation
}

func (l *dynamicAuthorityLease) add(reservation *dynamicAuthorityReservation) {
	if l != nil && reservation != nil {
		l.reservations = append(l.reservations, reservation)
	}
}

func (l *dynamicAuthorityLease) retainThroughRewrite() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.retained = true
	l.mu.Unlock()
}

func (l *dynamicAuthorityLease) rollbackOnBodyClose() {
	if l == nil {
		return
	}
	l.mu.Lock()
	retained := l.retained
	l.mu.Unlock()
	if !retained {
		l.rollback()
	}
}

func (l *dynamicAuthorityLease) finish(commit bool) {
	if l == nil {
		return
	}
	l.once.Do(func() {
		for _, reservation := range l.reservations {
			if commit {
				reservation.commit()
			} else {
				reservation.rollback()
			}
		}
	})
}

func (l *dynamicAuthorityLease) commit() {
	l.finish(true)
}

func (l *dynamicAuthorityLease) rollback() {
	l.finish(false)
}

func (s *dynamicSiteState) reserveAuthority(authority string, now time.Time) (*dynamicAuthorityReservation, string) {
	if s == nil || s.runtime == nil || authority == "" {
		return nil, dynamicObservationReasonRuntimeUnavailable
	}
	runtime := s.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry := s.authorities[authority]; entry != nil {
		entry.inFlight++
		if entry.resolution == nil {
			entry.resolution = newDynamicAuthorityResolution()
		}
		return &dynamicAuthorityReservation{
			state:      s,
			authority:  authority,
			entry:      entry,
			resolution: entry.resolution,
		}, ""
	}

	s.newAuthorities = pruneDynamicRateWindow(s.newAuthorities, now)
	runtime.newAuthorities = pruneDynamicRateWindow(runtime.newAuthorities, now)
	if len(s.authorities) >= s.limits.MaxAuthorities || runtime.authorities[authority] == 0 && len(runtime.authorities) >= globalDynamicMaxAuthorities {
		return nil, dynamicObservationReasonCapacityLimit
	}
	if len(s.newAuthorities) >= s.limits.MaxNewAuthoritiesPerMinute || runtime.authorities[authority] == 0 && len(runtime.newAuthorities) >= globalDynamicMaxNewAuthoritiesMinute {
		return nil, dynamicObservationReasonRateLimit
	}
	resolution := newDynamicAuthorityResolution()
	entry := &dynamicAuthorityEntry{inFlight: 1, resolution: resolution}
	s.authorities[authority] = entry
	s.newAuthorities = append(s.newAuthorities, now)
	if runtime.authorities[authority] == 0 {
		runtime.newAuthorities = append(runtime.newAuthorities, now)
	}
	runtime.authorities[authority]++
	return &dynamicAuthorityReservation{
		state:      s,
		authority:  authority,
		entry:      entry,
		resolution: resolution,
	}, ""
}

func (r *dynamicAuthorityReservation) resolve(ctx context.Context, target *url.URL, selfTargets *dynamicSelfTargetPolicy) ([]net.IP, string) {
	if r == nil || r.state == nil || r.resolution == nil || ctx == nil || target == nil || selfTargets == nil {
		return nil, dynamicObservationReasonRuntimeUnavailable
	}
	resolution := r.resolution
	resolution.start.Do(func() {
		go func() {
			ips, reasonCode := r.state.resolve(resolution.ctx, target, selfTargets)
			resolution.ips = ips
			resolution.reasonCode = reasonCode
			close(resolution.done)
		}()
	})
	select {
	case <-ctx.Done():
		return nil, dynamicObservationReasonDNSFailure
	case <-resolution.done:
	}
	if resolution.reasonCode != "" {
		return nil, resolution.reasonCode
	}
	validated, err := validateDynamicResolvedIPsWithPolicy(resolution.ips, selfTargets)
	if err != nil {
		if errors.Is(err, errDynamicSelfTarget) {
			return nil, dynamicObservationReasonSelfTarget
		}
		return nil, dynamicObservationReasonAddressDenied
	}
	return validated, ""
}

func (r *dynamicAuthorityReservation) finishLocked(commit bool) {
	if r == nil || r.state == nil || r.state.runtime == nil {
		return
	}
	r.once.Do(func() {
		s := r.state
		runtime := s.runtime
		entry := s.authorities[r.authority]
		if entry == nil || entry != r.entry {
			return
		}
		if commit {
			entry.committed = true
		}
		if entry.inFlight > 0 {
			entry.inFlight--
		}
		if entry.inFlight == 0 && entry.resolution != nil {
			entry.resolution.cancel()
			entry.resolution = nil
		}
		if entry.committed || entry.inFlight > 0 {
			return
		}
		delete(s.authorities, r.authority)
		if runtime.authorities[r.authority] <= 1 {
			delete(runtime.authorities, r.authority)
		} else {
			runtime.authorities[r.authority]--
		}
	})
}

func (r *dynamicAuthorityReservation) finish(commit bool) {
	if r == nil || r.state == nil || r.state.runtime == nil {
		return
	}
	runtime := r.state.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	r.finishLocked(commit)
}

func (r *dynamicAuthorityReservation) commit() {
	r.finish(true)
}

func (r *dynamicAuthorityReservation) rollback() {
	r.finish(false)
}

func (s *dynamicSiteState) acquireStream() (func(), bool) {
	if s == nil || s.runtime == nil {
		return nil, false
	}
	select {
	case s.runtime.streams <- struct{}{}:
	default:
		return nil, false
	}
	select {
	case s.streams <- struct{}{}:
	default:
		<-s.runtime.streams
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-s.streams
			<-s.runtime.streams
		})
	}, true
}

func (s *dynamicSiteState) resolve(ctx context.Context, target *url.URL, selfTargets *dynamicSelfTargetPolicy) ([]net.IP, string) {
	if s == nil || s.runtime == nil || selfTargets == nil {
		return nil, dynamicObservationReasonRuntimeUnavailable
	}
	if err := selfTargets.validateNormalizedTarget(target); err != nil {
		return nil, dynamicObservationReasonSelfTarget
	}
	if ip := net.ParseIP(target.Hostname()); ip != nil {
		validated, err := validateDynamicResolvedIPsWithPolicy([]net.IP{ip}, selfTargets)
		if err != nil {
			if errors.Is(err, errDynamicSelfTarget) {
				return nil, dynamicObservationReasonSelfTarget
			}
			return nil, dynamicObservationReasonAddressDenied
		}
		return validated, ""
	}
	select {
	case s.runtime.dnsWorkers <- struct{}{}:
		defer func() { <-s.runtime.dnsWorkers }()
	default:
		return nil, dynamicObservationReasonCapacityLimit
	}
	resolver := s.runtime.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	answers, err := resolver.LookupIPAddr(ctx, target.Hostname())
	if err != nil {
		return nil, dynamicObservationReasonDNSFailure
	}
	if len(answers) == 0 {
		return nil, dynamicObservationReasonDNSFailure
	}
	if len(answers) > s.limits.MaxDNSIPs {
		return nil, dynamicObservationReasonCapacityLimit
	}
	ips := make([]net.IP, 0, len(answers))
	for _, answer := range answers {
		if answer.Zone != "" {
			return nil, dynamicObservationReasonAddressDenied
		}
		ips = append(ips, answer.IP)
	}
	validated, err := validateDynamicResolvedIPsWithPolicy(ips, selfTargets)
	if err != nil {
		if errors.Is(err, errDynamicSelfTarget) {
			return nil, dynamicObservationReasonSelfTarget
		}
		return nil, dynamicObservationReasonAddressDenied
	}
	return validated, ""
}

func (s *dynamicSiteState) close() {
	if s == nil || s.runtime == nil {
		return
	}
	s.closeOnce.Do(func() {
		runtime := s.runtime
		runtime.mu.Lock()
		defer runtime.mu.Unlock()
		delete(runtime.states, s)
		s.mu.Lock()
		defer s.mu.Unlock()
		for authority := range s.authorities {
			if runtime.authorities[authority] <= 1 {
				delete(runtime.authorities, authority)
			} else {
				runtime.authorities[authority]--
			}
		}
		if count := len(s.capabilities); count > 0 {
			runtime.activeCapabilities -= count
			if runtime.activeCapabilities < 0 {
				runtime.activeCapabilities = 0
			}
		}
		runtime.capabilityMemory -= s.capabilityMemory
		if runtime.capabilityMemory < 0 {
			runtime.capabilityMemory = 0
		}
		s.capabilityMemory = 0
		s.capabilities = nil
		s.capabilityByTarget = nil
		s.learnedPlaybackPaths = nil
		s.authorities = nil
	})
}

func dynamicCanonicalAuthority(target *url.URL) string {
	if target == nil {
		return ""
	}
	scheme := strings.ToLower(target.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	host, _, err := normalizeDynamicHost(target.Hostname())
	if err != nil {
		return ""
	}
	port, ok := dynamicEffectivePort(target)
	if !ok {
		return ""
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}
