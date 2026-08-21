package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func dynamicTransportFailureReason(err error) string {
	var certificateVerification *tls.CertificateVerificationError
	var recordHeader tls.RecordHeaderError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var certificateInvalid x509.CertificateInvalidError
	var systemRoots x509.SystemRootsError
	if errors.As(err, &certificateVerification) || errors.As(err, &recordHeader) ||
		errors.As(err, &unknownAuthority) || errors.As(err, &hostnameError) ||
		errors.As(err, &certificateInvalid) || errors.As(err, &systemRoots) {
		return dynamicObservationReasonTLSFailure
	}
	var networkError *net.OpError
	if errors.As(err, &networkError) {
		return dynamicObservationReasonDialFailure
	}
	return dynamicObservationReasonResponseFailure
}

func dynamicHandledRedirectStatus(status int, profile string) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	case http.StatusSeeOther:
		return profile == dynamicProfileExtreme
	default:
		return false
	}
}

func dynamicRejectedRedirectStatus(status int, profile string) bool {
	return status >= 300 && status < 400 && status != http.StatusNotModified && !dynamicHandledRedirectStatus(status, profile)
}

func singleDynamicLocation(resp *http.Response) (string, bool) {
	if resp == nil {
		return "", false
	}
	values := resp.Header.Values("Location")
	if len(values) != 1 || values[0] == "" || values[0] != strings.TrimSpace(values[0]) {
		return "", false
	}
	return values[0], true
}

func replaceResponseWithMainVideoRedirect(resp *http.Response, target *url.URL) *http.Response {
	if resp == nil || target == nil {
		return resp
	}
	resp = replaceResponseWithMainVideoDirectTarget(resp, target)
	if resp.Request != nil {
		ctx := context.WithValue(resp.Request.Context(), mainVideoDirectResolvedContextKey{}, true)
		resp.Request = resp.Request.WithContext(ctx)
	}
	return resp
}

func replaceResponseWithMainVideoDirectTarget(resp *http.Response, target *url.URL) *http.Response {
	if resp == nil || target == nil {
		return resp
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	resp.StatusCode = http.StatusTemporaryRedirect
	resp.Status = strconv.Itoa(http.StatusTemporaryRedirect) + " " + http.StatusText(http.StatusTemporaryRedirect)
	resp.Header = make(http.Header)
	resp.Header.Set("Location", target.String())
	resp.Header.Set("Cache-Control", "private, no-store")
	resp.Header.Set("Referrer-Policy", "no-referrer")
	resp.Header.Set("Content-Length", "0")
	resp.Body = http.NoBody
	resp.ContentLength = 0
	resp.Trailer = nil
	return resp
}

func mainVideoDirectFallbackTarget(ctx context.Context) *url.URL {
	if ctx == nil {
		return nil
	}
	target, _ := ctx.Value(mainVideoDirectFallbackContextKey{}).(*url.URL)
	return target
}

func mainVideoDirectResponseResolved(resp *http.Response) bool {
	if resp == nil || resp.Request == nil {
		return false
	}
	resolved, _ := resp.Request.Context().Value(mainVideoDirectResolvedContextKey{}).(bool)
	return resolved
}

func newMainVideoDirectFallbackResponse(req *http.Request, target *url.URL) *http.Response {
	if req == nil || target == nil {
		return nil
	}
	resp := &http.Response{
		StatusCode: http.StatusTemporaryRedirect,
		Status:     strconv.Itoa(http.StatusTemporaryRedirect) + " " + http.StatusText(http.StatusTemporaryRedirect),
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}
	return replaceResponseWithMainVideoDirectTarget(resp, target)
}

type dynamicTransportFactory func(*url.URL, []net.IP, *dynamicSelfTargetPolicy) (*http.Transport, error)

type redirectFollowTransport struct {
	base                   http.RoundTripper
	playbackHosts          map[string]bool
	configuredAuthorities  map[string]bool
	disableLegacyRedirects bool
	// Media requests should not make the client walk an intermediate dynamic
	// redirect chain.  Following a validated unknown authority inside the
	// proxy keeps the first byte on the same request and avoids the common
	// Emby 308 -> capability -> 502/context-canceled startup sequence.
	followUnknownRedirects  bool
	policy                  UAHeaderPolicy
	clientIPMode            string
	upstreamHeaderPolicy    upstreamHeaderPolicy
	dynamicTransportFactory dynamicTransportFactory
	dynamicPolicy           dynamicRedirectPolicy
	dynamicState            *dynamicSiteState
	capabilityIssuer        *dynamicCapabilityIssuer
	streamLeaseHeld         bool
	mainVideoDirect         bool
	database                *DB
	siteID                  int64
}

func shouldInternallyFollowDynamicRedirect(r *http.Request) bool {
	if r == nil || r.URL == nil || r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	path := r.URL.Path
	return isPlaybackRequest(path) ||
		isPlaybackRedirectEndpoint(path) ||
		isPlaybackInfoRequest(path) ||
		dynamicStructuredRequestSource(path) != "" ||
		isReservedDynamicRoute(path)
}

func (t *redirectFollowTransport) newDynamicTransport(target *url.URL, pinnedIPs []net.IP, selfTargets *dynamicSelfTargetPolicy) (*http.Transport, error) {
	if t.dynamicTransportFactory != nil {
		return t.dynamicTransportFactory(target, pinnedIPs, selfTargets)
	}
	return newDynamicTransport(target, pinnedIPs, selfTargets)
}

func extremeDynamicRedirectBehavior(status int, method string) (redirectMethod string, replayBody bool) {
	switch status {
	case http.StatusSeeOther:
		if method == http.MethodHead {
			return http.MethodHead, false
		}
		return http.MethodGet, false
	case http.StatusMovedPermanently, http.StatusFound:
		switch method {
		case http.MethodPost:
			return http.MethodGet, false
		case http.MethodGet, http.MethodHead:
			return method, false
		default:
			return method, true
		}
	case http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return method, true
	default:
		return method, false
	}
}

func stripExtremeDynamicRedirectBodyHeaders(header http.Header) {
	for _, name := range []string{
		"Content-Disposition", "Content-Encoding", "Content-Language", "Content-Length",
		"Content-Location", "Content-MD5", "Content-Range", "Content-Type", "Digest",
		"Expect", "Trailer", "Transfer-Encoding",
	} {
		header.Del(name)
	}
}

func (t *redirectFollowTransport) newExtremeCompatibleDynamicRedirectRequest(ctx context.Context, previous *http.Request, status int, target *url.URL) (*http.Request, bool, string) {
	if previous == nil || target == nil {
		return nil, false, dynamicObservationReasonInvalidLocation
	}
	method := previous.Method
	replayBody := false
	stripBodyHeaders := false
	var body io.ReadCloser
	if t.dynamicPolicy.profile == dynamicProfileExtreme {
		method, replayBody = extremeDynamicRedirectBehavior(status, method)
		stripBodyHeaders = !replayBody
		requestHasBody := previous.Body != nil && previous.Body != http.NoBody ||
			previous.ContentLength != 0 || len(previous.TransferEncoding) != 0 || len(previous.Trailer) != 0
		if replayBody && requestHasBody {
			// GetBody is Go's explicit replay contract. Requiring a positive,
			// profile-bounded length and rejecting transfer/trailer framing keeps
			// an unavailable replay from reaching any follow-up authority.
			if previous.Body == nil || previous.Body == http.NoBody || previous.GetBody == nil ||
				previous.ContentLength <= 0 || previous.ContentLength > t.dynamicPolicy.limits.MaxBodyBytes ||
				len(previous.TransferEncoding) != 0 || len(previous.Trailer) != 0 {
				return nil, false, dynamicObservationReasonRedirectBodyReplayDenied
			}
			var err error
			body, err = previous.GetBody()
			if err != nil || body == nil || body == http.NoBody {
				if body != nil {
					_ = body.Close()
				}
				return nil, false, dynamicObservationReasonRedirectBodyReplayDenied
			}
		}
	}
	// #nosec G704 -- callers restrict target to an administrator-configured authority or a normalized, policy-checked, DNS-pinned dynamic URL before this request is sent.
	newRequest, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		if body != nil {
			_ = body.Close()
		}
		return nil, false, dynamicObservationReasonInvalidLocation
	}
	newRequest.Host = target.Host
	if replayBody && body != nil {
		newRequest.GetBody = previous.GetBody
		newRequest.ContentLength = previous.ContentLength
	}
	return newRequest, stripBodyHeaders, ""
}

func prepareExtremeRedirectReplayBody(r *http.Request, state *dynamicSiteState, maxBodyBytes int64) (func(), error) {
	if r == nil || state == nil || r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 || r.GetBody != nil {
		return nil, nil
	}
	// A server request has no GetBody by default. Buffer only a declared,
	// profile-bounded body under the existing global/per-site parse-memory and
	// concurrency budgets; unknown/chunked bodies still reach the configured
	// upstream, but a later body-preserving redirect fails closed.
	if r.ContentLength < 0 || r.ContentLength > maxBodyBytes || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		return nil, nil
	}
	release, acquired := state.acquireParse(r.ContentLength)
	if !acquired {
		return nil, nil
	}
	fail := func(err error) (func(), error) {
		_ = r.Body.Close()
		release()
		return nil, err
	}
	body := make([]byte, int(r.ContentLength))
	if _, err := io.ReadFull(r.Body, body); err != nil {
		return fail(fmt.Errorf("read replayable request body: %w", err))
	}
	var extra [1]byte
	if count, err := r.Body.Read(extra[:]); count != 0 || !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("request body exceeds its declared length")
		}
		return fail(fmt.Errorf("validate replayable request body: %w", err))
	}
	if err := r.Body.Close(); err != nil {
		release()
		return nil, fmt.Errorf("close replayable request body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return release, nil
}

func crossAuthorityHeaders(source http.Header, additionalAllowed ...string) http.Header {
	// Cross-authority requests enter a distinct trust domain. Rebuild only the
	// media negotiation/resume fields plus the Meridian-normalized User-Agent;
	// arbitrary identity, forwarding, and application headers may be secrets.
	allowed := []string{
		"Accept", "Accept-Encoding", "Cache-Control", "If-Modified-Since",
		"If-None-Match", "If-Range", "Pragma", "Range", "User-Agent",
	}
	allowed = append(allowed, additionalAllowed...)
	header := make(http.Header, len(allowed))
	for _, name := range allowed {
		if values := source.Values(name); len(values) > 0 {
			header[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
	stripSensitiveRedirectHeaders(header)
	return header
}

func crossAuthorityRedirectHeaders(source http.Header) http.Header {
	return crossAuthorityHeaders(source)
}

func copyNormalizedClientIPHeaders(destination, source http.Header, mode string) {
	var names []string
	switch mode {
	case clientIPModeBoth:
		names = []string{"X-Real-IP", "X-Forwarded-For"}
	case clientIPModeRealIP:
		names = []string{"X-Real-IP"}
	}
	for _, name := range names {
		if values := source.Values(name); len(values) > 0 {
			destination[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
}

func crossAuthorityRedirectHeadersWithClientIPMode(source http.Header, mode string) http.Header {
	header := crossAuthorityRedirectHeaders(source)
	copyNormalizedClientIPHeaders(header, source, mode)
	return header
}

var dynamicReplayBodyHeaderNames = [...]string{
	"Content-Encoding",
	"Content-Language",
	"Content-MD5",
	"Content-Type",
	"Digest",
}

func copyDynamicReplayBodyHeaders(destination, source http.Header) {
	for _, name := range dynamicReplayBodyHeaderNames {
		if values := source.Values(name); len(values) > 0 {
			destination[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
}

func crossAuthorityRedirectBodyHeaders(source http.Header) http.Header {
	header := crossAuthorityRedirectHeaders(source)
	copyDynamicReplayBodyHeaders(header, source)
	return header
}

func crossAuthorityRedirectBodyHeadersWithClientIPMode(source http.Header, mode string) http.Header {
	header := crossAuthorityRedirectBodyHeaders(source)
	copyNormalizedClientIPHeaders(header, source, mode)
	return header
}

func dynamicRedirectBodyHeaders(source http.Header) http.Header {
	header := dynamicRedirectHeaders(source)
	copyDynamicReplayBodyHeaders(header, source)
	return header
}

func crossAuthorityWebSocketHeaders(source http.Header) http.Header {
	header := crossAuthorityHeaders(
		source,
		"Origin",
		"Sec-WebSocket-Extensions",
		"Sec-WebSocket-Key",
		"Sec-WebSocket-Protocol",
		"Sec-WebSocket-Version",
	)
	// These hop-by-hop fields are generated by Meridian, not copied from the
	// client. Rebuild them after the cross-authority allowlist has run.
	header.Set("Connection", "Upgrade")
	header.Set("Upgrade", "websocket")
	return header
}

func crossAuthorityWebSocketHeadersWithClientIPMode(source http.Header, mode string) http.Header {
	header := crossAuthorityWebSocketHeaders(source)
	copyNormalizedClientIPHeaders(header, source, mode)
	return header
}

func (t *redirectFollowTransport) observe(decision, reasonCode, authority string) {
	t.observeWithStatus(decision, reasonCode, authority, 0)
}

func (t *redirectFollowTransport) observeWithStatus(decision, reasonCode, authority string, redirectStatus int) {
	if t.database == nil || authority == "" {
		return
	}
	targetKind := dynamicObservationTargetDiscovered
	configured := t.configuredAuthorities[authority]
	if !configured {
		for candidate := range t.configuredAuthorities {
			if strings.TrimSuffix(candidate, ":80") == strings.TrimSuffix(authority, ":80") || strings.TrimSuffix(candidate, ":443") == strings.TrimSuffix(authority, ":443") {
				configured = true
				break
			}
		}
	}
	if configured {
		targetKind = dynamicObservationTargetConfigured
	}
	t.database.EnqueueDynamicObservation(dynamicObservationEvent{
		SiteID:             t.siteID,
		CanonicalAuthority: authority,
		Source:             dynamicObservationSourceRedirect,
		TargetKind:         targetKind,
		Decision:           decision,
		ReasonCode:         reasonCode,
		RedirectStatus:     redirectStatus,
	})
}

func (t *redirectFollowTransport) denied(reasonCode, authority string) error {
	t.observe(dynamicObservationDecisionDenied, reasonCode, authority)
	return newDynamicProxyError(reasonCode)
}

func dynamicRedirectURLKey(target *url.URL) string {
	if target == nil {
		return ""
	}
	if normalized, err := normalizeDynamicURL(target.String()); err == nil {
		return normalized.String()
	}
	return target.String()
}

func isManualRedirectEligibleRequest(req *http.Request) bool {
	return req != nil && (req.Method == http.MethodGet || req.Method == http.MethodHead) && !hasUpgradeIntent(req) && req.URL != nil && !isReservedDynamicRoute(req.URL.Path)
}

func manualHandledRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func (t *redirectFollowTransport) roundTripLegacy(req *http.Request, resp *http.Response) (*http.Response, error) {
	if !isManualRedirectEligibleRequest(req) {
		return resp, nil
	}
	visited := map[string]struct{}{dynamicRedirectURLKey(req.URL): {}}
	for followed := 0; followed < manualRedirectMaxHops; followed++ {
		if !manualHandledRedirectStatus(resp.StatusCode) {
			break
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			break
		}
		locURL, err := url.Parse(loc)
		if err != nil {
			break
		}
		locURL = req.URL.ResolveReference(locURL)
		locURL.Scheme = strings.ToLower(locURL.Scheme)
		if (locURL.Scheme != "http" && locURL.Scheme != "https") || locURL.User != nil || locURL.Fragment != "" || locURL.RawFragment != "" || !t.playbackHosts[redirectHostKey(locURL)] {
			if authority := dynamicCanonicalAuthority(locURL); authority != "" {
				t.observeWithStatus(dynamicObservationDecisionDenied, dynamicObservationReasonInvalidLocation, authority, resp.StatusCode)
			}
			break
		}
		key := dynamicRedirectURLKey(locURL)
		if followed > 0 {
			if _, seen := visited[key]; seen {
				break
			}
		}
		redirectStatus := resp.StatusCode
		resp.Body.Close()
		// #nosec G704 -- the redirect authority must match an administrator-configured playback authority.
		newReq, err := http.NewRequestWithContext(req.Context(), req.Method, locURL.String(), nil)
		if err != nil {
			break
		}
		newReq.Host = locURL.Host
		if !sameRedirectAuthority(req.URL, locURL) {
			newReq.Header = crossAuthorityRedirectHeadersWithClientIPMode(req.Header, t.clientIPMode)
		} else {
			newReq.Header = req.Header.Clone()
		}
		applyUAHeaderPolicy(newReq.Header, t.policy)
		t.upstreamHeaderPolicy.apply(newReq.Header, locURL)
		if tracker := backendAddressTrackerFromContext(newReq.Context()); tracker != nil {
			tracker.SetURL(locURL)
		}
		resp, err = t.base.RoundTrip(newReq)
		if err != nil {
			return nil, err
		}
		visited[key] = struct{}{}
		t.observeWithStatus(dynamicObservationDecisionAllowed, dynamicObservationReasonRedirectAllowed, dynamicCanonicalAuthority(locURL), redirectStatus)
		req = newReq
	}
	return resp, nil
}

func (t *redirectFollowTransport) roundTripDynamic(req *http.Request, resp *http.Response) (*http.Response, error) {
	var selfTargets *dynamicSelfTargetPolicy
	if t.dynamicState != nil && t.dynamicState.runtime != nil {
		selfTargets = t.dynamicState.runtime.selfTargets.Load()
	}
	dynamicActive := false
	redirectsFollowed := 0
	visited := map[string]struct{}{dynamicRedirectURLKey(req.URL): struct{}{}}
	var currentTransport *http.Transport
	var streamRelease func()
	streamLeaseHeld := t.streamLeaseHeld
	lease := &dynamicAuthorityLease{}

	closeResponse := func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if currentTransport != nil {
			currentTransport.CloseIdleConnections()
			currentTransport = nil
		}
	}
	expectedStructuredSource, _ := req.Context().Value(dynamicExpectedStructuredSourceContextKey{}).(string)
	fail := func(reasonCode, authority string) (*http.Response, error) {
		closeResponse()
		lease.rollback()
		if streamRelease != nil {
			streamRelease()
			streamRelease = nil
		}
		return nil, t.denied(reasonCode, authority)
	}
	for {
		if resp == nil {
			return fail(dynamicObservationReasonResponseFailure, dynamicCanonicalAuthority(req.URL))
		}
		if dynamicRejectedRedirectStatus(resp.StatusCode, t.dynamicPolicy.profile) {
			return fail(dynamicObservationReasonUnsupportedStatus, dynamicCanonicalAuthority(req.URL))
		}
		if !dynamicHandledRedirectStatus(resp.StatusCode, t.dynamicPolicy.profile) {
			if !dynamicActive {
				return resp, nil
			}
			if resp.StatusCode == http.StatusSwitchingProtocols {
				return fail(dynamicObservationReasonResponseFailure, dynamicCanonicalAuthority(req.URL))
			}
			if resp.Body == nil {
				resp.Body = http.NoBody
			}
			transport := currentTransport
			currentTransport = nil
			release := streamRelease
			streamRelease = nil
			resp.Body = &dynamicResponseBody{
				ReadCloser: resp.Body,
				trailers:   &resp.Trailer,
				release: func() {
					if transport != nil {
						transport.CloseIdleConnections()
					}
					lease.rollbackOnBodyClose()
					if release != nil {
						release()
					}
				},
			}
			markDynamicResponse(resp, lease, expectedStructuredSource)
			return resp, nil
		}

		location, ok := singleDynamicLocation(resp)
		if !ok {
			return fail(dynamicObservationReasonInvalidLocation, dynamicCanonicalAuthority(req.URL))
		}
		locationURL, err := url.Parse(location)
		if err != nil {
			return fail(dynamicObservationReasonInvalidLocation, dynamicCanonicalAuthority(req.URL))
		}
		locationURL = req.URL.ResolveReference(locationURL)
		locationURL.Scheme = strings.ToLower(locationURL.Scheme)
		manualAuthority := redirectHostKey(locationURL)
		sameAuthority := sameRedirectAuthority(req.URL, locationURL)
		unknownAuthority := !sameAuthority && !t.configuredAuthorities[manualAuthority]
		directMainVideo := t.mainVideoDirect && expectedStructuredSource != dynamicDiscoverySourceHLS && expectedStructuredSource != dynamicDiscoverySourceDASH && (isMainVideoStreamRequest(req) || isMainVideoStreamURL(locationURL))
		if directMainVideo && !unknownAuthority && locationURL.User == nil && (locationURL.Scheme == "http" || locationURL.Scheme == "https") {
			if tracker := backendAddressTrackerFromContext(req.Context()); tracker != nil {
				tracker.SetURL(locationURL)
			}
			return replaceResponseWithMainVideoRedirect(resp, locationURL), nil
		}
		if !dynamicActive && sameAuthority {
			observationAuthority := dynamicCanonicalAuthority(locationURL)
			if observationAuthority == "" {
				observationAuthority = dynamicCanonicalAuthority(req.URL)
			}
			if locationURL.User != nil || locationURL.Scheme != "http" && locationURL.Scheme != "https" {
				return fail(dynamicObservationReasonInvalidLocation, observationAuthority)
			}
			key := dynamicRedirectURLKey(locationURL)
			if _, seen := visited[key]; seen {
				return fail(dynamicObservationReasonRedirectLoop, observationAuthority)
			}
			if redirectsFollowed >= t.dynamicPolicy.limits.MaxRedirects {
				return fail(dynamicObservationReasonHopLimit, observationAuthority)
			}
			newReq, stripBodyHeaders, reasonCode := t.newExtremeCompatibleDynamicRedirectRequest(req.Context(), req, resp.StatusCode, locationURL)
			if reasonCode != "" {
				return fail(reasonCode, observationAuthority)
			}
			newReq.Header = req.Header.Clone()
			applyUAHeaderPolicy(newReq.Header, t.policy)
			t.upstreamHeaderPolicy.apply(newReq.Header, locationURL)
			if stripBodyHeaders {
				stripExtremeDynamicRedirectBodyHeaders(newReq.Header)
			}
			if tracker := backendAddressTrackerFromContext(newReq.Context()); tracker != nil {
				tracker.SetURL(locationURL)
			}
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			// #nosec G704 -- this redirect remains on the already configured upstream authority.
			resp, err = t.base.RoundTrip(newReq)
			if err != nil {
				return nil, err
			}
			req = newReq
			redirectsFollowed++
			visited[key] = struct{}{}
			continue
		}

		if !dynamicActive && !unknownAuthority {
			if t.disableLegacyRedirects || !t.playbackHosts[manualAuthority] || redirectsFollowed >= manualRedirectMaxHops {
				return resp, nil
			}
			newReq, stripBodyHeaders, reasonCode := t.newExtremeCompatibleDynamicRedirectRequest(req.Context(), req, resp.StatusCode, locationURL)
			if reasonCode != "" {
				return fail(reasonCode, dynamicCanonicalAuthority(req.URL))
			}
			if !sameRedirectAuthority(req.URL, locationURL) {
				if newReq.Body != nil {
					newReq.Header = crossAuthorityRedirectBodyHeadersWithClientIPMode(req.Header, t.clientIPMode)
				} else {
					newReq.Header = crossAuthorityRedirectHeadersWithClientIPMode(req.Header, t.clientIPMode)
				}
			} else {
				newReq.Header = req.Header.Clone()
			}
			applyUAHeaderPolicy(newReq.Header, t.policy)
			t.upstreamHeaderPolicy.apply(newReq.Header, locationURL)
			if stripBodyHeaders {
				stripExtremeDynamicRedirectBodyHeaders(newReq.Header)
			}
			if tracker := backendAddressTrackerFromContext(newReq.Context()); tracker != nil {
				tracker.SetURL(locationURL)
			}
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			// #nosec G704 -- the redirect authority must match an administrator-configured playback authority.
			resp, err = t.base.RoundTrip(newReq)
			if err != nil {
				return nil, err
			}
			req = newReq
			redirectsFollowed++
			visited[dynamicRedirectURLKey(locationURL)] = struct{}{}
			continue
		}

		if !t.dynamicPolicy.sourceEnabled(dynamicDiscoverySourceRedirect) {
			return fail(dynamicObservationReasonUnsupportedStatus, dynamicCanonicalAuthority(req.URL))
		}
		normalized, err := normalizeDynamicURL(locationURL.String())
		if err != nil {
			return fail(dynamicObservationReasonInvalidLocation, dynamicCanonicalAuthority(req.URL))
		}
		authority := dynamicCanonicalAuthority(normalized)
		if !t.dynamicPolicy.available {
			return fail(dynamicObservationReasonRuntimeUnavailable, authority)
		}
		key := normalized.String()
		if _, seen := visited[key]; seen {
			return fail(dynamicObservationReasonRedirectLoop, authority)
		}
		if redirectsFollowed >= t.dynamicPolicy.limits.MaxRedirects {
			return fail(dynamicObservationReasonHopLimit, authority)
		}
		if directMainVideo {
			if reasonCode := t.dynamicPolicy.validateTarget(req.URL, normalized, selfTargets); reasonCode != "" {
				return fail(reasonCode, authority)
			}
			reservation, reasonCode := t.dynamicState.reserveAuthority(authority, time.Now())
			if reasonCode != "" {
				return fail(reasonCode, authority)
			}
			if _, reasonCode = reservation.resolve(req.Context(), normalized, selfTargets); reasonCode != "" {
				reservation.rollback()
				return fail(reasonCode, authority)
			}
			reservation.commit()
			if tracker := backendAddressTrackerFromContext(req.Context()); tracker != nil {
				tracker.SetURL(normalized)
			}
			t.observe(dynamicObservationDecisionAllowed, dynamicObservationReasonRedirectAllowed, authority)
			return replaceResponseWithMainVideoRedirect(resp, normalized), nil
		}
		if t.followUnknownRedirects && shouldInternallyFollowDynamicRedirect(req) {
			if reasonCode := t.dynamicPolicy.validateTarget(req.URL, normalized, selfTargets); reasonCode != "" {
				return fail(reasonCode, authority)
			}
			reservation, reasonCode := t.dynamicState.reserveAuthority(authority, time.Now())
			if reasonCode != "" {
				return fail(reasonCode, authority)
			}
			pinnedIPs, reasonCode := reservation.resolve(req.Context(), normalized, selfTargets)
			if reasonCode != "" {
				reservation.rollback()
				return fail(reasonCode, authority)
			}
			transport, err := t.newDynamicTransport(normalized, pinnedIPs, selfTargets)
			if err != nil {
				reservation.rollback()
				if errors.Is(err, errDynamicSelfTarget) {
					return fail(dynamicObservationReasonSelfTarget, authority)
				}
				return fail(dynamicObservationReasonAddressDenied, authority)
			}
			if !streamLeaseHeld {
				var acquired bool
				streamRelease, acquired = t.dynamicState.acquireStream()
				if !acquired {
					transport.CloseIdleConnections()
					reservation.rollback()
					return fail(dynamicObservationReasonCapacityLimit, authority)
				}
				streamLeaseHeld = true
			}
			newReq, stripBodyHeaders, reasonCode := t.newExtremeCompatibleDynamicRedirectRequest(isolateDynamicOutboundContext(req.Context()), req, resp.StatusCode, normalized)
			if reasonCode != "" {
				transport.CloseIdleConnections()
				reservation.rollback()
				return fail(reasonCode, authority)
			}
			newReq.Close = true
			if newReq.Body != nil {
				newReq.Header = dynamicRedirectBodyHeaders(req.Header)
			} else {
				newReq.Header = dynamicRedirectHeaders(req.Header)
			}
			if stripBodyHeaders {
				stripExtremeDynamicRedirectBodyHeaders(newReq.Header)
			}
			if tracker := backendAddressTrackerFromContext(newReq.Context()); tracker != nil {
				tracker.SetURL(normalized)
			}
			closeResponse()
			resp = nil
			newResp, roundTripErr := transport.RoundTrip(newReq)
			if roundTripErr != nil {
				if newResp != nil && newResp.Body != nil {
					_ = newResp.Body.Close()
				}
				transport.CloseIdleConnections()
				reservation.rollback()
				return fail(dynamicTransportFailureReason(roundTripErr), authority)
			}
			if newResp == nil {
				transport.CloseIdleConnections()
				reservation.rollback()
				return fail(dynamicObservationReasonResponseFailure, authority)
			}
			newResp.Request = newReq
			lease.add(reservation)
			t.observe(dynamicObservationDecisionAllowed, dynamicObservationReasonRedirectAllowed, authority)
			currentTransport = transport
			resp = newResp
			req = newReq
			dynamicActive = true
			redirectsFollowed++
			visited[key] = struct{}{}
			continue
		}

		if t.capabilityIssuer != nil && (req.Method == http.MethodGet || req.Method == http.MethodHead) {
			route, discoveryErr := t.capabilityIssuer.mint(req.Context(), req.URL, normalized, dynamicDiscoverySourceRedirect)
			if discoveryErr != nil {
				return fail(discoveryErr.reasonCode, authority)
			}
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			resp.Body = http.NoBody
			resp.ContentLength = 0
			resp.Trailer = nil
			for _, name := range []string{"Content-Encoding", "Content-Language", "Content-MD5", "Content-Range", "Content-Type", "Digest", "ETag", "Last-Modified", "Trailer", "Transfer-Encoding"} {
				resp.Header.Del(name)
			}
			resp.Header.Set("Content-Length", "0")
			resp.Header.Set("Location", route)
			t.observe(dynamicObservationDecisionAllowed, dynamicObservationReasonRedirectAllowed, authority)
			markDynamicResponse(resp, nil, expectedStructuredSource)
			return resp, nil
		}
		if reasonCode := t.dynamicPolicy.validateTarget(req.URL, normalized, selfTargets); reasonCode != "" {
			return fail(reasonCode, authority)
		}
		reservation, reasonCode := t.dynamicState.reserveAuthority(authority, time.Now())
		if reasonCode != "" {
			return fail(reasonCode, authority)
		}
		pinnedIPs, reasonCode := reservation.resolve(req.Context(), normalized, selfTargets)
		if reasonCode != "" {
			reservation.rollback()
			return fail(reasonCode, authority)
		}
		transport, err := t.newDynamicTransport(normalized, pinnedIPs, selfTargets)
		if err != nil {
			reservation.rollback()
			if errors.Is(err, errDynamicSelfTarget) {
				return fail(dynamicObservationReasonSelfTarget, authority)
			}
			return fail(dynamicObservationReasonAddressDenied, authority)
		}
		if !streamLeaseHeld {
			var acquired bool
			streamRelease, acquired = t.dynamicState.acquireStream()
			if !acquired {
				transport.CloseIdleConnections()
				reservation.rollback()
				return fail(dynamicObservationReasonCapacityLimit, authority)
			}
			streamLeaseHeld = true
		}

		// #nosec G704 -- target is normalized, policy-checked, DNS-pinned, and sent through a dedicated proxy-free transport.
		newReq, stripBodyHeaders, reasonCode := t.newExtremeCompatibleDynamicRedirectRequest(isolateDynamicOutboundContext(req.Context()), req, resp.StatusCode, normalized)
		if reasonCode != "" {
			transport.CloseIdleConnections()
			reservation.rollback()
			return fail(reasonCode, authority)
		}
		newReq.Close = true
		if newReq.Body != nil {
			newReq.Header = dynamicRedirectBodyHeaders(req.Header)
		} else {
			newReq.Header = dynamicRedirectHeaders(req.Header)
		}
		if stripBodyHeaders {
			stripExtremeDynamicRedirectBodyHeaders(newReq.Header)
		}
		if tracker := backendAddressTrackerFromContext(newReq.Context()); tracker != nil {
			tracker.SetURL(normalized)
		}
		closeResponse()
		resp = nil
		newResp, roundTripErr := transport.RoundTrip(newReq)
		if roundTripErr != nil {
			if newResp != nil && newResp.Body != nil {
				_ = newResp.Body.Close()
			}
			transport.CloseIdleConnections()
			reservation.rollback()
			return fail(dynamicTransportFailureReason(roundTripErr), authority)
		}
		if newResp == nil {
			transport.CloseIdleConnections()
			reservation.rollback()
			return fail(dynamicObservationReasonResponseFailure, authority)
		}
		newResp.Request = newReq
		lease.add(reservation)
		t.observe(dynamicObservationDecisionAllowed, dynamicObservationReasonRedirectAllowed, authority)
		currentTransport = transport
		resp = newResp
		req = newReq
		dynamicActive = true
		redirectsFollowed++
		visited[key] = struct{}{}
	}
}

func (t *redirectFollowTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	directFallback := mainVideoDirectFallbackTarget(req.Context())
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		if t.mainVideoDirect && directFallback != nil {
			if tracker := backendAddressTrackerFromContext(req.Context()); tracker != nil {
				tracker.SetURL(directFallback)
			}
			return newMainVideoDirectFallbackResponse(req, directFallback), nil
		}
		if t.database != nil && req != nil && req.URL != nil && t.dynamicPolicy.configured {
			authority := dynamicCanonicalAuthority(req.URL)
			t.database.EnqueueDynamicObservation(dynamicObservationEvent{
				SiteID: t.siteID, CanonicalAuthority: authority, Source: dynamicObservationSourceRedirect,
				TargetKind: dynamicObservationTargetSameAuthority, Decision: dynamicObservationDecisionDenied,
				ReasonCode: dynamicObservationReasonResponseFailure, RedirectStatus: 0,
			})
		}
		return nil, err
	}
	if t.mainVideoDirect && directFallback != nil {
		if t.dynamicPolicy.configured && t.dynamicPolicy.sourceEnabled(dynamicDiscoverySourceRedirect) {
			resolved, resolveErr := t.roundTripDynamic(req, resp)
			if resolveErr != nil {
				return nil, resolveErr
			}
			if mainVideoDirectResponseResolved(resolved) {
				return resolved, nil
			}
			resp = resolved
		}
		if tracker := backendAddressTrackerFromContext(req.Context()); tracker != nil {
			tracker.SetURL(directFallback)
		}
		return replaceResponseWithMainVideoDirectTarget(resp, directFallback), nil
	}
	eligible, _ := req.Context().Value(dynamicRequestEligibleContextKey{}).(bool)
	if (req.Method != http.MethodGet && req.Method != http.MethodHead) && len(t.playbackHosts) > 0 {
		return resp, nil
	}
	manualAllowed := len(t.playbackHosts) > 0 && (!eligible || !t.dynamicPolicy.configured || !t.dynamicPolicy.sourceEnabled(dynamicDiscoverySourceRedirect))
	if manualAllowed {
		resp, err = t.roundTripLegacy(req, resp)
		if err != nil {
			return nil, err
		}
	}
	if !t.dynamicPolicy.configured {
		return resp, nil
	}
	if !eligible || !t.dynamicPolicy.sourceEnabled(dynamicDiscoverySourceRedirect) {
		return resp, nil
	}
	return t.roundTripDynamic(req, resp)
}
