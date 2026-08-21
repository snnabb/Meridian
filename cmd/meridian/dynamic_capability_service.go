package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

func dynamicRedirectHeaders(source http.Header) http.Header {
	allowed := []string{"Accept", "Accept-Encoding", "Range", "If-Range"}
	header := make(http.Header, len(allowed)+1)
	for _, name := range allowed {
		if values := source.Values(name); len(values) > 0 {
			header[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
	if userAgent := strings.TrimSpace(source.Get("User-Agent")); userAgent != "" {
		header.Set("User-Agent", userAgent)
	} else {
		header.Set("User-Agent", dynamicRedirectUserAgent)
	}
	return header
}

func validDynamicRetryAfter(values []string, now time.Time) string {
	if len(values) != 1 {
		return ""
	}
	value := strings.TrimSpace(values[0])
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds >= 0 && seconds <= 24*60*60 {
			return strconv.FormatInt(seconds, 10)
		}
		return ""
	}
	deadline, err := http.ParseTime(value)
	if err != nil || deadline.Before(now.Add(-time.Minute)) || deadline.After(now.Add(24*time.Hour)) {
		return ""
	}
	return deadline.UTC().Format(http.TimeFormat)
}

func rebuildDynamicResponseHeaders(resp *http.Response) {
	if resp == nil {
		return
	}
	redirectLocation := dynamicCapabilityRedirectLocation(resp)
	allowed := []string{
		"Accept-Ranges", "Content-Disposition", "Content-Encoding", "Content-Language",
		"Content-Length", "Content-Range", "Content-Type", "Date", "ETag", "Last-Modified",
	}
	retryAfter := validDynamicRetryAfter(resp.Header.Values("Retry-After"), time.Now())
	header := make(http.Header, len(allowed)+4)
	for _, name := range allowed {
		if values := resp.Header.Values(name); len(values) > 0 {
			header[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
	if retryAfter != "" {
		header.Set("Retry-After", retryAfter)
	}
	if redirectLocation != "" {
		header.Set("Location", redirectLocation)
	}
	if resp.ContentLength >= 0 && header.Get("Content-Length") == "" {
		header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	if contentType := strings.ToLower(header.Get("Content-Type")); strings.HasPrefix(contentType, "text/html") || strings.HasPrefix(contentType, "application/xhtml+xml") {
		header.Set("Content-Type", "text/plain; charset=utf-8")
		header.Set("Content-Disposition", "attachment")
	}
	header.Set("Cache-Control", "private, no-store")
	header.Set("Content-Security-Policy", "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	resp.Trailer = nil
	resp.Header = header
}

func dynamicCapabilityRedirectLocation(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return ""
	}
	location, ok := singleDynamicLocation(resp)
	if !ok {
		return ""
	}
	parsed, err := url.ParseRequestURI(location)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" || parsed.RawPath != "" || parsed.RawQuery != "" || !isReservedDynamicRoute(parsed.Path) {
		return ""
	}
	return location
}

type dynamicAuthorityLeaseContextKey struct{}

func markDynamicResponse(resp *http.Response, lease *dynamicAuthorityLease, expectedSource string) {
	if resp == nil || resp.Request == nil {
		return
	}
	ctx := context.WithValue(resp.Request.Context(), dynamicResponseContextKey{}, true)
	if lease != nil {
		ctx = context.WithValue(ctx, dynamicAuthorityLeaseContextKey{}, lease)
	}
	if expectedSource != "" {
		ctx = context.WithValue(ctx, dynamicExpectedStructuredSourceContextKey{}, expectedSource)
	}
	resp.Request = resp.Request.WithContext(ctx)
}

func responseIsDynamic(resp *http.Response) bool {
	if resp == nil || resp.Request == nil {
		return false
	}
	marked, _ := resp.Request.Context().Value(dynamicResponseContextKey{}).(bool)
	return marked
}

func dynamicResponseExpectedStructuredSource(resp *http.Response) string {
	if resp == nil || resp.Request == nil {
		return ""
	}
	source, _ := resp.Request.Context().Value(dynamicExpectedStructuredSourceContextKey{}).(string)
	return source
}

func dynamicResponseAuthorityLease(resp *http.Response) *dynamicAuthorityLease {
	if resp == nil || resp.Request == nil {
		return nil
	}
	lease, _ := resp.Request.Context().Value(dynamicAuthorityLeaseContextKey{}).(*dynamicAuthorityLease)
	return lease
}

func commitDynamicResponseAuthorities(resp *http.Response) {
	dynamicResponseAuthorityLease(resp).commit()
}

func rollbackDynamicResponseAuthorities(resp *http.Response) {
	dynamicResponseAuthorityLease(resp).rollback()
}

type dynamicResponseBody struct {
	io.ReadCloser
	once     sync.Once
	release  func()
	trailers *http.Header
}

func (b *dynamicResponseBody) clearTrailers() {
	if b.trailers != nil {
		*b.trailers = nil
	}
}

func (b *dynamicResponseBody) Read(payload []byte) (int, error) {
	count, err := b.ReadCloser.Read(payload)
	if err != nil {
		// net/http populates Response.Trailer only when the chunked body reaches
		// EOF. Clear it before ReverseProxy observes and forwards late trailers.
		b.clearTrailers()
	}
	return count, err
}

func (b *dynamicResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.clearTrailers()
	b.once.Do(func() {
		if b.release != nil {
			b.release()
		}
	})
	return err
}

func writeDynamicCapabilityUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"error":"dynamic route unavailable"}`))
}

func copyDynamicResponse(w http.ResponseWriter, resp *http.Response, method string) error {
	if resp == nil {
		return fmt.Errorf("dynamic response is unavailable")
	}
	rebuildDynamicResponseHeaders(resp)
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if method == http.MethodHead || resp.Body == nil {
		return nil
	}
	// codeql[go/reflected-xss] -- dynamic responses are restricted to capability-authorized upstream data and hardened with CSP sandbox, no-store, nosniff, and non-active HTML content handling.
	_, err := io.Copy(w, resp.Body)
	return err
}

var dashTemplateExpressionPattern = regexp.MustCompile(`^(RepresentationID|Number|SubNumber|Bandwidth|Time)(?:%0([1-9][0-9]?)([diouxX]))?$`)
var dynamicPathIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)
var dashDecimalTemplateValuePattern = regexp.MustCompile(`^[0-9]{1,20}$`)
var dashOctalTemplateValuePattern = regexp.MustCompile(`^[0-7]{1,20}$`)
var dashLowerHexTemplateValuePattern = regexp.MustCompile(`^[0-9a-f]{1,20}$`)
var dashUpperHexTemplateValuePattern = regexp.MustCompile(`^[0-9A-F]{1,20}$`)

func validDynamicPathIdentifier(value string) bool {
	return dynamicPathIdentifierPattern.MatchString(value) && !strings.Contains(value, "..")
}

func isDASHPCharByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || strings.ContainsRune("-._~!$&'()*+,;=:@", rune(value))
}

func dashHexByte(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func validDASHRepresentationID(value string) bool {
	if value == "" || len(value) > maxDynamicTargetURLBytes || value == "." || value == ".." {
		return false
	}
	for offset := 0; offset < len(value); {
		if value[offset] != '%' {
			if !isDASHPCharByte(value[offset]) {
				return false
			}
			offset++
			continue
		}
		if offset+2 >= len(value) {
			return false
		}
		high, highOK := dashHexByte(value[offset+1])
		low, lowOK := dashHexByte(value[offset+2])
		if !highOK || !lowOK {
			return false
		}
		decoded := high<<4 | low
		if decoded != '%' && !isDASHPCharByte(decoded) {
			return false
		}
		offset += 3
	}
	return true
}

func dashTemplateIdentifier(expression string) string {
	match := dashTemplateExpressionPattern.FindStringSubmatch(expression)
	if match == nil || match[1] == "RepresentationID" && match[2] != "" {
		return ""
	}
	if match[2] != "" {
		width, err := strconv.Atoi(match[2])
		if err != nil || width > 20 {
			return ""
		}
	}
	return match[1]
}

func validDASHTemplateValue(expression, value string) bool {
	match := dashTemplateExpressionPattern.FindStringSubmatch(expression)
	identifier := dashTemplateIdentifier(expression)
	if match == nil || identifier == "" || identifier == "RepresentationID" || identifier == "Bandwidth" {
		return false
	}
	if match[2] != "" {
		width, err := strconv.Atoi(match[2])
		if err != nil || len(value) < width {
			return false
		}
	}
	base := 10
	validLexically := false
	switch match[3] {
	case "o":
		base = 8
		validLexically = dashOctalTemplateValuePattern.MatchString(value)
	case "x":
		base = 16
		validLexically = dashLowerHexTemplateValuePattern.MatchString(value)
	case "X":
		base = 16
		validLexically = dashUpperHexTemplateValuePattern.MatchString(value)
	default:
		validLexically = dashDecimalTemplateValuePattern.MatchString(value)
	}
	if !validLexically {
		return false
	}
	_, err := strconv.ParseUint(value, base, 64)
	return err == nil
}

func parseDASHVariableTemplateValue(expression, value string) (uint64, bool) {
	if !validDASHTemplateValue(expression, value) {
		return 0, false
	}
	match := dashTemplateExpressionPattern.FindStringSubmatch(expression)
	base := 10
	switch match[3] {
	case "o":
		base = 8
	case "x", "X":
		base = 16
	}
	parsed, err := strconv.ParseUint(value, base, 64)
	return parsed, err == nil
}

func restoreDASHLiteralDollarClaim(source, value string) string {
	if source != dynamicDiscoverySourceDASH {
		return value
	}
	return strings.ReplaceAll(value, dashLiteralDollarClaimMarker, "$")
}

func restoreDASHFixedTemplateClaims(claims dynamicCapabilityClaims) (string, error) {
	if len(claims.TemplateFixed) == 0 {
		return claims.Target, nil
	}
	if claims.Source != dynamicDiscoverySourceDASH || len(claims.TemplateFixed) > 64 {
		return "", fmt.Errorf("fixed DASH template claims are not allowed")
	}
	parsed, err := url.Parse(claims.Target)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" || parsed.Opaque != "" {
		return "", fmt.Errorf("invalid fixed DASH template target")
	}
	value := claims.Target
	for index, fixedValue := range claims.TemplateFixed {
		if !validDASHRepresentationID(fixedValue) {
			return "", fmt.Errorf("invalid fixed DASH template value")
		}
		marker := dashFixedTemplateClaimMarker(index)
		inHost := strings.Count(parsed.Host, marker)
		inPath := strings.Count(parsed.EscapedPath(), marker)
		inQuery := strings.Count(parsed.RawQuery, marker)
		if inHost+inPath+inQuery != 1 {
			return "", fmt.Errorf("fixed DASH template marker does not match its claims")
		}
		value = strings.Replace(value, marker, fixedValue, 1)
	}
	return value, nil
}

func resolveDASHCapabilityTarget(claims dynamicCapabilityClaims, suffix string) (*url.URL, error) {
	if len(claims.Template) == 0 {
		reconstructed, err := restoreDASHFixedTemplateClaims(claims)
		if err != nil {
			return nil, err
		}
		if suffix != "" {
			return nil, fmt.Errorf("unexpected capability suffix")
		}
		targetText := restoreDASHLiteralDollarClaim(claims.Source, reconstructed)
		if claims.Trusted {
			target, err := normalizeTrustedCapabilityURL(targetText)
			if err != nil || len(claims.TemplateFixed) == 0 && target.String() != targetText {
				return nil, fmt.Errorf("invalid trusted capability target")
			}
			return target, nil
		}
		target, err := normalizeDynamicURL(targetText)
		if err != nil || len(claims.TemplateFixed) == 0 && target.String() != targetText {
			return nil, fmt.Errorf("invalid capability target")
		}
		return target, nil
	}
	if len(claims.Template) > 64 || suffix == "" {
		return nil, fmt.Errorf("invalid capability template")
	}
	segments := strings.Split(suffix, "/")
	if len(segments) != len(claims.Template) {
		return nil, fmt.Errorf("invalid capability template values")
	}
	values := make([]string, len(segments))
	consistent := make(map[string]uint64)
	for index, expression := range claims.Template {
		identifier := dashTemplateIdentifier(expression)
		prefix := "v" + strconv.Itoa(index) + "-"
		if identifier == "" || !strings.HasPrefix(segments[index], prefix) {
			return nil, fmt.Errorf("invalid capability template expression")
		}
		value := strings.TrimPrefix(segments[index], prefix)
		parsedValue, valid := parseDASHVariableTemplateValue(expression, value)
		if !valid {
			return nil, fmt.Errorf("invalid DASH template value")
		}
		if existing, ok := consistent[identifier]; ok && existing != parsedValue {
			return nil, fmt.Errorf("inconsistent DASH template value")
		}
		consistent[identifier] = parsedValue
		values[index] = value
	}
	reconstructed := claims.Target
	searchFrom := 0
	var output strings.Builder
	output.Grow(len(reconstructed))
	for index, expression := range claims.Template {
		needle := "$" + expression + "$"
		relative := strings.Index(reconstructed[searchFrom:], needle)
		if relative < 0 {
			return nil, fmt.Errorf("capability template does not match its claims")
		}
		position := searchFrom + relative
		if strings.Contains(reconstructed[searchFrom:position], "$") {
			return nil, fmt.Errorf("capability template contains an unknown expression")
		}
		output.WriteString(reconstructed[searchFrom:position])
		output.WriteString(values[index])
		searchFrom = position + len(needle)
	}
	if strings.Contains(reconstructed[searchFrom:], "$") {
		return nil, fmt.Errorf("capability template contains an unknown expression")
	}
	output.WriteString(reconstructed[searchFrom:])
	expandedClaims := claims
	expandedClaims.Target = output.String()
	targetText, err := restoreDASHFixedTemplateClaims(expandedClaims)
	if err != nil {
		return nil, err
	}
	targetText = restoreDASHLiteralDollarClaim(claims.Source, targetText)
	var target *url.URL
	if claims.Trusted {
		target, err = normalizeTrustedCapabilityURL(targetText)
	} else {
		target, err = normalizeDynamicURL(targetText)
	}
	if err != nil || len(claims.TemplateFixed) == 0 && target.String() != targetText {
		return nil, fmt.Errorf("invalid expanded capability target")
	}
	return target, nil
}

var hlsThroughputDirectivePattern = regexp.MustCompile(`^[0-9]{1,20}(?:\.[0-9]{1,6})?$`)
var hlsOffsetDirectivePattern = regexp.MustCompile(`^-?[0-9]{1,20}(?:\.[0-9]{1,6})?$`)

func applyHLSCapabilityDirectives(target *url.URL, claims dynamicCapabilityClaims, rawQuery string) (*url.URL, error) {
	if rawQuery == "" {
		return target, nil
	}
	if target == nil {
		return nil, fmt.Errorf("capability target is missing")
	}
	// Some Emby clients append their normal API authentication query parameters
	// to every request, including capability URLs. Those parameters must not
	// alter or cross into the signed target; only LL-HLS manifests may add the
	// explicitly validated delivery directives below.
	if claims.Source != dynamicDiscoverySourceHLS || claims.Kind != dynamicCapabilityKindManifest || len(claims.Template) != 0 || len(claims.TemplateFixed) != 0 || len(rawQuery) > 2048 {
		return target, nil
	}
	directives, err := url.ParseQuery(rawQuery)
	if err != nil || len(directives) == 0 {
		return nil, fmt.Errorf("invalid HLS delivery directives")
	}
	for key, values := range directives {
		if len(values) != 1 {
			return nil, fmt.Errorf("duplicate HLS delivery directive")
		}
		value := values[0]
		switch key {
		case "_HLS_skip":
			if value != "YES" && value != "v2" {
				return nil, fmt.Errorf("invalid HLS skip directive")
			}
		case "_HLS_msn", "_HLS_part":
			if !dashDecimalTemplateValuePattern.MatchString(value) {
				return nil, fmt.Errorf("invalid HLS numeric directive")
			}
		case "_HLS_pathway", "_HLS_interstitial_id", "_HLS_primary_id":
			if !validDynamicPathIdentifier(value) {
				return nil, fmt.Errorf("invalid HLS identifier directive")
			}
		case "_HLS_throughput":
			if !hlsThroughputDirectivePattern.MatchString(value) {
				return nil, fmt.Errorf("invalid HLS throughput directive")
			}
		case "_HLS_start_offset":
			if !hlsOffsetDirectivePattern.MatchString(value) {
				return nil, fmt.Errorf("invalid HLS offset directive")
			}
		default:
			return nil, fmt.Errorf("unsupported capability query parameter")
		}
	}
	merged, err := url.ParseQuery(target.RawQuery)
	if err != nil || target.RawQuery != merged.Encode() {
		return nil, fmt.Errorf("signed target query does not support HLS delivery directives")
	}
	for key, values := range directives {
		merged[key] = append([]string(nil), values...)
	}
	updated := *target
	updated.RawQuery = merged.Encode()
	if len(updated.String()) > maxDynamicTargetURLBytes {
		return nil, fmt.Errorf("HLS delivery directives exceed the URL limit")
	}
	return &updated, nil
}

func applyDynamicCapabilityRequiredHeaders(header http.Header, claims dynamicCapabilityClaims) {
	for _, required := range claims.RequiredHeaders {
		header.Set(required.Name, required.Value)
	}
}

func (i *dynamicCapabilityIssuer) serve(w http.ResponseWriter, r *http.Request) {
	if i == nil || i.state == nil || r == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) || r.ContentLength > 0 || len(r.TransferEncoding) > 0 || r.Body != nil && r.Body != http.NoBody || r.URL.RawPath != "" {
		writeDynamicCapabilityUnavailable(w)
		return
	}
	requestPath := normalizeDynamicCapabilityPath(r.URL.Path)
	if requestPath == "" {
		writeDynamicCapabilityUnavailable(w)
		return
	}
	remainder := strings.TrimPrefix(requestPath, dynamicRoutePrefix)
	token, suffix, hasSuffix := strings.Cut(remainder, "/")
	if token == "" || hasSuffix && suffix == "" {
		writeDynamicCapabilityUnavailable(w)
		return
	}
	claims, err := openDynamicCapability(i.key, token)
	if err != nil {
		writeDynamicCapabilityUnavailable(w)
		return
	}
	hasTemplateClaims := len(claims.Template) != 0 || len(claims.TemplateFixed) != 0
	if claims.Kind == dynamicCapabilityKindManifest && hasTemplateClaims || hasTemplateClaims && claims.Source != dynamicDiscoverySourceDASH {
		writeDynamicCapabilityUnavailable(w)
		return
	}
	now := time.Now()
	issuedAt := time.Unix(claims.IssuedAt, 0)
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	maximumLifetime := time.Duration(i.policy.limits.AbsoluteLifetimeSeconds) * time.Second
	if claims.Version != dynamicCapabilityVersion || claims.SiteID != i.siteID || claims.PolicyRevision != i.policyRevision ||
		!i.policy.sourceEnabled(claims.Source) || claims.Target == "" || !validDynamicCapabilityResource(claims.Source, claims.Kind, claims.Depth) ||
		claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt || issuedAt.After(now.Add(30*time.Second)) ||
		!expiresAt.After(now) || expiresAt.Sub(issuedAt) > maximumLifetime || !i.state.hasCapability(token, now) {
		writeDynamicCapabilityUnavailable(w)
		return
	}
	if claims.Trusted && (claims.PreviousScheme != "" || i.configuredTransport == nil) {
		writeDynamicCapabilityUnavailable(w)
		return
	}
	target, err := resolveDASHCapabilityTarget(claims, suffix)
	if err != nil || claims.Trusted && !i.configuredAuthorities[redirectHostKey(target)] {
		writeDynamicCapabilityUnavailable(w)
		return
	}
	if len(claims.RequiredHeaders) > 0 && (i.policy.profile != dynamicProfileExtreme || hasSuffix || r.URL.RawQuery != "" || target.String() != claims.Target || dynamicRequiredHeadersConflictWithFixedPolicy(claims.RequiredHeaders, i.upstreamHeaderPolicy)) {
		writeDynamicCapabilityUnavailable(w)
		return
	}
	target, err = applyHLSCapabilityDirectives(target, claims, r.URL.RawQuery)
	if err != nil {
		writeDynamicCapabilityUnavailable(w)
		return
	}
	if tracker := backendAddressTrackerFromContext(r.Context()); tracker != nil {
		tracker.SetURL(target)
	}
	var previous *url.URL
	if claims.PreviousScheme != "" {
		if claims.PreviousScheme != "http" && claims.PreviousScheme != "https" {
			writeDynamicCapabilityUnavailable(w)
			return
		}
		previous = &url.URL{Scheme: claims.PreviousScheme}
	}
	authority := dynamicCanonicalAuthority(target)
	var transport http.RoundTripper
	var dynamicTransport *http.Transport
	rollback := func() {}
	commit := func() {}
	if claims.Trusted {
		transport = i.configuredTransport
	} else {
		selfTargets := i.state.runtime.selfTargets.Load()
		if reasonCode := i.policy.validateTarget(previous, target, selfTargets); reasonCode != "" {
			i.observe(claims.Source, dynamicObservationDecisionDenied, reasonCode, authority)
			newDynamicProxyError(reasonCode).writeResponse(w)
			return
		}
		reservation, reasonCode := i.state.reserveAuthority(authority, now)
		if reasonCode != "" {
			i.observe(claims.Source, dynamicObservationDecisionDenied, reasonCode, authority)
			newDynamicProxyError(reasonCode).writeResponse(w)
			return
		}
		rollback = reservation.rollback
		commit = reservation.commit
		pinnedIPs, reasonCode := reservation.resolve(r.Context(), target, selfTargets)
		if reasonCode != "" {
			rollback()
			i.observe(claims.Source, dynamicObservationDecisionDenied, reasonCode, authority)
			newDynamicProxyError(reasonCode).writeResponse(w)
			return
		}
		dynamicTransport, err = i.newTransport(target, pinnedIPs, selfTargets)
		if err != nil {
			rollback()
			reasonCode = dynamicObservationReasonAddressDenied
			if errors.Is(err, errDynamicSelfTarget) {
				reasonCode = dynamicObservationReasonSelfTarget
			}
			i.observe(claims.Source, dynamicObservationDecisionDenied, reasonCode, authority)
			newDynamicProxyError(reasonCode).writeResponse(w)
			return
		}
		defer dynamicTransport.CloseIdleConnections()
		transport = dynamicTransport
	}
	defer rollback()
	mainVideoDirect := i.site.MainVideoStreamMode == mainVideoStreamModeDirect && claims.Kind == dynamicCapabilityKindResource && claims.Source != dynamicDiscoverySourceHLS && claims.Source != dynamicDiscoverySourceDASH && len(claims.RequiredHeaders) == 0 && isMainVideoStreamURL(target)
	if mainVideoDirect {
		if !i.state.useCapability(token, time.Now()) {
			writeDynamicCapabilityUnavailable(w)
			return
		}
		commit()
		i.observe(claims.Source, dynamicObservationDecisionAllowed, dynamicObservationReasonCandidateAllowed, authority)
		writeMainVideoDirectRedirect(w, target)
		return
	}
	releaseStream, acquired := i.state.acquireStream()
	if !acquired {
		rollback()
		i.observe(claims.Source, dynamicObservationDecisionDenied, dynamicObservationReasonCapacityLimit, authority)
		newDynamicProxyError(dynamicObservationReasonCapacityLimit).writeResponse(w)
		return
	}
	defer releaseStream()

	// #nosec G704 -- the target is either administrator-configured or normalized, policy-checked, DNS-pinned, and sent through a proxy-free transport.
	outbound, err := http.NewRequestWithContext(isolateDynamicOutboundContext(r.Context()), r.Method, target.String(), nil)
	if err != nil {
		rollback()
		writeDynamicCapabilityUnavailable(w)
		return
	}
	outbound.Host = target.Host
	outbound.Close = !claims.Trusted
	if claims.Trusted {
		outbound.Header = r.Header.Clone()
		prepareUpstreamHeadersWithClientIPMode(outbound.Header, r, i.uaPolicy, i.site.ClientIPMode, i.trustedProxies)
		if redirectHostKey(target) != i.primaryAuthority {
			outbound.Header = crossAuthorityRedirectHeadersWithClientIPMode(outbound.Header, i.site.ClientIPMode)
		}
		applySiteForwardedHost(outbound.Header, r, i.site)
		i.upstreamHeaderPolicy.apply(outbound.Header, target)
	} else {
		outbound.Header = dynamicRedirectHeaders(r.Header)
		applyUAHeaderPolicy(outbound.Header, i.uaPolicy)
	}
	outbound.Header.Set("Accept-Encoding", "identity")
	if claims.Kind == dynamicCapabilityKindManifest {
		for _, name := range []string{"Range", "If-Range", "If-Modified-Since", "If-None-Match"} {
			outbound.Header.Del(name)
		}
	}
	var redirectHeaders http.Header
	if len(claims.RequiredHeaders) > 0 {
		redirectHeaders = outbound.Header.Clone()
		applyDynamicCapabilityRequiredHeaders(outbound.Header, claims)
	}
	resp, roundTripErr := transport.RoundTrip(outbound)
	if roundTripErr != nil || resp == nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		rollback()
		reasonCode := dynamicTransportFailureReason(roundTripErr)
		i.observe(claims.Source, dynamicObservationDecisionDenied, reasonCode, authority)
		newDynamicProxyError(reasonCode).writeResponse(w)
		return
	}
	if dynamicHandledRedirectStatus(resp.StatusCode, i.policy.profile) || dynamicRejectedRedirectStatus(resp.StatusCode, i.policy.profile) {
		if !claims.Trusted && !i.policy.sourceEnabled(dynamicDiscoverySourceRedirect) {
			_ = resp.Body.Close()
			i.observe(claims.Source, dynamicObservationDecisionDenied, dynamicObservationReasonUnsupportedStatus, authority)
			newDynamicProxyError(dynamicObservationReasonUnsupportedStatus).writeResponse(w)
			return
		}
		configuredAuthorities := map[string]bool{}
		playbackHosts := map[string]bool{}
		disableLegacyRedirects := true
		uaPolicy := UAHeaderPolicy{}
		upstreamPolicy := upstreamHeaderPolicy{}
		if claims.Trusted {
			configuredAuthorities = i.configuredAuthorities
			playbackHosts = i.configuredAuthorities
			disableLegacyRedirects = false
			uaPolicy = i.uaPolicy
			upstreamPolicy = i.upstreamHeaderPolicy
		}
		follower := &redirectFollowTransport{
			base:                    transport,
			playbackHosts:           playbackHosts,
			configuredAuthorities:   configuredAuthorities,
			disableLegacyRedirects:  disableLegacyRedirects,
			followUnknownRedirects:  true,
			policy:                  uaPolicy,
			clientIPMode:            i.site.ClientIPMode,
			upstreamHeaderPolicy:    upstreamPolicy,
			dynamicPolicy:           i.policy,
			dynamicTransportFactory: i.transportFactory,
			dynamicState:            i.state,
			capabilityIssuer:        i,
			streamLeaseHeld:         true,
			mainVideoDirect:         i.site.MainVideoStreamMode == mainVideoStreamModeDirect,
			database:                i.database,
			siteID:                  i.siteID,
		}
		followRequest := outbound
		if redirectHeaders != nil {
			followRequest = outbound.Clone(outbound.Context())
			followRequest.Header = redirectHeaders
		}
		resp, err = follower.roundTripDynamic(followRequest, resp)
		if err != nil {
			var discoveryErr *dynamicProxyError
			if errors.As(err, &discoveryErr) {
				discoveryErr.writeResponse(w)
			} else {
				newDynamicProxyError(dynamicTransportFailureReason(err)).writeResponse(w)
			}
			return
		}
	}
	defer rollbackDynamicResponseAuthorities(resp)
	if claims.Kind == dynamicCapabilityKindManifest {
		inheritedHeaders := claims.RequiredHeaders
		if len(inheritedHeaders) > 0 && (resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.String() != claims.Target) {
			inheritedHeaders = nil
		}
		err = rewriteDynamicStructuredResponseAccepted(resp, i, true, claims.Source, claims.Depth, true, inheritedHeaders, func() bool {
			return i.state.useCapability(token, time.Now())
		})
	} else if resp.StatusCode >= http.StatusBadRequest {
		sanitizeDynamicResourceErrorResponse(resp)
	} else {
		if dynamicResponseHasPositiveStructuredContentType(resp) || dynamicResponseIsActiveContent(resp) {
			i.observe(claims.Source, dynamicObservationDecisionDenied, dynamicObservationReasonRequestUnclassified, authority)
			err = newDynamicProxyError(dynamicObservationReasonRequestUnclassified)
		}
	}
	if errors.Is(err, errDynamicCapabilityExpiredDuringUse) {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		writeDynamicCapabilityUnavailable(w)
		return
	}
	if claims.Kind == dynamicCapabilityKindResource && err == nil && resp.StatusCode < http.StatusBadRequest && !i.state.useCapability(token, time.Now()) {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		writeDynamicCapabilityUnavailable(w)
		return
	}
	if err != nil {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		var discoveryErr *dynamicProxyError
		if errors.As(err, &discoveryErr) {
			discoveryErr.writeResponse(w)
		} else {
			newDynamicProxyError(dynamicObservationReasonParseFailure).writeResponse(w)
		}
		return
	}
	if resp.StatusCode < http.StatusBadRequest {
		commit()
		commitDynamicResponseAuthorities(resp)
	} else {
		rollbackDynamicResponseAuthorities(resp)
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	_ = copyDynamicResponse(w, resp, r.Method)
}
