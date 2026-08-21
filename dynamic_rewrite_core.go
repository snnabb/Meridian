package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type dynamicRewriteSession struct {
	ctx                  context.Context
	issuer               *dynamicCapabilityIssuer
	base                 *url.URL
	learningBase         *url.URL
	source               string
	depth                int
	outputLimit          int64
	rewriteRelative      bool
	inheritedHeaders     []dynamicCapabilityHeaderClaim
	seen                 map[string]string
	minted               []string
	urlCount             int
	learnedPlaybackPaths []string
}

func (s *dynamicRewriteSession) rememberRelativePlaybackPath(value string) {
	if s == nil || s.learningBase == nil || !playbackInfoSafeRelativeURL(value) {
		return
	}
	reference, err := url.Parse(value)
	if err != nil || reference.Path == "" {
		return
	}
	resolved := s.learningBase.ResolveReference(reference)
	pathValue := canonicalDynamicPlaybackPath(resolved.Path)
	if pathValue == "" {
		return
	}
	for _, existing := range s.learnedPlaybackPaths {
		if existing == pathValue {
			return
		}
	}
	s.learnedPlaybackPaths = append(s.learnedPlaybackPaths, pathValue)
}

func (s *dynamicRewriteSession) publishLearnedPlaybackPaths() {
	if s == nil || s.issuer == nil || s.issuer.state == nil || len(s.learnedPlaybackPaths) == 0 {
		return
	}
	paths := s.learnedPlaybackPaths
	s.learnedPlaybackPaths = nil
	now := time.Now()
	for _, pathValue := range paths {
		s.issuer.state.learnPlaybackPath(pathValue, now)
	}
}

func (s *dynamicRewriteSession) rememberCapability(seenKey, token string) string {
	route := s.issuer.clientRoute(dynamicRoutePrefix + token)
	if s.seen == nil {
		s.seen = make(map[string]string)
	}
	s.seen[seenKey] = route
	s.minted = append(s.minted, token)
	return route
}

func (s *dynamicRewriteSession) reuseShallowTrustedManifest(target *url.URL, source, kind string, depth int) (string, bool) {
	if s == nil || s.issuer == nil || s.issuer.state == nil || s.issuer.configuredTransport == nil || target == nil || kind != dynamicCapabilityKindManifest || depth <= 1 {
		return "", false
	}
	for candidateDepth := 1; candidateDepth < depth; candidateDepth++ {
		cacheKey := trustedCapabilityCacheKey(source, kind, candidateDepth, target.String(), nil, nil)
		if token, exists := s.issuer.state.reuseCapability(cacheKey, time.Now()); exists {
			seenKey := "trusted\x00" + source + "\x00" + kind + "\x00" + strconv.Itoa(depth) + "\x00" + target.String()
			return s.rememberCapability(seenKey, token), true
		}
	}
	return "", false
}

func (s *dynamicRewriteSession) reuseShallowDynamicManifest(base, target *url.URL, source, kind string, depth int) (string, bool, *dynamicProxyError) {
	if s == nil || s.issuer == nil || s.issuer.state == nil || base == nil || target == nil || kind != dynamicCapabilityKindManifest || depth <= 1 {
		return "", false, nil
	}
	previousScheme := ""
	if strings.EqualFold(base.Scheme, "http") || strings.EqualFold(base.Scheme, "https") {
		previousScheme = strings.ToLower(base.Scheme)
	}
	for candidateDepth := 1; candidateDepth < depth; candidateDepth++ {
		cacheKey := dynamicCapabilityCacheKey(source, kind, candidateDepth, previousScheme, target.String(), nil, nil)
		token, exists := s.issuer.state.reuseCapability(cacheKey, time.Now())
		if !exists {
			continue
		}
		undo := func() {
			_ = s.issuer.state.settleCapabilities([]string{token}, false, time.Now())
		}
		selfTargets := s.issuer.state.runtime.selfTargets.Load()
		authority := dynamicCanonicalAuthority(target)
		if reasonCode := s.issuer.policy.validateTarget(base, target, selfTargets); reasonCode != "" {
			undo()
			s.issuer.observe(source, dynamicObservationDecisionDenied, reasonCode, authority)
			return "", false, newDynamicProxyError(reasonCode)
		}
		reservation, reasonCode := s.issuer.state.reserveAuthority(authority, time.Now())
		if reasonCode != "" {
			undo()
			s.issuer.observe(source, dynamicObservationDecisionDenied, reasonCode, authority)
			return "", false, newDynamicProxyError(reasonCode)
		}
		if _, reasonCode = reservation.resolve(s.ctx, target, selfTargets); reasonCode != "" {
			reservation.rollback()
			undo()
			s.issuer.observe(source, dynamicObservationDecisionDenied, reasonCode, authority)
			return "", false, newDynamicProxyError(reasonCode)
		}
		reservation.rollback()
		s.issuer.observe(source, dynamicObservationDecisionAllowed, dynamicObservationReasonCandidateAllowed, authority)
		seenKey := "dynamic\x00" + source + "\x00" + kind + "\x00" + strconv.Itoa(depth) + "\x00" + target.String()
		return s.rememberCapability(seenKey, token), true, nil
	}
	return "", false, nil
}

func (s *dynamicRewriteSession) structuredOutputLimit() int64 {
	if s == nil || s.issuer == nil {
		return 0
	}
	limit := s.outputLimit
	if limit <= 0 || limit > globalDynamicMaxStructuredOutputBytes {
		limit = globalDynamicMaxStructuredOutputBytes
	}
	if limit > s.issuer.policy.limits.MaxBodyBytes {
		limit = s.issuer.policy.limits.MaxBodyBytes
	}
	return limit
}

func (s *dynamicRewriteSession) rewrite(raw string) (string, error) {
	return s.rewriteAgainstKind(raw, s.base, dynamicCapabilityKindResource)
}

func (s *dynamicRewriteSession) rewriteManifest(raw string) (string, error) {
	return s.rewriteAgainstKind(raw, s.base, dynamicCapabilityKindManifest)
}

func structuredURLSharesAuthority(raw string, base *url.URL) bool {
	if base == nil || raw == "" || strings.Contains(raw, `\`) || containsDynamicUnsafeRune(raw) {
		return false
	}
	reference, err := url.Parse(raw)
	if err != nil || reference.User != nil || reference.Fragment != "" || reference.RawFragment != "" {
		return false
	}
	return sameRedirectAuthority(base, base.ResolveReference(reference))
}

func validateSameAuthorityStructuredURL(target *url.URL) error {
	if target == nil || len(target.String()) > maxDynamicTargetURLBytes || target.User != nil || target.Fragment != "" || target.RawFragment != "" || target.Host == "" {
		return fmt.Errorf("invalid same-authority structured URL")
	}
	scheme := strings.ToLower(target.Scheme)
	if scheme != "http" && scheme != "https" || !dynamicURLDecodedComponentIsSafe(target.EscapedPath(), false) || !dynamicURLDecodedComponentIsSafe(target.RawQuery, true) {
		return fmt.Errorf("invalid same-authority structured URL")
	}
	if dynamicURLPathHasDotSegments(target.EscapedPath()) {
		return fmt.Errorf("invalid same-authority structured URL")
	}
	if target.Port() != "" {
		port, err := strconv.Atoi(target.Port())
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid same-authority structured URL")
		}
	}
	return nil
}

func normalizeTrustedCapabilityURL(value string) (*url.URL, error) {
	if value == "" || len(value) > maxDynamicTargetURLBytes || value != strings.TrimSpace(value) || containsDynamicUnsafeRune(value) || strings.Contains(value, `\`) || strings.Contains(value, "#") {
		return nil, fmt.Errorf("invalid trusted capability URL")
	}
	target, err := url.Parse(value)
	if err != nil || !target.IsAbs() || target.Opaque != "" {
		return nil, fmt.Errorf("invalid trusted capability URL")
	}
	target.Scheme = strings.ToLower(target.Scheme)
	host, _, err := normalizeDynamicHostSyntax(target.Hostname())
	if err != nil {
		return nil, fmt.Errorf("invalid trusted capability URL")
	}
	explicitPort := target.Port() != ""
	if !explicitPort && strings.HasSuffix(target.Host, ":") {
		return nil, fmt.Errorf("invalid trusted capability URL")
	}
	port, ok := dynamicEffectivePort(target)
	if !ok {
		return nil, fmt.Errorf("invalid trusted capability URL")
	}
	target.Host = dynamicURLHost(host, port, explicitPort)
	if err := validateSameAuthorityStructuredURL(target); err != nil {
		return nil, fmt.Errorf("invalid trusted capability URL")
	}
	return target, nil
}

func (s *dynamicRewriteSession) rewriteAgainst(raw string, base *url.URL) (string, error) {
	return s.rewriteAgainstKind(raw, base, dynamicCapabilityKindResource)
}

func (s *dynamicRewriteSession) rewriteAgainstKind(raw string, base *url.URL, kind string) (string, error) {
	return s.rewriteAgainstSourceKind(raw, base, s.source, kind)
}

func (s *dynamicRewriteSession) rewriteAgainstSourceKind(raw string, base *url.URL, source, kind string) (string, error) {
	return s.rewriteAgainstSourceKindWithRequiredHeaders(raw, base, source, kind, nil)
}

func (s *dynamicRewriteSession) rewriteAgainstSourceKindWithRequiredHeaders(raw string, base *url.URL, source, kind string, requiredHeaders []dynamicCapabilityHeaderClaim) (string, error) {
	depth := 0
	if kind == dynamicCapabilityKindManifest {
		depth = s.depth + 1
	}
	return s.rewriteAgainstSourceKindDepthWithRequiredHeaders(raw, base, source, kind, depth, requiredHeaders)
}

func (s *dynamicRewriteSession) rewriteAgainstSourceKindDepth(raw string, base *url.URL, source, kind string, depth int) (string, error) {
	return s.rewriteAgainstSourceKindDepthWithRequiredHeaders(raw, base, source, kind, depth, nil)
}

func (s *dynamicRewriteSession) rewriteAgainstSourceKindDepthWithRequiredHeaders(raw string, base *url.URL, source, kind string, depth int, requiredHeaders []dynamicCapabilityHeaderClaim) (string, error) {
	if s == nil || s.issuer == nil || base == nil {
		return "", fmt.Errorf("invalid discovered URL: context")
	}
	switch {
	case raw == "":
		return "", fmt.Errorf("invalid discovered URL: empty")
	case raw != strings.TrimSpace(raw):
		return "", fmt.Errorf("invalid discovered URL: surrounding whitespace")
	case containsDynamicUnsafeRune(raw):
		return "", fmt.Errorf("invalid discovered URL: unsafe character")
	case strings.Contains(raw, `\`):
		return "", fmt.Errorf("invalid discovered URL: backslash")
	}
	if source == dynamicDiscoverySourcePlaybackInfo && (s.issuer.policy.profile == dynamicProfileCompatible || s.issuer.policy.profile == dynamicProfileExtreme) {
		if normalized, ok := normalizePlaybackInfoSchemelessURL(raw, base); ok {
			raw = normalized
		}
	}
	if err := validateDynamicCapabilityRequiredHeaderClaims(requiredHeaders); err != nil || len(requiredHeaders) > 0 && (s.issuer.policy.profile != dynamicProfileExtreme || dynamicRequiredHeadersConflictWithFixedPolicy(requiredHeaders, s.issuer.upstreamHeaderPolicy)) {
		return "", fmt.Errorf("invalid discovered URL required headers")
	}
	if source == dynamicDiscoverySourceDASH && strings.Contains(raw, dashLiteralDollarClaimMarker) {
		return "", fmt.Errorf("DASH URL contains a reserved marker")
	}
	if err := s.ctx.Err(); err != nil {
		return "", fmt.Errorf("structured response deadline exceeded")
	}
	resourceDepthValid := validDynamicCapabilityResource(source, kind, depth)
	mayReuseOverDepth := kind == dynamicCapabilityKindManifest && (source == dynamicDiscoverySourceHLS || source == dynamicDiscoverySourceDASH) && depth > maxDynamicManifestDepth
	if !resourceDepthValid && !mayReuseOverDepth {
		return "", fmt.Errorf("invalid structured resource kind or depth")
	}
	s.urlCount++
	if s.urlCount > s.issuer.policy.limits.MaxURLsPerResponse {
		return "", fmt.Errorf("discovered URL count exceeds its limit")
	}
	reference, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid discovered URL: parse")
	}
	if reference.User != nil {
		return "", fmt.Errorf("invalid discovered URL: userinfo")
	}
	if reference.Fragment != "" || reference.RawFragment != "" {
		return "", fmt.Errorf("invalid discovered URL: fragment")
	}
	resolved := base.ResolveReference(reference)
	if len(requiredHeaders) == 0 && len(s.inheritedHeaders) > 0 && sameRedirectAuthority(s.base, resolved) {
		requiredHeaders = s.inheritedHeaders
	}
	headerKey := dynamicCapabilityRequiredHeadersCacheKey(requiredHeaders)
	configuredStructuredTarget := s.issuer.configuredAuthorities[redirectHostKey(resolved)] && (source == dynamicDiscoverySourceHLS || source == dynamicDiscoverySourceDASH || source == dynamicDiscoverySourcePlaybackInfo && (reference.IsAbs() || reference.Host != "") || len(requiredHeaders) > 0)
	if configuredStructuredTarget {
		target, err := normalizeTrustedCapabilityURL(resolved.String())
		if err != nil {
			return "", fmt.Errorf("invalid configured structured URL")
		}
		seenKey := "trusted\x00" + source + "\x00" + kind + "\x00" + strconv.Itoa(depth) + "\x00" + target.String() + headerKey
		if route, exists := s.seen[seenKey]; exists {
			return route, nil
		}
		if len(requiredHeaders) == 0 {
			if route, reused := s.reuseShallowTrustedManifest(target, source, kind, depth); reused {
				return route, nil
			}
		}
		if !resourceDepthValid {
			return "", fmt.Errorf("manifest nesting exceeds its depth limit")
		}
		route, acquired, discoveryErr := s.issuer.mintTrustedValidatedWithRequiredHeadersTracked(target, target.String(), nil, nil, requiredHeaders, source, kind, depth)
		if discoveryErr != nil {
			return "", discoveryErr
		}
		if s.seen == nil {
			s.seen = make(map[string]string)
		}
		s.seen[seenKey] = route
		if acquired {
			s.minted = append(s.minted, s.issuer.capabilityToken(route))
		}
		return route, nil
	}
	if resourceDepthValid && len(requiredHeaders) == 0 && !s.rewriteRelative && sameRedirectAuthority(s.base, resolved) {
		if err := validateSameAuthorityStructuredURL(resolved); err != nil {
			return "", err
		}
		return resolved.RequestURI(), nil
	}
	target, err := normalizeDynamicURL(resolved.String())
	if err != nil {
		return "", fmt.Errorf("invalid discovered URL: target normalization %s", dynamicURLNormalizationDiagnosticCode(err))
	}
	seenKey := "dynamic\x00" + source + "\x00" + kind + "\x00" + strconv.Itoa(depth) + "\x00" + target.String() + headerKey
	if route, exists := s.seen[seenKey]; exists {
		return route, nil
	}
	if len(requiredHeaders) == 0 {
		if route, reused, reuseErr := s.reuseShallowDynamicManifest(base, target, source, kind, depth); reuseErr != nil {
			return "", reuseErr
		} else if reused {
			return route, nil
		}
	}
	if !resourceDepthValid {
		return "", fmt.Errorf("manifest nesting exceeds its depth limit")
	}
	route, acquired, discoveryErr := s.issuer.mintValidatedResourceWithRequiredHeadersTracked(s.ctx, base, target, source, target.String(), nil, nil, requiredHeaders, kind, depth)
	if discoveryErr != nil {
		return "", discoveryErr
	}
	if s.seen == nil {
		s.seen = make(map[string]string)
	}
	s.seen[seenKey] = route
	if acquired {
		s.minted = append(s.minted, s.issuer.capabilityToken(route))
	}
	return route, nil
}

func (s *dynamicRewriteSession) commit() bool {
	if s == nil || s.issuer == nil || s.issuer.state == nil {
		return false
	}
	tokens := s.minted
	s.minted = nil
	return s.issuer.state.settleCapabilities(tokens, true, time.Now())
}

func (s *dynamicRewriteSession) rollback() {
	if s == nil || s.issuer == nil || s.issuer.state == nil {
		return
	}
	tokens := s.minted
	s.minted = nil
	s.learnedPlaybackPaths = nil
	_ = s.issuer.state.settleCapabilities(tokens, false, time.Now())
}

func dynamicResponseMediaType(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return ""
	}
	return strings.ToLower(mediaType)
}

func dynamicResponseIsActiveContent(resp *http.Response) bool {
	switch dynamicResponseMediaType(resp) {
	case "text/html", "application/xhtml+xml", "image/svg+xml", "text/javascript", "application/javascript", "application/ecmascript", "text/ecmascript":
		return true
	default:
		return false
	}
}

func dynamicStructuredMethodAllowed(source, method string) bool {
	switch source {
	case dynamicDiscoverySourcePlaybackInfo:
		return method == http.MethodGet || method == http.MethodPost || method == http.MethodHead
	case dynamicDiscoverySourceHLS, dynamicDiscoverySourceDASH:
		return method == http.MethodGet || method == http.MethodHead
	default:
		return false
	}
}

func dynamicStructuredContentTypeAllowed(source string, resp *http.Response) bool {
	mediaType := dynamicResponseMediaType(resp)
	switch source {
	case dynamicDiscoverySourcePlaybackInfo:
		return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
	case dynamicDiscoverySourceHLS:
		return mediaType == "application/vnd.apple.mpegurl" || mediaType == "application/x-mpegurl" || mediaType == "audio/mpegurl" || mediaType == "audio/x-mpegurl" || mediaType == "text/plain" || mediaType == "application/octet-stream"
	case dynamicDiscoverySourceDASH:
		return mediaType == "application/dash+xml" || mediaType == "application/xml" || mediaType == "text/xml" || mediaType == "application/octet-stream"
	default:
		return false
	}
}

func dynamicStructuredResponseSource(resp *http.Response) (string, bool) {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return "", false
	}
	requestPath := strings.ToLower(resp.Request.URL.Path)
	mediaType := dynamicResponseMediaType(resp)
	if isPlaybackInfoRequest(requestPath) && dynamicStructuredMethodAllowed(dynamicDiscoverySourcePlaybackInfo, resp.Request.Method) {
		return dynamicDiscoverySourcePlaybackInfo, dynamicStructuredContentTypeAllowed(dynamicDiscoverySourcePlaybackInfo, resp)
	}
	hlsType := mediaType == "application/vnd.apple.mpegurl" || mediaType == "application/x-mpegurl" || mediaType == "audio/mpegurl" || mediaType == "audio/x-mpegurl"
	if (hlsType || strings.HasSuffix(requestPath, ".m3u8") || strings.HasSuffix(requestPath, ".m3u")) && dynamicStructuredMethodAllowed(dynamicDiscoverySourceHLS, resp.Request.Method) {
		return dynamicDiscoverySourceHLS, dynamicStructuredContentTypeAllowed(dynamicDiscoverySourceHLS, resp)
	}
	dashType := mediaType == "application/dash+xml"
	if (dashType || strings.HasSuffix(requestPath, ".mpd")) && dynamicStructuredMethodAllowed(dynamicDiscoverySourceDASH, resp.Request.Method) {
		return dynamicDiscoverySourceDASH, dynamicStructuredContentTypeAllowed(dynamicDiscoverySourceDASH, resp)
	}
	return "", false
}

func dynamicResponseHasPositiveStructuredContentType(resp *http.Response) bool {
	mediaType := dynamicResponseMediaType(resp)
	switch mediaType {
	case "application/vnd.apple.mpegurl", "application/x-mpegurl", "audio/mpegurl", "audio/x-mpegurl", "application/dash+xml":
		return true
	case "application/json":
		return resp != nil && resp.Request != nil && resp.Request.URL != nil && isPlaybackInfoRequest(resp.Request.URL.Path)
	default:
		return strings.HasSuffix(mediaType, "+json") && resp != nil && resp.Request != nil && resp.Request.URL != nil && isPlaybackInfoRequest(resp.Request.URL.Path)
	}
}

func dynamicStructuredWorkingSet(resp *http.Response, profileLimit int64) (memory, inputLimit, outputLimit int64, err error) {
	return dynamicStructuredWorkingSetWithin(resp, profileLimit, globalDynamicMaxSiteParseMemoryBytes)
}

func dynamicStructuredWorkingSetWithin(resp *http.Response, profileLimit, memoryLimit int64) (memory, inputLimit, outputLimit int64, err error) {
	if resp == nil || profileLimit <= 0 || memoryLimit < 8<<20 {
		return 0, 0, 0, fmt.Errorf("structured response budget is unavailable")
	}
	memoryLimit = min(memoryLimit, int64(globalDynamicMaxSiteParseMemoryBytes))
	inputLimit = min(profileLimit, int64(globalDynamicMaxStructuredInputBytes))
	outputLimit = min(profileLimit, int64(globalDynamicMaxStructuredOutputBytes))
	memory = memoryLimit
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if (encoding == "" || encoding == "identity") && resp.ContentLength >= 0 {
		if resp.ContentLength > inputLimit {
			return 0, 0, 0, fmt.Errorf("structured response working set exceeds its limit")
		}
		memory = resp.ContentLength*8 + (4 << 20)
		if memory < 8<<20 {
			memory = 8 << 20
		}
		if memory > memoryLimit {
			return 0, 0, 0, fmt.Errorf("structured response working set exceeds its limit")
		}
	}
	if (encoding != "" && encoding != "identity" || resp.ContentLength < 0) && inputLimit > memory/8 {
		inputLimit = memory / 8
	}
	if quarter := memory / 4; outputLimit > quarter {
		outputLimit = quarter
	}
	if inputLimit <= 0 || outputLimit <= 0 {
		return 0, 0, 0, fmt.Errorf("structured response working set exceeds its limit")
	}
	return memory, inputLimit, outputLimit, nil
}

type dynamicBoundedBuffer struct {
	buffer bytes.Buffer
	limit  int64
}

func (b *dynamicBoundedBuffer) Write(payload []byte) (int, error) {
	if b == nil || b.limit < 0 || int64(len(payload)) > b.limit-int64(b.buffer.Len()) {
		return 0, fmt.Errorf("structured response output exceeds its limit")
	}
	return b.buffer.Write(payload)
}

func (b *dynamicBoundedBuffer) WriteString(value string) (int, error) {
	if b == nil || b.limit < 0 || int64(len(value)) > b.limit-int64(b.buffer.Len()) {
		return 0, fmt.Errorf("structured response output exceeds its limit")
	}
	return b.buffer.WriteString(value)
}

func (b *dynamicBoundedBuffer) Bytes() []byte {
	if b == nil {
		return nil
	}
	return b.buffer.Bytes()
}

func readDynamicStructuredBody(resp *http.Response, limit int64) ([]byte, error) {
	if resp == nil || resp.Body == nil || limit <= 0 {
		return nil, fmt.Errorf("structured response body is unavailable")
	}
	defer resp.Body.Close()
	timer := time.AfterFunc(dynamicStructuredBodyTimeout, func() {
		_ = resp.Body.Close()
	})
	defer timer.Stop()
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	var reader io.Reader = resp.Body
	var gzipReader *gzip.Reader
	var compressed *io.LimitedReader
	switch encoding {
	case "", "identity":
		if resp.ContentLength > limit {
			return nil, fmt.Errorf("structured response body exceeds its limit")
		}
	case "gzip":
		if resp.ContentLength > limit {
			return nil, fmt.Errorf("compressed structured response body exceeds its limit")
		}
		compressed = &io.LimitedReader{R: resp.Body, N: limit + 1}

		var err error
		gzipReader, err = gzip.NewReader(compressed)
		if err != nil {
			return nil, fmt.Errorf("invalid gzip response body")
		}
		defer gzipReader.Close()
		reader = gzipReader
	default:
		return nil, fmt.Errorf("unsupported structured response encoding")
	}
	payload, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read structured response body: %w", err)
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("structured response body exceeds its limit")
	}
	if compressed != nil {
		compressedBytes := limit + 1 - compressed.N
		if compressedBytes > limit {
			return nil, fmt.Errorf("compressed structured response body exceeds its limit")
		}
		if int64(len(payload)) > minDynamicCompressionRatioBytes && (compressedBytes <= 0 || int64(len(payload)) > compressedBytes*maxDynamicCompressionRatio) {
			return nil, fmt.Errorf("structured response compression ratio exceeds its limit")
		}
	}
	return payload, nil
}

func installDynamicStructuredBody(resp *http.Response, payload []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(payload))
	resp.ContentLength = int64(len(payload))
	resp.Uncompressed = true
	resp.Trailer = nil
	for _, name := range []string{
		"Accept-Ranges", "Content-Encoding", "Content-MD5", "Content-Range", "Digest",
		"ETag", "Last-Modified", "Vary",
	} {
		resp.Header.Del(name)
	}
	resp.Header.Set("Content-Length", strconv.Itoa(len(payload)))
	resp.Header.Set("Cache-Control", "private, no-store")
	resp.Header.Set("Referrer-Policy", "no-referrer")
	resp.Header.Set("X-Content-Type-Options", "nosniff")
}

func sanitizeDynamicUpstreamErrorResponse(resp *http.Response, payload []byte) {
	if resp == nil {
		return
	}
	retryAfter := append([]string(nil), resp.Header.Values("Retry-After")...)
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	header := make(http.Header)
	if len(retryAfter) > 0 {
		header["Retry-After"] = retryAfter
	}
	resp.Header = header
	resp.Trailer = nil
	if resp.Request != nil && resp.Request.Method == http.MethodHead {
		resp.Body = http.NoBody
		resp.ContentLength = -1
		return
	}
	resp.Body = io.NopCloser(bytes.NewReader(payload))
	resp.ContentLength = int64(len(payload))
	resp.Header.Set("Content-Length", strconv.Itoa(len(payload)))
	resp.Header.Set("Content-Type", "application/json")
}

func sanitizeDynamicManifestErrorResponse(resp *http.Response) {
	sanitizeDynamicUpstreamErrorResponse(resp, []byte(`{"error":"upstream manifest request failed"}`))
}

func sanitizeDynamicResourceErrorResponse(resp *http.Response) {
	sanitizeDynamicUpstreamErrorResponse(resp, []byte(`{"error":"upstream dynamic request failed"}`))
}

var errDynamicCapabilityExpiredDuringUse = errors.New("dynamic capability expired during use")

func rewriteDynamicStructuredResponse(resp *http.Response, issuer *dynamicCapabilityIssuer, rewriteRelative bool) error {
	return rewriteDynamicStructuredResponseExpected(resp, issuer, rewriteRelative, "", 0, false)
}

func rewriteDynamicStructuredResponseExpected(resp *http.Response, issuer *dynamicCapabilityIssuer, rewriteRelative bool, expectedSource string, depth int, required bool) error {
	return rewriteDynamicStructuredResponseAccepted(resp, issuer, rewriteRelative, expectedSource, depth, required, nil, nil)
}

func dynamicStructuredRewriteDeniedReason(source string) string {
	switch source {
	case dynamicDiscoverySourcePlaybackInfo:
		return dynamicObservationReasonPlaybackInfoDenied
	case dynamicDiscoverySourceHLS:
		return dynamicObservationReasonHLSFeatureDenied
	case dynamicDiscoverySourceDASH:
		return dynamicObservationReasonDASHFeatureDenied
	default:
		return dynamicObservationReasonParseFailure
	}
}

func rewriteDynamicStructuredResponseAccepted(resp *http.Response, issuer *dynamicCapabilityIssuer, rewriteRelative bool, expectedSource string, depth int, required bool, inheritedHeaders []dynamicCapabilityHeaderClaim, accept func() bool) error {
	dynamicResponseAuthorityLease(resp).retainThroughRewrite()
	source, contentTypeAllowed := dynamicStructuredResponseSource(resp)
	if expectedSource != "" && dynamicStructuredContentTypeAllowed(expectedSource, resp) {
		source = expectedSource
		contentTypeAllowed = true
	}
	if issuer == nil {
		return nil
	}
	authority := ""
	if resp != nil && resp.Request != nil {
		authority = dynamicCanonicalAuthority(resp.Request.URL)
	}
	recordFailure := func(reasonCode string) error {
		observationSource := source
		if expectedSource != "" {
			observationSource = expectedSource
		}
		issuer.observe(observationSource, dynamicObservationDecisionDenied, reasonCode, authority)
		return newDynamicProxyError(reasonCode)
	}
	if expectedSource != "" && rewriteRelative && !required && !issuer.policy.sourceEnabled(expectedSource) {
		return nil
	}
	if expectedSource != "" && rewriteRelative && resp != nil && resp.StatusCode < http.StatusBadRequest && (source != expectedSource || !contentTypeAllowed) {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return recordFailure(dynamicObservationReasonRequestUnclassified)
	}
	if required && (!issuer.policy.sourceEnabled(expectedSource) || !validDynamicCapabilityResource(expectedSource, dynamicCapabilityKindManifest, depth)) {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return recordFailure(dynamicObservationReasonRequestUnclassified)
	}
	if required && resp != nil && resp.StatusCode >= http.StatusBadRequest {
		sanitizeDynamicManifestErrorResponse(resp)
		return nil
	}
	if required && (source == "" || source != expectedSource || !contentTypeAllowed) {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return recordFailure(dynamicObservationReasonRequestUnclassified)
	}
	if rewriteRelative && resp != nil && resp.StatusCode < http.StatusBadRequest && source != "" && contentTypeAllowed && !issuer.policy.sourceEnabled(source) {
		if expectedSource == source && !required {
			return nil
		}
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return recordFailure(dynamicObservationReasonRequestUnclassified)
	}
	if source == "" || !issuer.policy.sourceEnabled(source) {
		return nil
	}
	if resp.Request.Method == http.MethodHead {
		if resp.StatusCode >= http.StatusBadRequest {
			return nil
		}
		if !contentTypeAllowed || resp.StatusCode != http.StatusOK {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			return recordFailure(dynamicObservationReasonRequestUnclassified)
		}
		resp.ContentLength = -1
		for _, name := range []string{"Accept-Ranges", "Content-Length", "Content-MD5", "Content-Range", "Digest", "ETag", "Last-Modified", "Vary"} {
			resp.Header.Del(name)
		}
		resp.Header.Set("Cache-Control", "private, no-store")
		resp.Header.Set("Referrer-Policy", "no-referrer")
		resp.Header.Set("X-Content-Type-Options", "nosniff")
		if accept != nil && !accept() {
			return errDynamicCapabilityExpiredDuringUse
		}
		return nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil
	}
	if !contentTypeAllowed || resp.StatusCode != http.StatusOK {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return recordFailure(dynamicObservationReasonRequestUnclassified)
	}
	parseContext, cancelParse := context.WithTimeout(resp.Request.Context(), dynamicStructuredBodyTimeout)
	defer cancelParse()
	workingMemory, inputLimit, outputLimit, budgetErr := dynamicStructuredWorkingSetWithin(resp, issuer.policy.limits.MaxBodyBytes, issuer.state.availableParseMemory())
	if budgetErr != nil {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		issuer.observe(source, dynamicObservationDecisionDenied, dynamicObservationReasonCapacityLimit, authority)
		return newDynamicProxyError(dynamicObservationReasonCapacityLimit)
	}
	release, acquired := issuer.state.acquireParse(workingMemory)
	if !acquired {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		issuer.observe(source, dynamicObservationDecisionDenied, dynamicObservationReasonCapacityLimit, authority)
		return newDynamicProxyError(dynamicObservationReasonCapacityLimit)
	}
	defer release()
	payload, err := readDynamicStructuredBody(resp, inputLimit)
	if err != nil {
		return recordFailure(dynamicObservationReasonStructuredBodyLimit)
	}
	var learningBase *url.URL
	if resp.Request != nil {
		if stored, ok := resp.Request.Context().Value(dynamicPlaybackInfoBaseContextKey{}).(*url.URL); ok && stored != nil {
			clone := *stored
			learningBase = &clone
		}
	}
	session := &dynamicRewriteSession{ctx: parseContext, issuer: issuer, base: resp.Request.URL, learningBase: learningBase, source: source, depth: depth, outputLimit: outputLimit, rewriteRelative: rewriteRelative, inheritedHeaders: inheritedHeaders}
	var rewritten []byte
	switch source {
	case dynamicDiscoverySourcePlaybackInfo:
		rewritten, err = rewritePlaybackInfoResponse(payload, session)
	case dynamicDiscoverySourceHLS:
		rewritten, err = rewriteHLSResponse(payload, session)
	case dynamicDiscoverySourceDASH:
		rewritten, err = rewriteDASHResponse(payload, session)
	}
	if err != nil && source == dynamicDiscoverySourcePlaybackInfo && playbackInfoAutomaticFallbackAllowed(err) {
		session.rollback()
		fallbackSession := &dynamicRewriteSession{
			ctx:              parseContext,
			issuer:           issuer,
			base:             resp.Request.URL,
			learningBase:     learningBase,
			source:           source,
			depth:            depth,
			outputLimit:      outputLimit,
			rewriteRelative:  false,
			inheritedHeaders: inheritedHeaders,
		}
		fallback, fallbackErr := rewriteAutomaticPlaybackInfoResponse(payload, fallbackSession)
		if fallbackErr == nil {
			log.Printf("[%s] PlaybackInfo switched to automatic URL proxy fallback: diagnostic=%s", issuer.site.Name, playbackInfoRewriteDiagnosticCode(err))
			session = fallbackSession
			rewritten = fallback
			err = nil
		} else {
			fallbackSession.rollback()
			if accept != nil && !accept() {
				return errDynamicCapabilityExpiredDuringUse
			}
			log.Printf("[%s] PlaybackInfo automatic URL proxy fallback preserved the upstream response", issuer.site.Name)
			installDynamicStructuredBody(resp, payload)
			return nil
		}
	}
	if err != nil {
		session.rollback()
		if source == dynamicDiscoverySourcePlaybackInfo {
			log.Printf("[%s] PlaybackInfo rewrite rejected: diagnostic=%s fingerprint=%s profile=%s", issuer.site.Name, playbackInfoRewriteDiagnosticCode(err), playbackInfoRewriteDiagnosticFingerprint(err), issuer.policy.profile)
		}
		return recordFailure(dynamicStructuredRewriteDeniedReason(source))
	}
	if int64(len(rewritten)) > outputLimit {
		session.rollback()
		return recordFailure(dynamicObservationReasonStructuredBodyLimit)
	}
	if accept != nil && !accept() {
		session.rollback()
		return errDynamicCapabilityExpiredDuringUse
	}
	if !session.commit() {
		issuer.observe(source, dynamicObservationDecisionDenied, dynamicObservationReasonCapacityLimit, authority)
		return newDynamicProxyError(dynamicObservationReasonCapacityLimit)
	}
	session.publishLearnedPlaybackPaths()
	installDynamicStructuredBody(resp, rewritten)
	return nil
}

func validateDynamicJSONStructure(ctx context.Context, payload []byte, maxTokens int) error {
	_, err := validateDynamicJSONStructureWithin(ctx, payload, maxTokens, globalDynamicMaxParseDepth)
	return err
}

func validateDynamicJSONStructureWithin(ctx context.Context, payload []byte, maxTokens, maxDepth int) (int, error) {
	if ctx == nil || ctx.Err() != nil {
		return 0, fmt.Errorf("JSON parsing deadline exceeded")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	depth := 0
	seenValue := false
	tokens := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		seenValue = true
		tokens++
		if tokens&255 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, fmt.Errorf("JSON parsing deadline exceeded")
			}
		}
		if tokens > maxTokens {
			return 0, fmt.Errorf("JSON token count exceeds its limit")
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{', '[':
				depth++
				if depth > maxDepth {
					return 0, fmt.Errorf("JSON nesting exceeds its limit")
				}
			case '}', ']':
				depth--
				if depth < 0 {
					return 0, fmt.Errorf("invalid JSON nesting")
				}
			}
		case string:
			if int64(len(value)) > globalDynamicMaxStringBytes {
				return 0, fmt.Errorf("JSON string exceeds its limit")
			}
		}
	}
	if !seenValue || depth != 0 {
		return 0, fmt.Errorf("invalid JSON body")
	}
	return tokens, nil
}
