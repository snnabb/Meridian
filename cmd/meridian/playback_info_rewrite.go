package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type extremePlaybackInfoJSONBudget struct {
	remainingTokens int
}

func playbackInfoIsExtreme(session *dynamicRewriteSession) bool {
	return session != nil && session.issuer != nil && session.issuer.policy.profile == dynamicProfileExtreme
}

func decodeExtremePlaybackInfoCollection(ctx context.Context, value, field string, containerDepth int, budget *extremePlaybackInfoJSONBudget) ([]any, error) {
	if budget == nil || containerDepth < 0 || containerDepth >= globalDynamicMaxParseDepth {
		return nil, fmt.Errorf("PlaybackInfo field %s exceeds its structural limits", field)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("PlaybackInfo field %s contains invalid stringified JSON", field)
	}
	isObject := value[0] == '{'
	isArray := value[0] == '['
	if !isObject && !isArray {
		return nil, fmt.Errorf("PlaybackInfo field %s must stringify an array or object", field)
	}
	wrapperTokens := 0
	maxDepth := globalDynamicMaxParseDepth - containerDepth
	if isObject {
		wrapperTokens = 2
		maxDepth--
	}
	tokenLimit := budget.remainingTokens + 1 - wrapperTokens
	if tokenLimit <= 0 || maxDepth <= 0 {
		return nil, fmt.Errorf("PlaybackInfo field %s exceeds its structural limits", field)
	}
	nestedTokens, err := validateDynamicJSONStructureWithin(ctx, []byte(value), tokenLimit, maxDepth)
	if err != nil {
		return nil, fmt.Errorf("PlaybackInfo field %s contains invalid stringified JSON", field)
	}
	additionalTokens := nestedTokens + wrapperTokens - 1
	if additionalTokens > budget.remainingTokens {
		return nil, fmt.Errorf("PlaybackInfo field %s exceeds its token limit", field)
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("PlaybackInfo field %s contains invalid stringified JSON", field)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("PlaybackInfo field %s contains invalid stringified JSON", field)
	}
	budget.remainingTokens -= additionalTokens
	switch collection := decoded.(type) {
	case []any:
		return collection, nil
	case map[string]any:
		return []any{collection}, nil
	default:
		return nil, fmt.Errorf("PlaybackInfo field %s must stringify an array or object", field)
	}
}

func normalizeExtremePlaybackInfoCollectionField(object map[string]any, field string, containerDepth int, budget *extremePlaybackInfoJSONBudget, session *dynamicRewriteSession) error {
	key, value, exists, err := playbackInfoField(object, field)
	if err != nil || !exists || value == nil {
		return err
	}
	text, stringified := value.(string)
	if !stringified {
		return nil
	}
	collection, err := decodeExtremePlaybackInfoCollection(session.ctx, text, field, containerDepth, budget)
	if err != nil {
		return err
	}
	object[key] = collection
	return nil
}

func dynamicURLNormalizationDiagnosticCode(err error) string {
	if err == nil {
		return "none"
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "scheme must be http or https"):
		return "scheme"
	case strings.Contains(message, "absolute hierarchical URL"):
		return "hierarchy"
	case strings.Contains(message, "userinfo"):
		return "userinfo"
	case strings.Contains(message, "fragment"):
		return "fragment"
	case strings.Contains(message, "invalid port"):
		return "port"
	case strings.Contains(message, "invalid dynamic URL host"):
		return "host"
	case strings.Contains(message, "dot path segments"):
		return "dot_segments"
	case strings.Contains(message, "escaped whitespace or control"):
		return "escaped_component"
	default:
		return "other"
	}
}

func normalizePlaybackInfoSchemelessURL(value string, base *url.URL) (string, bool) {
	if base == nil || value == "" || value != strings.TrimSpace(value) || containsDynamicUnsafeRune(value) || strings.Contains(value, `\`) {
		return "", false
	}
	tail := value
	explicitScheme := ""
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
		return "", false
	case strings.HasPrefix(lower, "http:"):
		explicitScheme = "http"
		tail = strings.TrimLeft(value[len("http:"):], "/")
	case strings.HasPrefix(lower, "https:"):
		explicitScheme = "https"
		tail = strings.TrimLeft(value[len("https:"):], "/")
	case strings.Contains(value, "://"):
		return "", false
	}
	if tail == "" {
		return "", false
	}
	authorityEnd := len(tail)
	if index := strings.IndexAny(tail, "/?#"); index >= 0 {
		authorityEnd = index
	}
	authority := tail[:authorityEnd]
	host, portText, err := net.SplitHostPort(authority)
	if err != nil || host == "" || portText == "" || strings.Contains(authority, "@") {
		return "", false
	}
	if _, _, err := normalizeDynamicHostSyntax(host); err != nil {
		return "", false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", false
	}
	scheme := explicitScheme
	if scheme == "" {
		scheme = strings.ToLower(base.Scheme)
		switch port {
		case 80:
			scheme = "http"
		case 443:
			scheme = "https"
		default:
			if scheme != "http" && scheme != "https" {
				return "", false
			}
		}
	}
	candidate := scheme + "://" + tail
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" {
		return "", false
	}
	return candidate, true
}

func playbackInfoExtremeNetworkURL(value string, session *dynamicRewriteSession) (string, bool) {
	if session != nil {
		if normalized, ok := normalizePlaybackInfoSchemelessURL(value, session.base); ok {
			value = normalized
		}
	}
	if value == "" || value != strings.TrimSpace(value) || strings.Contains(value, `\`) || containsDynamicUnsafeRune(value) {
		return "", false
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Opaque != "" || parsed.Host == "" || (!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https")) {
		return "", false
	}
	return value, true
}

func playbackInfoExtremeCapabilityType(value string, session *dynamicRewriteSession) (string, string, error) {
	if normalized, ok := playbackInfoExtremeNetworkURL(value, session); ok {
		value = normalized
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", "", fmt.Errorf("PlaybackInfo fallback URL is invalid")
	}
	manifestSource := ""
	path := strings.ToLower(parsed.Path)
	switch {
	case strings.HasSuffix(path, ".m3u8"), strings.HasSuffix(path, ".m3u"):
		manifestSource = dynamicDiscoverySourceHLS
	case strings.HasSuffix(path, ".mpd"):
		manifestSource = dynamicDiscoverySourceDASH
	}
	if manifestSource == "" {
		return dynamicDiscoverySourcePlaybackInfo, dynamicCapabilityKindResource, nil
	}
	if session == nil || session.issuer == nil || !session.issuer.policy.sourceEnabled(manifestSource) {
		return "", "", fmt.Errorf("external PlaybackInfo manifest source is unavailable")
	}
	return manifestSource, dynamicCapabilityKindManifest, nil
}

func rewriteExtremePlaybackInfoValue(value any, session *dynamicRewriteSession, requiredHeaders []dynamicCapabilityHeaderClaim, ancestorDepth int) (any, error) {
	if err := session.ctx.Err(); err != nil {
		return nil, fmt.Errorf("PlaybackInfo parsing deadline exceeded")
	}
	switch typed := value.(type) {
	case string:
		normalized, ok := playbackInfoExtremeNetworkURL(typed, session)
		if !ok {
			return typed, nil
		}
		source, kind, err := playbackInfoExtremeCapabilityType(normalized, session)
		if err != nil {
			return nil, err
		}
		return session.rewriteAgainstSourceKindWithRequiredHeaders(normalized, session.base, source, kind, requiredHeaders)
	case map[string]any:
		depth := ancestorDepth + 1
		if depth > globalDynamicMaxParseDepth {
			return nil, fmt.Errorf("PlaybackInfo nesting exceeds its limit")
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if strings.EqualFold(key, "RequiredHttpHeaders") {
				continue
			}
			rewritten, err := rewriteExtremePlaybackInfoValue(typed[key], session, requiredHeaders, depth)
			if err != nil {
				return nil, err
			}
			typed[key] = rewritten
		}
		return typed, nil
	case []any:
		depth := ancestorDepth + 1
		if depth > globalDynamicMaxParseDepth {
			return nil, fmt.Errorf("PlaybackInfo nesting exceeds its limit")
		}
		for index := range typed {
			rewritten, err := rewriteExtremePlaybackInfoValue(typed[index], session, requiredHeaders, depth)
			if err != nil {
				return nil, err
			}
			typed[index] = rewritten
		}
		return typed, nil
	default:
		return value, nil
	}
}

func rewriteExtremePlaybackInfoRootValues(root map[string]any, mediaSourcesKey string, session *dynamicRewriteSession) error {
	keys := make([]string, 0, len(root))
	for key := range root {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == mediaSourcesKey || strings.EqualFold(key, "RequiredHttpHeaders") {
			continue
		}
		rewritten, err := rewriteExtremePlaybackInfoValue(root[key], session, nil, 1)
		if err != nil {
			return err
		}
		root[key] = rewritten
	}
	return nil
}

func playbackInfoURLCandidate(value string) bool {
	if value == "" {
		return false
	}
	if strings.Contains(value, `\`) {
		return true
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return true
	}
	return parsed.IsAbs() || parsed.Host != ""
}

func playbackInfoSafeRelativeURL(value string) bool {
	if value == "" || len(value) > maxDynamicTargetURLBytes || value != strings.TrimSpace(value) || containsDynamicUnsafeRune(value) || strings.Contains(value, `\`) || strings.Contains(value, "#") || strings.HasPrefix(value, "//") {
		return false
	}
	reference, err := url.Parse(value)
	if err != nil || reference.IsAbs() || reference.Opaque != "" || reference.Host != "" || reference.User != nil || reference.Fragment != "" || reference.RawFragment != "" {
		return false
	}
	return dynamicURLDecodedComponentIsSafe(reference.EscapedPath(), false) &&
		dynamicURLDecodedComponentIsSafe(reference.RawQuery, true) &&
		!dynamicURLPathHasDotSegments(reference.EscapedPath())
}

func playbackInfoShouldRewriteURL(value string, session *dynamicRewriteSession) bool {
	return playbackInfoURLCandidate(value) || session != nil && session.rewriteRelative && value != ""
}

func playbackInfoRequiredHeadersUnsupported(value string, hasRequiredHeaders bool, session *dynamicRewriteSession) bool {
	if !hasRequiredHeaders || !playbackInfoShouldRewriteURL(value, session) {
		return false
	}
	if playbackInfoIsExtreme(session) {
		return false
	}
	if session == nil || session.rewriteRelative {
		return true
	}
	reference, err := url.Parse(value)
	if err == nil && (reference.IsAbs() || reference.Host != "") {
		resolved := session.base.ResolveReference(reference)
		if session.issuer != nil && session.issuer.configuredAuthorities[redirectHostKey(resolved)] {
			return true
		}
	}
	return !structuredURLSharesAuthority(value, session.base)
}

func playbackInfoField(object map[string]any, field string) (string, any, bool, error) {
	camel := strings.ToLower(field[:1]) + field[1:]
	pascalValue, pascalExists := object[field]
	camelValue, camelExists := object[camel]
	if pascalExists && camelExists {
		return "", nil, false, fmt.Errorf("PlaybackInfo contains duplicate casing for %s", field)
	}
	if pascalExists {
		return field, pascalValue, true, nil
	}
	if camelExists {
		return camel, camelValue, true, nil
	}
	return "", nil, false, nil
}

func rewritePlaybackInfoField(object map[string]any, field string, session *dynamicRewriteSession) error {
	return rewritePlaybackInfoFieldAs(object, field, session, dynamicDiscoverySourcePlaybackInfo, dynamicCapabilityKindResource)
}

func rewritePlaybackInfoFieldAs(object map[string]any, field string, session *dynamicRewriteSession, source, kind string) error {
	return rewritePlaybackInfoFieldAsWithRequiredHeaders(object, field, session, source, kind, nil)
}

func rewritePlaybackInfoFieldAsWithRequiredHeaders(object map[string]any, field string, session *dynamicRewriteSession, source, kind string, requiredHeaders []dynamicCapabilityHeaderClaim) error {
	key, value, exists, err := playbackInfoField(object, field)
	if err != nil || !exists || value == nil {
		return err
	}
	text, ok := value.(string)
	if !ok {
		return fmt.Errorf("PlaybackInfo field %s has an invalid type", field)
	}
	if !playbackInfoShouldRewriteURL(text, session) {
		return nil
	}
	rewritten, err := session.rewriteAgainstSourceKindWithRequiredHeaders(text, session.base, source, kind, requiredHeaders)
	if err != nil {
		return err
	}
	object[key] = rewritten
	return nil
}

func playbackInfoBool(object map[string]any, field string) (bool, bool, error) {
	_, value, exists, err := playbackInfoField(object, field)
	if err != nil || !exists || value == nil {
		return false, false, err
	}
	result, ok := value.(bool)
	if !ok {
		return false, false, fmt.Errorf("PlaybackInfo field %s has an invalid type", field)
	}
	return result, true, nil
}

func playbackInfoString(object map[string]any, field string) (string, bool, error) {
	_, value, exists, err := playbackInfoField(object, field)
	if err != nil || !exists || value == nil {
		return "", false, err
	}
	result, ok := value.(string)
	if !ok {
		return "", false, fmt.Errorf("PlaybackInfo field %s has an invalid type", field)
	}
	return result, true, nil
}

func playbackInfoManifestSource(object map[string]any, field, value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("PlaybackInfo field %s has an invalid URL", field)
	}
	path := strings.ToLower(parsed.Path)
	if strings.HasSuffix(path, ".m3u8") || strings.HasSuffix(path, ".m3u") {
		return dynamicDiscoverySourceHLS, nil
	}
	if strings.HasSuffix(path, ".mpd") {
		return dynamicDiscoverySourceDASH, nil
	}
	if field == "TranscodingUrl" {
		protocol, exists, err := playbackInfoString(object, "TranscodingSubProtocol")
		if err != nil {
			return "", err
		}
		if exists {
			switch strings.ToLower(protocol) {
			case "hls":
				return dynamicDiscoverySourceHLS, nil
			case "dash":
				return dynamicDiscoverySourceDASH, nil
			}
		}
	}
	if field == "DeliveryUrl" {
		method, exists, err := playbackInfoString(object, "DeliveryMethod")
		if err != nil {
			return "", err
		}
		if exists && strings.EqualFold(method, "Hls") {
			return dynamicDiscoverySourceHLS, nil
		}
	}
	return "", nil
}

func playbackInfoCapabilityType(object map[string]any, field, value string, session *dynamicRewriteSession) (string, string, error) {
	source := dynamicDiscoverySourcePlaybackInfo
	kind := dynamicCapabilityKindResource
	manifestSource, err := playbackInfoManifestSource(object, field, value)
	if err != nil {
		return "", "", err
	}
	if manifestSource != "" {
		if session == nil || session.issuer == nil || !session.issuer.policy.sourceEnabled(manifestSource) {
			return "", "", fmt.Errorf("external PlaybackInfo manifest source is unavailable")
		}
		source = manifestSource
		kind = dynamicCapabilityKindManifest
	}
	return source, kind, nil
}

func playbackInfoHasRequiredHeaders(object map[string]any) (bool, error) {
	_, value, exists, err := playbackInfoField(object, "RequiredHttpHeaders")
	if err != nil || !exists || value == nil {
		return false, err
	}
	headers, ok := value.(map[string]any)
	if !ok {
		return false, fmt.Errorf("PlaybackInfo RequiredHttpHeaders has an invalid type")
	}
	for name, headerValue := range headers {
		if name == "" {
			return false, fmt.Errorf("PlaybackInfo RequiredHttpHeaders has an empty name")
		}
		if _, ok := headerValue.(string); !ok {
			return false, fmt.Errorf("PlaybackInfo RequiredHttpHeaders has an invalid value")
		}
	}
	return len(headers) > 0, nil
}

func playbackInfoExtremeRequiredHeaders(object map[string]any, hasRequiredHeaders bool, session *dynamicRewriteSession) ([]dynamicCapabilityHeaderClaim, error) {
	if !hasRequiredHeaders || !playbackInfoIsExtreme(session) {
		return nil, nil
	}
	_, value, exists, err := playbackInfoField(object, "RequiredHttpHeaders")
	if err != nil || !exists {
		return nil, err
	}
	headers, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("PlaybackInfo RequiredHttpHeaders has an invalid type")
	}
	return normalizeExtremeRequiredHeaderClaims(headers, session.issuer.upstreamHeaderPolicy)
}

func playbackInfoRewriteDiagnosticCode(err error) string {
	if err == nil {
		return "none"
	}
	var discoveryErr *dynamicProxyError
	if errors.As(err, &discoveryErr) {
		switch discoveryErr.reasonCode {
		case dynamicObservationReasonSchemeDenied,
			dynamicObservationReasonPortDenied,
			dynamicObservationReasonDomainDenied,
			dynamicObservationReasonHTTPSDowngradeDenied,
			dynamicObservationReasonSelfTarget,
			dynamicObservationReasonDNSFailure,
			dynamicObservationReasonAddressDenied,
			dynamicObservationReasonDialFailure,
			dynamicObservationReasonTLSFailure,
			dynamicObservationReasonCapacityLimit,
			dynamicObservationReasonRateLimit:
			return "capability_" + discoveryErr.reasonCode
		default:
			return "capability_denied"
		}
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "parsing deadline exceeded"), strings.Contains(message, "structured response deadline exceeded"):
		return "parsing_deadline"
	case strings.Contains(message, "structural limits"), strings.Contains(message, "token limit"), strings.Contains(message, "nesting exceeds"):
		return "structural_limit"
	case strings.Contains(message, "invalid PlaybackInfo JSON"), strings.Contains(message, "invalid PlaybackInfo object"):
		return "invalid_json"
	case strings.Contains(message, "missing or duplicates MediaSources"):
		return "media_sources_missing_or_duplicate"
	case strings.Contains(message, "MediaSources has an invalid type"), strings.Contains(message, "MediaSources contains an invalid entry"):
		return "media_sources_invalid"
	case strings.Contains(message, "stringified JSON"), strings.Contains(message, "must stringify an array or object"):
		return "stringified_collection_invalid"
	case strings.Contains(message, "RequiredHttpHeaders"), strings.Contains(message, "capability required headers"), strings.Contains(message, "invalid discovered URL required headers"):
		return "required_headers_invalid"
	case strings.Contains(message, "requires unsupported origin headers"):
		return "origin_headers_unsupported"
	case strings.Contains(message, "MediaStreams has an invalid type"), strings.Contains(message, "MediaStreams contains an invalid entry"):
		return "media_streams_invalid"
	case strings.Contains(message, "DeliveryUrl"):
		return "delivery_url_invalid"
	case strings.Contains(message, "PlaybackInfo Path has an invalid type"):
		return "path_invalid"
	case strings.Contains(message, "PlaybackInfo field Protocol has an invalid type"):
		return "protocol_invalid"
	case strings.Contains(message, "PlaybackInfo field TranscodingSubProtocol has an invalid type"):
		return "transcoding_subprotocol_invalid"
	case strings.Contains(message, "PlaybackInfo field DeliveryMethod has an invalid type"):
		return "delivery_method_invalid"
	case strings.Contains(message, "PlaybackInfo field IsExternalUrl has an invalid type"):
		return "external_url_flag_invalid"
	case strings.Contains(message, "PlaybackInfo field TranscodingUrl has an invalid type"):
		return "transcoding_url_invalid"
	case strings.Contains(message, "PlaybackInfo field DirectStreamUrl has an invalid type"):
		return "direct_stream_url_invalid"
	case strings.Contains(message, "duplicate casing"):
		return "field_case_duplicate"
	case strings.Contains(message, "unsupported protocol"), strings.Contains(message, "manifest source is unavailable"):
		return "protocol_or_manifest_unsupported"
	case strings.Contains(message, "invalid discovered URL: context"):
		return "url_context_invalid"
	case strings.Contains(message, "invalid discovered URL: empty"):
		return "url_empty"
	case strings.Contains(message, "invalid discovered URL: surrounding whitespace"):
		return "url_surrounding_whitespace"
	case strings.Contains(message, "invalid discovered URL: unsafe character"):
		return "url_unsafe_character"
	case strings.Contains(message, "invalid discovered URL: backslash"):
		return "url_backslash"
	case strings.Contains(message, "invalid discovered URL: parse"):
		return "url_parse_invalid"
	case strings.Contains(message, "invalid discovered URL: userinfo"):
		return "url_userinfo"
	case strings.Contains(message, "invalid discovered URL: fragment"):
		return "url_fragment"
	case strings.Contains(message, "target normalization scheme"):
		return "url_target_scheme"
	case strings.Contains(message, "target normalization hierarchy"):
		return "url_target_hierarchy"
	case strings.Contains(message, "target normalization userinfo"):
		return "url_target_userinfo"
	case strings.Contains(message, "target normalization fragment"):
		return "url_target_fragment"
	case strings.Contains(message, "target normalization port"):
		return "url_target_port"
	case strings.Contains(message, "target normalization host"):
		return "url_target_host"
	case strings.Contains(message, "target normalization dot_segments"):
		return "url_target_dot_segments"
	case strings.Contains(message, "target normalization escaped_component"):
		return "url_target_escaped_component"
	case strings.Contains(message, "invalid discovered URL: target normalization"):
		return "url_target_normalization"
	case strings.Contains(message, "invalid discovered URL"), strings.Contains(message, "invalid configured structured URL"), strings.Contains(message, "invalid same-authority structured URL"), strings.Contains(message, "invalid trusted capability URL"), strings.Contains(message, "invalid URL"), strings.Contains(message, "fallback URL is invalid"):
		return "url_invalid"
	case strings.Contains(message, "discovered URL count exceeds"):
		return "url_count_limit"
	case strings.Contains(message, "manifest nesting exceeds"):
		return "manifest_depth_limit"
	case strings.Contains(message, "structured response output exceeds"):
		return "output_limit"
	case strings.Contains(message, "invalid structured resource kind or depth"):
		return "resource_shape_invalid"
	case strings.Contains(message, "rewrite session is unavailable"):
		return "rewrite_session_unavailable"
	default:
		return "unclassified"
	}
}

func playbackInfoRewriteDiagnosticFingerprint(err error) string {
	if err == nil {
		return "00000000"
	}
	sum := sha256.Sum256([]byte(err.Error()))
	return fmt.Sprintf("%x", sum[:4])
}

func playbackInfoAutomaticFallbackAllowed(err error) bool {
	return strings.HasPrefix(playbackInfoRewriteDiagnosticCode(err), "url_")
}

func rewritePlaybackInfoResponse(payload []byte, session *dynamicRewriteSession) ([]byte, error) {
	if session == nil || session.issuer == nil {
		return nil, fmt.Errorf("PlaybackInfo rewrite session is unavailable")
	}
	maxTokens := min(session.issuer.policy.limits.MaxURLsPerResponse*64+8192, globalDynamicMaxJSONTokens)
	tokenCount, err := validateDynamicJSONStructureWithin(session.ctx, payload, maxTokens, globalDynamicMaxParseDepth)
	if err != nil {
		return nil, fmt.Errorf("invalid PlaybackInfo JSON")
	}
	extreme := playbackInfoIsExtreme(session)
	budget := &extremePlaybackInfoJSONBudget{remainingTokens: maxTokens - tokenCount}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil || root == nil {
		return nil, fmt.Errorf("invalid PlaybackInfo object")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("invalid PlaybackInfo JSON")
	}
	mediaSourcesKey, mediaSourcesValue, exists, err := playbackInfoField(root, "MediaSources")
	if err != nil || !exists {
		return nil, fmt.Errorf("PlaybackInfo is missing or duplicates MediaSources")
	}
	mediaSources, ok := mediaSourcesValue.([]any)
	if !ok && extreme {
		if err := normalizeExtremePlaybackInfoCollectionField(root, "MediaSources", 1, budget, session); err != nil {
			return nil, err
		}
		mediaSourcesValue = root[mediaSourcesKey]
		mediaSources, ok = mediaSourcesValue.([]any)
	}
	if !ok {
		return nil, fmt.Errorf("PlaybackInfo MediaSources has an invalid type")
	}
	for _, sourceValue := range mediaSources {
		if err := session.ctx.Err(); err != nil {
			return nil, fmt.Errorf("PlaybackInfo parsing deadline exceeded")
		}
		source, ok := sourceValue.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("PlaybackInfo MediaSources contains an invalid entry")
		}
		if extreme {
			if err := normalizeExtremePlaybackInfoCollectionField(source, "MediaStreams", 3, budget, session); err != nil {
				return nil, err
			}
			if err := normalizeExtremePlaybackInfoCollectionField(source, "MediaAttachments", 3, budget, session); err != nil {
				return nil, err
			}
		}
		hasRequiredHeaders, err := playbackInfoHasRequiredHeaders(source)
		if err != nil {
			return nil, err
		}
		requiredHeaders, err := playbackInfoExtremeRequiredHeaders(source, hasRequiredHeaders, session)
		if err != nil {
			return nil, err
		}
		for _, field := range []string{"TranscodingUrl", "DirectStreamUrl"} {
			_, value, exists, err := playbackInfoField(source, field)
			if err != nil {
				return nil, err
			}
			text, isString := value.(string)
			if exists && value != nil && !isString {
				return nil, fmt.Errorf("PlaybackInfo field %s has an invalid type", field)
			}
			relativeMainURL := exists && isString && text != "" && !playbackInfoURLCandidate(text)
			if relativeMainURL {
				reference, parseErr := url.Parse(text)
				if !playbackInfoSafeRelativeURL(text) || parseErr != nil || reference.Path == "" {
					return nil, fmt.Errorf("PlaybackInfo field %s is not a safe relative URL", field)
				}
				if hasRequiredHeaders && session.rewriteRelative && !playbackInfoIsExtreme(session) {
					return nil, fmt.Errorf("external PlaybackInfo URL requires unsupported origin headers")
				}
				// Preserve the same-origin URL exactly as the server returned it. The
				// client will request it through Meridian, while the short-lived learned
				// path only enables safe 30x backend discovery for that later request.
				session.rememberRelativePlaybackPath(text)
				if session.rewriteRelative && session.issuer != nil && session.issuer.pathPrefix != "" {
					source[field] = addIngressPathPrefix(text, session.issuer.pathPrefix)
				}
			}
			shouldRewrite := exists && isString && !relativeMainURL && playbackInfoShouldRewriteURL(text, session)
			if shouldRewrite && playbackInfoRequiredHeadersUnsupported(text, hasRequiredHeaders, session) {
				return nil, fmt.Errorf("external PlaybackInfo URL requires unsupported origin headers")
			}
			if !shouldRewrite {
				continue
			}
			capabilitySource := dynamicDiscoverySourcePlaybackInfo
			kind := dynamicCapabilityKindResource
			capabilitySource, kind, err = playbackInfoCapabilityType(source, field, text, session)
			if err != nil {
				return nil, err
			}
			if err := rewritePlaybackInfoFieldAsWithRequiredHeaders(source, field, session, capabilitySource, kind, requiredHeaders); err != nil {
				return nil, err
			}
		}
		protocol, protocolExists, protocolErr := playbackInfoString(source, "Protocol")
		if protocolErr != nil && !extreme {
			return nil, protocolErr
		}
		_, pathValue, pathExists, pathErr := playbackInfoField(source, "Path")
		if pathErr != nil {
			return nil, pathErr
		}
		pathText, pathIsString := pathValue.(string)
		if pathExists && !pathIsString && pathValue != nil {
			return nil, fmt.Errorf("PlaybackInfo Path has an invalid type")
		}
		_, absoluteHTTPPath := playbackInfoExtremeNetworkURL(pathText, session)
		absoluteHTTPPath = extreme && pathIsString && absoluteHTTPPath
		if protocolErr != nil && !absoluteHTTPPath {
			return nil, protocolErr
		}
		if pathIsString && playbackInfoShouldRewriteURL(pathText, session) {
			switch {
			case absoluteHTTPPath:
				capabilitySource, kind, err := playbackInfoCapabilityType(source, "Path", pathText, session)
				if err != nil {
					return nil, err
				}
				if err := rewritePlaybackInfoFieldAsWithRequiredHeaders(source, "Path", session, capabilitySource, kind, requiredHeaders); err != nil {
					return nil, err
				}
			case protocolExists && strings.EqualFold(protocol, "File"):
				// File paths are server-local, including Windows drive and UNC forms.
			case protocolExists && strings.EqualFold(protocol, "Http"):
				if playbackInfoRequiredHeadersUnsupported(pathText, hasRequiredHeaders, session) {
					return nil, fmt.Errorf("remote PlaybackInfo Path requires unsupported origin headers")
				}
				capabilitySource, kind, err := playbackInfoCapabilityType(source, "Path", pathText, session)
				if err != nil {
					return nil, err
				}
				if err := rewritePlaybackInfoFieldAsWithRequiredHeaders(source, "Path", session, capabilitySource, kind, requiredHeaders); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("external PlaybackInfo Path uses an unsupported protocol")
			}
		}
		_, streamsValue, streamsExist, err := playbackInfoField(source, "MediaStreams")
		if err != nil {
			return nil, err
		}
		if streamsExist && streamsValue != nil {
			streams, ok := streamsValue.([]any)
			if !ok {
				return nil, fmt.Errorf("PlaybackInfo MediaStreams has an invalid type")
			}
			for _, streamValue := range streams {
				stream, ok := streamValue.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("PlaybackInfo MediaStreams contains an invalid entry")
				}
				isExternalURL, _, err := playbackInfoBool(stream, "IsExternalUrl")
				if err != nil {
					return nil, err
				}
				deliveryKey, deliveryValue, deliveryExists, err := playbackInfoField(stream, "DeliveryUrl")
				if err != nil {
					return nil, err
				}
				deliveryText, deliveryIsString := deliveryValue.(string)
				if deliveryExists && !deliveryIsString && deliveryValue != nil {
					return nil, fmt.Errorf("PlaybackInfo DeliveryUrl has an invalid type")
				}
				shouldRewriteDelivery := deliveryIsString && playbackInfoShouldRewriteURL(deliveryText, session)
				relativeExternalDelivery := deliveryIsString && isExternalURL && !playbackInfoURLCandidate(deliveryText)
				if relativeExternalDelivery && !playbackInfoSafeRelativeURL(deliveryText) {
					return nil, fmt.Errorf("external PlaybackInfo DeliveryUrl is not a safe relative URL")
				}
				if deliveryIsString && (isExternalURL || shouldRewriteDelivery) {
					if (relativeExternalDelivery && hasRequiredHeaders && !extreme) || playbackInfoRequiredHeadersUnsupported(deliveryText, hasRequiredHeaders, session) {
						return nil, fmt.Errorf("external subtitle URL requires unsupported origin headers")
					}
					capabilitySource, kind, err := playbackInfoCapabilityType(stream, "DeliveryUrl", deliveryText, session)
					if err != nil {
						return nil, err
					}
					if relativeExternalDelivery {
						// Some Emby-compatible servers mark relative subtitle DeliveryUrl
						// values as external. Resolve them against the real upstream
						// PlaybackInfo URL so the optional subtitle cannot reject the video.
						rewritten, err := session.rewriteAgainstSourceKindWithRequiredHeaders(deliveryText, session.base, capabilitySource, kind, requiredHeaders)
						if err != nil {
							return nil, err
						}
						stream[deliveryKey] = rewritten
					} else if err := rewritePlaybackInfoFieldAsWithRequiredHeaders(stream, "DeliveryUrl", session, capabilitySource, kind, requiredHeaders); err != nil {
						return nil, err
					}
				}
			}
		}
		if extreme {
			if _, err := rewriteExtremePlaybackInfoValue(source, session, requiredHeaders, 2); err != nil {
				return nil, err
			}
		}
	}
	if extreme {
		if err := rewriteExtremePlaybackInfoRootValues(root, mediaSourcesKey, session); err != nil {
			return nil, err
		}
	}
	output := dynamicBoundedBuffer{limit: session.structuredOutputLimit()}
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(root); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), nil
}

// rewriteAutomaticPlaybackInfoResponse follows the response-rewrite model used
// by simple Emby reverse proxies: every complete HTTP(S) URL in the JSON value
// tree is routed back through Meridian. Invalid or unsupported URL candidates
// are preserved instead of rejecting the entire PlaybackInfo response.
func rewriteAutomaticPlaybackInfoResponse(payload []byte, session *dynamicRewriteSession) ([]byte, error) {
	if session == nil || session.issuer == nil || session.base == nil {
		return nil, fmt.Errorf("automatic PlaybackInfo rewrite session is unavailable")
	}
	maxTokens := min(session.issuer.policy.limits.MaxURLsPerResponse*64+8192, globalDynamicMaxJSONTokens)
	if _, err := validateDynamicJSONStructureWithin(session.ctx, payload, maxTokens, globalDynamicMaxParseDepth); err != nil {
		return nil, fmt.Errorf("invalid automatic PlaybackInfo JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var root any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("invalid automatic PlaybackInfo JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("invalid automatic PlaybackInfo JSON")
	}
	rewritten := rewriteAutomaticPlaybackInfoValue(root, session, 0, "")
	output := dynamicBoundedBuffer{limit: session.structuredOutputLimit()}
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(rewritten); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), nil
}

func rewriteAutomaticPlaybackInfoValue(value any, session *dynamicRewriteSession, depth int, field string) any {
	if session == nil || depth > globalDynamicMaxParseDepth || session.ctx.Err() != nil {
		return value
	}
	switch typed := value.(type) {
	case string:
		candidate, ok := automaticPlaybackInfoURLCandidate(typed, session.base)
		if !ok && (strings.EqualFold(field, "DirectStreamUrl") || strings.EqualFold(field, "TranscodingUrl")) {
			session.rememberRelativePlaybackPath(typed)
		}
		if !ok {
			return typed
		}
		source, kind, err := playbackInfoExtremeCapabilityType(candidate, session)
		if err != nil {
			return typed
		}
		route, err := session.rewriteAgainstSourceKindWithRequiredHeaders(candidate, session.base, source, kind, nil)
		if err != nil {
			return typed
		}
		return route
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if strings.EqualFold(key, "RequiredHttpHeaders") {
				continue
			}
			typed[key] = rewriteAutomaticPlaybackInfoValue(typed[key], session, depth+1, key)
		}
		return typed
	case []any:
		for index := range typed {
			typed[index] = rewriteAutomaticPlaybackInfoValue(typed[index], session, depth+1, field)
		}
		return typed
	default:
		return value
	}
}

func automaticPlaybackInfoURLCandidate(value string, base *url.URL) (string, bool) {
	if base == nil || value == "" || value != strings.TrimSpace(value) || containsDynamicUnsafeRune(value) || strings.Contains(value, `\`) {
		return "", false
	}
	if normalized, ok := normalizePlaybackInfoSchemelessURL(value, base); ok {
		value = normalized
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" {
		return "", false
	}
	if !parsed.IsAbs() && parsed.Host != "" {
		parsed = base.ResolveReference(parsed)
	}
	if !parsed.IsAbs() || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return "", false
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return "", false
	}
	return parsed.String(), true
}
