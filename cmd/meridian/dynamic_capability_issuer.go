package main

import (
	"context"
	"crypto/sha256"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type dynamicCapabilityIssuer struct {
	key                   []byte
	siteID                int64
	policyRevision        int64
	policy                dynamicRedirectPolicy
	state                 *dynamicSiteState
	database              *DB
	transportFactory      dynamicTransportFactory
	configuredAuthorities map[string]bool
	primaryAuthority      string
	site                  Site
	trustedProxies        []*net.IPNet
	configuredTransport   http.RoundTripper
	uaPolicy              UAHeaderPolicy
	upstreamHeaderPolicy  upstreamHeaderPolicy
	pathPrefix            string
}

func (i *dynamicCapabilityIssuer) clientRoute(route string) string {
	if i == nil {
		return route
	}
	return addIngressPathPrefix(route, i.pathPrefix)
}

func (i *dynamicCapabilityIssuer) capabilityToken(route string) string {
	if i == nil {
		return strings.TrimPrefix(route, dynamicRoutePrefix)
	}
	return strings.TrimPrefix(strings.TrimPrefix(route, i.pathPrefix), dynamicRoutePrefix)
}

func validDynamicCapabilityResource(source, kind string, depth int) bool {
	switch kind {
	case dynamicCapabilityKindResource:
		return depth == 0
	case dynamicCapabilityKindManifest:
		return (source == dynamicDiscoverySourceHLS || source == dynamicDiscoverySourceDASH) && depth >= 1 && depth <= maxDynamicManifestDepth
	default:
		return false
	}
}

func (i *dynamicCapabilityIssuer) newTransport(target *url.URL, pinnedIPs []net.IP, selfTargets *dynamicSelfTargetPolicy) (*http.Transport, error) {
	if i != nil && i.transportFactory != nil {
		return i.transportFactory(target, pinnedIPs, selfTargets)
	}
	return newDynamicTransport(target, pinnedIPs, selfTargets)
}

func (i *dynamicCapabilityIssuer) observe(source, decision, reasonCode, authority string) {
	if i == nil || i.database == nil || authority == "" {
		return
	}
	targetKind := dynamicObservationTargetDiscovered
	if authority == i.primaryAuthority || strings.TrimSuffix(authority, ":443") == strings.TrimSuffix(i.primaryAuthority, ":443") || strings.TrimSuffix(authority, ":80") == strings.TrimSuffix(i.primaryAuthority, ":80") {
		targetKind = dynamicObservationTargetSameAuthority
	} else if i.configuredAuthorities[authority] {
		targetKind = dynamicObservationTargetConfigured
	}
	i.database.EnqueueDynamicObservation(dynamicObservationEvent{
		SiteID:             i.siteID,
		CanonicalAuthority: authority,
		Source:             source,
		TargetKind:         targetKind,
		Decision:           decision,
		ReasonCode:         reasonCode,
		RedirectStatus:     0,
	})
}

func (i *dynamicCapabilityIssuer) mint(ctx context.Context, previous, target *url.URL, source string) (string, *dynamicProxyError) {
	route, acquired, err := i.mintTracked(ctx, previous, target, source)
	if err == nil && acquired && !i.state.settleCapabilities([]string{i.capabilityToken(route)}, true, time.Now()) {
		return "", newDynamicProxyError(dynamicObservationReasonCapacityLimit)
	}
	return route, err
}

func (i *dynamicCapabilityIssuer) mintTracked(ctx context.Context, previous, target *url.URL, source string) (string, bool, *dynamicProxyError) {
	if target == nil {
		return "", false, newDynamicProxyError(dynamicObservationReasonInvalidLocation)
	}
	return i.mintValidatedTracked(ctx, previous, target, source, target.String(), nil)
}

func (i *dynamicCapabilityIssuer) mintValidated(ctx context.Context, previous, validationTarget *url.URL, source, claimTarget string, template []string) (string, *dynamicProxyError) {
	route, acquired, err := i.mintValidatedTracked(ctx, previous, validationTarget, source, claimTarget, template)
	if err == nil && acquired && !i.state.settleCapabilities([]string{i.capabilityToken(route)}, true, time.Now()) {
		return "", newDynamicProxyError(dynamicObservationReasonCapacityLimit)
	}
	return route, err
}

func (i *dynamicCapabilityIssuer) mintValidatedTracked(ctx context.Context, previous, validationTarget *url.URL, source, claimTarget string, template []string) (string, bool, *dynamicProxyError) {
	return i.mintValidatedResourceTracked(ctx, previous, validationTarget, source, claimTarget, template, nil, dynamicCapabilityKindResource, 0)
}

func (i *dynamicCapabilityIssuer) mintValidatedDASHTemplateTracked(ctx context.Context, previous, validationTarget *url.URL, source, claimTarget string, template, templateFixed []string) (string, bool, *dynamicProxyError) {
	return i.mintValidatedResourceTracked(ctx, previous, validationTarget, source, claimTarget, template, templateFixed, dynamicCapabilityKindResource, 0)
}

func dynamicCapabilityRequiredHeadersCacheKey(headers []dynamicCapabilityHeaderClaim) string {
	if len(headers) == 0 {
		return ""
	}
	var key strings.Builder
	key.WriteString("\x00required-headers")
	for _, header := range headers {
		key.WriteByte('\x00')
		key.WriteString(header.Name)
		key.WriteByte('\x1f')
		key.WriteString(header.Value)
	}
	return key.String()
}

func dynamicCapabilityCacheKey(source, kind string, depth int, previousScheme, claimTarget string, template, templateFixed []string) string {
	return "dynamic\x00" + source + "\x00" + kind + "\x00" + strconv.Itoa(depth) + "\x00" + previousScheme + "\x00" + claimTarget + "\x00" + strings.Join(template, "\x1f") + "\x00" + strings.Join(templateFixed, "\x1f")
}

func dynamicCapabilityCacheKeyWithRequiredHeaders(source, kind string, depth int, previousScheme, claimTarget string, template, templateFixed []string, headers []dynamicCapabilityHeaderClaim) string {
	return dynamicCapabilityCacheKey(source, kind, depth, previousScheme, claimTarget, template, templateFixed) + dynamicCapabilityRequiredHeadersCacheKey(headers)
}

func trustedCapabilityCacheKey(source, kind string, depth int, claimTarget string, template, templateFixed []string) string {
	return "trusted\x00" + source + "\x00" + kind + "\x00" + strconv.Itoa(depth) + "\x00" + claimTarget + "\x00" + strings.Join(template, "\x1f") + "\x00" + strings.Join(templateFixed, "\x1f")
}

func trustedCapabilityCacheKeyWithRequiredHeaders(source, kind string, depth int, claimTarget string, template, templateFixed []string, headers []dynamicCapabilityHeaderClaim) string {
	return trustedCapabilityCacheKey(source, kind, depth, claimTarget, template, templateFixed) + dynamicCapabilityRequiredHeadersCacheKey(headers)
}

func (i *dynamicCapabilityIssuer) mintValidatedResourceTracked(ctx context.Context, previous, validationTarget *url.URL, source, claimTarget string, template, templateFixed []string, kind string, depth int) (string, bool, *dynamicProxyError) {
	return i.mintValidatedResourceWithRequiredHeadersTracked(ctx, previous, validationTarget, source, claimTarget, template, templateFixed, nil, kind, depth)
}

func (i *dynamicCapabilityIssuer) mintValidatedResourceWithRequiredHeadersTracked(ctx context.Context, previous, validationTarget *url.URL, source, claimTarget string, template, templateFixed []string, requiredHeaders []dynamicCapabilityHeaderClaim, kind string, depth int) (string, bool, *dynamicProxyError) {
	if i == nil || !i.policy.available || !i.policy.sourceEnabled(source) || i.state == nil || len(i.key) != sha256.Size {
		return "", false, newDynamicProxyError(dynamicObservationReasonRuntimeUnavailable)
	}
	if !validDynamicCapabilityResource(source, kind, depth) {
		return "", false, newDynamicProxyError(dynamicObservationReasonInvalidLocation)
	}
	if err := validateDynamicCapabilityRequiredHeaderClaims(requiredHeaders); err != nil || len(requiredHeaders) > 0 && (i.policy.profile != dynamicProfileExtreme || dynamicRequiredHeadersConflictWithFixedPolicy(requiredHeaders, i.upstreamHeaderPolicy)) {
		return "", false, newDynamicProxyError(dynamicObservationReasonInvalidLocation)
	}
	selfTargets := i.state.runtime.selfTargets.Load()
	authority := dynamicCanonicalAuthority(validationTarget)
	if validationTarget == nil || authority == "" || claimTarget == "" || len(claimTarget) > maxDynamicTargetURLBytes {
		return "", false, newDynamicProxyError(dynamicObservationReasonInvalidLocation)
	}
	if reasonCode := i.policy.validateTarget(previous, validationTarget, selfTargets); reasonCode != "" {
		i.observe(source, dynamicObservationDecisionDenied, reasonCode, authority)
		return "", false, newDynamicProxyError(reasonCode)
	}
	reservation, reasonCode := i.state.reserveAuthority(authority, time.Now())
	if reasonCode != "" {
		i.observe(source, dynamicObservationDecisionDenied, reasonCode, authority)
		return "", false, newDynamicProxyError(reasonCode)
	}
	if _, reasonCode = reservation.resolve(ctx, validationTarget, selfTargets); reasonCode != "" {
		reservation.rollback()
		i.observe(source, dynamicObservationDecisionDenied, reasonCode, authority)
		return "", false, newDynamicProxyError(reasonCode)
	}
	now := time.Now()
	expiresAt := time.Unix(now.Unix()+i.policy.limits.AbsoluteLifetimeSeconds, 0)
	previousScheme := ""
	if previous != nil && (strings.EqualFold(previous.Scheme, "http") || strings.EqualFold(previous.Scheme, "https")) {
		previousScheme = strings.ToLower(previous.Scheme)
	}
	cacheKey := dynamicCapabilityCacheKeyWithRequiredHeaders(source, kind, depth, previousScheme, claimTarget, template, templateFixed, requiredHeaders)
	if token, exists := i.state.reuseCapability(cacheKey, time.Now()); exists {
		reservation.rollback()
		i.observe(source, dynamicObservationDecisionAllowed, dynamicObservationReasonCandidateAllowed, authority)
		return i.clientRoute(dynamicRoutePrefix + token), true, nil
	}
	claims := dynamicCapabilityClaims{
		Version:         dynamicCapabilityVersion,
		SiteID:          i.siteID,
		PolicyRevision:  i.policyRevision,
		Source:          source,
		Target:          claimTarget,
		Kind:            kind,
		Depth:           depth,
		IssuedAt:        now.Unix(),
		ExpiresAt:       expiresAt.Unix(),
		Template:        append([]string(nil), template...),
		TemplateFixed:   append([]string(nil), templateFixed...),
		RequiredHeaders: append([]dynamicCapabilityHeaderClaim(nil), requiredHeaders...),
	}
	if previousScheme != "" {
		claims.PreviousScheme = previousScheme
	}
	token, err := sealDynamicCapability(i.key, claims)
	if err != nil {
		reservation.rollback()
		i.observe(source, dynamicObservationDecisionDenied, dynamicObservationReasonResponseFailure, authority)
		return "", false, newDynamicProxyError(dynamicObservationReasonResponseFailure)
	}
	registeredToken, registered := i.state.registerCapability(token, cacheKey, expiresAt, now, reservation)
	if !registered {
		reservation.rollback()
		i.observe(source, dynamicObservationDecisionDenied, dynamicObservationReasonCapacityLimit, authority)
		return "", false, newDynamicProxyError(dynamicObservationReasonCapacityLimit)
	}
	if registeredToken != token {
		reservation.rollback()
	}
	i.observe(source, dynamicObservationDecisionAllowed, dynamicObservationReasonCandidateAllowed, authority)
	return i.clientRoute(dynamicRoutePrefix + registeredToken), true, nil
}

func (i *dynamicCapabilityIssuer) mintTrustedTracked(target *url.URL, source, kind string, depth int) (string, bool, *dynamicProxyError) {
	if target == nil {
		return "", false, newDynamicProxyError(dynamicObservationReasonInvalidLocation)
	}
	return i.mintTrustedValidatedTracked(target, target.String(), nil, nil, source, kind, depth)
}

func (i *dynamicCapabilityIssuer) mintTrustedValidatedTracked(validationTarget *url.URL, claimTarget string, template, templateFixed []string, source, kind string, depth int) (string, bool, *dynamicProxyError) {
	return i.mintTrustedValidatedWithRequiredHeadersTracked(validationTarget, claimTarget, template, templateFixed, nil, source, kind, depth)
}

func (i *dynamicCapabilityIssuer) mintTrustedValidatedWithRequiredHeadersTracked(validationTarget *url.URL, claimTarget string, template, templateFixed []string, requiredHeaders []dynamicCapabilityHeaderClaim, source, kind string, depth int) (string, bool, *dynamicProxyError) {
	if i == nil || !i.policy.available || !i.policy.sourceEnabled(source) || i.state == nil || len(i.key) != sha256.Size || i.configuredTransport == nil || !validDynamicCapabilityResource(source, kind, depth) {
		return "", false, newDynamicProxyError(dynamicObservationReasonRuntimeUnavailable)
	}
	if err := validateDynamicCapabilityRequiredHeaderClaims(requiredHeaders); err != nil || len(requiredHeaders) > 0 && (i.policy.profile != dynamicProfileExtreme || dynamicRequiredHeadersConflictWithFixedPolicy(requiredHeaders, i.upstreamHeaderPolicy)) {
		return "", false, newDynamicProxyError(dynamicObservationReasonInvalidLocation)
	}
	normalized, err := normalizeTrustedCapabilityURL(validationTarget.String())
	hasTemplate := len(template) != 0 || len(templateFixed) != 0
	if err != nil || !i.configuredAuthorities[redirectHostKey(normalized)] || claimTarget == "" || len(claimTarget) > maxDynamicTargetURLBytes || hasTemplate && (source != dynamicDiscoverySourceDASH || kind != dynamicCapabilityKindResource || depth != 0) || !hasTemplate && claimTarget != normalized.String() {
		return "", false, newDynamicProxyError(dynamicObservationReasonInvalidLocation)
	}
	now := time.Now()
	expiresAt := time.Unix(now.Unix()+i.policy.limits.AbsoluteLifetimeSeconds, 0)
	cacheKey := trustedCapabilityCacheKeyWithRequiredHeaders(source, kind, depth, claimTarget, template, templateFixed, requiredHeaders)
	if token, exists := i.state.reuseCapability(cacheKey, now); exists {
		return i.clientRoute(dynamicRoutePrefix + token), true, nil
	}
	claims := dynamicCapabilityClaims{
		Version:         dynamicCapabilityVersion,
		SiteID:          i.siteID,
		PolicyRevision:  i.policyRevision,
		Source:          source,
		Target:          claimTarget,
		Kind:            kind,
		Depth:           depth,
		Trusted:         true,
		IssuedAt:        now.Unix(),
		ExpiresAt:       expiresAt.Unix(),
		Template:        append([]string(nil), template...),
		TemplateFixed:   append([]string(nil), templateFixed...),
		RequiredHeaders: append([]dynamicCapabilityHeaderClaim(nil), requiredHeaders...),
	}
	token, err := sealDynamicCapability(i.key, claims)
	if err != nil {
		return "", false, newDynamicProxyError(dynamicObservationReasonResponseFailure)
	}
	registeredToken, registered := i.state.registerCapability(token, cacheKey, expiresAt, now, nil)
	if !registered {
		return "", false, newDynamicProxyError(dynamicObservationReasonCapacityLimit)
	}
	return i.clientRoute(dynamicRoutePrefix + registeredToken), true, nil
}
