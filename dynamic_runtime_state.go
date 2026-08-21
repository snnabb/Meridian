package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dynamicRedirectUserAgent        = "Meridian-Redirect/1.0"
	dynamicDNSResolutionTimeout     = 30 * time.Second
	dynamicPinnedDialTimeout        = 30 * time.Second
	dynamicStructuredBodyTimeout    = 20 * time.Second
	dynamicLearnedPlaybackPathTTL   = 15 * time.Minute
	dynamicLearnedPlaybackPathLimit = 128
)

type dynamicRequestEligibleContextKey struct{}
type dynamicResponseContextKey struct{}
type dynamicExpectedStructuredSourceContextKey struct{}
type dynamicPlaybackInfoBaseContextKey struct{}
type mainVideoDirectFallbackContextKey struct{}
type mainVideoDirectResolvedContextKey struct{}

// dynamicOutboundContext keeps request cancellation and deadlines while
// dropping ReverseProxy's outbound httptrace and every other caller value.
// Otherwise an unknown authority can emit 1xx headers directly to the client
// before ModifyResponse applies the dynamic response allowlist.
type dynamicOutboundContext struct {
	context.Context
}

func (outbound dynamicOutboundContext) Value(key any) any {
	// Preserve only Meridian's internal PlaybackInfo learning base across a
	// dynamic hop. All caller-provided context values remain isolated.
	if _, ok := key.(dynamicPlaybackInfoBaseContextKey); ok {
		return outbound.Context.Value(key)
	}
	if _, ok := key.(backendAddressContextKey); ok {
		return outbound.Context.Value(key)
	}
	return nil
}

func isolateDynamicOutboundContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return dynamicOutboundContext{Context: ctx}
}

type dynamicProxyError struct {
	statusCode int
	retryAfter string
	reasonCode string
}

func (e *dynamicProxyError) Error() string {
	return "dynamic discovery unavailable"
}

func newDynamicProxyError(reasonCode string) *dynamicProxyError {
	err := &dynamicProxyError{statusCode: http.StatusBadGateway, reasonCode: reasonCode}
	switch reasonCode {
	case dynamicObservationReasonCapacityLimit:
		err.statusCode = http.StatusServiceUnavailable
		err.retryAfter = "1"
	case dynamicObservationReasonRateLimit:
		err.statusCode = http.StatusServiceUnavailable
		err.retryAfter = "60"
	}
	return err
}

func (e *dynamicProxyError) writeResponse(w http.ResponseWriter) {
	w.Header().Del("Location")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if e.retryAfter != "" {
		w.Header().Set("Retry-After", e.retryAfter)
	}
	w.WriteHeader(e.statusCode)
	_, _ = w.Write([]byte(`{"error":"dynamic discovery unavailable"}`))
}

type dynamicRedirectPolicy struct {
	configured          bool
	available           bool
	profile             string
	limits              DynamicProfileLimits
	sources             []string
	domainRules         []DynamicDomainRule
	allowHTTPSDowngrade bool
}

func newDynamicRedirectPolicy(site Site, available bool) (dynamicRedirectPolicy, error) {
	_ = site
	limits, ok := dynamicLimitsForProfile(dynamicProfileCompatible)
	if !ok {
		return dynamicRedirectPolicy{}, fmt.Errorf("automatic proxy policy is unavailable")
	}
	return dynamicRedirectPolicy{
		configured:          true,
		available:           available,
		profile:             dynamicProfileCompatible,
		limits:              limits,
		sources:             allDynamicDiscoverySources(),
		domainRules:         nil,
		allowHTTPSDowngrade: true,
	}, nil
}
func (p dynamicRedirectPolicy) sourceEnabled(source string) bool {
	return p.configured && dynamicDiscoverySourceEnabled(p.sources, source)
}

func (p dynamicRedirectPolicy) validateTarget(previous, target *url.URL, selfTargets *dynamicSelfTargetPolicy) string {
	allowedScheme := false
	for _, scheme := range p.limits.AllowedSchemes {
		if target.Scheme == scheme {
			allowedScheme = true
			break
		}
	}
	if !allowedScheme {
		return dynamicObservationReasonSchemeDenied
	}
	portText, ok := dynamicEffectivePort(target)
	if !ok {
		return dynamicObservationReasonPortDenied
	}
	port, _ := strconv.Atoi(portText)
	if !p.limits.AllowAnyPort {
		allowedPort := false
		for _, candidate := range p.limits.AllowedPorts {
			if port == candidate {
				allowedPort = true
				break
			}
		}
		if !allowedPort {
			return dynamicObservationReasonPortDenied
		}
	}
	if p.profile == dynamicProfileSafe && !dynamicSafeDomainAllowed(target.Hostname(), p.domainRules) {
		return dynamicObservationReasonDomainDenied
	}
	if previous != nil && strings.EqualFold(previous.Scheme, "https") && target.Scheme == "http" && !p.allowHTTPSDowngrade {
		return dynamicObservationReasonHTTPSDowngradeDenied
	}
	if selfTargets == nil {
		return dynamicObservationReasonRuntimeUnavailable
	}
	if err := selfTargets.validateNormalizedTarget(target); err != nil {
		return dynamicObservationReasonSelfTarget
	}
	return ""
}

type dynamicAuthorityResolution struct {
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	start      sync.Once
	ips        []net.IP
	reasonCode string
}

func newDynamicAuthorityResolution() *dynamicAuthorityResolution {
	ctx, cancel := context.WithTimeout(context.Background(), dynamicDNSResolutionTimeout)
	return &dynamicAuthorityResolution{
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
}

type dynamicAuthorityEntry struct {
	inFlight   int
	committed  bool
	resolution *dynamicAuthorityResolution
}

type dynamicCapabilityEntry struct {
	expiresAt   time.Time
	lastUsed    time.Time
	token       string
	cacheKey    string
	pendingUses int
	published   bool
	reservation *dynamicAuthorityReservation
}

type dynamicLearnedPlaybackPath struct {
	lastSeen  time.Time
	expiresAt time.Time
}

type dynamicRuntime struct {
	dnsWorkers  chan struct{}
	streams     chan struct{}
	parses      chan struct{}
	resolver    dynamicIPResolver
	selfTargets atomic.Pointer[dynamicSelfTargetPolicy]

	mu                  sync.Mutex
	authorities         map[string]int
	newAuthorities      []time.Time
	activeCapabilities  int
	capabilityMemory    int64
	states              map[*dynamicSiteState]struct{}
	lastCapabilityPrune time.Time
	parseMemory         int64
}

func newDynamicRuntime() *dynamicRuntime {
	return &dynamicRuntime{
		dnsWorkers:  make(chan struct{}, globalDynamicMaxDNSWorkers),
		streams:     make(chan struct{}, globalDynamicMaxStreams),
		parses:      make(chan struct{}, globalDynamicMaxConcurrentParses),
		resolver:    net.DefaultResolver,
		authorities: make(map[string]int),
		states:      make(map[*dynamicSiteState]struct{}),
	}
}

type dynamicSiteState struct {
	runtime *dynamicRuntime
	limits  DynamicProfileLimits
	streams chan struct{}
	parses  chan struct{}

	mu                   sync.Mutex
	authorities          map[string]*dynamicAuthorityEntry
	capabilities         map[[sha256.Size]byte]dynamicCapabilityEntry
	capabilityByTarget   map[string]string
	capabilityMemory     int64
	learnedPlaybackPaths map[string]dynamicLearnedPlaybackPath
	newAuthorities       []time.Time
	parseMemory          int64
	closeOnce            sync.Once
}

func newDynamicSiteState(runtime *dynamicRuntime, limits DynamicProfileLimits) *dynamicSiteState {
	if runtime == nil {
		return nil
	}
	state := &dynamicSiteState{
		runtime:              runtime,
		limits:               limits,
		streams:              make(chan struct{}, limits.MaxStreams),
		parses:               make(chan struct{}, globalDynamicMaxSiteConcurrentParses),
		authorities:          make(map[string]*dynamicAuthorityEntry),
		capabilities:         make(map[[sha256.Size]byte]dynamicCapabilityEntry),
		capabilityByTarget:   make(map[string]string),
		learnedPlaybackPaths: make(map[string]dynamicLearnedPlaybackPath),
	}
	runtime.mu.Lock()
	runtime.states[state] = struct{}{}
	runtime.mu.Unlock()
	return state
}

func canonicalDynamicPlaybackPath(pathValue string) string {
	if pathValue == "" || len(pathValue) > maxDynamicTargetURLBytes || !strings.HasPrefix(pathValue, "/") || strings.HasPrefix(pathValue, "//") || strings.HasPrefix(pathValue, "/\\") || strings.ContainsAny(pathValue, "?#\\") || containsDynamicUnsafeRune(pathValue) {
		return ""
	}
	canonical := (&url.URL{Path: pathValue}).EscapedPath()
	if canonical == "" || !strings.HasPrefix(canonical, "/") || len(canonical) > maxDynamicTargetURLBytes || !dynamicURLDecodedComponentIsSafe(canonical, false) || dynamicURLPathHasDotSegments(canonical) {
		return ""
	}
	return canonical
}

func (s *dynamicSiteState) pruneLearnedPlaybackPathsLocked(now time.Time) {
	if s == nil || len(s.learnedPlaybackPaths) == 0 {
		return
	}
	for path, entry := range s.learnedPlaybackPaths {
		if !now.Before(entry.expiresAt) {
			delete(s.learnedPlaybackPaths, path)
		}
	}
}

func (s *dynamicSiteState) learnPlaybackPath(pathValue string, now time.Time) {
	if s == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	pathValue = canonicalDynamicPlaybackPath(pathValue)
	if pathValue == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.learnedPlaybackPaths == nil {
		s.learnedPlaybackPaths = make(map[string]dynamicLearnedPlaybackPath)
	}
	s.pruneLearnedPlaybackPathsLocked(now)
	entry := dynamicLearnedPlaybackPath{lastSeen: now, expiresAt: now.Add(dynamicLearnedPlaybackPathTTL)}
	if _, exists := s.learnedPlaybackPaths[pathValue]; !exists && len(s.learnedPlaybackPaths) >= dynamicLearnedPlaybackPathLimit {
		oldestPath := ""
		var oldest time.Time
		for candidate, candidateEntry := range s.learnedPlaybackPaths {
			if oldestPath == "" || candidateEntry.lastSeen.Before(oldest) {
				oldestPath = candidate
				oldest = candidateEntry.lastSeen
			}
		}
		if oldestPath != "" {
			delete(s.learnedPlaybackPaths, oldestPath)
		}
	}
	s.learnedPlaybackPaths[pathValue] = entry
}

func (s *dynamicSiteState) hasLearnedPlaybackPath(pathValue string, now time.Time) bool {
	if s == nil {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	pathValue = canonicalDynamicPlaybackPath(pathValue)
	if pathValue == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLearnedPlaybackPathsLocked(now)
	entry, exists := s.learnedPlaybackPaths[pathValue]
	return exists && now.Before(entry.expiresAt)
}

func (s *dynamicSiteState) acquireParse(memory int64) (func(), bool) {
	if s == nil || s.runtime == nil || memory <= 0 || memory > globalDynamicMaxSiteParseMemoryBytes {
		return nil, false
	}
	select {
	case s.runtime.parses <- struct{}{}:
	default:
		return nil, false
	}
	select {
	case s.parses <- struct{}{}:
	default:
		<-s.runtime.parses
		return nil, false
	}
	runtime := s.runtime
	runtime.mu.Lock()
	s.mu.Lock()
	if runtime.parseMemory+memory > globalDynamicMaxParseMemoryBytes || s.parseMemory+memory > globalDynamicMaxSiteParseMemoryBytes {
		s.mu.Unlock()
		runtime.mu.Unlock()
		<-s.parses
		<-runtime.parses
		return nil, false
	}
	runtime.parseMemory += memory
	s.parseMemory += memory
	s.mu.Unlock()
	runtime.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			runtime.mu.Lock()
			s.mu.Lock()
			runtime.parseMemory -= memory
			s.parseMemory -= memory
			s.mu.Unlock()
			runtime.mu.Unlock()
			<-runtime.parses
			<-s.parses
		})
	}, true
}

func (s *dynamicSiteState) availableParseMemory() int64 {
	if s == nil || s.runtime == nil {
		return 0
	}
	runtime := s.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	siteAvailable := globalDynamicMaxSiteParseMemoryBytes - s.parseMemory
	globalAvailable := globalDynamicMaxParseMemoryBytes - runtime.parseMemory
	if siteAvailable <= 0 || globalAvailable <= 0 {
		return 0
	}
	return min(siteAvailable, globalAvailable)
}

type dynamicCapabilityHeaderClaim struct {
	Name  string `json:"n"`
	Value string `json:"v"`
}

type dynamicCapabilityClaims struct {
	Version         int                            `json:"v"`
	SiteID          int64                          `json:"s"`
	PolicyRevision  int64                          `json:"r"`
	Source          string                         `json:"o"`
	Target          string                         `json:"t"`
	Kind            string                         `json:"k"`
	Depth           int                            `json:"d,omitempty"`
	Trusted         bool                           `json:"u,omitempty"`
	PreviousScheme  string                         `json:"p,omitempty"`
	IssuedAt        int64                          `json:"i"`
	ExpiresAt       int64                          `json:"e"`
	Template        []string                       `json:"x,omitempty"`
	TemplateFixed   []string                       `json:"f,omitempty"`
	RequiredHeaders []dynamicCapabilityHeaderClaim `json:"h,omitempty"`
}

func normalizeExtremeRequiredHeaderName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxUpstreamHeaderName {
		return "", fmt.Errorf("RequiredHttpHeaders contains an invalid name")
	}
	for index := 0; index < len(value); index++ {
		if !isHTTPTokenByte(value[index]) {
			return "", fmt.Errorf("RequiredHttpHeaders contains an invalid name")
		}
	}
	name := http.CanonicalHeaderKey(value)
	switch name {
	case "Accept", "Accept-Language", "Origin", "Referer", "User-Agent":
		return name, nil
	default:
		return "", fmt.Errorf("RequiredHttpHeaders contains a forbidden header")
	}
}

func normalizeExtremeRequiredHeaderValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("RequiredHttpHeaders contains an empty value")
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return "", fmt.Errorf("RequiredHttpHeaders values must contain printable ASCII only")
		}
	}
	return value, nil
}

func validateDynamicCapabilityRequiredHeaderClaims(headers []dynamicCapabilityHeaderClaim) error {
	if headers == nil {
		return nil
	}
	if len(headers) == 0 || len(headers) > maxExtremeRequiredHeaderClaims {
		return fmt.Errorf("invalid capability required header count")
	}
	totalBytes := 0
	previousName := ""
	for _, header := range headers {
		name, err := normalizeExtremeRequiredHeaderName(header.Name)
		if err != nil || name != header.Name || previousName != "" && header.Name <= previousName {
			return fmt.Errorf("invalid capability required header name")
		}
		value, err := normalizeExtremeRequiredHeaderValue(header.Value)
		if err != nil || value != header.Value {
			return fmt.Errorf("invalid capability required header value")
		}
		totalBytes += len(header.Name) + len(header.Value)
		if totalBytes > maxExtremeRequiredHeaderClaimBytes {
			return fmt.Errorf("capability required headers exceed their size limit")
		}
		previousName = header.Name
	}
	return nil
}

func dynamicRequiredHeadersConflictWithFixedPolicy(headers []dynamicCapabilityHeaderClaim, policy upstreamHeaderPolicy) bool {
	for _, header := range headers {
		for fixedName := range policy.values {
			if strings.EqualFold(header.Name, fixedName) {
				return true
			}
		}
	}
	return false
}

func normalizeExtremeRequiredHeaderClaims(headers map[string]any, fixedPolicy upstreamHeaderPolicy) ([]dynamicCapabilityHeaderClaim, error) {
	if len(headers) == 0 {
		return nil, nil
	}
	if len(headers) > maxExtremeRequiredHeaderClaims {
		return nil, fmt.Errorf("RequiredHttpHeaders exceeds its entry limit")
	}
	normalized := make([]dynamicCapabilityHeaderClaim, 0, len(headers))
	seen := make(map[string]bool, len(headers))
	totalBytes := 0
	for rawName, rawValue := range headers {
		name, err := normalizeExtremeRequiredHeaderName(rawName)
		if err != nil {
			return nil, err
		}
		nameKey := strings.ToLower(name)
		if seen[nameKey] {
			return nil, fmt.Errorf("RequiredHttpHeaders contains a duplicate header")
		}
		seen[nameKey] = true
		value, ok := rawValue.(string)
		if !ok {
			return nil, fmt.Errorf("RequiredHttpHeaders contains a non-string value")
		}
		value, err = normalizeExtremeRequiredHeaderValue(value)
		if err != nil {
			return nil, err
		}
		totalBytes += len(name) + len(value)
		if totalBytes > maxExtremeRequiredHeaderClaimBytes {
			return nil, fmt.Errorf("RequiredHttpHeaders exceeds its size limit")
		}
		normalized = append(normalized, dynamicCapabilityHeaderClaim{Name: name, Value: value})
	}
	sort.Slice(normalized, func(left, right int) bool {
		return normalized[left].Name < normalized[right].Name
	})
	if dynamicRequiredHeadersConflictWithFixedPolicy(normalized, fixedPolicy) {
		return nil, fmt.Errorf("RequiredHttpHeaders conflicts with a configured upstream header")
	}
	if err := validateDynamicCapabilityRequiredHeaderClaims(normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

func validateDynamicCapabilityRequiredHeaderBinding(claims dynamicCapabilityClaims) error {
	if err := validateDynamicCapabilityRequiredHeaderClaims(claims.RequiredHeaders); err != nil {
		return err
	}
	if len(claims.RequiredHeaders) == 0 {
		return nil
	}
	if len(claims.Template) != 0 || len(claims.TemplateFixed) != 0 || !validDynamicCapabilityResource(claims.Source, claims.Kind, claims.Depth) {
		return fmt.Errorf("capability required headers are not target-bound")
	}
	switch claims.Source {
	case dynamicDiscoverySourcePlaybackInfo, dynamicDiscoverySourceHLS, dynamicDiscoverySourceDASH:
	default:
		return fmt.Errorf("capability required headers use an invalid source")
	}
	var target *url.URL
	var err error
	if claims.Trusted {
		target, err = normalizeTrustedCapabilityURL(claims.Target)
	} else {
		target, err = normalizeDynamicURL(claims.Target)
	}
	if err != nil || target.String() != claims.Target {
		return fmt.Errorf("capability required headers use an invalid target")
	}
	return nil
}

func sealDynamicCapability(key []byte, claims dynamicCapabilityClaims) (string, error) {
	if len(key) != sha256.Size {
		return "", fmt.Errorf("dynamic capability key is unavailable")
	}
	if err := validateDynamicCapabilityRequiredHeaderBinding(claims); err != nil {
		return "", fmt.Errorf("dynamic capability headers are invalid")
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, payload, []byte(dynamicCapabilityAAD))
	token := base64.RawURLEncoding.EncodeToString(sealed)
	if len(token) > maxDynamicCapabilityBytes {
		return "", fmt.Errorf("dynamic capability exceeds its size limit")
	}
	return token, nil
}

func openDynamicCapability(key []byte, token string) (dynamicCapabilityClaims, error) {
	var claims dynamicCapabilityClaims
	if len(key) != sha256.Size || token == "" || len(token) > maxDynamicCapabilityBytes {
		return claims, fmt.Errorf("dynamic capability is invalid")
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil {
		return claims, fmt.Errorf("dynamic capability is invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return claims, fmt.Errorf("dynamic capability is invalid")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(sealed) < aead.NonceSize()+aead.Overhead() {
		return claims, fmt.Errorf("dynamic capability is invalid")
	}
	nonce := sealed[:aead.NonceSize()]
	payload, err := aead.Open(nil, nonce, sealed[aead.NonceSize():], []byte(dynamicCapabilityAAD))
	if err != nil {
		return claims, fmt.Errorf("dynamic capability is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return dynamicCapabilityClaims{}, fmt.Errorf("dynamic capability is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return dynamicCapabilityClaims{}, fmt.Errorf("dynamic capability is invalid")
	}
	if err := validateDynamicCapabilityRequiredHeaderBinding(claims); err != nil {
		return dynamicCapabilityClaims{}, fmt.Errorf("dynamic capability is invalid")
	}
	return claims, nil
}

func dynamicCapabilityEntryMemory(token, cacheKey string) int64 {
	return int64(sha256.Size + len(token) + len(cacheKey) + 128)
}

func dynamicCapabilityEntryValid(entry dynamicCapabilityEntry, now time.Time, idleExpiry time.Duration) bool {
	return entry.token != "" && now.Before(entry.expiresAt) && idleExpiry > 0 && now.Before(entry.lastUsed.Add(idleExpiry))
}

func (s *dynamicSiteState) deleteCapabilityLocked(key [sha256.Size]byte, entry dynamicCapabilityEntry) {
	if entry.reservation != nil {
		entry.reservation.finishLocked(false)
	}
	delete(s.capabilities, key)
	if entry.cacheKey != "" && s.capabilityByTarget[entry.cacheKey] == entry.token {
		delete(s.capabilityByTarget, entry.cacheKey)
	}
	memory := dynamicCapabilityEntryMemory(entry.token, entry.cacheKey)
	s.capabilityMemory -= memory
	s.runtime.capabilityMemory -= memory
	if s.capabilityMemory < 0 {
		s.capabilityMemory = 0
	}
	if s.runtime.capabilityMemory < 0 {
		s.runtime.capabilityMemory = 0
	}
	if s.runtime.activeCapabilities > 0 {
		s.runtime.activeCapabilities--
	}
}

func (s *dynamicSiteState) pruneCapabilitiesLocked(now time.Time) {
	if s == nil || s.runtime == nil {
		return
	}
	idleExpiry := time.Duration(s.limits.IdleExpirySeconds) * time.Second
	for key, entry := range s.capabilities {
		if entry.pendingUses == 0 && !dynamicCapabilityEntryValid(entry, now, idleExpiry) {
			s.deleteCapabilityLocked(key, entry)
		}
	}
}

func (r *dynamicRuntime) pruneCapabilitiesLocked(now time.Time) {
	if r == nil || !r.lastCapabilityPrune.IsZero() && now.Sub(r.lastCapabilityPrune) < dynamicCapabilityPruneInterval {
		return
	}
	r.lastCapabilityPrune = now
	for state := range r.states {
		state.mu.Lock()
		state.pruneCapabilitiesLocked(now)
		state.mu.Unlock()
	}
}

func (s *dynamicSiteState) reuseCapability(cacheKey string, now time.Time) (string, bool) {
	if s == nil || s.runtime == nil || cacheKey == "" {
		return "", false
	}
	runtime := s.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.pruneCapabilitiesLocked(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	token := s.capabilityByTarget[cacheKey]
	key := sha256.Sum256([]byte(token))
	entry, exists := s.capabilities[key]
	idleExpiry := time.Duration(s.limits.IdleExpirySeconds) * time.Second
	if !exists || entry.token != token || entry.cacheKey != cacheKey || !dynamicCapabilityEntryValid(entry, now, idleExpiry) {
		delete(s.capabilityByTarget, cacheKey)
		if exists && entry.token == token && entry.pendingUses == 0 {
			s.deleteCapabilityLocked(key, entry)
		}
		return "", false
	}
	entry.pendingUses++
	s.capabilities[key] = entry
	return token, true
}

func (s *dynamicSiteState) registerCapability(token, cacheKey string, expiresAt, now time.Time, reservation *dynamicAuthorityReservation) (string, bool) {
	if s == nil || s.runtime == nil || token == "" || cacheKey == "" || !expiresAt.After(now) {
		return "", false
	}
	runtime := s.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.pruneCapabilitiesLocked(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existingToken := s.capabilityByTarget[cacheKey]; existingToken != "" {
		key := sha256.Sum256([]byte(existingToken))
		if entry, exists := s.capabilities[key]; exists && entry.token == existingToken && entry.cacheKey == cacheKey {
			entry.pendingUses++
			s.capabilities[key] = entry
			return existingToken, true
		}
		delete(s.capabilityByTarget, cacheKey)
	}
	memory := dynamicCapabilityEntryMemory(token, cacheKey)
	if len(s.capabilities) >= s.limits.MaxActiveCapabilities || runtime.activeCapabilities >= globalDynamicMaxActiveCapabilities || s.capabilityMemory+memory > globalDynamicMaxSiteCapabilityMemoryBytes || runtime.capabilityMemory+memory > globalDynamicMaxCapabilityMemoryBytes {
		return "", false
	}
	key := sha256.Sum256([]byte(token))
	if _, exists := s.capabilities[key]; exists {
		return "", false
	}
	s.capabilities[key] = dynamicCapabilityEntry{expiresAt: expiresAt, lastUsed: now, token: token, cacheKey: cacheKey, pendingUses: 1, reservation: reservation}
	s.capabilityByTarget[cacheKey] = token
	runtime.activeCapabilities++
	s.capabilityMemory += memory
	runtime.capabilityMemory += memory
	return token, true
}

func (s *dynamicSiteState) settleCapabilities(tokens []string, publish bool, now time.Time) bool {
	if len(tokens) == 0 {
		return true
	}
	if s == nil || s.runtime == nil {
		return false
	}
	runtime := s.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	counts := make(map[[sha256.Size]byte]int, len(tokens))
	valid := true
	idleExpiry := time.Duration(s.limits.IdleExpirySeconds) * time.Second
	for _, token := range tokens {
		key := sha256.Sum256([]byte(token))
		counts[key]++
		entry, exists := s.capabilities[key]
		if !exists || entry.token != token || entry.pendingUses < counts[key] || publish && !dynamicCapabilityEntryValid(entry, now, idleExpiry) {
			valid = false
		}
	}
	for key, count := range counts {
		entry, exists := s.capabilities[key]
		if !exists || entry.pendingUses < count {
			continue
		}
		entry.pendingUses -= count
		if publish && valid {
			entry.published = true
			if entry.reservation != nil {
				entry.reservation.finishLocked(true)
				entry.reservation = nil
			}
			s.capabilities[key] = entry
			continue
		}
		if entry.pendingUses == 0 && !entry.published {
			s.deleteCapabilityLocked(key, entry)
		} else {
			s.capabilities[key] = entry
		}
	}
	return valid
}

func (s *dynamicSiteState) hasCapability(token string, now time.Time) bool {
	if s == nil || s.runtime == nil || token == "" {
		return false
	}
	runtime := s.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.pruneCapabilitiesLocked(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(token))
	entry, exists := s.capabilities[key]
	valid := exists && entry.token == token && entry.published && dynamicCapabilityEntryValid(entry, now, time.Duration(s.limits.IdleExpirySeconds)*time.Second)
	if exists && !valid && entry.pendingUses == 0 {
		s.deleteCapabilityLocked(key, entry)
	}
	return valid
}

func (s *dynamicSiteState) useCapability(token string, now time.Time) bool {
	if s == nil || s.runtime == nil || token == "" {
		return false
	}
	runtime := s.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.pruneCapabilitiesLocked(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(token))
	entry, exists := s.capabilities[key]
	if !exists || entry.token != token || !entry.published || !dynamicCapabilityEntryValid(entry, now, time.Duration(s.limits.IdleExpirySeconds)*time.Second) {
		if exists && entry.pendingUses == 0 {
			s.deleteCapabilityLocked(key, entry)
		}
		return false
	}
	entry.lastUsed = now
	s.capabilities[key] = entry
	return true
}

func (s *dynamicSiteState) removeCapability(token string) {
	if s == nil || s.runtime == nil || token == "" {
		return
	}
	runtime := s.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(token))
	if entry, exists := s.capabilities[key]; exists {
		s.deleteCapabilityLocked(key, entry)
	}
}
