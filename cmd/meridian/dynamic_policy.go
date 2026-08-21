package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	maxUpstreamHeaders                 = 16
	maxUpstreamHeaderName              = 64
	maxUpstreamHeaderValue             = 1024
	maxPlaybackAddresses               = 128
	maxTargetURLLength                 = 2048
	ingressModePort                    = "port"
	ingressModeHost                    = "host"
	ingressModeBoth                    = "both"
	ingressModePath                    = "path"
	ingressModeUnset                   = "unset"
	mainVideoStreamModeProxy           = "proxy"
	mainVideoStreamModeDirect          = "direct"
	dynamicRoutePrefix                 = "/_meridian/d/"
	dynamicDiscoverySourceRedirect     = "redirect"
	dynamicDiscoverySourcePlaybackInfo = "playback_info"
	dynamicDiscoverySourceHLS          = "hls"
	dynamicDiscoverySourceDASH         = "dash"
	dynamicCapabilityKindResource      = "resource"
	dynamicCapabilityKindManifest      = "manifest"
	maxDynamicManifestDepth            = 3
)

const (
	dynamicProfileSafe                 = "safe"
	dynamicProfileCompatible           = "compatible"
	dynamicCapabilityVersion           = 1
	maxDynamicCapabilityBytes          = 16384
	dynamicCapabilityAAD               = "meridian-dynamic-capability-v1"
	dynamicProfileExtreme              = "extreme"
	maxExtremeRequiredHeaderClaims     = 8
	maxExtremeRequiredHeaderClaimBytes = 4 << 10

	maxDynamicTargetURLBytes  = 4096
	maxDynamicResolvedIPCount = 64

	globalDynamicMaxAuthorities               = 16384
	globalDynamicMaxActiveCapabilities        = 131072
	globalDynamicMaxStreams                   = 1024
	globalDynamicMaxNewAuthoritiesMinute      = 2400
	globalDynamicMaxDNSWorkers                = 32
	globalDynamicMaxConcurrentParses          = 8
	globalDynamicMaxSiteConcurrentParses      = 2
	globalDynamicMaxParseMemoryBytes          = 256 << 20
	globalDynamicMaxSiteParseMemoryBytes      = 64 << 20
	globalDynamicMaxCapabilityMemoryBytes     = 256 << 20
	globalDynamicMaxSiteCapabilityMemoryBytes = 64 << 20
	dynamicCapabilityPruneInterval            = 30 * time.Second
	globalDynamicMaxParseDepth                = 64
	globalDynamicMaxStringBytes               = 1 << 20
	globalDynamicMaxStructuredInputBytes      = 8 << 20
	globalDynamicMaxStructuredOutputBytes     = 16 << 20
	globalDynamicMaxJSONTokens                = 32768
	maxDynamicCompressionRatio                = 100
	globalDynamicMaxXMLTokens                 = 100000
	globalDynamicMaxXMLNodes                  = 50000
	globalDynamicMaxXMLAttributes             = 50000
	globalDynamicMaxXMLAttributesPerElement   = 256
	globalDynamicMaxHLSAttributesPerTag       = 256
	minDynamicCompressionRatioBytes           = 1 << 20
)

// DynamicDomainRule is a structured host allow rule. Suffix rules match the
// named registrable domain and its subdomains at DNS-label boundaries; they
// never use a raw string suffix or wildcard syntax.
type DynamicDomainRule struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type DynamicFeatureFlags struct {
	RedirectDiscovery bool `json:"redirect_discovery"`
	PlaybackInfo      bool `json:"playback_info"`
	HLS               bool `json:"hls"`
	DASH              bool `json:"dash"`
	PrivateTargets    bool `json:"private_targets"`
	CustomCA          bool `json:"custom_ca"`
	RawFallback       bool `json:"raw_fallback"`
}

type DynamicProfileLimits struct {
	AllowedSchemes             []string `json:"allowed_schemes"`
	AllowedPorts               []int    `json:"allowed_ports"`
	AllowAnyPort               bool     `json:"allow_any_port"`
	MaxRedirects               int      `json:"max_redirects"`
	MaxAuthorities             int      `json:"max_authorities"`
	MaxActiveCapabilities      int      `json:"max_active_capabilities"`
	MaxURLsPerResponse         int      `json:"max_urls_per_response"`
	MaxBodyBytes               int64    `json:"max_body_bytes"`
	MaxDNSIPs                  int      `json:"max_dns_ips"`
	MaxNewAuthoritiesPerMinute int      `json:"max_new_authorities_per_minute"`
	MaxStreams                 int      `json:"max_streams"`
	IdleExpirySeconds          int64    `json:"idle_expiry_seconds"`
	AbsoluteLifetimeSeconds    int64    `json:"absolute_lifetime_seconds"`
}

type DynamicProfile struct {
	ID               string               `json:"id"`
	Label            string               `json:"label"`
	Recommended      bool                 `json:"recommended"`
	DiscoverySources []string             `json:"discovery_sources"`
	Limits           DynamicProfileLimits `json:"limits"`
	Features         DynamicFeatureFlags  `json:"features"`
}

type DynamicGlobalLimits struct {
	MaxAuthorities               int   `json:"max_authorities"`
	MaxActiveCapabilities        int   `json:"max_active_capabilities"`
	MaxStreams                   int   `json:"max_streams"`
	MaxNewAuthoritiesPerMinute   int   `json:"max_new_authorities_per_minute"`
	MaxDNSWorkers                int   `json:"max_dns_workers"`
	MaxConcurrentParses          int   `json:"max_concurrent_parses"`
	MaxSiteConcurrentParses      int   `json:"max_site_concurrent_parses"`
	MaxParseMemoryBytes          int64 `json:"max_parse_memory_bytes"`
	MaxSiteParseMemoryBytes      int64 `json:"max_site_parse_memory_bytes"`
	MaxCapabilityMemoryBytes     int64 `json:"max_capability_memory_bytes"`
	MaxSiteCapabilityMemoryBytes int64 `json:"max_site_capability_memory_bytes"`
	MaxParseDepth                int   `json:"max_parse_depth"`
	MaxStringBytes               int64 `json:"max_string_bytes"`
	MaxTargetURLBytes            int   `json:"max_target_url_bytes"`
}

type DynamicDefaultPolicy struct {
	DynamicDiscoveryEnabled    bool                `json:"dynamic_discovery_enabled"`
	DynamicProfile             string              `json:"dynamic_profile"`
	DynamicDiscoverySources    []string            `json:"dynamic_discovery_sources"`
	DynamicDomainRules         []DynamicDomainRule `json:"dynamic_domain_rules"`
	DynamicAllowHTTPSDowngrade bool                `json:"dynamic_allow_https_downgrade"`
}

type DynamicRollbackReadiness struct {
	EnabledSafeEmptyRules      int64 `json:"enabled_safe_empty_rules"`
	EnabledLegacySourceSubsets int64 `json:"enabled_legacy_source_subsets"`
}

type DynamicProfilesResponse struct {
	Stage               string                   `json:"stage"`
	Available           bool                     `json:"available"`
	KeyConfigured       bool                     `json:"key_configured"`
	DefaultPolicy       DynamicDefaultPolicy     `json:"default_policy"`
	EmptyRulesSemantics string                   `json:"empty_rules_semantics"`
	RollbackReadiness   DynamicRollbackReadiness `json:"rollback_readiness"`
	Profiles            []DynamicProfile         `json:"profiles"`
	GlobalLimits        DynamicGlobalLimits      `json:"global_limits"`
}

func dynamicProfilesCatalog() []DynamicProfile {
	return []DynamicProfile{
		{
			ID:               dynamicProfileSafe,
			Label:            "Safe",
			Recommended:      false,
			DiscoverySources: []string{dynamicDiscoverySourceRedirect, dynamicDiscoverySourcePlaybackInfo},
			Limits: DynamicProfileLimits{
				AllowedSchemes:             []string{"https"},
				AllowedPorts:               []int{443},
				AllowAnyPort:               false,
				MaxRedirects:               3,
				MaxAuthorities:             256,
				MaxActiveCapabilities:      4096,
				MaxURLsPerResponse:         256,
				MaxBodyBytes:               4 << 20,
				MaxDNSIPs:                  16,
				MaxNewAuthoritiesPerMinute: 60,
				MaxStreams:                 32,
				IdleExpirySeconds:          int64((30 * time.Minute) / time.Second),
				AbsoluteLifetimeSeconds:    int64((8 * time.Hour) / time.Second),
			},
			Features: DynamicFeatureFlags{RedirectDiscovery: true, PlaybackInfo: true},
		},
		{
			ID:               dynamicProfileCompatible,
			Label:            "Compatible",
			Recommended:      true,
			DiscoverySources: allDynamicDiscoverySources(),
			Limits: DynamicProfileLimits{
				AllowedSchemes:             []string{"http", "https"},
				AllowedPorts:               []int{},
				AllowAnyPort:               true,
				MaxRedirects:               5,
				MaxAuthorities:             1024,
				MaxActiveCapabilities:      16384,
				MaxURLsPerResponse:         1024,
				MaxBodyBytes:               16 << 20,
				MaxDNSIPs:                  32,
				MaxNewAuthoritiesPerMinute: 300,
				MaxStreams:                 128,
				IdleExpirySeconds:          int64((2 * time.Hour) / time.Second),
				AbsoluteLifetimeSeconds:    int64((24 * time.Hour) / time.Second),
			},
			Features: DynamicFeatureFlags{RedirectDiscovery: true, PlaybackInfo: true, HLS: true, DASH: true},
		},
		{
			ID:               dynamicProfileExtreme,
			Label:            "Extreme",
			Recommended:      false,
			DiscoverySources: allDynamicDiscoverySources(),
			Limits: DynamicProfileLimits{
				AllowedSchemes:             []string{"http", "https"},
				AllowedPorts:               []int{},
				AllowAnyPort:               true,
				MaxRedirects:               10,
				MaxAuthorities:             4096,
				MaxActiveCapabilities:      65536,
				MaxURLsPerResponse:         4096,
				MaxBodyBytes:               64 << 20,
				MaxDNSIPs:                  64,
				MaxNewAuthoritiesPerMinute: 1200,
				MaxStreams:                 512,
				IdleExpirySeconds:          int64((24 * time.Hour) / time.Second),
				AbsoluteLifetimeSeconds:    int64((7 * 24 * time.Hour) / time.Second),
			},
			Features: DynamicFeatureFlags{RedirectDiscovery: true, PlaybackInfo: true, HLS: true, DASH: true},
		},
	}
}

func dynamicLimitsForProfile(profile string) (DynamicProfileLimits, bool) {
	for _, candidate := range dynamicProfilesCatalog() {
		if candidate.ID == profile {
			return candidate.Limits, true
		}
	}
	return DynamicProfileLimits{}, false
}

func dynamicGlobalLimits() DynamicGlobalLimits {
	return DynamicGlobalLimits{
		MaxAuthorities:               globalDynamicMaxAuthorities,
		MaxActiveCapabilities:        globalDynamicMaxActiveCapabilities,
		MaxStreams:                   globalDynamicMaxStreams,
		MaxNewAuthoritiesPerMinute:   globalDynamicMaxNewAuthoritiesMinute,
		MaxDNSWorkers:                globalDynamicMaxDNSWorkers,
		MaxConcurrentParses:          globalDynamicMaxConcurrentParses,
		MaxSiteConcurrentParses:      globalDynamicMaxSiteConcurrentParses,
		MaxParseMemoryBytes:          globalDynamicMaxParseMemoryBytes,
		MaxSiteParseMemoryBytes:      globalDynamicMaxSiteParseMemoryBytes,
		MaxCapabilityMemoryBytes:     globalDynamicMaxCapabilityMemoryBytes,
		MaxSiteCapabilityMemoryBytes: globalDynamicMaxSiteCapabilityMemoryBytes,
		MaxParseDepth:                globalDynamicMaxParseDepth,
		MaxStringBytes:               globalDynamicMaxStringBytes,
		MaxTargetURLBytes:            maxDynamicTargetURLBytes,
	}
}

func resolveDynamicRouteKey(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	if strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return nil, fmt.Errorf("DYNAMIC_ROUTE_KEY must not contain whitespace")
	}
	if len(value) < 32 {
		return nil, fmt.Errorf("DYNAMIC_ROUTE_KEY must be at least 32 bytes")
	}
	sum := sha256.Sum256([]byte(value))
	key := make([]byte, len(sum))
	copy(key, sum[:])
	return key, nil
}

func validateDynamicRouteKeySeparation(dynamicKey, effectiveJWTSecret, effectiveUpstreamHeaderKey []byte) error {
	if len(dynamicKey) == 0 {
		return nil
	}
	if len(dynamicKey) != sha256.Size || len(effectiveJWTSecret) == 0 {
		return fmt.Errorf("resolved DYNAMIC_ROUTE_KEY and JWT_SECRET are required for key separation")
	}
	jwtDigest := sha256.Sum256(effectiveJWTSecret)
	if subtle.ConstantTimeCompare(dynamicKey, jwtDigest[:]) == 1 {
		return fmt.Errorf("DYNAMIC_ROUTE_KEY must differ from JWT_SECRET")
	}
	if len(effectiveUpstreamHeaderKey) > 0 {
		if len(effectiveUpstreamHeaderKey) != sha256.Size {
			return fmt.Errorf("resolved UPSTREAM_HEADER_KEY has an invalid length")
		}
		if subtle.ConstantTimeCompare(dynamicKey, effectiveUpstreamHeaderKey) == 1 {
			return fmt.Errorf("DYNAMIC_ROUTE_KEY must differ from UPSTREAM_HEADER_KEY")
		}
	}
	return nil
}

func normalizeDynamicProfile(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return dynamicProfileCompatible, nil
	}
	switch value {
	case dynamicProfileSafe, dynamicProfileCompatible, dynamicProfileExtreme:
		return value, nil
	default:
		return "", fmt.Errorf("dynamic_profile must be safe, compatible, or extreme")
	}
}

func normalizeDynamicDomainRules(profile string, rules []DynamicDomainRule) ([]DynamicDomainRule, error) {
	switch profile {
	case dynamicProfileSafe, dynamicProfileCompatible, dynamicProfileExtreme:
	default:
		return nil, fmt.Errorf("dynamic_profile must be normalized before dynamic domain rules")
	}
	normalized := make([]DynamicDomainRule, 0, len(rules))
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		rule.Type = strings.ToLower(strings.TrimSpace(rule.Type))
		switch rule.Type {
		case "exact", "suffix":
		default:
			return nil, fmt.Errorf("dynamic domain rule type must be exact or suffix")
		}
		if strings.HasPrefix(strings.TrimSpace(rule.Value), ".") || strings.Contains(rule.Value, "*") {
			return nil, fmt.Errorf("dynamic domain rules must use structured host values without wildcards or leading dots")
		}
		host, isIP, err := normalizeDynamicHost(rule.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid dynamic domain rule %q: %w", rule.Value, err)
		}
		if isIP {
			if profile == dynamicProfileSafe {
				return nil, fmt.Errorf("safe dynamic profile does not permit IP-literal domain rules")
			}
			if rule.Type != "exact" {
				return nil, fmt.Errorf("suffix dynamic domain rules require a DNS hostname")
			}
			if _, err := validateDynamicResolvedIPs([]net.IP{net.ParseIP(host)}); err != nil {
				return nil, fmt.Errorf("invalid dynamic exact IP rule: %w", err)
			}
		}
		rule.Value = host
		key := rule.Type + "\x00" + rule.Value
		if seen[key] {
			return nil, fmt.Errorf("duplicate dynamic domain rule %s %s", rule.Type, rule.Value)
		}
		seen[key] = true
		normalized = append(normalized, rule)
	}
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Type != normalized[j].Type {
			return normalized[i].Type < normalized[j].Type
		}
		return normalized[i].Value < normalized[j].Value
	})
	return normalized, nil
}

func dynamicDomainRuleMatches(host string, rules []DynamicDomainRule) bool {
	normalizedHost, isIP, err := normalizeDynamicHost(host)
	if err != nil {
		return false
	}
	for _, rule := range rules {
		switch rule.Type {
		case "exact":
			if normalizedHost == rule.Value {
				return true
			}
		case "suffix":
			if !isIP && (normalizedHost == rule.Value || strings.HasSuffix(normalizedHost, "."+rule.Value)) {
				return true
			}
		}
	}
	return false
}

func decodeDynamicDomainRules(raw string) ([]DynamicDomainRule, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var rules []DynamicDomainRule
	if err := decoder.Decode(&rules); err != nil {
		return nil, fmt.Errorf("invalid dynamic_domain_rules JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("invalid dynamic_domain_rules JSON: multiple values")
		}
		return nil, fmt.Errorf("invalid dynamic_domain_rules JSON: %w", err)
	}
	return rules, nil
}

func decodeOptionalBoolAPI(raw json.RawMessage, field string) (bool, bool, error) {
	if len(raw) == 0 {
		return false, false, nil
	}
	if strings.EqualFold(strings.TrimSpace(string(raw)), "null") {
		return false, true, fmt.Errorf("%s must be a JSON boolean, not null", field)
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, true, fmt.Errorf("%s must be a JSON boolean", field)
	}
	return value, true, nil
}

func decodeDynamicDomainRulesAPI(raw json.RawMessage) ([]DynamicDomainRule, bool, error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	if strings.EqualFold(strings.TrimSpace(string(raw)), "null") {
		return nil, true, fmt.Errorf("dynamic_domain_rules must be a JSON array, not null")
	}
	rules, err := decodeDynamicDomainRules(string(raw))
	if err != nil {
		return nil, true, err
	}
	if rules == nil {
		return nil, true, fmt.Errorf("dynamic_domain_rules must be a JSON array, not null")
	}
	return rules, true, nil
}

func allDynamicDiscoverySources() []string {
	return []string{
		dynamicDiscoverySourceRedirect,
		dynamicDiscoverySourcePlaybackInfo,
		dynamicDiscoverySourceHLS,
		dynamicDiscoverySourceDASH,
	}
}

func defaultDynamicDiscoverySources() []string {
	return []string{
		dynamicDiscoverySourceRedirect,
		dynamicDiscoverySourcePlaybackInfo,
	}
}
func dynamicDiscoverySourcesForProfile(profile string) ([]string, bool) {
	switch profile {
	case dynamicProfileSafe:
		return []string{dynamicDiscoverySourceRedirect, dynamicDiscoverySourcePlaybackInfo}, true
	case dynamicProfileCompatible, dynamicProfileExtreme:
		return allDynamicDiscoverySources(), true
	default:
		return nil, false
	}
}

func validateDynamicDiscoverySourcesForProfile(profile string, sources []string) error {
	allowed, ok := dynamicDiscoverySourcesForProfile(profile)
	if !ok {
		return fmt.Errorf("unsupported dynamic discovery profile")
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, source := range allowed {
		allowedSet[source] = true
	}
	for _, source := range sources {
		if !allowedSet[source] {
			return fmt.Errorf("dynamic discovery source %q is unavailable for profile %q", source, profile)
		}
	}
	return nil
}

func normalizeDynamicDiscoverySources(sources []string) ([]string, error) {
	if sources == nil {
		return nil, nil
	}
	seen := make(map[string]bool, len(sources))
	for _, source := range sources {
		source = strings.ToLower(strings.TrimSpace(source))
		switch source {
		case dynamicDiscoverySourceRedirect,
			dynamicDiscoverySourcePlaybackInfo,
			dynamicDiscoverySourceHLS,
			dynamicDiscoverySourceDASH:
		default:
			return nil, fmt.Errorf("dynamic_discovery_sources contains an unsupported source")
		}
		if seen[source] {
			return nil, fmt.Errorf("dynamic_discovery_sources contains a duplicate source")
		}
		seen[source] = true
	}
	normalized := make([]string, 0, len(seen))
	for _, source := range allDynamicDiscoverySources() {
		if seen[source] {
			normalized = append(normalized, source)
		}
	}
	return normalized, nil
}

func decodeDynamicDiscoverySources(raw string) ([]string, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var sources []string
	if err := decoder.Decode(&sources); err != nil {
		return nil, fmt.Errorf("invalid dynamic_discovery_sources JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("invalid dynamic_discovery_sources JSON: multiple values")
		}
		return nil, fmt.Errorf("invalid dynamic_discovery_sources JSON: %w", err)
	}
	return sources, nil
}
func decodeDynamicDiscoverySourcesAPI(raw json.RawMessage) ([]string, bool, error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	sources, err := decodeDynamicDiscoverySources(string(raw))
	if err != nil {
		return nil, true, err
	}
	if sources == nil {
		return nil, true, fmt.Errorf("dynamic_discovery_sources must be a JSON array, not null")
	}
	return sources, true, nil
}

func dynamicDiscoverySourceEnabled(sources []string, source string) bool {
	for _, candidate := range sources {
		if candidate == source {
			return true
		}
	}
	return false
}

func storedDynamicBool(field string, value int) (bool, error) {
	switch value {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("stored %s must be the integer 0 or 1", field)
	}
}

func hydrateStoredDynamicSitePolicy(site *Site, dynamicEnabled, dynamicDowngrade int) error {
	enabled, err := storedDynamicBool("dynamic_discovery_enabled", dynamicEnabled)
	if err != nil {
		return err
	}
	downgrade, err := storedDynamicBool("dynamic_allow_https_downgrade", dynamicDowngrade)
	if err != nil {
		return err
	}
	switch site.DynamicProfile {
	case dynamicProfileSafe, dynamicProfileCompatible, dynamicProfileExtreme:
	default:
		return fmt.Errorf("stored dynamic_profile must be a canonical supported value")
	}
	if strings.TrimSpace(site.StoredDynamicDiscoverySources) == "" {
		return fmt.Errorf("stored dynamic_discovery_sources must be a non-blank JSON array")
	}
	sources, err := decodeDynamicDiscoverySources(site.StoredDynamicDiscoverySources)
	if err != nil {
		return fmt.Errorf("invalid stored dynamic_discovery_sources: %w", err)
	}
	if sources == nil {
		return fmt.Errorf("stored dynamic_discovery_sources must be a JSON array, not null")
	}
	sources, err = normalizeDynamicDiscoverySources(sources)
	if err != nil {
		return fmt.Errorf("invalid stored dynamic_discovery_sources: %w", err)
	}
	if err := validateDynamicDiscoverySourcesForProfile(site.DynamicProfile, sources); err != nil {
		return fmt.Errorf("invalid stored dynamic_discovery_sources: %w", err)
	}
	if site.DynamicProfile == dynamicProfileSafe && downgrade {
		return fmt.Errorf("safe dynamic profile must not allow HTTPS downgrade")
	}
	canonicalSources, err := json.Marshal(sources)
	if err != nil {
		return err
	}
	if site.StoredDynamicDiscoverySources != string(canonicalSources) {
		return fmt.Errorf("stored dynamic_discovery_sources is not canonical")
	}
	if strings.TrimSpace(site.StoredDynamicDomainRules) == "" {
		return fmt.Errorf("stored dynamic_domain_rules must be a non-blank JSON array")
	}
	rules, err := decodeDynamicDomainRules(site.StoredDynamicDomainRules)
	if err != nil {
		return fmt.Errorf("invalid stored dynamic_domain_rules: %w", err)
	}
	if rules == nil {
		return fmt.Errorf("stored dynamic_domain_rules must be a JSON array, not null")
	}
	normalized, err := normalizeDynamicDomainRules(site.DynamicProfile, rules)
	if err != nil {
		return fmt.Errorf("invalid stored dynamic_domain_rules: %w", err)
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return err
	}
	if site.StoredDynamicDomainRules != string(canonical) {
		return fmt.Errorf("stored dynamic_domain_rules is not canonical")
	}
	if site.DynamicPolicyRevision < 1 {
		return fmt.Errorf("stored dynamic_policy_revision must be at least 1")
	}
	site.DynamicDiscoveryEnabled = enabled
	site.DynamicAllowHTTPSDowngrade = downgrade
	site.DynamicDomainRules = normalized
	site.DynamicDiscoverySources = sources
	return nil
}

func normalizeDynamicSitePolicy(site *Site) error {
	profile, err := normalizeDynamicProfile(site.DynamicProfile)
	if err != nil {
		return err
	}
	site.DynamicProfile = profile
	if profile == dynamicProfileSafe {
		if site.DynamicAllowHTTPSDowngrade {
			return fmt.Errorf("safe dynamic profile must not allow HTTPS downgrade")
		}
		site.DynamicAllowHTTPSDowngrade = false
	} else if profile == dynamicProfileCompatible {
		site.DynamicAllowHTTPSDowngrade = true
	}
	sources := site.DynamicDiscoverySources
	if sources == nil && strings.TrimSpace(site.StoredDynamicDiscoverySources) != "" {
		sources, err = decodeDynamicDiscoverySources(site.StoredDynamicDiscoverySources)
		if err != nil {
			return err
		}
	}
	if sources == nil {
		sources, _ = dynamicDiscoverySourcesForProfile(profile)
	}
	sources, err = normalizeDynamicDiscoverySources(sources)
	if err != nil {
		return err
	}
	if err := validateDynamicDiscoverySourcesForProfile(profile, sources); err != nil {
		return err
	}
	if site.DynamicDiscoveryEnabled && len(sources) == 0 {
		return fmt.Errorf("dynamic discovery requires at least one discovery source")
	}
	rawSources, err := json.Marshal(sources)
	if err != nil {
		return err
	}
	site.DynamicDiscoverySources = sources
	site.StoredDynamicDiscoverySources = string(rawSources)
	rules := site.DynamicDomainRules
	if rules == nil && strings.TrimSpace(site.StoredDynamicDomainRules) != "" {
		rules, err = decodeDynamicDomainRules(site.StoredDynamicDomainRules)
		if err != nil {
			return err
		}
	}
	if rules == nil {
		rules = []DynamicDomainRule{}
	}
	rules, err = normalizeDynamicDomainRules(profile, rules)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	site.DynamicDomainRules = rules
	site.StoredDynamicDomainRules = string(raw)
	if site.DynamicPolicyRevision < 1 {
		site.DynamicPolicyRevision = 1
	}
	return nil
}

func validateDynamicDiscoveryAPIEnablement(site Site, keyConfigured, alreadyEnabled bool) error {
	if site.DynamicDiscoveryEnabled && !alreadyEnabled && !keyConfigured {
		return fmt.Errorf("dynamic discovery requires a configured DYNAMIC_ROUTE_KEY")
	}
	return nil
}
