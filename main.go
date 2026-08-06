package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"container/list"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"meridian/web"
)

type UAProfile struct {
	Name      string `json:"name"`
	UserAgent string `json:"user_agent"`
	Client    string `json:"client"`
	Version   string `json:"version"`
}

var uaProfiles = map[string]UAProfile{
	"infuse": {Name: "Infuse", UserAgent: "Infuse/7.8.1", Client: "Infuse", Version: "7.8.1"},
	"web":    {Name: "Web", UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Emby Theater", Client: "Emby Web", Version: "4.9.0.42"},
	"client": {Name: "Client", UserAgent: "Emby-Theater/4.7.0", Client: "Emby Theater", Version: "4.7.0"},
}

const (
	customUAMode          = "custom"
	passthroughUAMode     = "passthrough"
	maxCustomUserAgentLen = 1024
	maxCustomClientLen    = 128
	maxCustomVersionLen   = 64
)

var errUnsafeHostOnlyIngress = errors.New("host-only ingress requires loopback PANEL_BIND_ADDR or a non-empty TRUSTED_PROXY_CIDRS source allowlist; use port/both only with the documented risk controls")
var errProxyManagerShuttingDown = errors.New("proxy manager is shutting down")

// UAHeaderPolicy is the explicit discriminator for how a site's inbound
// identity headers are handled on the way upstream. Rewrite=true applies
// Profile (the configured User-Agent plus Emby Client/Version identity);
// Rewrite=false is passthrough, preserving the client's identity headers byte
// for byte. Passthrough is never encoded as an empty UAProfile sentinel: the
// policy itself carries the mode, and every header-preparation path branches
// on this discriminator.
type UAHeaderPolicy struct {
	Rewrite bool
	Profile UAProfile
}

func getUAProfile(mode string) UAProfile {
	if p, ok := uaProfiles[strings.ToLower(mode)]; ok {
		return p
	}
	return uaProfiles["infuse"]
}

func validateCustomUAValue(field, value string, maxLen int, allowQuotes bool) error {
	if value == "" {
		return fmt.Errorf("custom %s is required", field)
	}
	if len(value) > maxLen {
		return fmt.Errorf("custom %s must be at most %d bytes", field, maxLen)
	}
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return fmt.Errorf("custom %s must contain printable ASCII characters only", field)
		}
		if !allowQuotes && (r == '"' || r == '\\') {
			return fmt.Errorf("custom %s must not contain quotes or backslashes", field)
		}
	}
	return nil
}

func normalizeUAConfig(mode, userAgent, client, version string) (string, string, string, string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == passthroughUAMode {
		// Passthrough carries no identity of its own: the client's headers are
		// preserved verbatim, so any stored custom triplet is cleared.
		return mode, "", "", "", nil
	}
	if mode != customUAMode {
		if _, ok := uaProfiles[mode]; !ok {
			return "", "", "", "", fmt.Errorf("unknown ua_mode")
		}
		return mode, "", "", "", nil
	}

	userAgent = strings.TrimSpace(userAgent)
	client = strings.TrimSpace(client)
	version = strings.TrimSpace(version)
	if err := validateCustomUAValue("user_agent", userAgent, maxCustomUserAgentLen, true); err != nil {
		return "", "", "", "", err
	}
	if err := validateCustomUAValue("client", client, maxCustomClientLen, false); err != nil {
		return "", "", "", "", err
	}
	if err := validateCustomUAValue("version", version, maxCustomVersionLen, false); err != nil {
		return "", "", "", "", err
	}
	return mode, userAgent, client, version, nil
}

// resolveUAHeaderPolicy resolves a site's stored UA configuration into the
// explicit header-handling policy used everywhere identity headers are
// prepared: the HTTP proxy path, WebSocket upgrade, redirect follow, and
// diagnostics.
func resolveUAHeaderPolicy(site Site) (UAHeaderPolicy, error) {
	mode, userAgent, client, version, err := normalizeUAConfig(site.UAMode, site.CustomUserAgent, site.CustomClient, site.CustomVersion)
	if err != nil {
		return UAHeaderPolicy{}, err
	}
	if mode == passthroughUAMode {
		return UAHeaderPolicy{}, nil
	}
	if mode == customUAMode {
		return UAHeaderPolicy{Rewrite: true, Profile: UAProfile{Name: "Custom", UserAgent: userAgent, Client: client, Version: version}}, nil
	}
	return UAHeaderPolicy{Rewrite: true, Profile: uaProfiles[mode]}, nil
}

func mergeSiteUAConfig(old Site, requestedMode, requestedUserAgent, requestedClient, requestedVersion *string) (string, string, string, string, error) {
	hasCustomFields := requestedUserAgent != nil || requestedClient != nil || requestedVersion != nil
	if hasCustomFields && (requestedUserAgent == nil || requestedClient == nil || requestedVersion == nil) {
		return "", "", "", "", fmt.Errorf("custom User-Agent, Client, and Version must be provided together")
	}

	mode := old.UAMode
	userAgent := old.CustomUserAgent
	client := old.CustomClient
	version := old.CustomVersion
	if requestedMode != nil {
		mode = *requestedMode
	}
	if hasCustomFields {
		userAgent = *requestedUserAgent
		client = *requestedClient
		version = *requestedVersion
	}

	if requestedMode == nil && !hasCustomFields {
		return normalizeUAConfig(mode, userAgent, client, version)
	}

	normalizedMode := strings.ToLower(strings.TrimSpace(mode))
	if normalizedMode != customUAMode {
		if hasCustomFields && (strings.TrimSpace(userAgent) != "" || strings.TrimSpace(client) != "" || strings.TrimSpace(version) != "") {
			return "", "", "", "", fmt.Errorf("custom fields require ua_mode custom")
		}
		return normalizeUAConfig(normalizedMode, "", "", "")
	}
	if !hasCustomFields {
		return "", "", "", "", fmt.Errorf("custom ua_mode requires User-Agent, Client, and Version")
	}
	return normalizeUAConfig(normalizedMode, userAgent, client, version)
}

const (
	maxUpstreamHeaders                 = 16
	maxUpstreamHeaderName              = 64
	maxUpstreamHeaderValue             = 1024
	maxPlaybackAddresses               = 128
	maxTargetURLLength                 = 2048
	ingressModePort                    = "port"
	ingressModeHost                    = "host"
	ingressModeBoth                    = "both"
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
			Recommended:      true,
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
			Recommended:      false,
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
func dynamicDefaultPolicy() DynamicDefaultPolicy {
	sources, _ := dynamicDiscoverySourcesForProfile(dynamicProfileSafe)
	return DynamicDefaultPolicy{
		DynamicDiscoveryEnabled:    true,
		DynamicProfile:             dynamicProfileSafe,
		DynamicDiscoverySources:    sources,
		DynamicDomainRules:         []DynamicDomainRule{},
		DynamicAllowHTTPSDowngrade: false,
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
		return dynamicProfileSafe, nil
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
func dynamicSafeDomainAllowed(host string, rules []DynamicDomainRule) bool {
	normalizedHost, isIP, err := normalizeDynamicHost(host)
	if err != nil || isIP {
		return false
	}
	if len(rules) == 0 {
		return true
	}
	return dynamicDomainRuleMatches(normalizedHost, rules)
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
func decodeDynamicDomainRulesAPI(raw json.RawMessage) ([]DynamicDomainRule, bool, error) {
	if len(raw) == 0 {
		return nil, false, nil
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
func decodeOptionalBoolAPI(raw json.RawMessage, field string) (bool, bool, error) {
	if len(raw) == 0 {
		return false, false, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false, true, fmt.Errorf("%s must be a JSON boolean, not null", field)
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, true, fmt.Errorf("%s must be a JSON boolean", field)
	}
	return value, true, nil
}

func allDynamicDiscoverySources() []string {
	return []string{
		dynamicDiscoverySourceRedirect,
		dynamicDiscoverySourcePlaybackInfo,
		dynamicDiscoverySourceHLS,
		dynamicDiscoverySourceDASH,
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

func dynamicSelectableDiscoverySourceSetsForProfile(profile string) ([][]string, bool) {
	full, ok := dynamicDiscoverySourcesForProfile(profile)
	if !ok {
		return nil, false
	}
	withoutPlaybackInfo := make([]string, 0, len(full))
	for _, source := range full {
		if source != dynamicDiscoverySourcePlaybackInfo {
			withoutPlaybackInfo = append(withoutPlaybackInfo, source)
		}
	}
	return [][]string{full, withoutPlaybackInfo}, true
}

func dynamicDiscoverySourcesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func normalizeDynamicDiscoverySourcesForAPI(profile string, sources []string) ([]string, error) {
	normalized, err := normalizeDynamicDiscoverySources(sources)
	if err != nil {
		return nil, err
	}
	if err := validateDynamicDiscoverySourcesForProfile(profile, normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

func validateSelectableDynamicDiscoverySources(profile string, sources []string) error {
	selectable, ok := dynamicSelectableDiscoverySourceSetsForProfile(profile)
	if !ok {
		return fmt.Errorf("unsupported dynamic discovery profile")
	}
	for _, allowed := range selectable {
		if dynamicDiscoverySourcesEqual(sources, allowed) {
			return nil
		}
	}
	return fmt.Errorf("dynamic_discovery_sources must equal a selectable source set for profile %q", profile)
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
	if site.DynamicProfile == dynamicProfileSafe && downgrade {
		return fmt.Errorf("stored safe dynamic policy must keep dynamic_allow_https_downgrade false")
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
	if enabled && len(sources) == 0 {
		return fmt.Errorf("dynamic discovery requires at least one discovery source")
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
	if profile == dynamicProfileSafe && site.DynamicAllowHTTPSDowngrade {
		return fmt.Errorf("safe dynamic profile requires dynamic_allow_https_downgrade=false")
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
func mergeDynamicSitePolicyForAPI(current Site, enabled *bool, profile *string, sources []string, sourcesProvided bool, rules []DynamicDomainRule, rulesProvided bool, allowHTTPSDowngrade *bool) (Site, error) {
	candidate := current
	if enabled != nil {
		candidate.DynamicDiscoveryEnabled = *enabled
	}
	targetProfile := current.DynamicProfile
	if profile != nil {
		var err error
		targetProfile, err = normalizeDynamicProfile(*profile)
		if err != nil {
			return Site{}, err
		}
	}
	profileChanged := targetProfile != current.DynamicProfile
	enabling := !current.DynamicDiscoveryEnabled && candidate.DynamicDiscoveryEnabled
	candidate.DynamicProfile = targetProfile
	if rulesProvided {
		candidate.DynamicDomainRules = rules
	}
	if allowHTTPSDowngrade != nil {
		candidate.DynamicAllowHTTPSDowngrade = *allowHTTPSDowngrade
	} else if profileChanged && targetProfile == dynamicProfileSafe {
		candidate.DynamicAllowHTTPSDowngrade = false
	}

	fullSources, ok := dynamicDiscoverySourcesForProfile(targetProfile)
	if !ok {
		return Site{}, fmt.Errorf("unsupported dynamic discovery profile")
	}
	if profileChanged || enabling {
		if !sourcesProvided {
			candidate.DynamicDiscoverySources = fullSources
		} else {
			normalizedSources, err := normalizeDynamicDiscoverySourcesForAPI(targetProfile, sources)
			if err != nil {
				return Site{}, err
			}
			if err := validateSelectableDynamicDiscoverySources(targetProfile, normalizedSources); err != nil {
				return Site{}, err
			}
			candidate.DynamicDiscoverySources = normalizedSources
		}
	} else if sourcesProvided {
		normalizedSources, err := normalizeDynamicDiscoverySourcesForAPI(targetProfile, sources)
		if err != nil {
			return Site{}, err
		}
		if err := validateSelectableDynamicDiscoverySources(targetProfile, normalizedSources); err != nil && !dynamicDiscoverySourcesEqual(normalizedSources, current.DynamicDiscoverySources) {
			return Site{}, fmt.Errorf("dynamic_discovery_sources must equal a selectable source set or the unchanged stored legacy subset")
		}
		candidate.DynamicDiscoverySources = normalizedSources
	}
	if err := normalizeDynamicSitePolicy(&candidate); err != nil {
		return Site{}, err
	}
	return candidate, nil
}

func validateDynamicDiscoveryAPIEnablement(site Site, keyConfigured, alreadyEnabled bool) error {
	if site.DynamicDiscoveryEnabled && !alreadyEnabled && !keyConfigured {
		return fmt.Errorf("dynamic discovery requires a configured DYNAMIC_ROUTE_KEY")
	}
	return nil
}

// UpstreamHeaderView is the write-only representation returned by the API.
// Header values are never serialized back to a browser.
type UpstreamHeaderView struct {
	Name       string `json:"name"`
	Configured bool   `json:"configured"`
}

// UpstreamHeaderInput is a full-snapshot API input. On update, an omitted or
// empty value preserves the existing encrypted value for the same header name.
// Omitting the header row from the snapshot removes it.
type UpstreamHeaderInput struct {
	Name  string  `json:"name"`
	Value *string `json:"value,omitempty"`
}

type storedUpstreamHeader struct {
	Name       string `json:"name"`
	Ciphertext string `json:"ciphertext"`
}

type upstreamHeaderPolicy struct {
	authority string
	values    http.Header
}

func isHTTPTokenByte(value byte) bool {
	if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", rune(value))
}

func normalizeUpstreamHeaderName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxUpstreamHeaderName {
		return "", fmt.Errorf("upstream header name must be 1-%d bytes", maxUpstreamHeaderName)
	}
	for i := 0; i < len(value); i++ {
		if !isHTTPTokenByte(value[i]) {
			return "", fmt.Errorf("upstream header name contains invalid characters")
		}
	}
	name := http.CanonicalHeaderKey(value)
	lower := strings.ToLower(name)
	if isManagedForwardingHeaderName(lower) {
		return "", fmt.Errorf("upstream header %s is managed by Meridian and cannot be overridden", name)
	}
	switch lower {
	case "authorization", "connection", "content-length", "cookie", "host",
		"keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
		"te", "trailer", "transfer-encoding", "upgrade", "user-agent",
		"x-emby-authorization", "x-emby-token", "x-mediabrowser-token":
		return "", fmt.Errorf("upstream header %s is managed by Meridian and cannot be overridden", name)
	}
	if strings.HasPrefix(lower, "sec-websocket-") {
		return "", fmt.Errorf("upstream header %s is managed by Meridian and cannot be overridden", name)
	}
	return name, nil
}

func normalizeUpstreamHeaderValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxUpstreamHeaderValue {
		return "", fmt.Errorf("upstream header value must be 1-%d bytes", maxUpstreamHeaderValue)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return "", fmt.Errorf("upstream header value must contain printable ASCII characters only")
		}
	}
	return value, nil
}

func resolveUpstreamHeaderKey(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	if strings.ContainsAny(value, " \t\r\n\v\f") {
		return nil, fmt.Errorf("UPSTREAM_HEADER_KEY must not contain whitespace")
	}
	if len(value) < 32 {
		return nil, fmt.Errorf("UPSTREAM_HEADER_KEY must be at least 32 bytes")
	}
	sum := sha256.Sum256([]byte(value))
	key := make([]byte, len(sum))
	copy(key, sum[:])
	return key, nil
}

func encryptUpstreamHeaderValue(name, value, authority string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("UPSTREAM_HEADER_KEY is required to configure upstream headers")
	}
	if authority == "" {
		return "", fmt.Errorf("a valid target authority is required to configure upstream headers")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate upstream header nonce: %w", err)
	}
	aad := []byte("meridian-upstream-header:v2:" + strings.ToLower(name) + "\x00" + authority)
	sealed := gcm.Seal(nil, nonce, []byte(value), aad)
	payload := append(append([]byte{}, nonce...), sealed...)
	return "v2:" + base64.RawURLEncoding.EncodeToString(payload), nil
}

func decryptUpstreamHeaderValue(name, ciphertext, authority string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("UPSTREAM_HEADER_KEY is required for configured upstream headers")
	}
	if !strings.HasPrefix(ciphertext, "v2:") {
		return "", fmt.Errorf("unsupported upstream header ciphertext version")
	}
	if authority == "" {
		return "", fmt.Errorf("a valid target authority is required for configured upstream headers")
	}
	aad := []byte("meridian-upstream-header:v2:" + strings.ToLower(name) + "\x00" + authority)
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(ciphertext, "v2:"))
	if err != nil {
		return "", fmt.Errorf("decode upstream header ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(payload) < gcm.NonceSize()+gcm.Overhead() {
		return "", fmt.Errorf("upstream header ciphertext is truncated")
	}
	nonce, sealed := payload[:gcm.NonceSize()], payload[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return "", fmt.Errorf("decrypt upstream header value: %w", err)
	}
	return string(plain), nil
}

func parseStoredUpstreamHeaders(raw string) ([]storedUpstreamHeader, error) {
	if strings.TrimSpace(raw) == "" {
		return []storedUpstreamHeader{}, nil
	}
	var headers []storedUpstreamHeader
	if err := json.Unmarshal([]byte(raw), &headers); err != nil {
		return nil, fmt.Errorf("invalid stored upstream_headers: %w", err)
	}
	if len(headers) > maxUpstreamHeaders {
		return nil, fmt.Errorf("stored upstream_headers exceeds %d entries", maxUpstreamHeaders)
	}
	seen := make(map[string]bool, len(headers))
	for i := range headers {
		name, err := normalizeUpstreamHeaderName(headers[i].Name)
		if err != nil {
			return nil, fmt.Errorf("invalid stored upstream header: %w", err)
		}
		key := strings.ToLower(name)
		if seen[key] {
			return nil, fmt.Errorf("duplicate stored upstream header %s", name)
		}
		seen[key] = true
		headers[i].Name = name
		if !strings.HasPrefix(headers[i].Ciphertext, "v2:") {
			return nil, fmt.Errorf("invalid stored ciphertext for upstream header %s", name)
		}
	}
	if headers == nil {
		headers = []storedUpstreamHeader{}
	}
	return headers, nil
}

func upstreamHeaderViews(raw string) ([]UpstreamHeaderView, error) {
	stored, err := parseStoredUpstreamHeaders(raw)
	if err != nil {
		return nil, err
	}
	views := make([]UpstreamHeaderView, len(stored))
	for i, header := range stored {
		views[i] = UpstreamHeaderView{Name: header.Name, Configured: true}
	}
	return views, nil
}

func mergeUpstreamHeaders(existingRaw string, requested []UpstreamHeaderInput, key []byte, targetURL string) (string, error) {
	if len(requested) > maxUpstreamHeaders {
		return "", fmt.Errorf("upstream_headers must contain at most %d entries", maxUpstreamHeaders)
	}
	existing, err := parseStoredUpstreamHeaders(existingRaw)
	if err != nil {
		return "", err
	}
	existingByName := make(map[string]storedUpstreamHeader, len(existing))
	for _, header := range existing {
		existingByName[strings.ToLower(header.Name)] = header
	}
	target, err := normalizeTargetURL(targetURL)
	if err != nil {
		return "", fmt.Errorf("invalid target_url: %w", err)
	}
	authority := redirectHostKey(target)

	merged := make([]storedUpstreamHeader, 0, len(requested))
	seen := make(map[string]bool, len(requested))
	for _, input := range requested {
		name, err := normalizeUpstreamHeaderName(input.Name)
		if err != nil {
			return "", err
		}
		nameKey := strings.ToLower(name)
		if seen[nameKey] {
			return "", fmt.Errorf("duplicate upstream header %s", name)
		}
		seen[nameKey] = true

		value := ""
		if input.Value != nil {
			value = strings.TrimSpace(*input.Value)
		}
		if value == "" {
			old, ok := existingByName[nameKey]
			if !ok {
				return "", fmt.Errorf("a value is required for new upstream header %s", name)
			}
			merged = append(merged, storedUpstreamHeader{Name: name, Ciphertext: old.Ciphertext})
			continue
		}
		value, err = normalizeUpstreamHeaderValue(value)
		if err != nil {
			return "", fmt.Errorf("invalid value for upstream header %s: %w", name, err)
		}
		ciphertext, err := encryptUpstreamHeaderValue(name, value, authority, key)
		if err != nil {
			return "", err
		}
		merged = append(merged, storedUpstreamHeader{Name: name, Ciphertext: ciphertext})
	}
	raw, err := json.Marshal(merged)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func resolveUpstreamHeaderPolicy(raw string, key []byte, target *url.URL) (upstreamHeaderPolicy, error) {
	stored, err := parseStoredUpstreamHeaders(raw)
	if err != nil {
		return upstreamHeaderPolicy{}, err
	}
	policy := upstreamHeaderPolicy{authority: redirectHostKey(target), values: make(http.Header, len(stored))}
	for _, header := range stored {
		value, err := decryptUpstreamHeaderValue(header.Name, header.Ciphertext, policy.authority, key)
		if err != nil {
			return upstreamHeaderPolicy{}, fmt.Errorf("resolve upstream header %s: %w", header.Name, err)
		}
		value, err = normalizeUpstreamHeaderValue(value)
		if err != nil {
			return upstreamHeaderPolicy{}, fmt.Errorf("resolve upstream header %s: %w", header.Name, err)
		}
		policy.values.Set(header.Name, value)
	}
	return policy, nil
}

func (p upstreamHeaderPolicy) apply(header http.Header, target *url.URL) {
	for name := range p.values {
		header.Del(name)
	}
	if target == nil || redirectHostKey(target) != p.authority {
		return
	}
	for name, values := range p.values {
		header[name] = append([]string(nil), values...)
	}
}

var jwtSecret []byte
var jwtSecretEphemeral bool

const (
	sessionCookieName = "meridian_session"
	sessionDuration   = 72 * time.Hour
)

func init() {
	var err error
	jwtSecret, jwtSecretEphemeral, err = resolveJWTSecret(os.Getenv("JWT_SECRET"))
	if err != nil {
		panic(err)
	}
}

func resolveJWTSecret(value string) ([]byte, bool, error) {
	if value != "" {
		if len(value) < 32 {
			return nil, false, fmt.Errorf("JWT_SECRET must be at least 32 bytes")
		}
		return []byte(value), false, nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, false, fmt.Errorf("generate JWT secret: %w", err)
	}
	return secret, true, nil
}

func generateToken(userID int64, username string) (string, error) {
	header := jwtHeaderEncoded
	payload, err := json.Marshal(struct {
		Sub  int64  `json:"sub"`
		Name string `json:"name"`
		Exp  int64  `json:"exp"`
	}{
		Sub:  userID,
		Name: username,
		Exp:  time.Now().Add(72 * time.Hour).Unix(),
	})
	if err != nil {
		return "", err
	}
	payloadEnc := base64url(payload)
	sig := hmacSHA256(header+"."+payloadEnc, jwtSecret)
	return header + "." + payloadEnc + "." + sig, nil
}

func validateToken(token string) (int64, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, "", fmt.Errorf("invalid token")
	}
	if parts[0] != jwtHeaderEncoded {
		return 0, "", fmt.Errorf("invalid token header")
	}
	expectedSig := hmacSHA256(parts[0]+"."+parts[1], jwtSecret)
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return 0, "", fmt.Errorf("invalid signature")
	}
	payload, err := base64urlDecode(parts[1])
	if err != nil {
		return 0, "", err
	}
	var claims struct {
		Sub  int64  `json:"sub"`
		Name string `json:"name"`
		Exp  int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, "", err
	}
	if time.Now().Unix() > claims.Exp {
		return 0, "", fmt.Errorf("token expired")
	}
	return claims.Sub, claims.Name, nil
}

var jwtHeaderEncoded = base64url([]byte(`{"alg":"HS256","typ":"JWT"}`))

func hmacSHA256(data string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return base64url(h.Sum(nil))
}

func base64url(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func base64urlDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func configuredSetupToken(userCount int, value string) (string, error) {
	if userCount > 0 {
		return "", nil
	}
	token := strings.TrimSpace(value)
	if token == "" {
		return "", errors.New("SETUP_TOKEN must be configured before creating the first administrator")
	}
	if len(token) < 32 {
		return "", errors.New("SETUP_TOKEN must be at least 32 bytes")
	}
	return token, nil
}

func setupTokenMatches(expected, provided string) bool {
	expectedHash := sha256.Sum256([]byte(expected))
	providedHash := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(expectedHash[:], providedHash[:]) == 1
}

const (
	dynamicObservationSourceRedirect     = dynamicDiscoverySourceRedirect
	dynamicObservationSourcePlaybackInfo = dynamicDiscoverySourcePlaybackInfo
	dynamicObservationSourceHLS          = dynamicDiscoverySourceHLS
	dynamicObservationSourceDASH         = dynamicDiscoverySourceDASH

	dynamicObservationDecisionAllowed = "allowed"
	dynamicObservationDecisionDenied  = "denied"

	dynamicObservationReasonRedirectAllowed      = "redirect_allowed"
	dynamicObservationReasonInvalidLocation      = "invalid_location"
	dynamicObservationReasonUnsupportedStatus    = "unsupported_status"
	dynamicObservationReasonRedirectLoop         = "redirect_loop"
	dynamicObservationReasonHopLimit             = "hop_limit"
	dynamicObservationReasonSchemeDenied         = "scheme_denied"
	dynamicObservationReasonPortDenied           = "port_denied"
	dynamicObservationReasonDomainDenied         = "domain_denied"
	dynamicObservationReasonHTTPSDowngradeDenied = "https_downgrade_denied"
	dynamicObservationReasonSelfTarget           = "self_target"
	dynamicObservationReasonDNSFailure           = "dns_failure"
	dynamicObservationReasonAddressDenied        = "address_denied"
	dynamicObservationReasonDialFailure          = "dial_failure"
	dynamicObservationReasonTLSFailure           = "tls_failure"
	dynamicObservationReasonCapacityLimit        = "capacity_limit"
	dynamicObservationReasonRateLimit            = "rate_limit"
	dynamicObservationReasonResponseFailure      = "response_failure"
	dynamicObservationReasonRuntimeUnavailable   = "runtime_unavailable"

	dynamicObservationQueueCapacity                  = 2048
	dynamicObservationBatchSize                      = 128
	dynamicObservationGlobalRowLimit                 = 10000
	dynamicObservationRetention                      = 30 * 24 * time.Hour
	dynamicObservationMaintenanceInterval            = time.Hour
	dynamicObservationReasonCandidateAllowed         = "candidate_allowed"
	dynamicObservationReasonParseFailure             = "parse_failure"
	dynamicObservationReasonCapabilityInvalid        = "capability_invalid"
	dynamicObservationReasonCapabilityExpired        = "capability_expired"
	dynamicObservationReasonRequestUnclassified      = "request_unclassified"
	dynamicObservationReasonStructuredBodyLimit      = "structured_body_limit"
	dynamicObservationReasonPlaybackInfoDenied       = "playback_info_denied"
	dynamicObservationReasonHLSFeatureDenied         = "hls_feature_denied"
	dynamicObservationReasonDASHFeatureDenied        = "dash_feature_denied"
	dynamicObservationReasonRedirectBodyReplayDenied = "redirect_body_replay_denied"
	dynamicObservationMaxAuthorityBytes              = 512
)

var errDynamicObservationWriterClosed = errors.New("dynamic observation writer is closed")

// dynamicObservationEvent is the complete hot-path observation contract. The
// database owns timestamps and aggregation so callers cannot inject chronology
// or counts into the operator-facing record.
type dynamicObservationEvent struct {
	SiteID             int64
	CanonicalAuthority string
	Source             string
	Decision           string
	ReasonCode         string
}

// DynamicObservation is deliberately identical to the frozen database/API
// shape. It never carries a redirect path, query, address, header, or body.
type DynamicObservation struct {
	SiteID             int64  `json:"site_id"`
	CanonicalAuthority string `json:"canonical_authority"`
	Source             string `json:"source"`
	Decision           string `json:"decision"`
	ReasonCode         string `json:"reason_code"`
	FirstSeenMS        int64  `json:"first_seen_ms"`
	LastSeenMS         int64  `json:"last_seen_ms"`
	Count              int64  `json:"count"`
}

type DynamicObservationsResponse struct {
	Observations        []DynamicObservation `json:"observations"`
	DroppedObservations uint64               `json:"dropped_observations"`
}

func validDynamicObservationEnums(source, decision, reasonCode string) bool {
	switch source {
	case dynamicObservationSourceRedirect,
		dynamicObservationSourcePlaybackInfo,
		dynamicObservationSourceHLS,
		dynamicObservationSourceDASH:
	default:
		return false
	}
	switch decision {
	case dynamicObservationDecisionAllowed:
		return reasonCode == dynamicObservationReasonRedirectAllowed || reasonCode == dynamicObservationReasonCandidateAllowed
	case dynamicObservationDecisionDenied:
		switch reasonCode {
		case dynamicObservationReasonInvalidLocation,
			dynamicObservationReasonUnsupportedStatus,
			dynamicObservationReasonRedirectLoop,
			dynamicObservationReasonHopLimit,
			dynamicObservationReasonSchemeDenied,
			dynamicObservationReasonPortDenied,
			dynamicObservationReasonDomainDenied,
			dynamicObservationReasonHTTPSDowngradeDenied,
			dynamicObservationReasonSelfTarget,
			dynamicObservationReasonDNSFailure,
			dynamicObservationReasonAddressDenied,
			dynamicObservationReasonDialFailure,
			dynamicObservationReasonTLSFailure,
			dynamicObservationReasonCapacityLimit,
			dynamicObservationReasonRateLimit,
			dynamicObservationReasonParseFailure,
			dynamicObservationReasonRequestUnclassified,
			dynamicObservationReasonStructuredBodyLimit,
			dynamicObservationReasonPlaybackInfoDenied,
			dynamicObservationReasonHLSFeatureDenied,
			dynamicObservationReasonDASHFeatureDenied,
			dynamicObservationReasonRedirectBodyReplayDenied,
			dynamicObservationReasonCapabilityInvalid,
			dynamicObservationReasonCapabilityExpired,
			dynamicObservationReasonResponseFailure,
			dynamicObservationReasonRuntimeUnavailable:
			return true
		}
	}
	return false
}

func isCanonicalDynamicObservationAuthority(value string) bool {
	if value == "" || len(value) > dynamicObservationMaxAuthorityBytes || strings.TrimSpace(value) != value {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Host == "" || parsed.Opaque != "" {
		return false
	}
	if parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" {
		return false
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil || host == "" || portText == "" {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
		return false
	}
	normalizedHost, _, err := normalizeDynamicHost(host)
	if err != nil {
		return false
	}
	return value == parsed.Scheme+"://"+net.JoinHostPort(normalizedHost, portText)
}

type queuedDynamicObservation struct {
	event        dynamicObservationEvent
	observedAtMS int64
}

type dynamicObservationCommandKind uint8

const (
	dynamicObservationCommandWrite dynamicObservationCommandKind = iota
	dynamicObservationCommandFlush
	dynamicObservationCommandClear
	dynamicObservationCommandStop
)

type dynamicObservationCommand struct {
	kind   dynamicObservationCommandKind
	event  queuedDynamicObservation
	siteID int64
	result chan error
}

type DB struct {
	db *sql.DB

	dynamicObservationQueue     chan dynamicObservationCommand
	dynamicObservationDone      chan struct{}
	dynamicObservationGate      sync.RWMutex
	dynamicObservationCloseOnce sync.Once
	dynamicObservationClosed    atomic.Bool
	droppedDynamicObservations  atomic.Uint64
}

func openDB(path string) (*DB, error) {
	setSecureFileCreationMask()
	sqlDB, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	d := &DB{db: sqlDB}
	if err := d.migrate(); err != nil {
		sqlDB.Close()
		return nil, err
	}
	if err := hardenDatabaseFilePermissions(path); err != nil {
		sqlDB.Close()
		return nil, err
	}
	if err := d.validateStoredDynamicPolicies(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("validate stored dynamic policies: %w", err)
	}
	d.dynamicObservationQueue = make(chan dynamicObservationCommand, dynamicObservationQueueCapacity)
	d.dynamicObservationDone = make(chan struct{})
	go d.runDynamicObservationWriter()
	return d, nil
}

func (d *DB) validateStoredDynamicPolicies() error {
	rows, err := d.db.Query("SELECT id, dynamic_discovery_enabled, dynamic_profile, dynamic_discovery_sources, dynamic_domain_rules, dynamic_allow_https_downgrade, dynamic_policy_revision FROM sites ORDER BY id")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var site Site
		var dynamicEnabled, dynamicDowngrade int
		if err := rows.Scan(&site.ID, &dynamicEnabled, &site.DynamicProfile, &site.StoredDynamicDiscoverySources, &site.StoredDynamicDomainRules, &dynamicDowngrade, &site.DynamicPolicyRevision); err != nil {
			return err
		}
		if err := hydrateStoredDynamicSitePolicy(&site, dynamicEnabled, dynamicDowngrade); err != nil {
			return fmt.Errorf("site %d: %w", site.ID, err)
		}
	}
	return rows.Err()
}

// warnUnenforcedFileModes keeps the platform warning to one line per process
// instead of one per openDB call.
var warnUnenforcedFileModes sync.Once

func hardenDatabaseFilePermissions(path string) error {
	if path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil
	}
	if !fileModesEnforced() {
		// Chmod would report success and change nothing, which is worse than not
		// trying: it would let the operator believe the database is protected.
		warnUnenforcedFileModes.Do(func() {
			log.Printf("This platform does not enforce POSIX file modes, so %s keeps whatever permissions it inherits from its directory. That file holds the administrator password hash and every configured upstream URL: restrict the directory yourself and do not leave it somewhere other local users can read.", path)
		})
		return nil
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		// #nosec G703 -- the database path is operator-controlled and never derived from a request.
		if err := os.Chmod(candidate, 0600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("secure database file %s: %w", candidate, err)
		}
	}
	return nil
}

func (d *DB) Close() {
	if d == nil {
		return
	}
	d.dynamicObservationCloseOnce.Do(func() {
		if d.dynamicObservationQueue != nil {
			result := make(chan error, 1)
			d.dynamicObservationGate.Lock()
			d.dynamicObservationClosed.Store(true)
			d.dynamicObservationGate.Unlock()
			d.dynamicObservationQueue <- dynamicObservationCommand{kind: dynamicObservationCommandStop, result: result}
			<-result
			<-d.dynamicObservationDone
		}
		_ = d.db.Close()
	})
}

// EnqueueDynamicObservation performs validation and a single bounded channel
// send. It never waits for SQLite or reports an optional telemetry failure to
// the media request path.
func (d *DB) EnqueueDynamicObservation(event dynamicObservationEvent) {
	if d == nil {
		return
	}
	if event.SiteID <= 0 || !validDynamicObservationEnums(event.Source, event.Decision, event.ReasonCode) || !isCanonicalDynamicObservationAuthority(event.CanonicalAuthority) {
		d.droppedDynamicObservations.Add(1)
		return
	}
	command := dynamicObservationCommand{
		kind: dynamicObservationCommandWrite,
		event: queuedDynamicObservation{
			event:        event,
			observedAtMS: time.Now().UnixMilli(),
		},
	}
	if !d.dynamicObservationGate.TryRLock() {
		d.droppedDynamicObservations.Add(1)
		return
	}
	defer d.dynamicObservationGate.RUnlock()
	if d.dynamicObservationClosed.Load() || d.dynamicObservationQueue == nil {
		d.droppedDynamicObservations.Add(1)
		return
	}
	select {
	case d.dynamicObservationQueue <- command:
	default:
		d.droppedDynamicObservations.Add(1)
	}
}

func (d *DB) DroppedDynamicObservations() uint64 {
	if d == nil {
		return 0
	}
	return d.droppedDynamicObservations.Load()
}

func (d *DB) sendDynamicObservationControl(kind dynamicObservationCommandKind, siteID int64) error {
	if d == nil {
		return errDynamicObservationWriterClosed
	}
	result := make(chan error, 1)
	command := dynamicObservationCommand{kind: kind, siteID: siteID, result: result}
	d.dynamicObservationGate.RLock()
	if d.dynamicObservationClosed.Load() || d.dynamicObservationQueue == nil {
		d.dynamicObservationGate.RUnlock()
		return errDynamicObservationWriterClosed
	}
	d.dynamicObservationQueue <- command
	d.dynamicObservationGate.RUnlock()
	return <-result
}

func (d *DB) flushDynamicObservations() error {
	return d.sendDynamicObservationControl(dynamicObservationCommandFlush, 0)
}

func (d *DB) ClearDynamicObservations(siteID int64) error {
	if siteID <= 0 {
		return fmt.Errorf("invalid dynamic observation site id")
	}
	return d.sendDynamicObservationControl(dynamicObservationCommandClear, siteID)
}

func (d *DB) ListDynamicObservations(siteID int64) ([]DynamicObservation, error) {
	if siteID <= 0 {
		return nil, fmt.Errorf("invalid dynamic observation site id")
	}
	// The ordered barrier makes observations already accepted by the nonblocking
	// queue visible before the read begins.
	if err := d.flushDynamicObservations(); err != nil {
		return nil, err
	}
	rows, err := d.db.Query(`
		SELECT site_id, canonical_authority, source, decision, reason_code, first_seen_ms, last_seen_ms, count
		FROM dynamic_observations
		WHERE site_id=?
		ORDER BY last_seen_ms DESC, first_seen_ms DESC, canonical_authority, source, decision, reason_code`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	observations := make([]DynamicObservation, 0)
	for rows.Next() {
		var observation DynamicObservation
		if err := rows.Scan(
			&observation.SiteID,
			&observation.CanonicalAuthority,
			&observation.Source,
			&observation.Decision,
			&observation.ReasonCode,
			&observation.FirstSeenMS,
			&observation.LastSeenMS,
			&observation.Count,
		); err != nil {
			return nil, err
		}
		if observation.SiteID != siteID || !isCanonicalDynamicObservationAuthority(observation.CanonicalAuthority) || !validDynamicObservationEnums(observation.Source, observation.Decision, observation.ReasonCode) || observation.FirstSeenMS < 0 || observation.LastSeenMS < observation.FirstSeenMS || observation.Count <= 0 {
			return nil, fmt.Errorf("stored dynamic observation failed validation")
		}
		observations = append(observations, observation)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return observations, nil
}

func (d *DB) runDynamicObservationWriter() {
	defer close(d.dynamicObservationDone)
	ticker := time.NewTicker(dynamicObservationMaintenanceInterval)
	defer ticker.Stop()

	batch := make([]queuedDynamicObservation, 0, dynamicObservationBatchSize)
	var pending dynamicObservationCommand
	hasPending := false
	for {
		var command dynamicObservationCommand
		if hasPending {
			command = pending
			hasPending = false
		} else {
			select {
			case command = <-d.dynamicObservationQueue:
			case <-ticker.C:
				if err := d.pruneDynamicObservations(); err != nil {
					d.droppedDynamicObservations.Add(1)
					log.Printf("[dynamic-observations] optional retention write failed: %v", err)
				}
				continue
			}
		}

		if command.kind == dynamicObservationCommandWrite {
			batch = batch[:0]
			batch = append(batch, command.event)
		drainBatch:
			for len(batch) < dynamicObservationBatchSize {
				select {
				case next := <-d.dynamicObservationQueue:
					if next.kind != dynamicObservationCommandWrite {
						pending = next
						hasPending = true
						break drainBatch
					}
					batch = append(batch, next.event)
				default:
					break drainBatch
				}
			}
			skipped, err := d.writeDynamicObservationBatch(batch)
			if err != nil {
				d.droppedDynamicObservations.Add(uint64(len(batch)))
				log.Printf("[dynamic-observations] optional batch write failed: %v", err)
			} else if skipped > 0 {
				d.droppedDynamicObservations.Add(uint64(skipped))
			}
			continue
		}

		switch command.kind {
		case dynamicObservationCommandFlush:
			command.result <- nil
		case dynamicObservationCommandClear:
			_, err := d.db.Exec("DELETE FROM dynamic_observations WHERE site_id=?", command.siteID)
			command.result <- err
		case dynamicObservationCommandStop:
			command.result <- nil
			return
		default:
			if command.result != nil {
				command.result <- fmt.Errorf("unknown dynamic observation command")
			}
		}
	}
}

func (d *DB) writeDynamicObservationBatch(batch []queuedDynamicObservation) (int, error) {
	type observationKey struct {
		siteID             int64
		canonicalAuthority string
		source             string
		decision           string
		reasonCode         string
	}
	type aggregate struct {
		event       dynamicObservationEvent
		firstSeenMS int64
		lastSeenMS  int64
		count       int64
	}
	aggregated := make([]aggregate, 0, len(batch))
	indexes := make(map[observationKey]int, len(batch))
	for _, queued := range batch {
		event := queued.event
		key := observationKey{
			siteID:             event.SiteID,
			canonicalAuthority: event.CanonicalAuthority,
			source:             event.Source,
			decision:           event.Decision,
			reasonCode:         event.ReasonCode,
		}
		if index, ok := indexes[key]; ok {
			current := &aggregated[index]
			current.firstSeenMS = min(current.firstSeenMS, queued.observedAtMS)
			current.lastSeenMS = max(current.lastSeenMS, queued.observedAtMS)
			current.count++
			continue
		}
		indexes[key] = len(aggregated)
		aggregated = append(aggregated, aggregate{
			event:       event,
			firstSeenMS: queued.observedAtMS,
			lastSeenMS:  queued.observedAtMS,
			count:       1,
		})
	}

	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	statement, err := tx.Prepare(`
		INSERT INTO dynamic_observations
			(site_id, canonical_authority, source, decision, reason_code, first_seen_ms, last_seen_ms, count)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?
		WHERE EXISTS (SELECT 1 FROM sites WHERE id=?)
		ON CONFLICT(site_id, canonical_authority, source, decision, reason_code) DO UPDATE SET
			first_seen_ms=MIN(dynamic_observations.first_seen_ms, excluded.first_seen_ms),
			last_seen_ms=MAX(dynamic_observations.last_seen_ms, excluded.last_seen_ms),
			count=CASE
				WHEN excluded.count >= 9223372036854775807-dynamic_observations.count THEN 9223372036854775807
				ELSE dynamic_observations.count+excluded.count
			END`)
	if err != nil {
		return 0, err
	}
	defer statement.Close()
	skipped := 0
	for _, current := range aggregated {
		event := current.event
		result, err := statement.Exec(
			event.SiteID,
			event.CanonicalAuthority,
			event.Source,
			event.Decision,
			event.ReasonCode,
			current.firstSeenMS,
			current.lastSeenMS,
			current.count,
			event.SiteID,
		)
		if err != nil {
			return 0, err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		if rows == 0 {
			skipped += int(current.count)
		}
	}
	if err := pruneDynamicObservationsTx(tx, time.Now()); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return skipped, nil
}

func pruneDynamicObservationsTx(tx *sql.Tx, now time.Time) error {
	cutoffMS := now.Add(-dynamicObservationRetention).UnixMilli()
	if _, err := tx.Exec("DELETE FROM dynamic_observations WHERE last_seen_ms<?", cutoffMS); err != nil {
		return err
	}
	_, err := tx.Exec(`
		DELETE FROM dynamic_observations
		WHERE (site_id, canonical_authority, source, decision, reason_code) IN (
			SELECT site_id, canonical_authority, source, decision, reason_code
			FROM dynamic_observations
			ORDER BY last_seen_ms DESC, first_seen_ms DESC, site_id, canonical_authority, source, decision, reason_code
			LIMIT -1 OFFSET ?
		)`, dynamicObservationGlobalRowLimit)
	return err
}

func (d *DB) pruneDynamicObservations() error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := pruneDynamicObservationsTx(tx, time.Now()); err != nil {
		return err
	}
	return tx.Commit()
}

const (
	migrationRetryDelay    = 25 * time.Millisecond
	migrationRetryDeadline = 5 * time.Second
)

func (d *DB) migrate() error {
	deadline := time.Now().Add(migrationRetryDeadline)
	for {
		err := d.migrateOnce()
		if err == nil || !isSQLiteBusyError(err) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(migrationRetryDelay)
	}
}

func isSQLiteBusyError(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	// SQLite encodes the primary result code in the low byte of extended errors.
	switch sqliteErr.Code() & 0xff {
	case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
		return true
	default:
		return false
	}
}

func isSQLiteUniqueConstraintError(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	switch sqliteErr.Code() {
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
		return true
	default:
		return false
	}
}

func (d *DB) migrateOnce() error {
	ctx := context.Background()
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	if _, err := conn.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
		CREATE TABLE IF NOT EXISTS sites (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			listen_port INTEGER NOT NULL UNIQUE,
			public_host TEXT NOT NULL DEFAULT '',
			ingress_mode TEXT NOT NULL DEFAULT 'port',
			target_url TEXT NOT NULL,
		playback_target_url TEXT NOT NULL DEFAULT '',
		playback_mode TEXT NOT NULL DEFAULT 'direct',
		stream_hosts TEXT NOT NULL DEFAULT '[]',
		ua_mode TEXT DEFAULT 'infuse',
		custom_user_agent TEXT NOT NULL DEFAULT '',
		custom_client TEXT NOT NULL DEFAULT '',
		custom_version TEXT NOT NULL DEFAULT '',
		upstream_headers TEXT NOT NULL DEFAULT '[]',
		ping_cache_enabled INTEGER NOT NULL DEFAULT 0,
		image_cache_enabled INTEGER NOT NULL DEFAULT 0,
		progress_coalescing_enabled INTEGER NOT NULL DEFAULT 0,
		dynamic_discovery_enabled INTEGER NOT NULL DEFAULT 0,
		dynamic_profile TEXT NOT NULL DEFAULT 'safe',
		dynamic_discovery_sources TEXT NOT NULL DEFAULT '["redirect"]',
		dynamic_domain_rules TEXT NOT NULL DEFAULT '[]',
		dynamic_allow_https_downgrade INTEGER NOT NULL DEFAULT 0,
		dynamic_policy_revision INTEGER NOT NULL DEFAULT 1,
		enabled INTEGER DEFAULT 1,
		traffic_quota BIGINT DEFAULT 0,
		traffic_used BIGINT DEFAULT 0,
		speed_limit INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS traffic_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
		bytes_in BIGINT DEFAULT 0,
		bytes_out BIGINT DEFAULT 0,
		recorded_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_traffic_site_time ON traffic_logs(site_id, recorded_at);
	CREATE TABLE IF NOT EXISTS traffic_minute_logs (
		site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
		minute_start_unix INTEGER NOT NULL,
		bytes_in INTEGER NOT NULL DEFAULT 0,
		bytes_out INTEGER NOT NULL DEFAULT 0,
		requests INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY(site_id, minute_start_unix)
	);
	`); err != nil {
		return err
	}
	if err := ensureDynamicObservationSchema(ctx, conn); err != nil {
		return err
	}
	if err := validateDynamicObservationSchema(ctx, conn); err != nil {
		return err
	}

	for _, migration := range []struct {
		column string
		sql    string
	}{
		{"playback_target_url", "ALTER TABLE sites ADD COLUMN playback_target_url TEXT NOT NULL DEFAULT ''"},
		{"playback_mode", "ALTER TABLE sites ADD COLUMN playback_mode TEXT NOT NULL DEFAULT 'direct'"},
		{"stream_hosts", "ALTER TABLE sites ADD COLUMN stream_hosts TEXT NOT NULL DEFAULT '[]'"},
		{"custom_user_agent", "ALTER TABLE sites ADD COLUMN custom_user_agent TEXT NOT NULL DEFAULT ''"},
		{"custom_client", "ALTER TABLE sites ADD COLUMN custom_client TEXT NOT NULL DEFAULT ''"},
		{"custom_version", "ALTER TABLE sites ADD COLUMN custom_version TEXT NOT NULL DEFAULT ''"},
		{"public_host", "ALTER TABLE sites ADD COLUMN public_host TEXT NOT NULL DEFAULT ''"},
		{"ingress_mode", "ALTER TABLE sites ADD COLUMN ingress_mode TEXT NOT NULL DEFAULT 'port'"},
		{"upstream_headers", "ALTER TABLE sites ADD COLUMN upstream_headers TEXT NOT NULL DEFAULT '[]'"},
		{"ping_cache_enabled", "ALTER TABLE sites ADD COLUMN ping_cache_enabled INTEGER NOT NULL DEFAULT 0"},
		{"image_cache_enabled", "ALTER TABLE sites ADD COLUMN image_cache_enabled INTEGER NOT NULL DEFAULT 0"},
		{"progress_coalescing_enabled", "ALTER TABLE sites ADD COLUMN progress_coalescing_enabled INTEGER NOT NULL DEFAULT 0"},
		{"dynamic_discovery_enabled", "ALTER TABLE sites ADD COLUMN dynamic_discovery_enabled INTEGER NOT NULL DEFAULT 0"},
		{"dynamic_profile", "ALTER TABLE sites ADD COLUMN dynamic_profile TEXT NOT NULL DEFAULT 'safe'"},
		{"dynamic_discovery_sources", "ALTER TABLE sites ADD COLUMN dynamic_discovery_sources TEXT NOT NULL DEFAULT '[\"redirect\"]'"},
		{"dynamic_domain_rules", "ALTER TABLE sites ADD COLUMN dynamic_domain_rules TEXT NOT NULL DEFAULT '[]'"},
		{"dynamic_allow_https_downgrade", "ALTER TABLE sites ADD COLUMN dynamic_allow_https_downgrade INTEGER NOT NULL DEFAULT 0"},
		{"dynamic_policy_revision", "ALTER TABLE sites ADD COLUMN dynamic_policy_revision INTEGER NOT NULL DEFAULT 1"},
	} {
		exists, err := sqliteColumnExists(ctx, conn, migration.column)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := conn.ExecContext(ctx, migration.sql); err != nil {
				return err
			}
		}
	}
	// public_host was introduced before ingress_mode on the unreleased Issue #28
	// branch. Migrate those rows to the secure host-only behavior instead of
	// silently retaining a public high-port listener.
	if _, err := conn.ExecContext(ctx, "UPDATE sites SET ingress_mode='host' WHERE public_host <> '' AND ingress_mode='port'"); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS idx_sites_public_host ON sites(public_host COLLATE NOCASE) WHERE public_host <> ''"); err != nil {
		return err
	}

	var hasHourlyIndex int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_traffic_site_hour'").Scan(&hasHourlyIndex); err != nil {
		return err
	}
	if hasHourlyIndex == 0 {
		if _, err := conn.ExecContext(ctx, `
			CREATE TABLE traffic_logs_dedup (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
				bytes_in BIGINT DEFAULT 0,
				bytes_out BIGINT DEFAULT 0,
				recorded_at DATETIME NOT NULL
			);
			INSERT INTO traffic_logs_dedup (site_id, bytes_in, bytes_out, recorded_at)
			SELECT site_id, SUM(bytes_in), SUM(bytes_out), recorded_at
			FROM traffic_logs
			GROUP BY site_id, recorded_at;
			DELETE FROM traffic_logs;
			INSERT INTO traffic_logs (site_id, bytes_in, bytes_out, recorded_at)
			SELECT site_id, bytes_in, bytes_out, recorded_at
			FROM traffic_logs_dedup;
			DROP TABLE traffic_logs_dedup;
			CREATE UNIQUE INDEX idx_traffic_site_hour ON traffic_logs(site_id, recorded_at);
		`); err != nil {
			return err
		}
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

func sqliteColumnExists(ctx context.Context, conn *sql.Conn, column string) (bool, error) {
	var count int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('sites') WHERE name=?", column).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

const dynamicObservationTableDDL = `
CREATE TABLE dynamic_observations (
	site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	canonical_authority TEXT NOT NULL,
	source TEXT NOT NULL CHECK(source IN ('redirect', 'playback_info', 'hls', 'dash')),
	decision TEXT NOT NULL CHECK(decision IN ('allowed', 'denied')),
	reason_code TEXT NOT NULL CHECK(reason_code IN (
		'redirect_allowed',
		'candidate_allowed',
		'invalid_location',
		'unsupported_status',
		'redirect_loop',
		'hop_limit',
		'scheme_denied',
		'port_denied',
		'domain_denied',
		'https_downgrade_denied',
		'self_target',
		'dns_failure',
		'address_denied',
		'dial_failure',
		'tls_failure',
		'capacity_limit',
		'rate_limit',
		'parse_failure',
		'request_unclassified',
		'structured_body_limit',
		'playback_info_denied',
		'hls_feature_denied',
		'dash_feature_denied',
		'redirect_body_replay_denied',
		'capability_invalid',
		'capability_expired',
		'response_failure',
		'runtime_unavailable'
	)),
	first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
	last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms >= first_seen_ms),
	count INTEGER NOT NULL CHECK(count > 0),
	PRIMARY KEY(site_id, canonical_authority, source, decision, reason_code)
) WITHOUT ROWID;`

const dynamicObservationIndexesDDL = `
CREATE INDEX IF NOT EXISTS idx_dynamic_observations_site_last_seen
	ON dynamic_observations(site_id, last_seen_ms DESC);
CREATE INDEX IF NOT EXISTS idx_dynamic_observations_last_seen
	ON dynamic_observations(last_seen_ms);`

const (
	dynamicObservationSchemaCurrent  = "current"
	dynamicObservationSchemaPrevious = "previous"
	dynamicObservationSchemaLegacy   = "legacy"
	dynamicObservationSchemaInvalid  = "invalid"
)

func compactSQLiteDDL(value string) string {
	var compact strings.Builder
	compact.Grow(len(value))
	for _, character := range strings.ToLower(value) {
		if !unicode.IsSpace(character) {
			compact.WriteRune(character)
		}
	}
	return compact.String()
}

func dynamicObservationSchemaState(tableSQL string) string {
	compact := compactSQLiteDDL(tableSQL)
	common := []string{
		"check(decisionin('allowed','denied'))",
		"check(first_seen_ms>=0)",
		"check(last_seen_ms>=first_seen_ms)",
		"check(count>0)",
		"site_idintegernotnullreferencessites(id)ondeletecascade",
		")withoutrowid",
	}
	for _, fragment := range common {
		if !strings.Contains(compact, fragment) {
			return dynamicObservationSchemaInvalid
		}
	}
	currentSource := "check(sourcein('redirect','playback_info','hls','dash'))"
	currentReasons := "check(reason_codein('redirect_allowed','candidate_allowed','invalid_location','unsupported_status','redirect_loop','hop_limit','scheme_denied','port_denied','domain_denied','https_downgrade_denied','self_target','dns_failure','address_denied','dial_failure','tls_failure','capacity_limit','rate_limit','parse_failure','request_unclassified','structured_body_limit','playback_info_denied','hls_feature_denied','dash_feature_denied','redirect_body_replay_denied','capability_invalid','capability_expired','response_failure','runtime_unavailable'))"
	if strings.Contains(compact, currentSource) && strings.Contains(compact, currentReasons) {
		return dynamicObservationSchemaCurrent
	}
	previousReasons := "check(reason_codein('redirect_allowed','candidate_allowed','invalid_location','unsupported_status','redirect_loop','hop_limit','scheme_denied','port_denied','domain_denied','https_downgrade_denied','self_target','dns_failure','address_denied','dial_failure','tls_failure','capacity_limit','rate_limit','parse_failure','capability_invalid','capability_expired','response_failure','runtime_unavailable'))"
	if strings.Contains(compact, currentSource) && strings.Contains(compact, previousReasons) {
		return dynamicObservationSchemaPrevious
	}
	legacySource := "check(source='redirect')"
	legacyReasons := "check(reason_codein('redirect_allowed','invalid_location','unsupported_status','redirect_loop','hop_limit','scheme_denied','port_denied','domain_denied','https_downgrade_denied','self_target','dns_failure','address_denied','dial_failure','tls_failure','capacity_limit','rate_limit','response_failure','runtime_unavailable'))"
	if strings.Contains(compact, legacySource) && strings.Contains(compact, legacyReasons) {
		return dynamicObservationSchemaLegacy
	}
	return dynamicObservationSchemaInvalid
}

func ensureDynamicObservationSchema(ctx context.Context, conn *sql.Conn) error {
	var tableSQL string
	err := conn.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='dynamic_observations'").Scan(&tableSQL)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := conn.ExecContext(ctx, dynamicObservationTableDDL+dynamicObservationIndexesDDL); err != nil {
			return fmt.Errorf("create dynamic_observations schema: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect dynamic_observations table SQL: %w", err)
	}
	switch dynamicObservationSchemaState(tableSQL) {
	case dynamicObservationSchemaCurrent:
		if _, err := conn.ExecContext(ctx, dynamicObservationIndexesDDL); err != nil {
			return fmt.Errorf("create dynamic observation indexes: %w", err)
		}
		return nil
	case dynamicObservationSchemaPrevious, dynamicObservationSchemaLegacy:
		var staleTable int
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='dynamic_observations_legacy'").Scan(&staleTable); err != nil {
			return fmt.Errorf("inspect legacy dynamic observation table: %w", err)
		}
		if staleTable != 0 {
			return fmt.Errorf("dynamic_observations_legacy already exists")
		}
		migrationSQL := `
ALTER TABLE dynamic_observations RENAME TO dynamic_observations_legacy;
` + dynamicObservationTableDDL + `
INSERT INTO dynamic_observations
	(site_id, canonical_authority, source, decision, reason_code, first_seen_ms, last_seen_ms, count)
SELECT site_id, canonical_authority, source, decision, reason_code, first_seen_ms, last_seen_ms, count
FROM dynamic_observations_legacy;
DROP TABLE dynamic_observations_legacy;
` + dynamicObservationIndexesDDL
		if _, err := conn.ExecContext(ctx, migrationSQL); err != nil {
			return fmt.Errorf("migrate dynamic_observations enum constraints: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("dynamic_observations contains unrecognized or unsafe constraints")
	}
}

func validateDynamicObservationSchema(ctx context.Context, conn *sql.Conn) error {
	type columnSpec struct {
		name               string
		typeName           string
		primaryKeyPosition int
	}
	expected := []columnSpec{
		{name: "site_id", typeName: "INTEGER", primaryKeyPosition: 1},
		{name: "canonical_authority", typeName: "TEXT", primaryKeyPosition: 2},
		{name: "source", typeName: "TEXT", primaryKeyPosition: 3},
		{name: "decision", typeName: "TEXT", primaryKeyPosition: 4},
		{name: "reason_code", typeName: "TEXT", primaryKeyPosition: 5},
		{name: "first_seen_ms", typeName: "INTEGER"},
		{name: "last_seen_ms", typeName: "INTEGER"},
		{name: "count", typeName: "INTEGER"},
	}
	rows, err := conn.QueryContext(ctx, `
		SELECT name, upper(type), "notnull", dflt_value, pk
		FROM pragma_table_info('dynamic_observations')
		ORDER BY cid`)
	if err != nil {
		return fmt.Errorf("inspect dynamic_observations schema: %w", err)
	}
	position := 0
	for rows.Next() {
		if position >= len(expected) {
			_ = rows.Close()
			return fmt.Errorf("dynamic_observations contains unexpected columns")
		}
		var name, typeName string
		var notNull, primaryKeyPosition int
		var defaultValue sql.NullString
		if err := rows.Scan(&name, &typeName, &notNull, &defaultValue, &primaryKeyPosition); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inspect dynamic_observations column: %w", err)
		}
		want := expected[position]
		if name != want.name || typeName != want.typeName || notNull != 1 || defaultValue.Valid || primaryKeyPosition != want.primaryKeyPosition {
			_ = rows.Close()
			return fmt.Errorf("dynamic_observations column %d has an invalid definition", position)
		}
		position++
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("inspect dynamic_observations schema: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close dynamic_observations schema rows: %w", err)
	}
	if position != len(expected) {
		return fmt.Errorf("dynamic_observations is missing required columns")
	}

	var tableSQL string
	if err := conn.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='dynamic_observations'").Scan(&tableSQL); err != nil {
		return fmt.Errorf("inspect dynamic_observations table SQL: %w", err)
	}
	if dynamicObservationSchemaState(tableSQL) != dynamicObservationSchemaCurrent {
		return fmt.Errorf("dynamic_observations enum constraints are invalid")
	}

	for _, index := range []struct {
		name    string
		columns []string
	}{
		{name: "idx_dynamic_observations_site_last_seen", columns: []string{"site_id", "last_seen_ms"}},
		{name: "idx_dynamic_observations_last_seen", columns: []string{"last_seen_ms"}},
	} {
		indexRows, err := conn.QueryContext(ctx, "SELECT name FROM pragma_index_info(?) ORDER BY seqno", index.name)
		if err != nil {
			return fmt.Errorf("inspect dynamic observation index %s: %w", index.name, err)
		}
		columns := make([]string, 0, len(index.columns))
		for indexRows.Next() {
			var column string
			if err := indexRows.Scan(&column); err != nil {
				_ = indexRows.Close()
				return fmt.Errorf("inspect dynamic observation index %s: %w", index.name, err)
			}
			columns = append(columns, column)
		}
		if err := indexRows.Err(); err != nil {
			_ = indexRows.Close()
			return fmt.Errorf("inspect dynamic observation index %s: %w", index.name, err)
		}
		if err := indexRows.Close(); err != nil {
			return fmt.Errorf("close dynamic observation index %s rows: %w", index.name, err)
		}
		if len(columns) != len(index.columns) {
			return fmt.Errorf("dynamic observation index %s has an invalid definition", index.name)
		}
		for i := range columns {
			if columns[i] != index.columns[i] {
				return fmt.Errorf("dynamic observation index %s has an invalid definition", index.name)
			}
		}
	}
	return nil
}

type Site struct {
	ID                            int64                `json:"id"`
	Name                          string               `json:"name"`
	ListenPort                    int                  `json:"listen_port"`
	PublicHost                    string               `json:"public_host"`
	IngressMode                   string               `json:"ingress_mode"`
	TargetURL                     string               `json:"target_url"`
	PlaybackTargetURL             string               `json:"playback_target_url"`
	PlaybackMode                  string               `json:"playback_mode"`
	StreamHosts                   string               `json:"-"`
	StreamHostList                []string             `json:"stream_hosts"`
	UAMode                        string               `json:"ua_mode"`
	CustomUserAgent               string               `json:"custom_user_agent"`
	CustomClient                  string               `json:"custom_client"`
	CustomVersion                 string               `json:"custom_version"`
	StoredUpstreamHeaders         string               `json:"-"`
	UpstreamHeaders               []UpstreamHeaderView `json:"upstream_headers"`
	PingCacheEnabled              bool                 `json:"ping_cache_enabled"`
	ImageCacheEnabled             bool                 `json:"image_cache_enabled"`
	ProgressCoalescingEnabled     bool                 `json:"progress_coalescing_enabled"`
	DynamicDiscoveryEnabled       bool                 `json:"dynamic_discovery_enabled"`
	DynamicProfile                string               `json:"dynamic_profile"`
	StoredDynamicDiscoverySources string               `json:"-"`
	DynamicDiscoverySources       []string             `json:"dynamic_discovery_sources"`
	StoredDynamicDomainRules      string               `json:"-"`
	DynamicDomainRules            []DynamicDomainRule  `json:"dynamic_domain_rules"`
	DynamicAllowHTTPSDowngrade    bool                 `json:"dynamic_allow_https_downgrade"`
	DynamicPolicyRevision         int64                `json:"dynamic_policy_revision"`
	Enabled                       bool                 `json:"enabled"`
	TrafficQuota                  int64                `json:"traffic_quota"`
	TrafficUsed                   int64                `json:"traffic_used"`
	SpeedLimit                    int                  `json:"speed_limit"`
	CreatedAt                     string               `json:"created_at"`
	UpdatedAt                     string               `json:"updated_at"`
}

func sqliteBool(value bool) int {
	if value {
		return 1
	}
	return 0
}

func hydrateSiteConfiguration(site *Site, pingCacheEnabled, imageCacheEnabled, progressCoalescingEnabled, dynamicEnabled, dynamicDowngrade int) error {
	site.PingCacheEnabled = pingCacheEnabled == 1
	site.ImageCacheEnabled = imageCacheEnabled == 1
	site.ProgressCoalescingEnabled = progressCoalescingEnabled == 1
	publicHost, err := normalizePublicHost(site.PublicHost)
	if err != nil {
		return err
	}
	site.PublicHost = publicHost
	ingressMode, err := normalizeIngressMode(site.IngressMode, site.PublicHost)
	if err != nil {
		return err
	}
	site.IngressMode = ingressMode
	if err := json.Unmarshal([]byte(site.StreamHosts), &site.StreamHostList); err != nil {
		return fmt.Errorf("invalid stored stream_hosts: %w", err)
	}
	if site.StreamHostList == nil {
		site.StreamHostList = []string{}
	}
	views, err := upstreamHeaderViews(site.StoredUpstreamHeaders)
	if err != nil {
		return err
	}
	site.UpstreamHeaders = views
	if err := hydrateStoredDynamicSitePolicy(site, dynamicEnabled, dynamicDowngrade); err != nil {
		return err
	}
	return nil
}

type TrafficLog struct {
	ID         int64  `json:"id"`
	SiteID     int64  `json:"site_id"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	RecordedAt string `json:"recorded_at"`
}

const (
	trafficMinuteSeconds        int64 = 60
	trafficTimelineMaxMinutes         = 7 * 24 * 60
	trafficMinuteRetention            = 7 * 24 * time.Hour
	trafficMinutePruneBatchSize       = 256
)

// TrafficMinuteLog is deliberately identity-free: timeline responses expose
// aggregate volume and request counts only, never a site/name/client field.
type TrafficMinuteLog struct {
	MinuteStartUnix int64 `json:"minute_start_unix"`
	BytesIn         int64 `json:"bytes_in"`
	BytesOut        int64 `json:"bytes_out"`
	Requests        int64 `json:"requests"`
}

type trafficMinuteDelta struct {
	BytesIn  int64
	BytesOut int64
	Requests int64
}

func trafficMinuteStart(at time.Time) int64 {
	return at.UTC().Truncate(time.Minute).Unix()
}

func validTrafficTimelineMinutes(minutes int) bool {
	switch minutes {
	case 60, 360, 1440, trafficTimelineMaxMinutes:
		return true
	default:
		return false
	}
}

// SiteTraffic is the authoritative per-site traffic state: the persisted
// baseline plus in-memory pending bytes. TrafficUsed is always
// PersistedTraffic + BytesIn + BytesOut (pending, not yet flushed).
type SiteTraffic struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	Running          bool   `json:"running"`
	TrafficQuota     int64  `json:"traffic_quota"`
	PersistedTraffic int64  `json:"persisted_traffic"`
	BytesIn          int64  `json:"bytes_in"`
	BytesOut         int64  `json:"bytes_out"`
	TrafficUsed      int64  `json:"traffic_used"`
	Requests         int64  `json:"requests"`
}

// TrafficSnapshot is the single authoritative global traffic payload shared by
// /api/dashboard, /api/traffic/overview and SSE events.
type TrafficSnapshot struct {
	TotalSites    int           `json:"total_sites"`
	OnlineSites   int           `json:"online_sites"`
	RunningSites  int           `json:"running_sites"`
	TotalTraffic  int64         `json:"total_traffic"`
	TotalRequests int64         `json:"total_requests"`
	UptimeSeconds int64         `json:"uptime_seconds"`
	LiveSites     []SiteTraffic `json:"live_sites"`
}

// TrafficHistory is the single-site envelope returned by
// /api/traffic/{id}/snapshot: an atomically captured live snapshot plus the
// log window with pending bytes merged into the current-hour bucket.
type TrafficHistory struct {
	Snapshot SiteTraffic  `json:"snapshot"`
	Logs     []TrafficLog `json:"logs"`
}

func (d *DB) UserCount() (int, error) {
	var n int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

var errAdminAlreadyExists = errors.New("admin user already exists")
var errInvalidCredentials = errors.New("invalid username or password")
var errAdminNotConfigured = errors.New("administrator is not configured")
var errMultipleAdmins = errors.New("multiple administrator accounts found")
var errInvalidAdminPassword = errors.New("password must be 12-72 bytes")

func validateAdminPassword(password string) error {
	if len(password) < 12 || len(password) > 72 {
		return errInvalidAdminPassword
	}
	return nil
}

func (d *DB) CreateInitialUser(username, password string) (int64, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	res, err := d.db.Exec(`
		INSERT INTO users (username, password_hash)
		SELECT ?, ?
		WHERE NOT EXISTS (SELECT 1 FROM users)
	`, username, string(hash))
	if err != nil {
		return 0, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if rows != 1 {
		return 0, errAdminAlreadyExists
	}
	return res.LastInsertId()
}

var invalidUserPasswordHash = func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("meridian-invalid-user"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return hash
}()

func (d *DB) VerifyUser(username, password string) (int64, error) {
	var id int64
	var hash string
	err := d.db.QueryRow("SELECT id, password_hash FROM users WHERE username=?", username).Scan(&id, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword(invalidUserPasswordHash, []byte(password))
		return 0, errInvalidCredentials
	}
	if err != nil {
		return 0, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return 0, errInvalidCredentials
	}
	return id, nil
}

func (d *DB) ResetAdminPassword(password string) error {
	if err := validateAdminPassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return err
	}
	switch {
	case count == 0:
		return errAdminNotConfigured
	case count != 1:
		return errMultipleAdmins
	}

	result, err := tx.Exec("UPDATE users SET password_hash=?", string(hash))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("updated %d administrator rows, want 1", rows)
	}
	return tx.Commit()
}

func (d *DB) ListSites() ([]Site, error) {
	rows, err := d.db.Query("SELECT id, name, listen_port, public_host, ingress_mode, target_url, playback_target_url, playback_mode, stream_hosts, ua_mode, custom_user_agent, custom_client, custom_version, upstream_headers, ping_cache_enabled, image_cache_enabled, progress_coalescing_enabled, dynamic_discovery_enabled, dynamic_profile, dynamic_discovery_sources, dynamic_domain_rules, dynamic_allow_https_downgrade, dynamic_policy_revision, enabled, traffic_quota, traffic_used, speed_limit, created_at, updated_at FROM sites ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sites []Site
	for rows.Next() {
		var s Site
		var enabled, pingCacheEnabled, imageCacheEnabled, progressCoalescingEnabled, dynamicEnabled, dynamicDowngrade int
		if err := rows.Scan(&s.ID, &s.Name, &s.ListenPort, &s.PublicHost, &s.IngressMode, &s.TargetURL, &s.PlaybackTargetURL, &s.PlaybackMode, &s.StreamHosts, &s.UAMode, &s.CustomUserAgent, &s.CustomClient, &s.CustomVersion, &s.StoredUpstreamHeaders, &pingCacheEnabled, &imageCacheEnabled, &progressCoalescingEnabled, &dynamicEnabled, &s.DynamicProfile, &s.StoredDynamicDiscoverySources, &s.StoredDynamicDomainRules, &dynamicDowngrade, &s.DynamicPolicyRevision, &enabled, &s.TrafficQuota, &s.TrafficUsed, &s.SpeedLimit, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		s.Enabled = enabled == 1
		if err := hydrateSiteConfiguration(&s, pingCacheEnabled, imageCacheEnabled, progressCoalescingEnabled, dynamicEnabled, dynamicDowngrade); err != nil {
			return nil, fmt.Errorf("site %d: %w", s.ID, err)
		}
		sites = append(sites, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if sites == nil {
		sites = []Site{}
	}
	return sites, nil
}
func (d *DB) DynamicRollbackReadiness() (DynamicRollbackReadiness, error) {
	rows, err := d.db.Query("SELECT dynamic_profile, dynamic_discovery_sources, dynamic_domain_rules FROM sites WHERE dynamic_discovery_enabled=1")
	if err != nil {
		return DynamicRollbackReadiness{}, err
	}
	defer rows.Close()

	var readiness DynamicRollbackReadiness
	for rows.Next() {
		var profile, storedSources, storedRules string
		if err := rows.Scan(&profile, &storedSources, &storedRules); err != nil {
			return DynamicRollbackReadiness{}, err
		}
		sources, err := decodeDynamicDiscoverySources(storedSources)
		if err != nil || sources == nil {
			return DynamicRollbackReadiness{}, fmt.Errorf("invalid stored dynamic discovery sources")
		}
		sources, err = normalizeDynamicDiscoverySourcesForAPI(profile, sources)
		if err != nil {
			return DynamicRollbackReadiness{}, fmt.Errorf("invalid stored dynamic discovery sources: %w", err)
		}
		canonicalSources, ok := dynamicDiscoverySourcesForProfile(profile)
		if !ok {
			return DynamicRollbackReadiness{}, fmt.Errorf("invalid stored dynamic discovery profile")
		}
		if !dynamicDiscoverySourcesEqual(sources, canonicalSources) {
			readiness.EnabledLegacySourceSubsets++
		}

		rules, err := decodeDynamicDomainRules(storedRules)
		if err != nil || rules == nil {
			return DynamicRollbackReadiness{}, fmt.Errorf("invalid stored dynamic domain rules")
		}
		rules, err = normalizeDynamicDomainRules(profile, rules)
		if err != nil {
			return DynamicRollbackReadiness{}, fmt.Errorf("invalid stored dynamic domain rules: %w", err)
		}
		if profile == dynamicProfileSafe && len(rules) == 0 {
			readiness.EnabledSafeEmptyRules++
		}
	}
	if err := rows.Err(); err != nil {
		return DynamicRollbackReadiness{}, err
	}
	return readiness, nil
}

func (d *DB) GetSite(id int64) (*Site, error) {
	var s Site
	var enabled, pingCacheEnabled, imageCacheEnabled, progressCoalescingEnabled, dynamicEnabled, dynamicDowngrade int
	err := d.db.QueryRow("SELECT id, name, listen_port, public_host, ingress_mode, target_url, playback_target_url, playback_mode, stream_hosts, ua_mode, custom_user_agent, custom_client, custom_version, upstream_headers, ping_cache_enabled, image_cache_enabled, progress_coalescing_enabled, dynamic_discovery_enabled, dynamic_profile, dynamic_discovery_sources, dynamic_domain_rules, dynamic_allow_https_downgrade, dynamic_policy_revision, enabled, traffic_quota, traffic_used, speed_limit, created_at, updated_at FROM sites WHERE id=?", id).
		Scan(&s.ID, &s.Name, &s.ListenPort, &s.PublicHost, &s.IngressMode, &s.TargetURL, &s.PlaybackTargetURL, &s.PlaybackMode, &s.StreamHosts, &s.UAMode, &s.CustomUserAgent, &s.CustomClient, &s.CustomVersion, &s.StoredUpstreamHeaders, &pingCacheEnabled, &imageCacheEnabled, &progressCoalescingEnabled, &dynamicEnabled, &s.DynamicProfile, &s.StoredDynamicDiscoverySources, &s.StoredDynamicDomainRules, &dynamicDowngrade, &s.DynamicPolicyRevision, &enabled, &s.TrafficQuota, &s.TrafficUsed, &s.SpeedLimit, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	s.Enabled = enabled == 1
	if err := hydrateSiteConfiguration(&s, pingCacheEnabled, imageCacheEnabled, progressCoalescingEnabled, dynamicEnabled, dynamicDowngrade); err != nil {
		return nil, fmt.Errorf("site %d: %w", s.ID, err)
	}
	return &s, nil
}

func (d *DB) CreateSite(name string, port int, targetURL, playbackTargetURL, playbackMode, streamHosts, uaMode string, quota int64, speedLimit int) (*Site, error) {
	return d.CreateSiteWithCustomUA(name, port, targetURL, playbackTargetURL, playbackMode, streamHosts, uaMode, "", "", "", quota, speedLimit)
}

func (d *DB) CreateSiteWithCustomUA(name string, port int, targetURL, playbackTargetURL, playbackMode, streamHosts, uaMode, customUserAgent, customClient, customVersion string, quota int64, speedLimit int) (*Site, error) {
	return d.CreateSiteRecord(Site{
		Name:              name,
		ListenPort:        port,
		TargetURL:         targetURL,
		PlaybackTargetURL: playbackTargetURL,
		PlaybackMode:      playbackMode,
		StreamHosts:       streamHosts,
		UAMode:            uaMode,
		CustomUserAgent:   customUserAgent,
		CustomClient:      customClient,
		CustomVersion:     customVersion,
		TrafficQuota:      quota,
		SpeedLimit:        speedLimit,
	})
}

func (d *DB) CreateSiteRecord(site Site) (*Site, error) {
	if site.StreamHosts == "" {
		site.StreamHosts = "[]"
	}
	if site.StoredUpstreamHeaders == "" {
		site.StoredUpstreamHeaders = "[]"
	}
	publicHost, err := normalizePublicHost(site.PublicHost)
	if err != nil {
		return nil, err
	}
	site.PublicHost = publicHost
	site.IngressMode, err = normalizeIngressMode(site.IngressMode, site.PublicHost)
	if err != nil {
		return nil, err
	}
	if err := normalizeDynamicSitePolicy(&site); err != nil {
		return nil, err
	}
	site.DynamicPolicyRevision = 1
	res, err := d.db.Exec(
		"INSERT INTO sites (name, listen_port, public_host, ingress_mode, target_url, playback_target_url, playback_mode, stream_hosts, ua_mode, custom_user_agent, custom_client, custom_version, upstream_headers, ping_cache_enabled, image_cache_enabled, progress_coalescing_enabled, dynamic_discovery_enabled, dynamic_profile, dynamic_discovery_sources, dynamic_domain_rules, dynamic_allow_https_downgrade, dynamic_policy_revision, traffic_quota, speed_limit) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		site.Name, site.ListenPort, site.PublicHost, site.IngressMode, site.TargetURL, site.PlaybackTargetURL, site.PlaybackMode, site.StreamHosts, site.UAMode, site.CustomUserAgent, site.CustomClient, site.CustomVersion, site.StoredUpstreamHeaders, sqliteBool(site.PingCacheEnabled), sqliteBool(site.ImageCacheEnabled), sqliteBool(site.ProgressCoalescingEnabled), sqliteBool(site.DynamicDiscoveryEnabled), site.DynamicProfile, site.StoredDynamicDiscoverySources, site.StoredDynamicDomainRules, sqliteBool(site.DynamicAllowHTTPSDowngrade), site.DynamicPolicyRevision, site.TrafficQuota, site.SpeedLimit,
	)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return d.GetSite(id)
}

func (d *DB) UpdateSite(id int64, name string, port int, targetURL, playbackTargetURL, playbackMode, streamHosts, uaMode string, quota int64, speedLimit int) error {
	return d.UpdateSiteWithCustomUA(id, name, port, targetURL, playbackTargetURL, playbackMode, streamHosts, uaMode, "", "", "", quota, speedLimit)
}

func (d *DB) UpdateSiteWithCustomUA(id int64, name string, port int, targetURL, playbackTargetURL, playbackMode, streamHosts, uaMode, customUserAgent, customClient, customVersion string, quota int64, speedLimit int) error {
	site, err := d.GetSite(id)
	if err != nil {
		return err
	}
	site.Name = name
	site.ListenPort = port
	site.TargetURL = targetURL
	site.PlaybackTargetURL = playbackTargetURL
	site.PlaybackMode = playbackMode
	site.StreamHosts = streamHosts
	site.UAMode = uaMode
	site.CustomUserAgent = customUserAgent
	site.CustomClient = customClient
	site.CustomVersion = customVersion
	site.TrafficQuota = quota
	site.SpeedLimit = speedLimit
	return d.UpdateSiteRecord(*site)
}

func (d *DB) UpdateSiteRecord(site Site) error {
	return d.updateSiteRecord(site, false)
}

func (d *DB) restoreSiteRecord(site Site) error {
	if site.DynamicPolicyRevision < 1 {
		return fmt.Errorf("cannot restore a dynamic policy revision below 1")
	}
	return d.updateSiteRecord(site, true)
}

func (d *DB) updateSiteRecord(site Site, restoreRevision bool) error {
	if site.StreamHosts == "" {
		site.StreamHosts = "[]"
	}
	if site.StoredUpstreamHeaders == "" {
		site.StoredUpstreamHeaders = "[]"
	}
	publicHost, err := normalizePublicHost(site.PublicHost)
	if err != nil {
		return err
	}
	site.PublicHost = publicHost
	site.IngressMode, err = normalizeIngressMode(site.IngressMode, site.PublicHost)
	if err != nil {
		return err
	}
	if err := normalizeDynamicSitePolicy(&site); err != nil {
		return err
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentTargetURL, currentHeaders string
	queryErr := tx.QueryRow("SELECT target_url, upstream_headers FROM sites WHERE id=?", site.ID).Scan(&currentTargetURL, &currentHeaders)
	if queryErr != nil && !errors.Is(queryErr, sql.ErrNoRows) {
		return queryErr
	}
	if queryErr == nil {
		currentTarget, currentErr := normalizeTargetURL(currentTargetURL)
		newTarget, newErr := normalizeTargetURL(site.TargetURL)
		if currentErr != nil {
			return fmt.Errorf("stored target_url is invalid: %w", currentErr)
		}
		if newErr != nil {
			return fmt.Errorf("invalid target_url: %w", newErr)
		}
		if !sameRedirectAuthority(currentTarget, newTarget) && site.StoredUpstreamHeaders == currentHeaders {
			// Data-layer callers must not accidentally carry an origin secret to
			// a different scheme/host/port. The HTTP API may supply freshly
			// encrypted v2 values for the new authority; unchanged ciphertext is
			// always cleared here, even if a caller bypasses the handler checks.
			site.StoredUpstreamHeaders = "[]"
		}
	}
	dynamicEnabled := sqliteBool(site.DynamicDiscoveryEnabled)
	dynamicDowngrade := sqliteBool(site.DynamicAllowHTTPSDowngrade)
	pingCacheEnabled := sqliteBool(site.PingCacheEnabled)
	imageCacheEnabled := sqliteBool(site.ImageCacheEnabled)
	progressCoalescingEnabled := sqliteBool(site.ProgressCoalescingEnabled)
	revisionExpression := "dynamic_policy_revision=dynamic_policy_revision+CASE WHEN dynamic_discovery_enabled<>? OR dynamic_profile<>? OR dynamic_discovery_sources<>? OR dynamic_domain_rules<>? OR dynamic_allow_https_downgrade<>? THEN 1 ELSE 0 END"
	args := []interface{}{
		site.Name, site.ListenPort, site.PublicHost, site.IngressMode, site.TargetURL,
		site.PlaybackTargetURL, site.PlaybackMode, site.StreamHosts, site.UAMode,
		site.CustomUserAgent, site.CustomClient, site.CustomVersion, site.StoredUpstreamHeaders,
		pingCacheEnabled, imageCacheEnabled, progressCoalescingEnabled,
		dynamicEnabled, site.DynamicProfile, site.StoredDynamicDiscoverySources, site.StoredDynamicDomainRules, dynamicDowngrade,
	}
	if restoreRevision {
		revisionExpression = "dynamic_policy_revision=?"
		args = append(args, site.DynamicPolicyRevision)
	} else {
		args = append(args, dynamicEnabled, site.DynamicProfile, site.StoredDynamicDiscoverySources, site.StoredDynamicDomainRules, dynamicDowngrade)
	}
	args = append(args, site.TrafficQuota, site.SpeedLimit, site.ID)
	_, err = tx.Exec(
		"UPDATE sites SET name=?, listen_port=?, public_host=?, ingress_mode=?, target_url=?, playback_target_url=?, playback_mode=?, stream_hosts=?, ua_mode=?, custom_user_agent=?, custom_client=?, custom_version=?, upstream_headers=?, ping_cache_enabled=?, image_cache_enabled=?, progress_coalescing_enabled=?, dynamic_discovery_enabled=?, dynamic_profile=?, dynamic_discovery_sources=?, dynamic_domain_rules=?, dynamic_allow_https_downgrade=?, "+revisionExpression+", traffic_quota=?, speed_limit=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
		args...,
	)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) DeleteSite(id int64) error {
	// Order the site deletion after every observation already accepted by the
	// nonblocking queue. The explicit child delete below then prevents those
	// events from reappearing even on databases where foreign keys were disabled
	// by an older deployment.
	if err := d.flushDynamicObservations(); err != nil {
		return err
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM traffic_logs WHERE site_id=?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM traffic_minute_logs WHERE site_id=?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM dynamic_observations WHERE site_id=?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM sites WHERE id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) ToggleSite(id int64) (bool, error) {
	var enabled int
	if err := d.db.QueryRow("SELECT enabled FROM sites WHERE id=?", id).Scan(&enabled); err != nil {
		return false, err
	}
	newVal := 1 - enabled
	_, err := d.db.Exec("UPDATE sites SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", newVal, id)
	return newVal == 1, err
}

func (d *DB) SetSiteEnabled(id int64, enabled bool) error {
	value := 0
	if enabled {
		value = 1
	}
	result, err := d.db.Exec("UPDATE sites SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", value, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("updated %d site rows, want 1", rows)
	}
	return nil
}

func (d *DB) AddTraffic(siteID, bytesIn, bytesOut int64) {
	if err := d.addTraffic(siteID, bytesIn, bytesOut); err != nil {
		log.Printf("[traffic] failed to persist usage for site %d: %v", siteID, err)
	}
}

func (d *DB) addTraffic(siteID, bytesIn, bytesOut int64) error {
	now := time.Now()
	buckets := make(map[int64]trafficMinuteDelta, 1)
	if bytesIn != 0 || bytesOut != 0 {
		buckets[trafficMinuteStart(now)] = trafficMinuteDelta{BytesIn: bytesIn, BytesOut: bytesOut}
	}
	return d.addTrafficMinuteBuckets(siteID, bytesIn, bytesOut, buckets, now)
}

// addTrafficMinuteBuckets is the only traffic persistence transaction. The
// legacy hourly log and sites.traffic_used remain authoritative, while minute
// UPSERTs commit atomically beside the exact same byte delta. Request handling
// only populates the in-memory buckets; it never writes SQLite directly.
func (d *DB) addTrafficMinuteBuckets(siteID, bytesIn, bytesOut int64, buckets map[int64]trafficMinuteDelta, now time.Time) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if bytesIn != 0 || bytesOut != 0 {
		hour := now.Truncate(time.Hour).Format("2006-01-02 15:04:05")
		if _, err := tx.Exec(
			`INSERT INTO traffic_logs (site_id, bytes_in, bytes_out, recorded_at)
			 VALUES (?,?,?,?)
			 ON CONFLICT(site_id, recorded_at) DO UPDATE SET
			bytes_in = traffic_logs.bytes_in + excluded.bytes_in,
			bytes_out = traffic_logs.bytes_out + excluded.bytes_out`,
			siteID, bytesIn, bytesOut, hour,
		); err != nil {
			return err
		}
	}

	minuteStarts := make([]int64, 0, len(buckets))
	for minuteStart, delta := range buckets {
		if minuteStart%trafficMinuteSeconds != 0 {
			return fmt.Errorf("traffic minute %d is not aligned", minuteStart)
		}
		if delta.BytesIn < 0 || delta.BytesOut < 0 || delta.Requests < 0 {
			return fmt.Errorf("traffic minute %d contains a negative counter", minuteStart)
		}
		if delta.BytesIn != 0 || delta.BytesOut != 0 || delta.Requests != 0 {
			minuteStarts = append(minuteStarts, minuteStart)
		}
	}
	sort.Slice(minuteStarts, func(i, j int) bool { return minuteStarts[i] < minuteStarts[j] })
	for _, minuteStart := range minuteStarts {
		delta := buckets[minuteStart]
		if _, err := tx.Exec(
			`INSERT INTO traffic_minute_logs (site_id, minute_start_unix, bytes_in, bytes_out, requests)
			 VALUES (?,?,?,?,?)
			 ON CONFLICT(site_id, minute_start_unix) DO UPDATE SET
			bytes_in = traffic_minute_logs.bytes_in + excluded.bytes_in,
			bytes_out = traffic_minute_logs.bytes_out + excluded.bytes_out,
			requests = traffic_minute_logs.requests + excluded.requests`,
			siteID, minuteStart, delta.BytesIn, delta.BytesOut, delta.Requests,
		); err != nil {
			return err
		}
	}

	if bytesIn != 0 || bytesOut != 0 {
		result, err := tx.Exec(
			"UPDATE sites SET traffic_used=traffic_used+?+?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
			bytesIn, bytesOut, siteID,
		)
		if err != nil {
			return err
		}
		if rows, err := result.RowsAffected(); err != nil {
			return err
		} else if rows != 1 {
			return fmt.Errorf("updated %d site traffic rows, want 1", rows)
		}
	}

	cutoff := trafficMinuteStart(now.Add(-trafficMinuteRetention))
	if _, err := tx.Exec(`
		DELETE FROM traffic_minute_logs
		WHERE (site_id, minute_start_unix) IN (
			SELECT site_id, minute_start_unix
			FROM traffic_minute_logs
			WHERE minute_start_unix < ?
			ORDER BY minute_start_unix, site_id
			LIMIT ?
		)`, cutoff, trafficMinutePruneBatchSize); err != nil {
		return err
	}

	return tx.Commit()
}

func (d *DB) GetTrafficLogs(siteID int64, hours int) ([]TrafficLog, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Format("2006-01-02 15:04:05")
	rows, err := d.db.Query(
		"SELECT id, site_id, bytes_in, bytes_out, recorded_at FROM traffic_logs WHERE site_id=? AND recorded_at>=? ORDER BY recorded_at",
		siteID, since,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []TrafficLog
	for rows.Next() {
		var l TrafficLog
		if err := rows.Scan(&l.ID, &l.SiteID, &l.BytesIn, &l.BytesOut, &l.RecordedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if logs == nil {
		logs = []TrafficLog{}
	}
	return logs, nil
}

// GetTrafficTimeline returns a dense UTC epoch-minute series. Sparse database
// rows are copied into their exact slot; missing minutes remain explicit zeroes.
func (d *DB) GetTrafficTimeline(siteID int64, minutes int, now time.Time) ([]TrafficMinuteLog, error) {
	if !validTrafficTimelineMinutes(minutes) {
		return nil, fmt.Errorf("invalid traffic timeline range: %d", minutes)
	}
	end := trafficMinuteStart(now)
	start := end - int64(minutes-1)*trafficMinuteSeconds
	timeline := make([]TrafficMinuteLog, minutes)
	for i := range timeline {
		timeline[i].MinuteStartUnix = start + int64(i)*trafficMinuteSeconds
	}

	rows, err := d.db.Query(`
		SELECT minute_start_unix, bytes_in, bytes_out, requests
		FROM traffic_minute_logs
		WHERE site_id=? AND minute_start_unix>=? AND minute_start_unix<=?
		ORDER BY minute_start_unix`, siteID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var bucket TrafficMinuteLog
		if err := rows.Scan(&bucket.MinuteStartUnix, &bucket.BytesIn, &bucket.BytesOut, &bucket.Requests); err != nil {
			return nil, err
		}
		offset := bucket.MinuteStartUnix - start
		if offset < 0 || offset%trafficMinuteSeconds != 0 {
			continue
		}
		index := int(offset / trafficMinuteSeconds)
		if index >= len(timeline) {
			continue
		}
		timeline[index] = bucket
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return timeline, nil
}

const (
	dynamicRedirectUserAgent     = "Meridian-Redirect/1.0"
	dynamicDNSResolutionTimeout  = 30 * time.Second
	dynamicPinnedDialTimeout     = 30 * time.Second
	dynamicStructuredBodyTimeout = 20 * time.Second
)

type dynamicRequestEligibleContextKey struct{}
type dynamicResponseContextKey struct{}
type dynamicExpectedStructuredSourceContextKey struct{}

// dynamicOutboundContext keeps request cancellation and deadlines while
// dropping ReverseProxy's outbound httptrace and every other caller value.
// Otherwise an unknown authority can emit 1xx headers directly to the client
// before ModifyResponse applies the dynamic response allowlist.
type dynamicOutboundContext struct {
	context.Context
}

func (dynamicOutboundContext) Value(any) any {
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
	if !site.DynamicDiscoveryEnabled {
		return dynamicRedirectPolicy{}, nil
	}
	candidate := site
	if err := normalizeDynamicSitePolicy(&candidate); err != nil {
		return dynamicRedirectPolicy{}, fmt.Errorf("invalid dynamic discovery policy: %w", err)
	}
	limits, ok := dynamicLimitsForProfile(candidate.DynamicProfile)
	if !ok {
		return dynamicRedirectPolicy{}, fmt.Errorf("invalid dynamic discovery profile")
	}
	return dynamicRedirectPolicy{
		configured:          true,
		available:           available,
		profile:             candidate.DynamicProfile,
		limits:              limits,
		sources:             append([]string(nil), candidate.DynamicDiscoverySources...),
		domainRules:         append([]DynamicDomainRule(nil), candidate.DynamicDomainRules...),
		allowHTTPSDowngrade: candidate.DynamicAllowHTTPSDowngrade,
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
	port, err := strconv.Atoi(target.Port())
	if err != nil {
		return dynamicObservationReasonPortDenied
	}
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

	mu                 sync.Mutex
	authorities        map[string]*dynamicAuthorityEntry
	capabilities       map[[sha256.Size]byte]dynamicCapabilityEntry
	capabilityByTarget map[string]string
	capabilityMemory   int64
	newAuthorities     []time.Time
	parseMemory        int64
	closeOnce          sync.Once
}

func newDynamicSiteState(runtime *dynamicRuntime, limits DynamicProfileLimits) *dynamicSiteState {
	if runtime == nil {
		return nil
	}
	state := &dynamicSiteState{
		runtime:            runtime,
		limits:             limits,
		streams:            make(chan struct{}, limits.MaxStreams),
		parses:             make(chan struct{}, globalDynamicMaxSiteConcurrentParses),
		authorities:        make(map[string]*dynamicAuthorityEntry),
		capabilities:       make(map[[sha256.Size]byte]dynamicCapabilityEntry),
		capabilityByTarget: make(map[string]string),
	}
	runtime.mu.Lock()
	runtime.states[state] = struct{}{}
	runtime.mu.Unlock()
	return state
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
	i.database.EnqueueDynamicObservation(dynamicObservationEvent{
		SiteID:             i.siteID,
		CanonicalAuthority: authority,
		Source:             source,
		Decision:           decision,
		ReasonCode:         reasonCode,
	})
}

func (i *dynamicCapabilityIssuer) mint(ctx context.Context, previous, target *url.URL, source string) (string, *dynamicProxyError) {
	route, acquired, err := i.mintTracked(ctx, previous, target, source)
	if err == nil && acquired && !i.state.settleCapabilities([]string{strings.TrimPrefix(route, dynamicRoutePrefix)}, true, time.Now()) {
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
	if err == nil && acquired && !i.state.settleCapabilities([]string{strings.TrimPrefix(route, dynamicRoutePrefix)}, true, time.Now()) {
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
		return dynamicRoutePrefix + token, true, nil
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
	return dynamicRoutePrefix + registeredToken, true, nil
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
		return dynamicRoutePrefix + token, true, nil
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
	return dynamicRoutePrefix + registeredToken, true, nil
}

type dynamicRewriteSession struct {
	ctx              context.Context
	issuer           *dynamicCapabilityIssuer
	base             *url.URL
	source           string
	depth            int
	outputLimit      int64
	rewriteRelative  bool
	inheritedHeaders []dynamicCapabilityHeaderClaim
	seen             map[string]string
	minted           []string
	urlCount         int
}

func (s *dynamicRewriteSession) rememberCapability(seenKey, token string) string {
	route := dynamicRoutePrefix + token
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
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else if target.Scheme == "http" {
			port = "80"
		}
	}
	target.Host = net.JoinHostPort(host, port)
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
	if s == nil || s.issuer == nil || base == nil || raw == "" || raw != strings.TrimSpace(raw) || containsDynamicUnsafeRune(raw) || strings.Contains(raw, `\`) {
		return "", fmt.Errorf("invalid discovered URL")
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
	if err != nil || reference.User != nil || reference.Fragment != "" || reference.RawFragment != "" {
		return "", fmt.Errorf("invalid discovered URL")
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
			s.minted = append(s.minted, strings.TrimPrefix(route, dynamicRoutePrefix))
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
		return "", fmt.Errorf("invalid discovered URL")
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
		s.minted = append(s.minted, strings.TrimPrefix(route, dynamicRoutePrefix))
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
	if expectedSource == dynamicDiscoverySourcePlaybackInfo && !required && !issuer.policy.sourceEnabled(dynamicDiscoverySourcePlaybackInfo) {
		// PlaybackInfo inspection is the only optional structured source. A
		// redirected response still uses the dynamic transport and response-header
		// hardening, but its body must remain opaque when inspection is disabled.
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
	session := &dynamicRewriteSession{ctx: parseContext, issuer: issuer, base: resp.Request.URL, source: source, depth: depth, outputLimit: outputLimit, rewriteRelative: rewriteRelative, inheritedHeaders: inheritedHeaders}
	var rewritten []byte
	switch source {
	case dynamicDiscoverySourcePlaybackInfo:
		rewritten, err = rewritePlaybackInfoResponse(payload, session)
	case dynamicDiscoverySourceHLS:
		rewritten, err = rewriteHLSResponse(payload, session)
	case dynamicDiscoverySourceDASH:
		rewritten, err = rewriteDASHResponse(payload, session)
	}
	if err != nil {
		session.rollback()
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

func playbackInfoExtremeAbsoluteHTTPURL(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || strings.Contains(value, `\`) || containsDynamicUnsafeRune(value) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && parsed.Opaque == "" && parsed.Host != "" && (strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https"))
}

func playbackInfoExtremeCapabilityType(value string, session *dynamicRewriteSession) (string, string, error) {
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
		if !playbackInfoExtremeAbsoluteHTTPURL(typed) {
			return typed, nil
		}
		source, kind, err := playbackInfoExtremeCapabilityType(typed, session)
		if err != nil {
			return nil, err
		}
		return session.rewriteAgainstSourceKindWithRequiredHeaders(typed, session.base, source, kind, requiredHeaders)
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
			if text, ok := value.(string); exists && ok && playbackInfoRequiredHeadersUnsupported(text, hasRequiredHeaders, session) {
				return nil, fmt.Errorf("external PlaybackInfo URL requires unsupported origin headers")
			}
			capabilitySource := dynamicDiscoverySourcePlaybackInfo
			kind := dynamicCapabilityKindResource
			if text, ok := value.(string); exists && ok && playbackInfoShouldRewriteURL(text, session) {
				capabilitySource, kind, err = playbackInfoCapabilityType(source, field, text, session)
				if err != nil {
					return nil, err
				}
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
		absoluteHTTPPath := extreme && pathIsString && playbackInfoExtremeAbsoluteHTTPURL(pathText)
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
				_, deliveryValue, deliveryExists, err := playbackInfoField(stream, "DeliveryUrl")
				if err != nil {
					return nil, err
				}
				deliveryText, deliveryIsString := deliveryValue.(string)
				if deliveryExists && !deliveryIsString && deliveryValue != nil {
					return nil, fmt.Errorf("PlaybackInfo DeliveryUrl has an invalid type")
				}
				if deliveryIsString && isExternalURL && !playbackInfoURLCandidate(deliveryText) {
					return nil, fmt.Errorf("external PlaybackInfo DeliveryUrl is not an absolute network URL")
				}
				if deliveryIsString && (isExternalURL || playbackInfoShouldRewriteURL(deliveryText, session)) {
					if playbackInfoRequiredHeadersUnsupported(deliveryText, hasRequiredHeaders, session) {
						return nil, fmt.Errorf("external subtitle URL requires unsupported origin headers")
					}
					capabilitySource, kind, err := playbackInfoCapabilityType(stream, "DeliveryUrl", deliveryText, session)
					if err != nil {
						return nil, err
					}
					if err := rewritePlaybackInfoFieldAsWithRequiredHeaders(stream, "DeliveryUrl", session, capabilitySource, kind, requiredHeaders); err != nil {
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

const (
	dashTemplateMarkerPrefix           = "__MERIDIAN_DASH_TEMPLATE_"
	dashLiteralDollarClaimMarker       = dashTemplateMarkerPrefix + "LITERAL_DOLLAR__"
	dashFixedTemplateClaimMarkerPrefix = "meridian-dash-fixed-"
)

type dashTemplateMarker struct {
	sentinel   string
	expression string
	literal    bool
	fixed      bool
	fixedIndex int
}

type dashTemplateBindings struct {
	representationID string
	bandwidth        string
}

func dashFixedTemplateClaimMarker(index int) string {
	return dashFixedTemplateClaimMarkerPrefix + strconv.Itoa(index) + "-x"
}

func sanitizeDASHTemplate(value string) (string, []dashTemplateMarker, error) {
	const markerPrefix = dashTemplateMarkerPrefix
	if value == "" || len(value) > maxDynamicTargetURLBytes || strings.Contains(value, markerPrefix) || strings.Contains(strings.ToLower(value), dashFixedTemplateClaimMarkerPrefix) || containsDynamicUnsafeRune(value) {
		return "", nil, fmt.Errorf("invalid DASH URL template")
	}
	markers := make([]dashTemplateMarker, 0, 4)
	var output strings.Builder
	output.Grow(len(value))
	for offset := 0; offset < len(value); {
		if value[offset] != '$' {
			output.WriteByte(value[offset])
			offset++
			continue
		}
		if offset+1 < len(value) && value[offset+1] == '$' {
			sentinel := markerPrefix + strconv.Itoa(len(markers)) + "__"
			markers = append(markers, dashTemplateMarker{sentinel: sentinel, literal: true})
			output.WriteString(sentinel)
			offset += 2
			continue
		}
		end := strings.IndexByte(value[offset+1:], '$')
		if end < 0 {
			return "", nil, fmt.Errorf("unterminated DASH URL template expression")
		}
		end += offset + 1
		expression := value[offset+1 : end]
		if dashTemplateIdentifier(expression) == "" {
			return "", nil, fmt.Errorf("unsupported DASH URL template expression")
		}
		sentinel := markerPrefix + strconv.Itoa(len(markers)) + "__"
		markers = append(markers, dashTemplateMarker{sentinel: sentinel, expression: expression})
		output.WriteString(sentinel)
		offset = end + 1
	}
	return output.String(), markers, nil
}

func formatDASHFixedTemplateValue(expression string, bindings dashTemplateBindings) (string, bool, error) {
	match := dashTemplateExpressionPattern.FindStringSubmatch(expression)
	if match == nil {
		return "", false, fmt.Errorf("invalid DASH template expression")
	}
	switch match[1] {
	case "RepresentationID":
		if !validDASHRepresentationID(bindings.representationID) {
			return "", true, fmt.Errorf("invalid DASH RepresentationID")
		}
		return bindings.representationID, true, nil
	case "Bandwidth":
		bandwidth, err := strconv.ParseUint(bindings.bandwidth, 10, 64)
		if err != nil {
			return "", true, fmt.Errorf("invalid DASH Bandwidth")
		}
		base := 10
		switch match[3] {
		case "o":
			base = 8
		case "x", "X":
			base = 16
		}
		formatted := strconv.FormatUint(bandwidth, base)
		if match[3] == "X" {
			formatted = strings.ToUpper(formatted)
		}
		if match[2] != "" {
			width, _ := strconv.Atoi(match[2])
			if len(formatted) < width {
				formatted = strings.Repeat("0", width-len(formatted)) + formatted
			}
		}
		return formatted, true, nil
	default:
		return "", false, nil
	}
}

func prepareDASHTemplateReferences(sanitized string, markers []dashTemplateMarker, bindings dashTemplateBindings) (string, string, []string, error) {
	reference, err := url.Parse(sanitized)
	if err != nil || reference.User != nil || reference.Fragment != "" || reference.RawFragment != "" || reference.Opaque != "" {
		return "", "", nil, fmt.Errorf("invalid DASH URL template")
	}
	validationText := sanitized
	claimText := sanitized
	fixedValues := make([]string, 0, len(markers))
	for index := range markers {
		marker := &markers[index]
		inHost := strings.Count(reference.Host, marker.sentinel)
		inPath := strings.Count(reference.EscapedPath(), marker.sentinel)
		inQuery := strings.Count(reference.RawQuery, marker.sentinel)
		if inHost+inPath+inQuery != 1 {
			return "", "", nil, fmt.Errorf("DASH template expression crosses or modifies a URL structural boundary")
		}
		if marker.literal {
			if inHost != 0 {
				return "", "", nil, fmt.Errorf("DASH literal dollar cannot modify an authority")
			}
			validationText = strings.Replace(validationText, marker.sentinel, "$", 1)
			continue
		}
		fixedValue, fixed, err := formatDASHFixedTemplateValue(marker.expression, bindings)
		if err != nil {
			return "", "", nil, err
		}
		if !fixed {
			if inHost != 0 {
				return "", "", nil, fmt.Errorf("client-bound DASH template expression cannot modify an authority")
			}
			continue
		}
		marker.fixed = true
		marker.fixedIndex = len(fixedValues)
		fixedValues = append(fixedValues, fixedValue)
		validationText = strings.Replace(validationText, marker.sentinel, fixedValue, 1)
		claimText = strings.Replace(claimText, marker.sentinel, dashFixedTemplateClaimMarker(marker.fixedIndex), 1)
	}
	return validationText, claimText, fixedValues, nil
}

func restoreDASHTemplateClaimMarkers(value string, markers []dashTemplateMarker) (string, []string, error) {
	expressions := make([]string, 0, len(markers))
	for _, marker := range markers {
		if marker.fixed {
			if strings.Count(value, dashFixedTemplateClaimMarker(marker.fixedIndex)) != 1 {
				return "", nil, fmt.Errorf("fixed DASH template marker was lost or duplicated")
			}
			continue
		}
		if strings.Count(value, marker.sentinel) != 1 {
			return "", nil, fmt.Errorf("DASH URL template marker was lost or duplicated")
		}
		replacement := dashLiteralDollarClaimMarker
		if !marker.literal {
			replacement = "$" + marker.expression + "$"
			expressions = append(expressions, marker.expression)
		}
		value = strings.Replace(value, marker.sentinel, replacement, 1)
	}
	return value, expressions, nil
}

func restoreDASHLocalTemplateMarkers(value string, markers []dashTemplateMarker) (string, error) {
	for _, marker := range markers {
		if marker.literal || marker.fixed {
			continue
		}
		if strings.Count(value, marker.sentinel) != 1 {
			return "", fmt.Errorf("DASH URL template marker was lost or duplicated")
		}
		value = strings.Replace(value, marker.sentinel, "$"+marker.expression+"$", 1)
	}
	return value, nil
}

func dashTemplatePublicSuffix(expressions []string) string {
	var output strings.Builder
	for index, expression := range expressions {
		output.WriteString("/v")
		output.WriteString(strconv.Itoa(index))
		output.WriteString("-$")
		output.WriteString(expression)
		output.WriteByte('$')
	}
	return output.String()
}

func rewriteDASHTemplate(value string, base *url.URL, session *dynamicRewriteSession, bindings dashTemplateBindings) (string, error) {
	if session == nil || session.issuer == nil || session.base == nil || base == nil {
		return "", fmt.Errorf("DASH rewrite session is unavailable")
	}
	if err := session.ctx.Err(); err != nil {
		return "", fmt.Errorf("DASH parsing deadline exceeded")
	}
	sanitized, markers, err := sanitizeDASHTemplate(value)
	if err != nil {
		return "", err
	}
	validationText, claimText, fixedValues, err := prepareDASHTemplateReferences(sanitized, markers, bindings)
	if err != nil {
		return "", err
	}
	validationReference, validationErr := url.Parse(validationText)
	claimReference, claimErr := url.Parse(claimText)
	if validationErr != nil || claimErr != nil || validationReference.User != nil || claimReference.User != nil || validationReference.Fragment != "" || claimReference.Fragment != "" || validationReference.RawFragment != "" || claimReference.RawFragment != "" || validationReference.Opaque != "" || claimReference.Opaque != "" {
		return "", fmt.Errorf("invalid DASH URL template")
	}
	resolvedValidation := base.ResolveReference(validationReference)
	resolvedClaim := base.ResolveReference(claimReference)
	configured := session.source == dynamicDiscoverySourceDASH && session.issuer.configuredAuthorities[redirectHostKey(resolvedValidation)]
	var validationTarget *url.URL
	var claimURL *url.URL
	if configured {
		validationTarget, validationErr = normalizeTrustedCapabilityURL(resolvedValidation.String())
		claimURL, claimErr = normalizeTrustedCapabilityURL(resolvedClaim.String())
	} else {
		validationTarget, validationErr = normalizeDynamicURL(resolvedValidation.String())
		claimURL, claimErr = normalizeDynamicURL(resolvedClaim.String())
	}
	if validationErr != nil || claimErr != nil {
		return "", fmt.Errorf("invalid DASH URL template")
	}
	claimTarget, expressions, err := restoreDASHTemplateClaimMarkers(claimURL.String(), markers)
	if err != nil {
		return "", err
	}
	if !configured && !session.rewriteRelative && sameRedirectAuthority(session.base, validationTarget) {
		localTemplate, err := restoreDASHLocalTemplateMarkers(validationTarget.RequestURI(), markers)
		return localTemplate, err
	}
	session.urlCount++
	if session.urlCount > session.issuer.policy.limits.MaxURLsPerResponse {
		return "", fmt.Errorf("discovered URL count exceeds its limit")
	}
	seenKey := "dash-template\x00" + strconv.FormatBool(configured) + "\x00" + claimTarget + "\x00" + strings.Join(expressions, "\x1f") + "\x00" + strings.Join(fixedValues, "\x1f")
	if route, exists := session.seen[seenKey]; exists {
		return route, nil
	}
	var route string
	var acquired bool
	var discoveryErr *dynamicProxyError
	if configured {
		route, acquired, discoveryErr = session.issuer.mintTrustedValidatedTracked(validationTarget, claimTarget, expressions, fixedValues, session.source, dynamicCapabilityKindResource, 0)
	} else {
		route, acquired, discoveryErr = session.issuer.mintValidatedDASHTemplateTracked(session.ctx, base, validationTarget, session.source, claimTarget, expressions, fixedValues)
	}
	if discoveryErr != nil {
		return "", discoveryErr
	}
	baseRoute := route
	route += dashTemplatePublicSuffix(expressions)
	if session.seen == nil {
		session.seen = make(map[string]string)
	}
	session.seen[seenKey] = route
	if acquired {
		token := strings.TrimPrefix(baseRoute, dynamicRoutePrefix)
		session.minted = append(session.minted, token)
	}
	return route, nil
}

type dashXMLContent struct {
	node *dashXMLNode
	text []byte
}

type dashXMLNode struct {
	start   xml.StartElement
	content []dashXMLContent
}

func parseDASHXML(ctx context.Context, payload []byte) (*dashXMLNode, error) {
	if !utf8.Valid(payload) || len(payload) == 0 {
		return nil, fmt.Errorf("invalid DASH XML encoding")
	}
	decoder := xml.NewDecoder(bytes.NewReader(payload))
	decoder.Strict = true
	if ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("DASH parsing deadline exceeded")
	}
	stack := make([]*dashXMLNode, 0, 16)
	var root *dashXMLNode
	nodeCount := 0
	tokenCount := 0
	attributeCount := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid DASH XML")
		}
		tokenCount++
		if tokenCount > globalDynamicMaxXMLTokens {
			return nil, fmt.Errorf("DASH XML token count exceeds its limit")
		}
		switch value := token.(type) {
		case xml.StartElement:
			nodeCount++
			if nodeCount&255 == 0 {
				if err := ctx.Err(); err != nil {
					return nil, fmt.Errorf("DASH parsing deadline exceeded")
				}
			}
			if nodeCount > globalDynamicMaxXMLNodes || len(stack)+1 > globalDynamicMaxParseDepth || int64(len(value.Name.Local)) > globalDynamicMaxStringBytes {
				return nil, fmt.Errorf("DASH XML exceeds its structural limits")
			}
			attributeCount += len(value.Attr)
			if len(value.Attr) > globalDynamicMaxXMLAttributesPerElement || attributeCount > globalDynamicMaxXMLAttributes {
				return nil, fmt.Errorf("DASH XML attribute count exceeds its limit")
			}
			for _, attribute := range value.Attr {
				if int64(len(attribute.Name.Space)) > globalDynamicMaxStringBytes || int64(len(attribute.Name.Local)) > globalDynamicMaxStringBytes || int64(len(attribute.Value)) > globalDynamicMaxStringBytes {
					return nil, fmt.Errorf("DASH XML attribute exceeds its limit")
				}
			}
			node := &dashXMLNode{start: value.Copy()}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("DASH XML has multiple roots")
				}
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.content = append(parent.content, dashXMLContent{node: node})
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("invalid DASH XML nesting")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			copyText := append([]byte(nil), value...)
			if int64(len(copyText)) > globalDynamicMaxStringBytes {
				return nil, fmt.Errorf("DASH XML text exceeds its limit")
			}
			if len(stack) == 0 {
				if len(bytes.TrimSpace(copyText)) != 0 {
					return nil, fmt.Errorf("DASH XML contains text outside its root")
				}
			} else {
				node := stack[len(stack)-1]
				node.content = append(node.content, dashXMLContent{text: copyText})
			}
		case xml.Comment:
			// Comments are not semantically relevant to URL resolution.
		case xml.ProcInst:
			if len(stack) != 0 || !strings.EqualFold(value.Target, "xml") {
				return nil, fmt.Errorf("unsupported DASH processing instruction")
			}
		case xml.Directive:
			return nil, fmt.Errorf("DASH XML directives are not supported")
		}
	}
	if root == nil || len(stack) != 0 || root.start.Name.Local != "MPD" || root.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
		return nil, fmt.Errorf("DASH XML root or namespace is invalid")
	}
	return root, nil
}

func encodeDASHXMLNode(ctx context.Context, encoder *xml.Encoder, node *dashXMLNode, extremeCompatibility bool) error {
	if node == nil {
		return fmt.Errorf("DASH XML node is unavailable")
	}
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("DASH encoding deadline exceeded")
	}
	if extremeCompatibility {
		attributes := node.start.Attr[:0]
		for _, attribute := range node.start.Attr {
			if !dashExtremeCompatibilityNamespaceDeclaration(attribute) || attribute.Name.Space == "" && attribute.Name.Local == "xmlns" && attribute.Value == "" {
				attributes = append(attributes, attribute)
			}
		}
		node.start.Attr = attributes
	}
	if err := encoder.EncodeToken(node.start); err != nil {
		return err
	}
	for _, child := range node.content {
		if child.node != nil {
			if err := encodeDASHXMLNode(ctx, encoder, child.node, extremeCompatibility); err != nil {
				return err
			}
		} else if len(child.text) > 0 {
			if err := encoder.EncodeToken(xml.CharData(child.text)); err != nil {
				return err
			}
		}
	}
	return encoder.EncodeToken(node.start.End())
}

func cloneDASHXMLNode(node *dashXMLNode) *dashXMLNode {
	if node == nil {
		return nil
	}
	clone := &dashXMLNode{start: node.start.Copy(), content: make([]dashXMLContent, len(node.content))}
	for index, child := range node.content {
		if child.node != nil {
			clone.content[index].node = cloneDASHXMLNode(child.node)
		} else {
			clone.content[index].text = append([]byte(nil), child.text...)
		}
	}
	return clone
}

func dashNodeText(node *dashXMLNode) (string, error) {
	if node == nil {
		return "", fmt.Errorf("DASH text node is unavailable")
	}
	var output strings.Builder
	for _, child := range node.content {
		if child.node != nil {
			return "", fmt.Errorf("DASH URL element contains nested XML")
		}
		output.Write(child.text)
	}
	value := strings.TrimSpace(output.String())
	if value == "" || int64(len(value)) > globalDynamicMaxStringBytes {
		return "", fmt.Errorf("DASH URL element is empty or too large")
	}
	return value, nil
}

func setDASHNodeText(node *dashXMLNode, value string) {
	node.content = []dashXMLContent{{text: []byte(value)}}
}

func dashExtremeCompatibilityEnabled(session *dynamicRewriteSession) bool {
	return session != nil && session.issuer != nil && session.issuer.policy.profile == dynamicProfileExtreme
}

func dashAttributeIndex(node *dashXMLNode, local string, extremeCompatibility bool) (int, error) {
	index := -1
	for candidate := range node.start.Attr {
		if node.start.Attr[candidate].Name.Local != local {
			continue
		}
		if node.start.Attr[candidate].Name.Space != "" {
			if extremeCompatibility {
				continue
			}
			return -1, fmt.Errorf("DASH standard attribute uses a foreign namespace")
		}
		if index >= 0 {
			return -1, fmt.Errorf("duplicate DASH attribute")
		}
		index = candidate
	}
	return index, nil
}

func resolveDASHReference(base *url.URL, value string) (*url.URL, error) {
	if base == nil || value == "" || value != strings.TrimSpace(value) || containsDynamicUnsafeRune(value) || strings.Contains(value, `\`) {
		return nil, fmt.Errorf("invalid DASH URL")
	}
	reference, err := url.Parse(value)
	if err != nil || reference.User != nil || reference.Fragment != "" || reference.RawFragment != "" {
		return nil, fmt.Errorf("invalid DASH URL")
	}
	resolved := base.ResolveReference(reference)
	resolved.Scheme = strings.ToLower(resolved.Scheme)
	if resolved.Scheme != "http" && resolved.Scheme != "https" || resolved.Host == "" || resolved.User != nil {
		return nil, fmt.Errorf("unsupported DASH URL")
	}
	return resolved, nil
}

func rewriteDASHReference(value string, base *url.URL, session *dynamicRewriteSession, kind string) (string, *url.URL, error) {
	resolved, err := resolveDASHReference(base, value)
	if err != nil {
		return "", nil, err
	}
	rewritten, err := session.rewriteAgainstKind(value, base, kind)
	return rewritten, resolved, err
}

type dashSegmentAddressing struct {
	kind string
	node *dashXMLNode
}

func isDASHSegmentAddressing(name string) bool {
	return name == "SegmentTemplate" || name == "SegmentList" || name == "SegmentBase"
}

func dashSegmentAddressingChildRank(content dashXMLContent) int {
	if content.node == nil {
		return -1
	}
	if content.node.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
		return 5
	}
	switch content.node.start.Name.Local {
	case "Initialization":
		return 0
	case "RepresentationIndex":
		return 1
	case "SegmentTimeline":
		return 2
	case "BitstreamSwitching":
		return 3
	case "SegmentURL":
		return 4
	default:
		return 5
	}
}

func mergeDASHSegmentAddressing(inherited, local *dashSegmentAddressing) *dashSegmentAddressing {
	if local == nil {
		if inherited == nil {
			return nil
		}
		return &dashSegmentAddressing{kind: inherited.kind, node: cloneDASHXMLNode(inherited.node)}
	}
	if inherited == nil || inherited.kind != local.kind {
		return &dashSegmentAddressing{kind: local.kind, node: cloneDASHXMLNode(local.node)}
	}
	merged := cloneDASHXMLNode(inherited.node)
	for _, attribute := range local.node.start.Attr {
		replaced := false
		for index := range merged.start.Attr {
			if merged.start.Attr[index].Name == attribute.Name {
				merged.start.Attr[index] = attribute
				replaced = true
				break
			}
		}
		if !replaced {
			merged.start.Attr = append(merged.start.Attr, attribute)
		}
	}
	localElementNames := make(map[xml.Name]bool)
	for _, child := range local.node.content {
		if child.node != nil {
			localElementNames[child.node.start.Name] = true
		}
	}
	if len(localElementNames) != 0 {
		filtered := merged.content[:0]
		for _, child := range merged.content {
			if child.node != nil && localElementNames[child.node.start.Name] {
				continue
			}
			filtered = append(filtered, child)
		}
		merged.content = filtered
		for _, child := range local.node.content {
			if child.node != nil {
				merged.content = append(merged.content, dashXMLContent{node: cloneDASHXMLNode(child.node)})
			}
		}
	}
	sort.SliceStable(merged.content, func(left, right int) bool {
		return dashSegmentAddressingChildRank(merged.content[left]) < dashSegmentAddressingChildRank(merged.content[right])
	})
	return &dashSegmentAddressing{kind: local.kind, node: merged}
}

func rewriteDASHURLAttribute(node *dashXMLNode, name string, base *url.URL, template bool, session *dynamicRewriteSession, bindings *dashTemplateBindings) error {
	index, err := dashAttributeIndex(node, name, dashExtremeCompatibilityEnabled(session))
	if err != nil || index < 0 {
		return err
	}
	value := node.start.Attr[index].Value
	if template {
		if bindings == nil {
			return fmt.Errorf("DASH template bindings are unavailable")
		}
		rewritten, err := rewriteDASHTemplate(value, base, session, *bindings)
		if err != nil {
			return err
		}
		node.start.Attr[index].Value = rewritten
		return nil
	}
	rewritten, _, err := rewriteDASHReference(value, base, session, dynamicCapabilityKindResource)
	if err != nil {
		return err
	}
	node.start.Attr[index].Value = rewritten
	return nil
}

func validateDASHLeafElement(node *dashXMLNode, ctx context.Context, extremeCompatibility bool) error {
	if err := validateDASHNodeNamespace(node, extremeCompatibility); err != nil {
		return err
	}
	for _, child := range node.content {
		if child.node != nil {
			if !extremeCompatibility || child.node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011" {
				return fmt.Errorf("DASH segment addressing element has unsupported content")
			}
			if err := validateDASHExtremeCompatibilityInertSubtree(ctx, child.node); err != nil {
				return err
			}
			continue
		}
		if strings.TrimSpace(string(child.text)) != "" {
			return fmt.Errorf("DASH segment addressing element has unsupported content")
		}
	}
	return nil
}

func validateDASHSegmentTimeline(node *dashXMLNode, ctx context.Context, extremeCompatibility bool) error {
	if err := validateDASHNodeNamespace(node, extremeCompatibility); err != nil {
		return err
	}
	for _, child := range node.content {
		if child.node == nil {
			if strings.TrimSpace(string(child.text)) != "" {
				return fmt.Errorf("DASH SegmentTimeline has unsupported text")
			}
			continue
		}
		if child.node.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
			if !extremeCompatibility {
				return fmt.Errorf("DASH SegmentTimeline has an unsupported child")
			}
			if err := validateDASHExtremeCompatibilityInertSubtree(ctx, child.node); err != nil {
				return err
			}
			continue
		}
		if child.node.start.Name.Local != "S" {
			return fmt.Errorf("DASH SegmentTimeline has an unsupported child")
		}
		if err := validateDASHLeafElement(child.node, ctx, extremeCompatibility); err != nil {
			return err
		}
	}
	return nil
}

func rewriteDASHSegmentAddressing(addressing *dashSegmentAddressing, base *url.URL, session *dynamicRewriteSession, bindings dashTemplateBindings) error {
	if addressing == nil || addressing.node == nil || !isDASHSegmentAddressing(addressing.kind) || addressing.node.start.Name.Local != addressing.kind {
		return fmt.Errorf("DASH segment addressing is unavailable")
	}
	extremeCompatibility := dashExtremeCompatibilityEnabled(session)
	if err := validateDASHNodeNamespace(addressing.node, extremeCompatibility); err != nil {
		return err
	}
	if addressing.kind == "SegmentTemplate" {
		for _, attribute := range []string{"media", "initialization", "index", "bitstreamSwitching"} {
			if err := rewriteDASHURLAttribute(addressing.node, attribute, base, true, session, &bindings); err != nil {
				return err
			}
		}
	}
	for _, content := range addressing.node.content {
		if content.node == nil {
			if strings.TrimSpace(string(content.text)) != "" {
				return fmt.Errorf("DASH segment addressing has unsupported text")
			}
			continue
		}
		child := content.node
		if err := validateDASHNodeNamespace(child, extremeCompatibility); err != nil {
			return err
		}
		if child.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
			if err := validateDASHExtremeCompatibilityInertSubtree(session.ctx, child); err != nil {
				return err
			}
			continue
		}
		switch child.start.Name.Local {
		case "SegmentURL":
			if addressing.kind != "SegmentList" {
				return fmt.Errorf("DASH SegmentURL is outside SegmentList")
			}
			for _, attribute := range []string{"media", "index"} {
				if err := rewriteDASHURLAttribute(child, attribute, base, false, session, nil); err != nil {
					return err
				}
			}
			if err := validateDASHLeafElement(child, session.ctx, extremeCompatibility); err != nil {
				return err
			}
		case "Initialization", "RepresentationIndex", "BitstreamSwitching":
			if addressing.kind == "SegmentBase" && child.start.Name.Local == "BitstreamSwitching" {
				return fmt.Errorf("DASH SegmentBase has an unsupported child")
			}
			if err := rewriteDASHURLAttribute(child, "sourceURL", base, false, session, nil); err != nil {
				return err
			}
			if err := validateDASHLeafElement(child, session.ctx, extremeCompatibility); err != nil {
				return err
			}
		case "SegmentTimeline":
			if addressing.kind == "SegmentBase" {
				return fmt.Errorf("DASH SegmentBase has an unsupported timeline")
			}
			if err := validateDASHSegmentTimeline(child, session.ctx, extremeCompatibility); err != nil {
				return err
			}
		default:
			return fmt.Errorf("DASH segment addressing has an unsupported child")
		}
	}
	return nil
}

func validateDASHNodeNamespace(node *dashXMLNode, extremeCompatibility bool) error {
	if !extremeCompatibility {
		if node == nil || node.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
			return fmt.Errorf("DASH foreign-namespace elements are unsupported")
		}
		for _, attribute := range node.start.Attr {
			if attribute.Name.Space == "http://www.w3.org/1999/xlink" && attribute.Name.Local == "href" {
				return fmt.Errorf("DASH xlink fetches are unsupported")
			}
			if attribute.Name.Space != "" && !(attribute.Name.Space == "http://www.w3.org/XML/1998/namespace" && attribute.Name.Local == "lang") {
				return fmt.Errorf("DASH foreign-namespace attributes are unsupported")
			}
		}
		return nil
	}
	if node == nil {
		return fmt.Errorf("DASH foreign-namespace elements are unsupported")
	}
	if node.start.Name.Space == "http://www.w3.org/1999/xlink" {
		return fmt.Errorf("DASH xlink fetches are unsupported")
	}
	for _, attribute := range node.start.Attr {
		if err := validateDASHExtremeCompatibilityAttribute(node.start.Name.Space, attribute); err != nil {
			return err
		}
	}
	if node.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
		if dashExtremeCompatibilityActiveNamespace(node.start.Name.Space) || dashExtremeCompatibilityNetworkName(node.start.Name.Local) {
			return fmt.Errorf("DASH foreign extension has active network semantics")
		}
		for _, content := range node.content {
			if content.node == nil && dashExtremeCompatibilityNetworkReference(string(content.text)) {
				return fmt.Errorf("DASH foreign extension contains an external reference")
			}
		}
	}
	return nil
}

func dashExtremeCompatibilityNamespaceDeclaration(attribute xml.Attr) bool {
	return attribute.Name.Space == "xmlns" || attribute.Name.Space == "" && attribute.Name.Local == "xmlns"
}

func dashExtremeCompatibilityNormalizedName(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			return unicode.ToLower(character)
		}
		return -1
	}, value)
}

func dashExtremeCompatibilityNetworkName(value string) bool {
	switch dashExtremeCompatibilityNormalizedName(value) {
	case "baseurl", "segmentbase", "segmentlist", "segmenturl", "segmenttemplate",
		"initialization", "representationindex", "bitstreamswitching", "location", "utctiming",
		"patchlocation", "contentsteering", "importedmpd", "metrics", "reporting",
		"href", "src", "url", "uri", "sourceurl", "sourceuri", "serverurl", "serveruri",
		"licenseurl", "licenseuri", "laurl", "certurl", "certificateurl", "callbackurl", "reloaduri",
		"targeturl", "asseturl", "asseturi", "manifesturl", "manifesturi", "resourceurl", "resourceuri",
		"fonturl", "fonturi", "endpoint", "redirect", "querytemplate", "includeinrequests",
		"urlqueryinfo", "exturlqueryinfo", "exthttpheaderinfo", "fontdownload":
		return true
	default:
		return false
	}
}

func dashExtremeCompatibilityActiveNamespace(namespace string) bool {
	switch namespace {
	case "urn:dvb:dash:fontdownload:2014",
		"urn:mpeg:dash:schema:urlparam:2014", "urn:mpeg:dash:schema:urlparam:2016",
		"urn:mpeg:dash:urlparam:2014", "urn:mpeg:dash:urlparam:2016":
		return true
	default:
		return false
	}
}

func dashExtremeCompatibilityNetworkReference(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	for _, marker := range []string{"http://", "https://", "ws://", "wss://", "ftp://", "ftps://", "file://", "smb://", "rtsp://"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.HasPrefix(lower, "/") || strings.HasPrefix(lower, "./") || strings.HasPrefix(lower, "../") || strings.HasPrefix(lower, "?")
}

func validateDASHExtremeCompatibilityAttribute(ownerNamespace string, attribute xml.Attr) error {
	if dashExtremeCompatibilityNamespaceDeclaration(attribute) {
		return nil
	}
	if attribute.Name.Space == "http://www.w3.org/1999/xlink" {
		return fmt.Errorf("DASH xlink fetches are unsupported")
	}
	if attribute.Name.Space == "http://www.w3.org/XML/1998/namespace" && attribute.Name.Local == "base" {
		return fmt.Errorf("DASH xml:base references are unsupported")
	}
	if ownerNamespace == "urn:mpeg:dash:schema:mpd:2011" && attribute.Name.Space == "" {
		return nil
	}
	name := dashExtremeCompatibilityNormalizedName(attribute.Name.Local)
	if dashExtremeCompatibilityActiveNamespace(attribute.Name.Space) || dashExtremeCompatibilityNetworkName(name) || name != "schemeiduri" && dashExtremeCompatibilityNetworkReference(attribute.Value) {
		return fmt.Errorf("DASH foreign attribute has active network semantics")
	}
	return nil
}

func validateDASHExtremeCompatibilityEncodedDRMMetadata(value string) error {
	compact := strings.Map(func(character rune) rune {
		if unicode.IsSpace(character) {
			return -1
		}
		return character
	}, value)
	if compact == "" {
		return fmt.Errorf("DASH DRM metadata is empty")
	}
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(compact)
	}
	if err != nil || len(decoded) == 0 {
		return fmt.Errorf("DASH DRM metadata is malformed")
	}
	normalized := make([]byte, 0, len(decoded))
	for _, value := range decoded {
		if value == 0 {
			continue
		}
		if value >= 'A' && value <= 'Z' {
			value += 'a' - 'A'
		}
		normalized = append(normalized, value)
	}
	markers := [...][]byte{
		[]byte("http://"), []byte("https://"), []byte("la_url"), []byte("lui_url"),
		[]byte("laurl"), []byte("certurl"), []byte("licenseurl"), []byte("license_url"),
		[]byte("serverurl"), []byte("server_url"),
	}
	for _, marker := range markers {
		if bytes.Contains(normalized, marker) {
			return fmt.Errorf("DASH DRM metadata contains an external license or certificate reference")
		}
	}
	return nil
}

func validateDASHExtremeCompatibilityDRMNode(ctx context.Context, node *dashXMLNode) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("DASH parsing deadline exceeded")
	}
	if err := validateDASHNodeNamespace(node, true); err != nil {
		return err
	}
	if dashExtremeCompatibilityNetworkName(node.start.Name.Local) {
		return fmt.Errorf("DASH DRM metadata contains active network semantics")
	}
	for _, attribute := range node.start.Attr {
		if dashExtremeCompatibilityNamespaceDeclaration(attribute) {
			continue
		}
		name := dashExtremeCompatibilityNormalizedName(attribute.Name.Local)
		if dashExtremeCompatibilityNetworkName(name) || name != "schemeiduri" && dashExtremeCompatibilityNetworkReference(attribute.Value) {
			return fmt.Errorf("DASH DRM metadata contains an external license or certificate reference")
		}
	}
	name := dashExtremeCompatibilityNormalizedName(node.start.Name.Local)
	if name == "pssh" || name == "pro" || name == "protectionheader" {
		value, err := dashNodeText(node)
		if err != nil {
			return fmt.Errorf("DASH DRM metadata is malformed")
		}
		return validateDASHExtremeCompatibilityEncodedDRMMetadata(value)
	}
	for _, content := range node.content {
		if content.node != nil {
			if err := validateDASHExtremeCompatibilityDRMNode(ctx, content.node); err != nil {
				return err
			}
			continue
		}
		if dashExtremeCompatibilityNetworkReference(string(content.text)) {
			return fmt.Errorf("DASH DRM metadata contains an external license or certificate reference")
		}
	}
	return nil
}

func validateDASHExtremeCompatibilityContentProtection(ctx context.Context, node *dashXMLNode) error {
	if node == nil || node.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" || node.start.Name.Local != "ContentProtection" {
		return fmt.Errorf("DASH ContentProtection metadata is unavailable")
	}
	return validateDASHExtremeCompatibilityDRMNode(ctx, node)
}

func validateDASHExtremeCompatibilityInertSubtree(ctx context.Context, node *dashXMLNode) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("DASH parsing deadline exceeded")
	}
	if err := validateDASHNodeNamespace(node, true); err != nil {
		return err
	}
	if node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011" && node.start.Name.Local == "ContentProtection" {
		return validateDASHExtremeCompatibilityContentProtection(ctx, node)
	}
	if node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011" && dashExtremeCompatibilityNetworkName(node.start.Name.Local) {
		return fmt.Errorf("DASH inert extension contains a fetch-capable element")
	}
	for _, attribute := range node.start.Attr {
		if dashExtremeCompatibilityNamespaceDeclaration(attribute) {
			continue
		}
		name := dashExtremeCompatibilityNormalizedName(attribute.Name.Local)
		if dashExtremeCompatibilityNetworkName(name) || name != "schemeiduri" && dashExtremeCompatibilityNetworkReference(attribute.Value) {
			return fmt.Errorf("DASH inert extension contains an external reference")
		}
	}
	for _, content := range node.content {
		if content.node != nil {
			if err := validateDASHExtremeCompatibilityInertSubtree(ctx, content.node); err != nil {
				return err
			}
			continue
		}
		if dashExtremeCompatibilityNetworkReference(string(content.text)) {
			return fmt.Errorf("DASH inert extension contains an external reference")
		}
	}
	return nil
}

func dashRepresentationBindings(node *dashXMLNode, extremeCompatibility bool) (dashTemplateBindings, error) {
	var bindings dashTemplateBindings
	idIndex, err := dashAttributeIndex(node, "id", extremeCompatibility)
	if err != nil {
		return bindings, err
	}
	if idIndex >= 0 {
		bindings.representationID = node.start.Attr[idIndex].Value
	}
	bandwidthIndex, err := dashAttributeIndex(node, "bandwidth", extremeCompatibility)
	if err != nil {
		return bindings, err
	}
	if bandwidthIndex >= 0 {
		bindings.bandwidth = node.start.Attr[bandwidthIndex].Value
	}
	return bindings, nil
}

func rewriteDASHUTCTiming(node *dashXMLNode, base *url.URL, session *dynamicRewriteSession) error {
	schemeIndex, err := dashAttributeIndex(node, "schemeIdUri", dashExtremeCompatibilityEnabled(session))
	if err != nil || schemeIndex < 0 {
		return fmt.Errorf("DASH UTCTiming requires one supported scheme")
	}
	valueIndex, err := dashAttributeIndex(node, "value", dashExtremeCompatibilityEnabled(session))
	if err != nil || valueIndex < 0 {
		return fmt.Errorf("DASH UTCTiming requires a value")
	}
	scheme := node.start.Attr[schemeIndex].Value
	switch scheme {
	case "urn:mpeg:dash:utc:direct:2012", "urn:mpeg:dash:utc:direct:2014":
		if _, err := time.Parse(time.RFC3339, node.start.Attr[valueIndex].Value); err != nil {
			return fmt.Errorf("invalid DASH direct UTC value")
		}
		return nil
	case "urn:mpeg:dash:utc:http-head:2012", "urn:mpeg:dash:utc:http-head:2014",
		"urn:mpeg:dash:utc:http-xsdate:2012", "urn:mpeg:dash:utc:http-xsdate:2014",
		"urn:mpeg:dash:utc:http-iso:2012", "urn:mpeg:dash:utc:http-iso:2014",
		"urn:mpeg:dash:utc:http-ntp:2014":
		return rewriteDASHURLAttribute(node, "value", base, false, session, nil)
	default:
		return fmt.Errorf("unsupported DASH UTCTiming scheme")
	}
}

func rewriteDASHEventDescriptor(node *dashXMLNode, base *url.URL, session *dynamicRewriteSession) error {
	extremeCompatibility := dashExtremeCompatibilityEnabled(session)
	schemeIndex, err := dashAttributeIndex(node, "schemeIdUri", extremeCompatibility)
	if err != nil || schemeIndex < 0 {
		return err
	}
	scheme := node.start.Attr[schemeIndex].Value
	valueIndex, err := dashAttributeIndex(node, "value", extremeCompatibility)
	if err != nil {
		return err
	}
	if scheme == "urn:mpeg:dash:event:2012" {
		if valueIndex < 0 || node.start.Attr[valueIndex].Value != "1" {
			return fmt.Errorf("DASH MPD patch or replacement events are unsupported")
		}
		return nil
	}
	if scheme != "urn:mpeg:dash:event:callback:2015" {
		return nil
	}
	if node.start.Name.Local == "InbandEventStream" {
		return fmt.Errorf("DASH in-band callback events are unsupported")
	}
	for _, content := range node.content {
		if content.node == nil {
			if strings.TrimSpace(string(content.text)) != "" {
				return fmt.Errorf("DASH callback EventStream has unsupported payload")
			}
			continue
		}
		event := content.node
		if event.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
			if !extremeCompatibility {
				return fmt.Errorf("DASH callback EventStream has an unsupported child")
			}
			if err := validateDASHExtremeCompatibilityInertSubtree(session.ctx, event); err != nil {
				return err
			}
			continue
		}
		if event.start.Name.Local != "Event" {
			return fmt.Errorf("DASH callback EventStream has an unsupported child")
		}
		if err := validateDASHLeafElement(event, session.ctx, extremeCompatibility); err != nil {
			return err
		}
		messageIndex, err := dashAttributeIndex(event, "messageData", extremeCompatibility)
		if err != nil || messageIndex < 0 {
			return fmt.Errorf("DASH callback Event requires messageData")
		}
		if err := rewriteDASHURLAttribute(event, "messageData", base, false, session, nil); err != nil {
			return err
		}
	}
	return nil
}

func rewriteDASHNode(node *dashXMLNode, inheritedBase *url.URL, inheritedAddressing *dashSegmentAddressing, session *dynamicRewriteSession) (int, error) {
	if node == nil || inheritedBase == nil || session == nil {
		return 0, fmt.Errorf("DASH traversal state is unavailable")
	}
	if err := session.ctx.Err(); err != nil {
		return 0, fmt.Errorf("DASH parsing deadline exceeded")
	}
	extremeCompatibility := dashExtremeCompatibilityEnabled(session)
	if err := validateDASHNodeNamespace(node, extremeCompatibility); err != nil {
		return 0, err
	}
	standardNode := node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011"
	if !standardNode && node.start.Name.Local == "ContentProtection" {
		return 0, fmt.Errorf("DASH foreign ContentProtection elements are unsupported")
	}
	if standardNode {
		switch node.start.Name.Local {
		case "PatchLocation", "ContentSteering", "ImportedMPD", "Metrics", "Reporting":
			return 0, fmt.Errorf("unsupported DASH external document or reporting")
		case "ContentProtection":
			if !extremeCompatibility {
				return 0, fmt.Errorf("DASH DRM is unsupported")
			}
			if err := validateDASHExtremeCompatibilityContentProtection(session.ctx, node); err != nil {
				return 0, err
			}
			return 0, nil
		}
	}
	currentBase := inheritedBase
	baseIndexes := make([]int, 0, 1)
	addressingIndex := -1
	var localAddressing *dashSegmentAddressing
	for index, child := range node.content {
		if child.node == nil || child.node.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
			continue
		}
		switch child.node.start.Name.Local {
		case "BaseURL":
			if err := validateDASHNodeNamespace(child.node, extremeCompatibility); err != nil {
				return 0, err
			}
			baseIndexes = append(baseIndexes, index)
		case "SegmentTemplate", "SegmentList", "SegmentBase":
			if err := validateDASHNodeNamespace(child.node, extremeCompatibility); err != nil {
				return 0, err
			}
			if localAddressing != nil {
				return 0, fmt.Errorf("multiple DASH segment addressing elements at one level")
			}
			localAddressing = &dashSegmentAddressing{kind: child.node.start.Name.Local, node: child.node}
			addressingIndex = index
		}
	}
	if len(baseIndexes) > 1 {
		return 0, fmt.Errorf("multiple DASH BaseURL alternatives are unsupported")
	}
	if len(baseIndexes) == 1 {
		baseNode := node.content[baseIndexes[0]].node
		value, err := dashNodeText(baseNode)
		if err != nil {
			return 0, err
		}
		rewritten, resolved, err := rewriteDASHReference(value, inheritedBase, session, dynamicCapabilityKindResource)
		if err != nil {
			return 0, err
		}
		setDASHNodeText(baseNode, rewritten)
		currentBase = resolved
	}
	effectiveAddressing := mergeDASHSegmentAddressing(inheritedAddressing, localAddressing)
	if standardNode && node.start.Name.Local == "Representation" && effectiveAddressing != nil {
		bindings, err := dashRepresentationBindings(node, extremeCompatibility)
		if err != nil {
			return 0, err
		}
		if err := rewriteDASHSegmentAddressing(effectiveAddressing, currentBase, session, bindings); err != nil {
			return 0, err
		}
		if addressingIndex >= 0 {
			node.content[addressingIndex].node = effectiveAddressing.node
		} else {
			node.content = append(node.content, dashXMLContent{node: effectiveAddressing.node})
			addressingIndex = len(node.content) - 1
		}
	}
	if standardNode {
		switch node.start.Name.Local {
		case "UTCTiming":
			if err := rewriteDASHUTCTiming(node, currentBase, session); err != nil {
				return 0, err
			}
		case "EventStream", "InbandEventStream":
			if err := rewriteDASHEventDescriptor(node, currentBase, session); err != nil {
				return 0, err
			}
		case "Location":
			value, err := dashNodeText(node)
			if err != nil {
				return 0, err
			}
			reloadDepth := max(1, session.depth)
			rewritten, err := session.rewriteAgainstSourceKindDepth(value, session.base, dynamicDiscoverySourceDASH, dynamicCapabilityKindManifest, reloadDepth)
			if err != nil {
				return 0, err
			}
			setDASHNodeText(node, rewritten)
		}
	}
	representations := 0
	if standardNode && node.start.Name.Local == "Representation" {
		representations = 1
	}
	for _, child := range node.content {
		if child.node == nil || child.node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011" && (child.node.start.Name.Local == "BaseURL" || isDASHSegmentAddressing(child.node.start.Name.Local)) {
			continue
		}
		count, err := rewriteDASHNode(child.node, currentBase, effectiveAddressing, session)
		if err != nil {
			return 0, err
		}
		representations += count
	}
	if !(standardNode && node.start.Name.Local == "Representation") && localAddressing != nil {
		if representations == 0 {
			return 0, fmt.Errorf("DASH segment addressing has no Representation scope")
		}
		node.content = append(node.content[:addressingIndex], node.content[addressingIndex+1:]...)
	}
	return representations, nil
}

func dashXMLShape(node *dashXMLNode) (int64, int64) {
	if node == nil {
		return 0, 0
	}
	nodes := int64(1)
	bytesUsed := int64(32 + len(node.start.Name.Space) + len(node.start.Name.Local))
	for _, attribute := range node.start.Attr {
		bytesUsed += int64(24 + len(attribute.Name.Space) + len(attribute.Name.Local) + len(attribute.Value))
	}
	for _, child := range node.content {
		if child.node != nil {
			childNodes, childBytes := dashXMLShape(child.node)
			nodes += childNodes
			bytesUsed += childBytes
		} else {
			bytesUsed += int64(len(child.text))
		}
	}
	return nodes, bytesUsed
}

func estimateDASHCloneExpansion(node *dashXMLNode, inheritedNodes, inheritedBytes int64, cloneNodes, cloneBytes *int64, maxCloneBytes int64) error {
	if node == nil {
		return nil
	}
	effectiveNodes := inheritedNodes
	effectiveBytes := inheritedBytes
	for _, child := range node.content {
		if child.node != nil && child.node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011" && isDASHSegmentAddressing(child.node.start.Name.Local) {
			localNodes, localBytes := dashXMLShape(child.node)
			effectiveNodes += localNodes
			effectiveBytes += localBytes
		}
	}
	if node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011" && node.start.Name.Local == "Representation" && effectiveNodes > 0 {
		if effectiveNodes > globalDynamicMaxXMLNodes-*cloneNodes || effectiveBytes > maxCloneBytes-*cloneBytes {
			return fmt.Errorf("DASH inherited template expansion exceeds its budget")
		}
		*cloneNodes += effectiveNodes
		*cloneBytes += effectiveBytes
	}
	for _, child := range node.content {
		if child.node == nil || child.node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011" && isDASHSegmentAddressing(child.node.start.Name.Local) {
			continue
		}
		if err := estimateDASHCloneExpansion(child.node, effectiveNodes, effectiveBytes, cloneNodes, cloneBytes, maxCloneBytes); err != nil {
			return err
		}
	}
	return nil
}

func rewriteDASHResponse(payload []byte, session *dynamicRewriteSession) ([]byte, error) {
	if session == nil || session.issuer == nil || session.ctx == nil {
		return nil, fmt.Errorf("DASH rewrite session is unavailable")
	}
	root, err := parseDASHXML(session.ctx, payload)
	if err != nil {
		return nil, err
	}
	maxCloneBytes := session.structuredOutputLimit() - int64(len(payload))
	if maxCloneBytes < 0 {
		return nil, fmt.Errorf("DASH response exceeds its body budget")
	}
	var cloneNodes, cloneBytes int64
	if err := estimateDASHCloneExpansion(root, 0, 0, &cloneNodes, &cloneBytes, maxCloneBytes); err != nil {
		return nil, err
	}
	if _, err := rewriteDASHNode(root, session.base, nil, session); err != nil {
		return nil, err
	}
	output := dynamicBoundedBuffer{limit: session.structuredOutputLimit()}
	if _, err := output.Write([]byte(xml.Header)); err != nil {
		return nil, err
	}
	encoder := xml.NewEncoder(&output)
	if err := encodeDASHXMLNode(session.ctx, encoder, root, dashExtremeCompatibilityEnabled(session)); err != nil {
		return nil, err
	}
	if err := encoder.Flush(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type hlsAttributeSpan struct {
	name       string
	valueStart int
	valueEnd   int
	quoted     bool
}

func isHLSAttributeNameByte(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '-'
}

func parseHLSAttributeList(value string) ([]hlsAttributeSpan, error) {
	spans := make([]hlsAttributeSpan, 0, 8)
	seen := make(map[string]bool)
	for offset := 0; offset < len(value); {
		nameStart := offset
		for offset < len(value) && isHLSAttributeNameByte(value[offset]) {
			offset++
		}
		if nameStart == offset || offset >= len(value) || value[offset] != '=' {
			return nil, fmt.Errorf("invalid HLS attribute list")
		}
		name := value[nameStart:offset]
		if seen[name] {
			return nil, fmt.Errorf("duplicate HLS attribute")
		}
		seen[name] = true
		offset++
		span := hlsAttributeSpan{name: name}
		if offset < len(value) && value[offset] == '"' {
			span.quoted = true
			offset++
			span.valueStart = offset
			for offset < len(value) && value[offset] != '"' {
				if value[offset] < 0x20 || value[offset] == 0x7f {
					return nil, fmt.Errorf("invalid HLS quoted string")
				}
				offset++
			}
			if offset >= len(value) {
				return nil, fmt.Errorf("unterminated HLS quoted string")
			}
			span.valueEnd = offset
			offset++
		} else {
			span.valueStart = offset
			for offset < len(value) && value[offset] != ',' {
				if value[offset] <= 0x20 || value[offset] == 0x7f {
					return nil, fmt.Errorf("invalid HLS attribute value")
				}
				offset++
			}
			span.valueEnd = offset
			if span.valueStart == span.valueEnd {
				return nil, fmt.Errorf("empty HLS attribute value")
			}
		}
		if len(spans) >= globalDynamicMaxHLSAttributesPerTag {
			return nil, fmt.Errorf("HLS attribute count exceeds its limit")
		}
		spans = append(spans, span)
		if offset == len(value) {
			break
		}
		if value[offset] != ',' || offset+1 == len(value) {
			return nil, fmt.Errorf("invalid HLS attribute delimiter")
		}
		offset++
	}
	if len(spans) == 0 {
		return nil, fmt.Errorf("empty HLS attribute list")
	}
	return spans, nil
}
func hlsAttributeValue(value string, attributes []hlsAttributeSpan, name string) (string, bool) {
	for _, attribute := range attributes {
		if attribute.name == name {
			return value[attribute.valueStart:attribute.valueEnd], true
		}
	}
	return "", false
}

func validateHLSURIAttributes(tag, value string, attributes []hlsAttributeSpan) error {
	uri, hasURI := hlsAttributeValue(value, attributes, "URI")
	requireURI := func() error {
		if !hasURI || uri == "" {
			return fmt.Errorf("HLS tag requires a URI attribute")
		}
		return nil
	}
	requireIdentityAES128 := func(method string) error {
		keyFormat, hasKeyFormat := hlsAttributeValue(value, attributes, "KEYFORMAT")
		if !strings.EqualFold(method, "AES-128") || hasKeyFormat && keyFormat != "identity" {
			return fmt.Errorf("HLS DRM key formats are unsupported")
		}
		return nil
	}
	switch tag {
	case "#EXT-X-KEY":
		method, hasMethod := hlsAttributeValue(value, attributes, "METHOD")
		if !hasMethod {
			return fmt.Errorf("HLS key tag requires METHOD")
		}
		if strings.EqualFold(method, "NONE") {
			if hasURI {
				return fmt.Errorf("HLS METHOD=NONE must not include URI")
			}
			return nil
		}
		if err := requireIdentityAES128(method); err != nil {
			return err
		}
		return requireURI()
	case "#EXT-X-SESSION-KEY":
		method, hasMethod := hlsAttributeValue(value, attributes, "METHOD")
		if !hasMethod || strings.EqualFold(method, "NONE") {
			return fmt.Errorf("HLS session key requires an encryption METHOD")
		}
		if err := requireIdentityAES128(method); err != nil {
			return err
		}
		return requireURI()
	case "#EXT-X-MEDIA":
		mediaType, hasType := hlsAttributeValue(value, attributes, "TYPE")
		if !hasType {
			return fmt.Errorf("HLS media tag requires TYPE")
		}
		switch strings.ToUpper(mediaType) {
		case "SUBTITLES":
			return requireURI()
		case "CLOSED-CAPTIONS":
			if hasURI {
				return fmt.Errorf("HLS closed captions must not include URI")
			}
		}
		return nil
	case "#EXT-X-SESSION-DATA":
		_, hasDataID := hlsAttributeValue(value, attributes, "DATA-ID")
		_, hasValue := hlsAttributeValue(value, attributes, "VALUE")
		if !hasDataID || hasURI == hasValue {
			return fmt.Errorf("HLS session data requires DATA-ID and exactly one of URI or VALUE")
		}
		return nil
	case "#EXT-X-PRELOAD-HINT":
		hintType, hasType := hlsAttributeValue(value, attributes, "TYPE")
		if !hasType || strings.ToUpper(hintType) != "PART" && strings.ToUpper(hintType) != "MAP" {
			return fmt.Errorf("unsupported HLS preload hint type")
		}
		return requireURI()
	case "#EXT-X-RENDITION-REPORT":
		if err := requireURI(); err != nil {
			return err
		}
		reference, err := url.Parse(uri)
		if err != nil || reference.IsAbs() || reference.Host != "" {
			return fmt.Errorf("HLS rendition report URI must be relative")
		}
		return nil
	case "#EXT-X-DATERANGE":
		return nil
	default:
		return requireURI()
	}
}

func rewriteHLSURI(value string, session *dynamicRewriteSession) (string, error) {
	return rewriteHLSURIKind(value, session, dynamicCapabilityKindResource)
}

func rewriteHLSURIKind(value string, session *dynamicRewriteSession, kind string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || containsDynamicUnsafeRune(value) || strings.Contains(value, `\`) {
		return "", fmt.Errorf("invalid HLS URI")
	}
	if strings.Contains(value, "{$") {
		return "", fmt.Errorf("HLS variable substitution is unsupported")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Fragment != "" || parsed.RawFragment != "" {
		return "", fmt.Errorf("invalid HLS URI")
	}
	if parsed.Scheme != "" && !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return "", fmt.Errorf("unsupported HLS URI scheme")
	}
	return session.rewriteAgainstKind(value, session.base, kind)
}

func hlsAttributeResourceKind(tag, name string) string {
	switch tag {
	case "#EXT-X-MEDIA", "#EXT-X-I-FRAME-STREAM-INF", "#EXT-X-IMAGE-STREAM-INF", "#EXT-X-RENDITION-REPORT":
		return dynamicCapabilityKindManifest
	case "#EXT-X-DATERANGE":
		if name == "X-ASSET-URI" {
			return dynamicCapabilityKindManifest
		}
	}
	return dynamicCapabilityKindResource
}

func rewriteHLSAttributeLine(line string, names map[string]bool, session *dynamicRewriteSession) (string, error) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 || colon+1 >= len(line) {
		return "", fmt.Errorf("invalid HLS tag attribute list")
	}
	attributes, err := parseHLSAttributeList(line[colon+1:])
	if err != nil {
		return "", err
	}
	if err := validateHLSURIAttributes(line[:colon], line[colon+1:], attributes); err != nil {
		return "", err
	}
	type replacement struct {
		start int
		end   int
		value string
	}
	replacements := make([]replacement, 0, 2)
	for _, attribute := range attributes {
		if !names[attribute.name] {
			continue
		}
		if !attribute.quoted {
			return "", fmt.Errorf("HLS URI attribute must be quoted")
		}
		start := colon + 1 + attribute.valueStart
		end := colon + 1 + attribute.valueEnd
		rewritten, err := rewriteHLSURIKind(line[start:end], session, hlsAttributeResourceKind(line[:colon], attribute.name))
		if err != nil {
			return "", err
		}
		if rewritten != line[start:end] {
			replacements = append(replacements, replacement{start: start, end: end, value: rewritten})
		}
	}
	for index := len(replacements) - 1; index >= 0; index-- {
		replacement := replacements[index]
		line = line[:replacement.start] + replacement.value + line[replacement.end:]
	}
	return line, nil
}

const (
	maxExtremeHLSVariableCount      = globalDynamicMaxHLSAttributesPerTag
	maxExtremeHLSVariableNameBytes  = 128
	maxExtremeHLSVariableValueBytes = maxDynamicTargetURLBytes
	maxExtremeHLSVariableTableBytes = globalDynamicMaxStringBytes
)

type extremeHLSVariableTable struct {
	values     map[string]string
	bytesUsed  int
	countLimit int
	byteLimit  int
}

func newExtremeHLSVariableTable(session *dynamicRewriteSession) *extremeHLSVariableTable {
	countLimit := maxExtremeHLSVariableCount
	if session != nil && session.issuer != nil && session.issuer.policy.limits.MaxURLsPerResponse < countLimit {
		countLimit = session.issuer.policy.limits.MaxURLsPerResponse
	}
	byteLimit := maxExtremeHLSVariableTableBytes
	if session != nil {
		if outputLimit := session.structuredOutputLimit(); outputLimit > 0 && outputLimit < int64(byteLimit) {
			byteLimit = int(outputLimit)
		}
	}
	return &extremeHLSVariableTable{
		values:     make(map[string]string),
		countLimit: countLimit,
		byteLimit:  byteLimit,
	}
}

func isExtremeHLSVariableName(value string) bool {
	if value == "" || len(value) > maxExtremeHLSVariableNameBytes {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func (table *extremeHLSVariableTable) defineFromExtremeHLSLine(line string) error {
	if table == nil {
		return fmt.Errorf("HLS variable table is unavailable")
	}
	colon := strings.IndexByte(line, ':')
	if colon < 0 || colon+1 >= len(line) {
		return fmt.Errorf("invalid HLS variable definition")
	}
	attributes, err := parseHLSAttributeList(line[colon+1:])
	if err != nil {
		return err
	}
	var name, value, imported string
	var hasName, hasValue, hasImport bool
	var nameQuoted, valueQuoted, importQuoted bool
	for _, attribute := range attributes {
		attributeValue := line[colon+1+attribute.valueStart : colon+1+attribute.valueEnd]
		switch attribute.name {
		case "NAME":
			name, hasName, nameQuoted = attributeValue, true, attribute.quoted
		case "VALUE":
			value, hasValue, valueQuoted = attributeValue, true, attribute.quoted
		case "IMPORT":
			imported, hasImport, importQuoted = attributeValue, true, attribute.quoted
		default:
			return fmt.Errorf("unsupported HLS variable definition attribute")
		}
	}
	if hasImport {
		if hasName || hasValue || len(attributes) != 1 || !importQuoted || !isExtremeHLSVariableName(imported) {
			return fmt.Errorf("invalid HLS variable import")
		}
		if _, exists := table.values[imported]; !exists {
			return fmt.Errorf("HLS variable import is not locally defined")
		}
		return nil
	}
	if !hasName || !hasValue || len(attributes) != 2 || !nameQuoted || !valueQuoted || !isExtremeHLSVariableName(name) {
		return fmt.Errorf("invalid HLS variable definition")
	}
	if len(value) > maxExtremeHLSVariableValueBytes || strings.Contains(value, "{$") || value != "" && (containsDynamicUnsafeRune(value) || strings.Contains(value, `\`)) {
		return fmt.Errorf("invalid HLS variable value")
	}
	if _, exists := table.values[name]; exists {
		return fmt.Errorf("duplicate HLS variable definition")
	}
	if len(table.values) >= table.countLimit {
		return fmt.Errorf("HLS variable count exceeds its limit")
	}
	entryBytes := len(name) + len(value)
	if entryBytes > table.byteLimit-table.bytesUsed {
		return fmt.Errorf("HLS variable table exceeds its budget")
	}
	table.values[name] = value
	table.bytesUsed += entryBytes
	return nil
}

func (table *extremeHLSVariableTable) substituteExtremeHLSURI(value string) (string, error) {
	if !strings.Contains(value, "{$") {
		return value, nil
	}
	if table == nil {
		return "", fmt.Errorf("HLS variable substitution is unavailable")
	}
	var output strings.Builder
	output.Grow(min(len(value), maxExtremeHLSVariableValueBytes))
	for cursor := 0; ; {
		markerOffset := strings.Index(value[cursor:], "{$")
		if markerOffset < 0 {
			if len(value)-cursor > maxDynamicTargetURLBytes-output.Len() {
				return "", fmt.Errorf("HLS substituted URI exceeds its limit")
			}
			output.WriteString(value[cursor:])
			break
		}
		markerStart := cursor + markerOffset
		markerEndOffset := strings.IndexByte(value[markerStart+2:], '}')
		if markerEndOffset < 0 {
			return "", fmt.Errorf("invalid HLS variable reference")
		}
		markerEnd := markerStart + 2 + markerEndOffset
		name := value[markerStart+2 : markerEnd]
		if !isExtremeHLSVariableName(name) {
			return "", fmt.Errorf("invalid HLS variable reference")
		}
		replacement, exists := table.values[name]
		if !exists {
			return "", fmt.Errorf("unresolved HLS variable")
		}
		literalBytes := markerStart - cursor
		if literalBytes > maxDynamicTargetURLBytes-output.Len() || len(replacement) > maxDynamicTargetURLBytes-output.Len()-literalBytes {
			return "", fmt.Errorf("HLS substituted URI exceeds its limit")
		}
		output.WriteString(value[cursor:markerStart])
		output.WriteString(replacement)
		cursor = markerEnd + 1
	}
	resolved := output.String()
	if resolved == "" || len(resolved) > maxDynamicTargetURLBytes || strings.Contains(resolved, "{$") {
		return "", fmt.Errorf("invalid substituted HLS URI")
	}
	return resolved, nil
}

type extremeHLSReplacement struct {
	start int
	end   int
	value string
}

func applyExtremeHLSReplacements(line string, replacements []extremeHLSReplacement) string {
	for index := len(replacements) - 1; index >= 0; index-- {
		replacement := replacements[index]
		line = line[:replacement.start] + replacement.value + line[replacement.end:]
	}
	return line
}

func isExtremeHLSURIAttributeName(name string) bool {
	return name == "URI" || strings.HasSuffix(name, "-URI")
}

func isExtremeHLSPotentialURLAttributeName(name string) bool {
	return name == "URL" || strings.HasSuffix(name, "-URL")
}

func isExtremeHLSSensitiveURIReference(tag, name string) bool {
	for _, marker := range []string{"KEY", "DRM", "LICENSE", "WIDEVINE", "PLAYREADY", "FAIRPLAY", "CENC", "SKD", "CKC"} {
		if strings.Contains(tag, marker) || strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func isExtremeHLSUnknownTagName(tag string) bool {
	const prefix = "#EXT-X-"
	if !strings.HasPrefix(tag, prefix) || len(tag) == len(prefix) || tag[len(tag)-1] == '-' {
		return false
	}
	for index := len(prefix); index < len(tag); index++ {
		if !isHLSAttributeNameByte(tag[index]) {
			return false
		}
	}
	return true
}

func extremeHLSValueMayExposeURI(value string) bool {
	candidate := strings.Trim(value, `"`)
	if candidate == "" {
		return false
	}
	if strings.Contains(candidate, `\`) || strings.HasPrefix(candidate, "//") || strings.Contains(candidate, "://") {
		return true
	}
	reference, err := url.Parse(candidate)
	return err == nil && (reference.IsAbs() || reference.Host != "")
}

func validateExtremeHLSOpaqueTagValue(value string) error {
	if strings.Contains(value, "{$") {
		return fmt.Errorf("unresolved HLS variable outside a URI")
	}
	upperValue := strings.ToUpper(value)
	if strings.Contains(value, "=") && (strings.Contains(upperValue, "URI") || strings.Contains(upperValue, "URL")) || extremeHLSValueMayExposeURI(value) {
		return fmt.Errorf("unsupported URI-bearing HLS extension tag")
	}
	return nil
}

func rewriteExtremeHLSParsedAttributeLine(line string, attributes []hlsAttributeSpan, baseNames map[string]bool, validateKnown, rejectPotentialURI bool, variables *extremeHLSVariableTable, session *dynamicRewriteSession) (string, error) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 || colon+1 >= len(line) {
		return "", fmt.Errorf("invalid HLS tag attribute list")
	}
	tag := line[:colon]
	names := make(map[string]bool, len(baseNames)+2)
	for name := range baseNames {
		names[name] = true
	}
	expansions := make([]extremeHLSReplacement, 0, 2)
	for _, attribute := range attributes {
		knownURIName := baseNames[attribute.name]
		if !knownURIName && !isExtremeHLSURIAttributeName(attribute.name) {
			attributeValue := line[colon+1+attribute.valueStart : colon+1+attribute.valueEnd]
			if strings.Contains(attributeValue, "{$") {
				return "", fmt.Errorf("unresolved HLS variable outside a URI")
			}
			if isExtremeHLSPotentialURLAttributeName(attribute.name) || rejectPotentialURI && extremeHLSValueMayExposeURI(attributeValue) {
				return "", fmt.Errorf("unsupported URI-bearing HLS extension attribute")
			}
			continue
		}
		if !knownURIName && isExtremeHLSSensitiveURIReference(tag, attribute.name) {
			return "", fmt.Errorf("unsupported HLS DRM or key URI extension")
		}
		if !attribute.quoted {
			return "", fmt.Errorf("HLS URI attribute must be quoted")
		}
		start := colon + 1 + attribute.valueStart
		end := colon + 1 + attribute.valueEnd
		expanded, err := variables.substituteExtremeHLSURI(line[start:end])
		if err != nil {
			return "", err
		}
		if expanded != line[start:end] {
			expansions = append(expansions, extremeHLSReplacement{start: start, end: end, value: expanded})
		}
		names[attribute.name] = true
	}
	if len(names) == 0 {
		return line, nil
	}
	expandedLine := applyExtremeHLSReplacements(line, expansions)
	expandedAttributes, err := parseHLSAttributeList(expandedLine[colon+1:])
	if err != nil {
		return "", err
	}
	if validateKnown {
		if err := validateHLSURIAttributes(tag, expandedLine[colon+1:], expandedAttributes); err != nil {
			return "", err
		}
	}
	rewrites := make([]extremeHLSReplacement, 0, len(names))
	for _, attribute := range expandedAttributes {
		if !names[attribute.name] {
			continue
		}
		if !attribute.quoted {
			return "", fmt.Errorf("HLS URI attribute must be quoted")
		}
		start := colon + 1 + attribute.valueStart
		end := colon + 1 + attribute.valueEnd
		rewritten, err := rewriteHLSURIKind(expandedLine[start:end], session, hlsAttributeResourceKind(tag, attribute.name))
		if err != nil {
			return "", err
		}
		if rewritten != expandedLine[start:end] {
			rewrites = append(rewrites, extremeHLSReplacement{start: start, end: end, value: rewritten})
		}
	}
	rewrittenLine := applyExtremeHLSReplacements(expandedLine, rewrites)
	if int64(len(rewrittenLine)) > globalDynamicMaxStringBytes {
		return "", fmt.Errorf("HLS rewritten line exceeds its limit")
	}
	return rewrittenLine, nil
}

func rewriteExtremeHLSKnownAttributeLine(line string, names map[string]bool, variables *extremeHLSVariableTable, session *dynamicRewriteSession) (string, error) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 || colon+1 >= len(line) {
		return "", fmt.Errorf("invalid HLS tag attribute list")
	}
	attributes, err := parseHLSAttributeList(line[colon+1:])
	if err != nil {
		return "", err
	}
	return rewriteExtremeHLSParsedAttributeLine(line, attributes, names, true, false, variables, session)
}

func rewriteExtremeHLSAdditionalAttributeLine(line string, variables *extremeHLSVariableTable, session *dynamicRewriteSession) (string, error) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return line, nil
	}
	if colon+1 >= len(line) {
		return line, validateExtremeHLSOpaqueTagValue("")
	}
	attributes, err := parseHLSAttributeList(line[colon+1:])
	if err != nil {
		if opaqueErr := validateExtremeHLSOpaqueTagValue(line[colon+1:]); opaqueErr != nil {
			return "", opaqueErr
		}
		return line, nil
	}
	return rewriteExtremeHLSParsedAttributeLine(line, attributes, nil, false, false, variables, session)
}

func rewriteExtremeHLSUnknownTagLine(line string, variables *extremeHLSVariableTable, session *dynamicRewriteSession) (string, error) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return line, nil
	}
	if colon+1 >= len(line) {
		return "", fmt.Errorf("invalid HLS extension tag value")
	}
	attributes, err := parseHLSAttributeList(line[colon+1:])
	if err != nil {
		if opaqueErr := validateExtremeHLSOpaqueTagValue(line[colon+1:]); opaqueErr != nil {
			return "", opaqueErr
		}
		return line, nil
	}
	return rewriteExtremeHLSParsedAttributeLine(line, attributes, nil, false, true, variables, session)
}

func knownHLSManifestTag(tag string) bool {
	switch tag {
	case "#EXTINF",
		"#EXT-X-VERSION", "#EXT-X-DEFINE", "#EXT-X-START", "#EXT-X-INDEPENDENT-SEGMENTS",
		"#EXT-X-KEY", "#EXT-X-BYTERANGE", "#EXT-X-DISCONTINUITY", "#EXT-X-MAP",
		"#EXT-X-PROGRAM-DATE-TIME", "#EXT-X-GAP", "#EXT-X-BITRATE", "#EXT-X-DATERANGE",
		"#EXT-X-TARGETDURATION", "#EXT-X-MEDIA-SEQUENCE", "#EXT-X-DISCONTINUITY-SEQUENCE",
		"#EXT-X-ENDLIST", "#EXT-X-PLAYLIST-TYPE", "#EXT-X-I-FRAMES-ONLY", "#EXT-X-ALLOW-CACHE",
		"#EXT-X-PART", "#EXT-X-SERVER-CONTROL", "#EXT-X-PART-INF", "#EXT-X-PRELOAD-HINT",
		"#EXT-X-RENDITION-REPORT", "#EXT-X-SKIP", "#EXT-X-MEDIA", "#EXT-X-STREAM-INF",
		"#EXT-X-I-FRAME-STREAM-INF", "#EXT-X-SESSION-DATA", "#EXT-X-SESSION-KEY",
		"#EXT-X-CONTENT-STEERING", "#EXT-X-IMAGE-STREAM-INF":
		return true
	default:
		return false
	}
}

func rewriteHLSResponse(payload []byte, session *dynamicRewriteSession) ([]byte, error) {
	if session == nil || session.issuer == nil || !utf8.Valid(payload) || len(payload) == 0 {
		return nil, fmt.Errorf("invalid HLS manifest")
	}
	sawCRLF := false
	sawLF := false
	for index, value := range payload {
		if (value < 0x20 && value != '\t' && value != '\r' && value != '\n') || value == 0x7f {
			return nil, fmt.Errorf("HLS manifest contains a control character")
		}
		if value == '\r' && (index+1 >= len(payload) || payload[index+1] != '\n') {
			return nil, fmt.Errorf("HLS manifest contains a bare carriage return")
		}
		if value == '\r' {
			sawCRLF = true
		}
		if value == '\n' && (index == 0 || payload[index-1] != '\r') {
			sawLF = true
		}
	}
	if sawCRLF && sawLF {
		return nil, fmt.Errorf("HLS manifest mixes newline styles")
	}
	maxLines := session.issuer.policy.limits.MaxURLsPerResponse*8 + 1024
	if bytes.Count(payload, []byte{'\n'})+1 > maxLines {
		return nil, fmt.Errorf("HLS manifest contains too many lines")
	}
	text := string(payload)
	separator := "\n"
	if sawCRLF {
		separator = "\r\n"
	}
	lines := strings.Split(text, separator)
	if len(lines) == 0 || lines[0] != "#EXTM3U" {
		return nil, fmt.Errorf("HLS manifest is missing EXTM3U")
	}
	extremeCompatibility := session.issuer.policy.profile == dynamicProfileExtreme
	var extremeVariables *extremeHLSVariableTable
	if extremeCompatibility {
		extremeVariables = newExtremeHLSVariableTable(session)
	}
	uriTags := map[string]map[string]bool{
		"#EXT-X-KEY":                {"URI": true},
		"#EXT-X-MAP":                {"URI": true},
		"#EXT-X-MEDIA":              {"URI": true},
		"#EXT-X-I-FRAME-STREAM-INF": {"URI": true},
		"#EXT-X-SESSION-KEY":        {"URI": true},
		"#EXT-X-SESSION-DATA":       {"URI": true},
		"#EXT-X-IMAGE-STREAM-INF":   {"URI": true},
		"#EXT-X-RENDITION-REPORT":   {"URI": true},
		"#EXT-X-PRELOAD-HINT":       {"URI": true},
		"#EXT-X-PART":               {"URI": true},
		"#EXT-X-DATERANGE":          {"X-ASSET-URI": true, "X-URI": true},
	}
	singletons := make(map[string]bool)
	multivariant := false
	media := false
	expectVariantURI := false
	sawUnscopedURI := false
	for index, line := range lines {
		if index&255 == 0 {
			if err := session.ctx.Err(); err != nil {
				return nil, fmt.Errorf("HLS parsing deadline exceeded")
			}
		}
		if int64(len(line)) > globalDynamicMaxStringBytes {
			return nil, fmt.Errorf("HLS line exceeds its limit")
		}
		if index == 0 {
			continue
		}
		if line == "" {
			if expectVariantURI {
				return nil, fmt.Errorf("HLS variant tag is not followed by a URI")
			}
			continue
		}
		if !strings.HasPrefix(line, "#") {
			if multivariant && !expectVariantURI {
				return nil, fmt.Errorf("HLS multivariant URI is missing STREAM-INF")
			}
			kind := dynamicCapabilityKindResource
			if expectVariantURI {
				kind = dynamicCapabilityKindManifest
				expectVariantURI = false
			} else {
				sawUnscopedURI = true
			}
			if strings.ContainsAny(line, " \t") {
				return nil, fmt.Errorf("HLS URI line contains whitespace")
			}
			if line != strings.TrimSpace(line) {
				return nil, fmt.Errorf("HLS URI line contains surrounding whitespace")
			}
			uriValue := line
			if extremeCompatibility {
				resolved, err := extremeVariables.substituteExtremeHLSURI(uriValue)
				if err != nil {
					return nil, err
				}
				uriValue = resolved
			}
			rewritten, err := rewriteHLSURIKind(uriValue, session, kind)
			if err != nil {
				return nil, err
			}
			lines[index] = rewritten
			continue
		}
		if expectVariantURI {
			return nil, fmt.Errorf("HLS variant tag is not followed by a URI")
		}
		tag := line
		if colon := strings.IndexByte(line, ':'); colon >= 0 {
			tag = line[:colon]
		}
		if strings.HasPrefix(tag, "#EXT") && !knownHLSManifestTag(tag) {
			if !extremeCompatibility || !isExtremeHLSUnknownTagName(tag) {
				return nil, fmt.Errorf("unsupported HLS tag")
			}
			rewritten, err := rewriteExtremeHLSUnknownTagLine(line, extremeVariables, session)
			if err != nil {
				return nil, err
			}
			lines[index] = rewritten
			continue
		}
		switch tag {
		case "#EXT-X-DEFINE":
			if !extremeCompatibility {
				return nil, fmt.Errorf("HLS variable substitution is unsupported")
			}
			if err := extremeVariables.defineFromExtremeHLSLine(line); err != nil {
				return nil, err
			}
			lines[index] = ""
			continue
		case "#EXT-X-CONTENT-STEERING":
			return nil, fmt.Errorf("HLS content steering is unsupported")
		case "#EXT-X-VERSION", "#EXT-X-START", "#EXT-X-INDEPENDENT-SEGMENTS", "#EXT-X-SKIP":
			if singletons[tag] {
				return nil, fmt.Errorf("duplicate singleton HLS tag")
			}
			singletons[tag] = true
		}
		if tag == "#EXT-X-VERSION" {
			versionText := strings.TrimPrefix(line, "#EXT-X-VERSION:")
			version, err := strconv.Atoi(versionText)
			if err != nil || version < 1 || version > 13 {
				return nil, fmt.Errorf("unsupported HLS protocol version")
			}
		}
		if tag == "#EXT-X-STREAM-INF" {
			expectVariantURI = true
		}
		switch tag {
		case "#EXT-X-MEDIA", "#EXT-X-STREAM-INF", "#EXT-X-I-FRAME-STREAM-INF", "#EXT-X-IMAGE-STREAM-INF", "#EXT-X-SESSION-DATA", "#EXT-X-SESSION-KEY":
			multivariant = true
			if sawUnscopedURI {
				return nil, fmt.Errorf("HLS multivariant URI is missing STREAM-INF")
			}
		case "#EXT-X-TARGETDURATION", "#EXT-X-MEDIA-SEQUENCE", "#EXT-X-DISCONTINUITY-SEQUENCE", "#EXT-X-ENDLIST", "#EXT-X-PLAYLIST-TYPE", "#EXT-X-I-FRAMES-ONLY", "#EXT-X-PART-INF", "#EXT-X-SERVER-CONTROL", "#EXT-X-PRELOAD-HINT", "#EXT-X-RENDITION-REPORT", "#EXT-X-SKIP", "#EXTINF", "#EXT-X-BYTERANGE", "#EXT-X-DISCONTINUITY", "#EXT-X-KEY", "#EXT-X-MAP", "#EXT-X-PROGRAM-DATE-TIME", "#EXT-X-DATERANGE", "#EXT-X-GAP", "#EXT-X-BITRATE", "#EXT-X-PART":
			media = true
		}
		if multivariant && media {
			return nil, fmt.Errorf("HLS manifest mixes multivariant and media tags")
		}
		if tag == "#EXT-X-DATERANGE" {
			colon := strings.IndexByte(line, ':')
			attributes, err := parseHLSAttributeList(line[colon+1:])
			if err != nil {
				return nil, err
			}
			for _, attribute := range attributes {
				if attribute.name == "X-ASSET-LIST" || attribute.name == "X-ASSET-URI" {
					return nil, fmt.Errorf("HLS interstitial asset URLs require an unavailable absolute public capability base")
				}
			}
		}
		if names := uriTags[tag]; names != nil {
			var rewritten string
			var err error
			if extremeCompatibility {
				rewritten, err = rewriteExtremeHLSKnownAttributeLine(line, names, extremeVariables, session)
			} else {
				rewritten, err = rewriteHLSAttributeLine(line, names, session)
			}
			if err != nil {
				return nil, err
			}
			lines[index] = rewritten
		} else if extremeCompatibility {
			rewritten, err := rewriteExtremeHLSAdditionalAttributeLine(line, extremeVariables, session)
			if err != nil {
				return nil, err
			}
			lines[index] = rewritten
		}
	}
	if !multivariant && !media {
		return nil, fmt.Errorf("HLS manifest type is not recognized")
	}
	if expectVariantURI {
		return nil, fmt.Errorf("HLS variant tag is not followed by a URI")
	}
	if extremeCompatibility {
		for _, line := range lines {
			if strings.Contains(line, "{$") {
				return nil, fmt.Errorf("unresolved HLS variable")
			}
			if int64(len(line)) > globalDynamicMaxStringBytes {
				return nil, fmt.Errorf("HLS rewritten line exceeds its limit")
			}
		}
	}
	outputLimit := session.structuredOutputLimit()
	outputSize := int64(len(separator) * (len(lines) - 1))
	for _, line := range lines {
		if int64(len(line)) > outputLimit-outputSize {
			return nil, fmt.Errorf("HLS rewritten manifest exceeds its body budget")
		}
		outputSize += int64(len(line))
	}
	output := dynamicBoundedBuffer{limit: outputLimit}
	for index, line := range lines {
		if index > 0 {
			if _, err := output.WriteString(separator); err != nil {
				return nil, err
			}
		}
		if _, err := output.WriteString(line); err != nil {
			return nil, err
		}
	}
	return output.Bytes(), nil
}

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
	port := target.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return ""
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(parsedPort))
}

func dynamicRedirectHeaders(source http.Header) http.Header {
	allowed := []string{"Accept", "Accept-Encoding", "Range", "If-Range"}
	header := make(http.Header, len(allowed)+1)
	for _, name := range allowed {
		if values := source.Values(name); len(values) > 0 {
			header[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
	header.Set("User-Agent", dynamicRedirectUserAgent)
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
	if resp.ContentLength >= 0 && header.Get("Content-Length") == "" {
		header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	header.Set("Cache-Control", "private, no-store")
	header.Set("Content-Security-Policy", "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	resp.Trailer = nil
	resp.Header = header
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
	// Dynamic resource responses reject active content before reaching this sink;
	// manifests are parsed and rewritten, and all responses receive a sandboxed
	// CSP plus nosniff in rebuildDynamicResponseHeaders.
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
	if target == nil || claims.Source != dynamicDiscoverySourceHLS || claims.Kind != dynamicCapabilityKindManifest || len(claims.Template) != 0 || len(claims.TemplateFixed) != 0 || len(rawQuery) > 2048 {
		return nil, fmt.Errorf("capability query is not allowed")
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
	remainder := strings.TrimPrefix(r.URL.Path, dynamicRoutePrefix)
	if remainder == r.URL.Path || remainder == "" {
		writeDynamicCapabilityUnavailable(w)
		return
	}
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
		prepareUpstreamHeaders(outbound.Header, r, i.uaPolicy, i.trustedProxies)
		if redirectHostKey(target) != i.primaryAuthority {
			outbound.Header = crossAuthorityRedirectHeaders(outbound.Header)
		}
		applySiteForwardedHost(outbound.Header, r, i.site)
		i.upstreamHeaderPolicy.apply(outbound.Header, target)
	} else {
		outbound.Header = dynamicRedirectHeaders(r.Header)
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
			policy:                  uaPolicy,
			upstreamHeaderPolicy:    upstreamPolicy,
			dynamicPolicy:           i.policy,
			dynamicTransportFactory: i.transportFactory,
			dynamicState:            i.state,
			streamLeaseHeld:         true,
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

type dynamicTransportFactory func(*url.URL, []net.IP, *dynamicSelfTargetPolicy) (*http.Transport, error)

type redirectFollowTransport struct {
	base                    http.RoundTripper
	playbackHosts           map[string]bool
	configuredAuthorities   map[string]bool
	disableLegacyRedirects  bool
	policy                  UAHeaderPolicy
	upstreamHeaderPolicy    upstreamHeaderPolicy
	dynamicTransportFactory dynamicTransportFactory
	dynamicPolicy           dynamicRedirectPolicy
	dynamicState            *dynamicSiteState
	streamLeaseHeld         bool
	database                *DB
	siteID                  int64
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

func (t *redirectFollowTransport) observe(decision, reasonCode, authority string) {
	if t.database == nil || authority == "" {
		return
	}
	t.database.EnqueueDynamicObservation(dynamicObservationEvent{
		SiteID:             t.siteID,
		CanonicalAuthority: authority,
		Source:             dynamicObservationSourceRedirect,
		Decision:           decision,
		ReasonCode:         reasonCode,
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

func (t *redirectFollowTransport) roundTripLegacy(req *http.Request, resp *http.Response) (*http.Response, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return resp, nil
	}
	for range 3 {
		if resp.StatusCode != 301 && resp.StatusCode != 302 && resp.StatusCode != 307 && resp.StatusCode != 308 {
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
		if (locURL.Scheme != "http" && locURL.Scheme != "https") || locURL.User != nil || !t.playbackHosts[redirectHostKey(locURL)] {
			break
		}
		resp.Body.Close()
		// #nosec G704 -- the redirect authority must match an administrator-configured playback authority.
		newReq, err := http.NewRequestWithContext(req.Context(), req.Method, locURL.String(), nil)
		if err != nil {
			break
		}
		newReq.Host = locURL.Host
		if !sameRedirectAuthority(req.URL, locURL) {
			newReq.Header = crossAuthorityRedirectHeaders(req.Header)
		} else {
			newReq.Header = req.Header.Clone()
		}
		applyUAHeaderPolicy(newReq.Header, t.policy)
		t.upstreamHeaderPolicy.apply(newReq.Header, locURL)
		resp, err = t.base.RoundTrip(newReq)
		if err != nil {
			return nil, err
		}
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
			if t.disableLegacyRedirects || !t.playbackHosts[manualAuthority] || redirectsFollowed >= 3 {
				return resp, nil
			}
			newReq, stripBodyHeaders, reasonCode := t.newExtremeCompatibleDynamicRedirectRequest(req.Context(), req, resp.StatusCode, locationURL)
			if reasonCode != "" {
				return fail(reasonCode, dynamicCanonicalAuthority(req.URL))
			}
			if !sameRedirectAuthority(req.URL, locationURL) {
				if newReq.Body != nil {
					newReq.Header = crossAuthorityRedirectBodyHeaders(req.Header)
				} else {
					newReq.Header = crossAuthorityRedirectHeaders(req.Header)
				}
			} else {
				newReq.Header = req.Header.Clone()
			}
			applyUAHeaderPolicy(newReq.Header, t.policy)
			t.upstreamHeaderPolicy.apply(newReq.Header, locationURL)
			if stripBodyHeaders {
				stripExtremeDynamicRedirectBodyHeaders(newReq.Header)
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
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	eligible, _ := req.Context().Value(dynamicRequestEligibleContextKey{}).(bool)
	if !t.dynamicPolicy.configured {
		if t.disableLegacyRedirects {
			return resp, nil
		}
		return t.roundTripLegacy(req, resp)
	}
	if !eligible || !t.dynamicPolicy.sourceEnabled(dynamicDiscoverySourceRedirect) {
		return resp, nil
	}
	return t.roundTripDynamic(req, resp)
}

type embyAuthAttribute struct {
	name       string
	attrStart  int
	attrEnd    int
	valueStart int
	valueEnd   int
}

func isEmbyAuthWhitespace(value byte) bool {
	return value == ' ' || value == '\t'
}

func isEmbyAuthToken(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '-' || value == '_'
}

func parseEmbyAuthorizationAttributes(value string, offset int) ([]embyAuthAttribute, bool) {
	attributes := make([]embyAuthAttribute, 0, 4)
	for {
		for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
			offset++
		}
		nameStart := offset
		for offset < len(value) && isEmbyAuthToken(value[offset]) {
			offset++
		}
		if nameStart == offset {
			return nil, false
		}
		name := value[nameStart:offset]
		for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
			offset++
		}
		if offset >= len(value) || value[offset] != '=' {
			return nil, false
		}
		offset++
		for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
			offset++
		}
		if offset >= len(value) || value[offset] != '"' {
			return nil, false
		}
		offset++
		valueStart := offset
		for offset < len(value) && value[offset] != '"' {
			if value[offset] == '\\' || value[offset] < 0x20 || value[offset] == 0x7f {
				return nil, false
			}
			offset++
		}
		if offset >= len(value) {
			return nil, false
		}
		attributes = append(attributes, embyAuthAttribute{
			name:       name,
			attrStart:  nameStart,
			attrEnd:    offset + 1,
			valueStart: valueStart,
			valueEnd:   offset,
		})
		offset++
		for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
			offset++
		}
		if offset == len(value) {
			return attributes, true
		}
		if value[offset] != ',' {
			return nil, false
		}
		offset++
		if offset == len(value) {
			return nil, false
		}
	}
}

func rewriteEmbyAuthorizationValue(value string, profile UAProfile) string {
	offset := 0
	for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
		offset++
	}
	schemeStart := offset
	for offset < len(value) && isEmbyAuthToken(value[offset]) {
		offset++
	}
	if schemeStart == offset {
		return value
	}
	scheme := value[schemeStart:offset]
	if !strings.EqualFold(scheme, "MediaBrowser") && !strings.EqualFold(scheme, "Emby") {
		return value
	}
	if offset < len(value) && !isEmbyAuthWhitespace(value[offset]) {
		return value
	}
	for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
		offset++
	}
	if offset == len(value) {
		prefix := value
		if len(value) == schemeStart+len(scheme) {
			prefix += " "
		}
		return prefix + "Client=\"" + profile.Client + "\", Version=\"" + profile.Version + "\""
	}

	attributes, ok := parseEmbyAuthorizationAttributes(value, offset)
	if !ok {
		return value
	}
	clientIndex, versionIndex := -1, -1
	for index, attribute := range attributes {
		switch {
		case strings.EqualFold(attribute.name, "Client"):
			if clientIndex >= 0 {
				return value
			}
			clientIndex = index
		case strings.EqualFold(attribute.name, "Version"):
			if versionIndex >= 0 {
				return value
			}
			versionIndex = index
		}
	}

	type replacement struct {
		start int
		end   int
		value string
	}
	replacements := make([]replacement, 0, 2)
	if clientIndex >= 0 {
		attribute := attributes[clientIndex]
		replacements = append(replacements, replacement{attribute.valueStart, attribute.valueEnd, profile.Client})
	}
	if versionIndex >= 0 {
		attribute := attributes[versionIndex]
		replacements = append(replacements, replacement{attribute.valueStart, attribute.valueEnd, profile.Version})
	}

	if len(replacements) == 2 && replacements[0].start < replacements[1].start {
		replacements[0], replacements[1] = replacements[1], replacements[0]
	}
	rewritten := value
	for _, replacement := range replacements {
		rewritten = rewritten[:replacement.start] + replacement.value + rewritten[replacement.end:]
	}
	if clientIndex < 0 {
		rewritten += ", Client=\"" + profile.Client + "\""
	}
	if versionIndex < 0 {
		rewritten += ", Version=\"" + profile.Version + "\""
	}
	return rewritten
}

func rewriteEmbyAuthorizationHeaders(header http.Header, headerName string, profile UAProfile) {
	for name, values := range header {
		if !strings.EqualFold(name, headerName) {
			continue
		}
		for index, value := range values {
			values[index] = rewriteEmbyAuthorizationValue(value, profile)
		}
	}
}

// stripEmbyAuthorizationToken removes the Token attribute from an Emby
// authorization value, leaving every other attribute byte-identical. The
// boolean result reports whether the value is safe to forward: false means the
// value carries (or may carry) an access token that could not be stripped, and
// the caller must drop the entire header instead of forwarding it. Values
// without any recognizable Token attribute are returned unchanged with true.
// A value whose only attribute is the token is reduced to its bare scheme.
func stripEmbyAuthorizationToken(value string) (string, bool) {
	offset := 0
	for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
		offset++
	}
	schemeStart := offset
	for offset < len(value) && isEmbyAuthToken(value[offset]) {
		offset++
	}
	if schemeStart == offset {
		// Empty or whitespace-only value: nothing to strip.
		return value, true
	}
	scheme := value[schemeStart:offset]
	if !strings.EqualFold(scheme, "MediaBrowser") && !strings.EqualFold(scheme, "Emby") {
		// Unknown scheme: it cannot be proven token-free, so fail closed.
		return value, false
	}
	schemeEnd := offset
	if offset < len(value) && !isEmbyAuthWhitespace(value[offset]) {
		return value, false
	}
	for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
		offset++
	}
	if offset == len(value) {
		// A bare scheme carries no attributes and therefore no token.
		return value, true
	}
	attributes, ok := parseEmbyAuthorizationAttributes(value, offset)
	if !ok {
		return value, false
	}
	tokenIndex := -1
	for index, attribute := range attributes {
		if strings.EqualFold(attribute.name, "Token") {
			if tokenIndex >= 0 {
				// Duplicate Token attributes cannot be stripped without
				// guessing which one the server honors: fail closed.
				return value, false
			}
			tokenIndex = index
		}
	}
	if tokenIndex < 0 {
		return value, true
	}
	attribute := attributes[tokenIndex]
	switch {
	case tokenIndex == 0 && len(attributes) == 1:
		// The only attribute is the token: leave the bare scheme.
		return value[:schemeEnd] + value[attribute.attrEnd:], true
	case tokenIndex == 0:
		// The token is the first attribute: drop it together with the
		// delimiter that followed it.
		return value[:attribute.attrStart] + value[attributes[1].attrStart:], true
	default:
		// The token sits after other attributes: drop the delimiter before
		// it together with the attribute itself.
		return value[:attributes[tokenIndex-1].attrEnd] + value[attribute.attrEnd:], true
	}
}

// stripSensitiveRedirectHeaders removes browser credentials and access tokens
// before a playback redirect crosses to a different authority. Only the Emby
// identity fields (Client/Version/Device/DeviceId) survive, and the UA profile
// is reapplied by the caller afterwards. Cross-authority protection is
// fail-closed: an X-Emby-Authorization value that may still carry a token is
// dropped together with the whole header rather than forwarded.
func stripSensitiveRedirectHeaders(header http.Header) {
	header.Del("Cookie")
	header.Del("Authorization")
	header.Del("Proxy-Authorization")
	// Dedicated token headers must not follow the hop either.
	header.Del("X-Emby-Token")
	header.Del("X-MediaBrowser-Token")
	for name, values := range header {
		if !strings.EqualFold(name, "X-Emby-Authorization") {
			continue
		}
		for index, value := range values {
			stripped, safe := stripEmbyAuthorizationToken(value)
			if !safe {
				header.Del(name)
				break
			}
			values[index] = stripped
		}
	}
}

const (
	progressRequestBodyLimit     = 64 << 10
	progressResponseBodyLimit    = 64 << 10
	progressMaxKeyComponentBytes = 256
	progressDebounceWindow       = time.Second
	progressMaxDispatchDelay     = 5 * time.Second
	progressIdleExpiry           = 5 * time.Minute
	progressCleanupInterval      = time.Minute
	progressMaxSiteKeys          = 1024
	progressMaxGlobalKeys        = 4096
	progressMaxWaitersPerKey     = 16
	progressMaxGlobalWaiters     = 1024
)

var (
	errProgressResponseTooLarge = errors.New("progress upstream response exceeds the coalescing limit")
	errProgressDispatchPanicked = errors.New("progress upstream dispatch panicked")
)

type progressRequestKind uint8

const (
	progressRequestNone progressRequestKind = iota
	progressRequestUpdate
	progressRequestStopped
)

// progressIdentity is deliberately limited to the three protocol identifiers
// needed for ordering. It is never logged or persisted.
type progressIdentity struct {
	SessionID     string
	PlaySessionID string
	ItemID        string
}

// progressInternalKey binds a protocol identity to an in-memory, process-keyed
// credential digest. Responses can therefore never be shared across distinct
// authenticated callers even if they submit the same protocol identifiers.
type progressInternalKey struct {
	Identity   progressIdentity
	Credential [sha256.Size]byte
}

type progressGlobalRuntime struct {
	mu                sync.Mutex
	activeKeys        int
	waiters           int
	maxActiveKeys     int
	maxWaiters        int
	credentialKey     [sha256.Size]byte
	credentialKeyGood bool
}

func newProgressGlobalRuntime(maxActiveKeys, maxWaiters int) *progressGlobalRuntime {
	runtime := &progressGlobalRuntime{maxActiveKeys: maxActiveKeys, maxWaiters: maxWaiters}
	_, runtimeErr := rand.Read(runtime.credentialKey[:])
	runtime.credentialKeyGood = runtimeErr == nil
	return runtime
}

func (r *progressGlobalRuntime) reserveKey() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maxActiveKeys <= 0 || r.activeKeys >= r.maxActiveKeys {
		return false
	}
	r.activeKeys++
	return true
}

func (r *progressGlobalRuntime) releaseKey() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.activeKeys > 0 {
		r.activeKeys--
	}
	r.mu.Unlock()
}

func (r *progressGlobalRuntime) reserveWaiter() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maxWaiters <= 0 || r.waiters >= r.maxWaiters {
		return false
	}
	r.waiters++
	return true
}

func (r *progressGlobalRuntime) releaseWaiter() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.waiters > 0 {
		r.waiters--
	}
	r.mu.Unlock()
}

func progressPathKind(r *http.Request) progressRequestKind {
	if r == nil || r.Method != http.MethodPost || r.URL == nil {
		return progressRequestNone
	}
	switch r.URL.Path {
	case "/Sessions/Playing/Progress", "/emby/Sessions/Playing/Progress":
		return progressRequestUpdate
	case "/Sessions/Playing/Stopped", "/emby/Sessions/Playing/Stopped":
		return progressRequestStopped
	default:
		return progressRequestNone
	}
}

type progressReplayBody struct {
	io.Reader
	closer io.Closer
}

func (b *progressReplayBody) Close() error {
	if b == nil || b.closer == nil {
		return nil
	}
	return b.closer.Close()
}

// readProgressRequestBody consumes no more than 64 KiB. Whenever completeness
// cannot be proven, it restores the consumed prefix in front of the original
// reader so the ordinary proxy path can fail open without changing the body.
func readProgressRequestBody(r *http.Request) ([]byte, bool) {
	if r == nil || r.Body == nil || r.ContentLength > progressRequestBodyLimit {
		return nil, false
	}
	original := r.Body
	limited := &io.LimitedReader{R: original, N: progressRequestBodyLimit}
	payload, err := io.ReadAll(limited)
	complete := err == nil
	if complete {
		switch {
		case r.ContentLength >= 0:
			complete = int64(len(payload)) == r.ContentLength
		case len(payload) == progressRequestBodyLimit:
			// With an unknown length, filling the entire allowance cannot prove EOF
			// without reading a forbidden extra byte. Conservatively fail open.
			complete = false
		}
	}
	if !complete {
		r.Body = &progressReplayBody{
			Reader: io.MultiReader(bytes.NewReader(payload), original),
			closer: original,
		}
		return nil, false
	}
	_ = original.Close()
	r.Body = io.NopCloser(bytes.NewReader(payload))
	return payload, true
}

func parseProgressIdentity(payload []byte) (progressIdentity, bool) {
	var decoded struct {
		SessionID     string `json:"SessionId"`
		PlaySessionID string `json:"PlaySessionId"`
		ItemID        string `json:"ItemId"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &decoded) != nil {
		return progressIdentity{}, false
	}
	identity := progressIdentity{
		SessionID:     decoded.SessionID,
		PlaySessionID: decoded.PlaySessionID,
		ItemID:        decoded.ItemID,
	}
	for _, component := range []string{identity.SessionID, identity.PlaySessionID, identity.ItemID} {
		if component == "" || len(component) > progressMaxKeyComponentBytes {
			return progressIdentity{}, false
		}
	}
	return identity, true
}

var progressCredentialHeaders = []string{
	"Authorization",
	"Cookie",
	"Proxy-Authorization",
	"X-Api-Key",
	"X-Emby-Authorization",
	"X-Emby-Token",
	"X-MediaBrowser-Token",
}

func progressCredentialDigest(runtime *progressGlobalRuntime, r *http.Request) ([sha256.Size]byte, bool) {
	var digest [sha256.Size]byte
	if runtime == nil || r == nil || !runtime.credentialKeyGood {
		return digest, false
	}
	mac := hmac.New(sha256.New, runtime.credentialKey[:])
	for index, name := range progressCredentialHeaders {
		_, _ = mac.Write([]byte{byte(index + 1)})
		for _, value := range r.Header.Values(name) {
			valueDigest := sha256.Sum256([]byte(value))
			_, _ = mac.Write([]byte{1})
			_, _ = mac.Write(valueDigest[:])
		}
		_, _ = mac.Write([]byte{0})
	}
	if r.URL != nil {
		queryDigest := sha256.Sum256([]byte(r.URL.RawQuery))
		_, _ = mac.Write(queryDigest[:])
		if r.URL.User != nil {
			userDigest := sha256.Sum256([]byte(r.URL.User.String()))
			_, _ = mac.Write(userDigest[:])
		}
	}
	if r.TLS != nil {
		for _, certificate := range r.TLS.PeerCertificates {
			certificateDigest := sha256.Sum256(certificate.Raw)
			_, _ = mac.Write(certificateDigest[:])
		}
	}
	copy(digest[:], mac.Sum(nil))
	return digest, true
}

type progressResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

type progressOutcome struct {
	Response progressResponse
	Err      error
}

type progressCaptureWriter struct {
	header        http.Header
	writtenHeader http.Header
	status        int
	body          bytes.Buffer
	overflow      bool
}

func newProgressCaptureWriter() *progressCaptureWriter {
	return &progressCaptureWriter{header: make(http.Header)}
}

func (w *progressCaptureWriter) Header() http.Header {
	return w.header
}

func (w *progressCaptureWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		return
	}
	if w.status != 0 {
		return
	}
	w.status = status
	w.writtenHeader = w.header.Clone()
}

func (w *progressCaptureWriter) Write(payload []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	remaining := progressResponseBodyLimit - w.body.Len()
	if remaining > 0 {
		amount := len(payload)
		if amount > remaining {
			amount = remaining
		}
		_, _ = w.body.Write(payload[:amount])
	}
	if len(payload) > remaining {
		w.overflow = true
	}
	return len(payload), nil
}

func (w *progressCaptureWriter) Flush() {}

func (w *progressCaptureWriter) response() (progressResponse, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.overflow {
		return progressBadGatewayResponse(), errProgressResponseTooLarge
	}
	return progressResponse{
		Status: w.status,
		Header: w.writtenHeader.Clone(),
		Body:   append([]byte(nil), w.body.Bytes()...),
	}, nil
}

func progressBadGatewayResponse() progressResponse {
	return progressResponse{
		Status: http.StatusBadGateway,
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   []byte(`{"error":"upstream unavailable"}`),
	}
}

func progressServiceUnavailableResponse() progressResponse {
	return progressResponse{
		Status: http.StatusServiceUnavailable,
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   []byte(`{"error":"site is stopping"}`),
	}
}

func progressDispatchPanicError(recovered any) error {
	if recoveredErr, ok := recovered.(error); ok && errors.Is(recoveredErr, http.ErrAbortHandler) {
		return http.ErrAbortHandler
	}
	return errProgressDispatchPanicked
}

func writeProgressResponse(w http.ResponseWriter, response progressResponse) {
	for name, values := range response.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	status := response.Status
	if status == 0 {
		status = http.StatusBadGateway
	}
	w.WriteHeader(status)
	if len(response.Body) > 0 {
		_, _ = w.Write(response.Body)
	}
}

type progressDispatchErrorContextKey struct{}

type progressDispatchErrorState struct {
	mu  sync.Mutex
	err error
}

func (s *progressDispatchErrorState) record(err error) {
	if s == nil || err == nil {
		return
	}
	s.mu.Lock()
	s.err = errors.Join(s.err, err)
	s.mu.Unlock()
}

func (s *progressDispatchErrorState) load() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func recordProgressDispatchError(r *http.Request, err error) {
	if r == nil || err == nil {
		return
	}
	if state, ok := r.Context().Value(progressDispatchErrorContextKey{}).(*progressDispatchErrorState); ok {
		state.record(err)
	}
}

type progressBufferedRequest struct {
	request *http.Request
	release func()
}

func newProgressBufferedRequest(runtimeCtx context.Context, r *http.Request, payload []byte) *progressBufferedRequest {
	valueCtx := context.WithoutCancel(r.Context())
	dispatchCtx, dispatchCancel := context.WithCancel(valueCtx)
	stopRuntimeCancel := context.AfterFunc(runtimeCtx, dispatchCancel)
	request := r.Clone(dispatchCtx)
	request.Body = io.NopCloser(bytes.NewReader(payload))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(payload)), nil
	}
	request.ContentLength = int64(len(payload))
	request.TransferEncoding = nil
	request.Trailer = nil
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			stopRuntimeCancel()
			dispatchCancel()
			if request.Body != nil {
				_ = request.Body.Close()
			}
		})
	}
	return &progressBufferedRequest{request: request, release: release}
}

type progressDispatchFunc func(*http.Request) (progressResponse, error)

type progressCoalescerConfig struct {
	debounce         time.Duration
	maxDispatchDelay time.Duration
	idleExpiry       time.Duration
	cleanupInterval  time.Duration
	maxSiteKeys      int
	maxWaitersPerKey int
}

func defaultProgressCoalescerConfig() progressCoalescerConfig {
	return progressCoalescerConfig{
		debounce:         progressDebounceWindow,
		maxDispatchDelay: progressMaxDispatchDelay,
		idleExpiry:       progressIdleExpiry,
		cleanupInterval:  progressCleanupInterval,
		maxSiteKeys:      progressMaxSiteKeys,
		maxWaitersPerKey: progressMaxWaitersPerKey,
	}
}

type progressWaiter struct {
	result chan progressOutcome
	batch  *progressBatch
	entry  *progressEntry
	active bool
}

type progressBatch struct {
	request         *progressBufferedRequest
	waiters         map[*progressWaiter]struct{}
	firstArrival    time.Time
	lastArrival     time.Time
	ready           bool
	timer           *time.Timer
	timerGeneration uint64
}

type progressBarrier struct {
	granted  chan struct{}
	active   bool
	canceled bool
	released bool
}

type progressWork struct {
	batch   *progressBatch
	barrier *progressBarrier
}

type progressEntry struct {
	queue         []*progressWork
	activeBatch   *progressBatch
	activeBarrier *progressBarrier
	waiters       int
	lastActivity  time.Time
}

type progressDrainCycle struct {
	done chan struct{}
	err  error
}

type progressCoalescerState uint8

const (
	progressCoalescerOpen progressCoalescerState = iota
	progressCoalescerQuiescing
	progressCoalescerDraining
	progressCoalescerDrained
	progressCoalescerClosed
)

type progressCoalescer struct {
	mu              sync.Mutex
	global          *progressGlobalRuntime
	config          progressCoalescerConfig
	dispatch        progressDispatchFunc
	entries         map[progressInternalKey]*progressEntry
	state           progressCoalescerState
	drain           *progressDrainCycle
	admissions      int
	ctx             context.Context
	cancel          context.CancelFunc
	maintenanceDone chan struct{}
}

func newProgressCoalescer(global *progressGlobalRuntime, config progressCoalescerConfig, dispatch progressDispatchFunc) *progressCoalescer {
	ctx, cancel := context.WithCancel(context.Background())
	coalescer := &progressCoalescer{
		global:          global,
		config:          config,
		dispatch:        dispatch,
		entries:         make(map[progressInternalKey]*progressEntry),
		ctx:             ctx,
		cancel:          cancel,
		maintenanceDone: make(chan struct{}),
	}
	if config.cleanupInterval <= 0 {
		close(coalescer.maintenanceDone)
	} else {
		go coalescer.runMaintenance()
	}
	return coalescer
}

func (c *progressCoalescer) beginProgressIngress() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != progressCoalescerOpen {
		return false
	}
	c.admissions++
	return true
}

func (c *progressCoalescer) endProgressIngress() {
	c.mu.Lock()
	if c.admissions > 0 {
		c.admissions--
	}
	c.advanceDrainLocked()
	c.mu.Unlock()
}

func (c *progressCoalescer) runMaintenance() {
	defer close(c.maintenanceDone)
	ticker := time.NewTicker(c.config.cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			c.cleanupIdle(now)
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *progressCoalescer) cleanupIdle(now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.config.idleExpiry <= 0 {
		return
	}
	for key, entry := range c.entries {
		if entry.activeBatch != nil || entry.activeBarrier != nil || len(entry.queue) != 0 || entry.waiters != 0 {
			continue
		}
		if now.Sub(entry.lastActivity) < c.config.idleExpiry {
			continue
		}
		delete(c.entries, key)
		c.global.releaseKey()
	}
}

func (c *progressCoalescer) getOrCreateEntryLocked(key progressInternalKey, now time.Time) (*progressEntry, bool) {
	if entry := c.entries[key]; entry != nil {
		return entry, false
	}
	if c.config.maxSiteKeys <= 0 || len(c.entries) >= c.config.maxSiteKeys || !c.global.reserveKey() {
		return nil, false
	}
	entry := &progressEntry{lastActivity: now}
	c.entries[key] = entry
	return entry, true
}

func (c *progressCoalescer) releaseEmptyNewEntryLocked(key progressInternalKey, entry *progressEntry, created bool) {
	if !created || entry == nil || entry.activeBatch != nil || entry.activeBarrier != nil || len(entry.queue) != 0 || entry.waiters != 0 {
		return
	}
	if c.entries[key] == entry {
		delete(c.entries, key)
		c.global.releaseKey()
	}
}

func (c *progressCoalescer) reserveWaiterLocked(entry *progressEntry) bool {
	if entry == nil || c.config.maxWaitersPerKey <= 0 || entry.waiters >= c.config.maxWaitersPerKey || !c.global.reserveWaiter() {
		return false
	}
	entry.waiters++
	return true
}

func (c *progressCoalescer) releaseWaiterLocked(entry *progressEntry) {
	if entry != nil && entry.waiters > 0 {
		entry.waiters--
		c.global.releaseWaiter()
	}
}

func (c *progressCoalescer) scheduleBatchLocked(key progressInternalKey, entry *progressEntry, batch *progressBatch, now time.Time) {
	if batch.ready {
		return
	}
	deadline := now.Add(c.config.debounce)
	maxDeadline := batch.firstArrival.Add(c.config.maxDispatchDelay)
	if deadline.After(maxDeadline) {
		deadline = maxDeadline
	}
	if !deadline.After(now) {
		batch.ready = true
		if batch.timer != nil {
			batch.timer.Stop()
			batch.timer = nil
		}
		return
	}
	if batch.timer != nil {
		batch.timer.Stop()
	}
	batch.timerGeneration++
	generation := batch.timerGeneration
	batch.timer = time.AfterFunc(deadline.Sub(now), func() {
		c.markBatchReady(key, entry, batch, generation)
	})
}

func (c *progressCoalescer) markBatchReady(key progressInternalKey, entry *progressEntry, batch *progressBatch, generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries[key] != entry || batch.timerGeneration != generation || batch.ready || c.state == progressCoalescerClosed {
		return
	}
	batch.ready = true
	batch.timer = nil
	c.advanceEntryLocked(key, entry)
}

func (c *progressCoalescer) forceQueuedBatchesLocked(entry *progressEntry) {
	for _, work := range entry.queue {
		if work.batch == nil {
			continue
		}
		work.batch.ready = true
		work.batch.timerGeneration++
		if work.batch.timer != nil {
			work.batch.timer.Stop()
			work.batch.timer = nil
		}
	}
}

func (c *progressCoalescer) advanceEntryLocked(key progressInternalKey, entry *progressEntry) {
	if entry == nil || entry.activeBatch != nil || entry.activeBarrier != nil || len(entry.queue) == 0 {
		return
	}
	work := entry.queue[0]
	if work.batch != nil && !work.batch.ready {
		return
	}
	entry.queue = entry.queue[1:]
	if work.batch != nil {
		entry.activeBatch = work.batch
		go c.dispatchBatch(key, entry, work.batch)
		return
	}
	entry.activeBarrier = work.barrier
	work.barrier.active = true
	close(work.barrier.granted)
}

func (c *progressCoalescer) dispatchBufferedRequest(buffered *progressBufferedRequest) (response progressResponse, dispatchErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			response = progressBadGatewayResponse()
			dispatchErr = progressDispatchPanicError(recovered)
		}
	}()
	defer func() {
		if buffered != nil && buffered.release != nil {
			buffered.release()
		}
	}()
	if buffered == nil || buffered.request == nil || c.dispatch == nil {
		return progressBadGatewayResponse(), errProgressDispatchPanicked
	}
	return c.dispatch(buffered.request)
}

func (c *progressCoalescer) dispatchBatch(key progressInternalKey, entry *progressEntry, batch *progressBatch) {
	response, dispatchErr := c.dispatchBufferedRequest(batch.request)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries[key] != entry || entry.activeBatch != batch {
		return
	}
	entry.activeBatch = nil
	entry.lastActivity = time.Now()
	if dispatchErr != nil && c.drain != nil && (c.state == progressCoalescerQuiescing || c.state == progressCoalescerDraining) {
		c.drain.err = errors.Join(c.drain.err, dispatchErr)
	}
	outcome := progressOutcome{Response: response, Err: dispatchErr}
	for waiter := range batch.waiters {
		if !waiter.active {
			continue
		}
		waiter.active = false
		c.releaseWaiterLocked(entry)
		waiter.result <- outcome
	}
	if c.state == progressCoalescerDraining {
		c.forceQueuedBatchesLocked(entry)
	}
	c.advanceEntryLocked(key, entry)
	c.completeDrainLocked()
}

func (c *progressCoalescer) enqueueUpdate(key progressInternalKey, request *progressBufferedRequest, now time.Time) (*progressWaiter, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != progressCoalescerOpen && c.state != progressCoalescerQuiescing {
		return nil, false
	}
	entry, created := c.getOrCreateEntryLocked(key, now)
	if entry == nil {
		return nil, false
	}
	if !c.reserveWaiterLocked(entry) {
		c.releaseEmptyNewEntryLocked(key, entry, created)
		return nil, false
	}
	waiter := &progressWaiter{result: make(chan progressOutcome, 1), entry: entry, active: true}
	var batch *progressBatch
	if len(entry.queue) > 0 {
		batch = entry.queue[len(entry.queue)-1].batch
	}
	if batch == nil {
		batch = &progressBatch{
			request:      request,
			waiters:      make(map[*progressWaiter]struct{}),
			firstArrival: now,
			lastArrival:  now,
		}
		entry.queue = append(entry.queue, &progressWork{batch: batch})
	} else {
		batch.request.release()
		batch.request = request
		batch.lastArrival = now
	}
	waiter.batch = batch
	batch.waiters[waiter] = struct{}{}
	entry.lastActivity = now
	c.scheduleBatchLocked(key, entry, batch, now)
	c.advanceEntryLocked(key, entry)
	return waiter, true
}

func (c *progressCoalescer) resolveCanceledWaiter(key progressInternalKey, entry *progressEntry, waiter *progressWaiter) (progressOutcome, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if waiter == nil {
		return progressOutcome{}, false
	}
	if !waiter.active {
		select {
		case outcome := <-waiter.result:
			return outcome, true
		default:
			return progressOutcome{}, false
		}
	}
	if c.entries[key] != entry {
		return progressOutcome{}, false
	}
	waiter.active = false
	delete(waiter.batch.waiters, waiter)
	c.releaseWaiterLocked(entry)
	entry.lastActivity = time.Now()
	return progressOutcome{}, false
}

func (c *progressCoalescer) waitForProgressOutcome(ctx context.Context, key progressInternalKey, waiter *progressWaiter) (progressOutcome, bool) {
	select {
	case outcome := <-waiter.result:
		return outcome, true
	default:
	}
	select {
	case outcome := <-waiter.result:
		return outcome, true
	case <-ctx.Done():
		return c.resolveCanceledWaiter(key, waiter.entry, waiter)
	}
}

func (c *progressCoalescer) enqueueBarrier(key progressInternalKey, now time.Time) (*progressEntry, *progressBarrier, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != progressCoalescerOpen && c.state != progressCoalescerQuiescing {
		return nil, nil, false
	}
	entry, created := c.getOrCreateEntryLocked(key, now)
	if entry == nil {
		return nil, nil, false
	}
	if !c.reserveWaiterLocked(entry) {
		c.releaseEmptyNewEntryLocked(key, entry, created)
		return nil, nil, false
	}
	barrier := &progressBarrier{granted: make(chan struct{})}
	c.forceQueuedBatchesLocked(entry)
	entry.queue = append(entry.queue, &progressWork{barrier: barrier})
	entry.lastActivity = now
	c.advanceEntryLocked(key, entry)
	return entry, barrier, true
}

func (c *progressCoalescer) removeBarrierLocked(entry *progressEntry, barrier *progressBarrier) bool {
	for index, work := range entry.queue {
		if work.barrier != barrier {
			continue
		}
		entry.queue = append(entry.queue[:index], entry.queue[index+1:]...)
		return true
	}
	return false
}

func (c *progressCoalescer) waitForBarrier(ctx context.Context, key progressInternalKey, entry *progressEntry, barrier *progressBarrier) bool {
	select {
	case <-barrier.granted:
		return true
	case <-ctx.Done():
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.entries[key] != entry || barrier.released {
			return false
		}
		if barrier.active {
			return true
		}
		if c.removeBarrierLocked(entry, barrier) {
			barrier.canceled = true
			c.releaseWaiterLocked(entry)
			entry.lastActivity = time.Now()
			c.advanceEntryLocked(key, entry)
			c.completeDrainLocked()
		}
		return false
	}
}

func (c *progressCoalescer) releaseBarrier(key progressInternalKey, entry *progressEntry, barrier *progressBarrier) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries[key] != entry || entry.activeBarrier != barrier || barrier.released {
		return
	}
	barrier.released = true
	barrier.active = false
	entry.activeBarrier = nil
	c.releaseWaiterLocked(entry)
	entry.lastActivity = time.Now()
	if c.state == progressCoalescerDraining {
		c.forceQueuedBatchesLocked(entry)
	}
	c.advanceEntryLocked(key, entry)
	c.completeDrainLocked()
}

func (c *progressCoalescer) serveProgressFallback(w http.ResponseWriter, r *http.Request, ordinary http.Handler) {
	c.mu.Lock()
	failOpen := c.state == progressCoalescerOpen
	c.mu.Unlock()
	if failOpen {
		ordinary.ServeHTTP(w, r)
		return
	}
	writeProgressResponse(w, progressServiceUnavailableResponse())
}

func (c *progressCoalescer) ServeHTTP(w http.ResponseWriter, r *http.Request, ordinary http.Handler) bool {
	if c == nil || ordinary == nil {
		return false
	}
	kind := progressPathKind(r)
	if kind == progressRequestNone {
		return false
	}
	if !c.beginProgressIngress() {
		writeProgressResponse(w, progressServiceUnavailableResponse())
		return true
	}
	admissionActive := true
	releaseAdmission := func() {
		if admissionActive {
			admissionActive = false
			c.endProgressIngress()
		}
	}
	defer releaseAdmission()

	payload, complete := readProgressRequestBody(r)
	if !complete {
		c.serveProgressFallback(w, r, ordinary)
		return true
	}
	identity, valid := parseProgressIdentity(payload)
	if !valid {
		c.serveProgressFallback(w, r, ordinary)
		return true
	}
	credential, valid := progressCredentialDigest(c.global, r)
	if !valid {
		c.serveProgressFallback(w, r, ordinary)
		return true
	}
	key := progressInternalKey{Identity: identity, Credential: credential}
	now := time.Now()

	if kind == progressRequestStopped {
		entry, barrier, accepted := c.enqueueBarrier(key, now)
		if !accepted {
			c.serveProgressFallback(w, r, ordinary)
			return true
		}
		releaseAdmission()
		if !c.waitForBarrier(r.Context(), key, entry, barrier) {
			return true
		}
		defer c.releaseBarrier(key, entry, barrier)
		if r.Context().Err() != nil {
			return true
		}
		ordinary.ServeHTTP(w, r)
		return true
	}

	request := newProgressBufferedRequest(c.ctx, r, payload)
	waiter, accepted := c.enqueueUpdate(key, request, now)
	if !accepted {
		request.release()
		c.serveProgressFallback(w, r, ordinary)
		return true
	}
	releaseAdmission()
	outcome, published := c.waitForProgressOutcome(r.Context(), key, waiter)
	if published {
		writeProgressResponse(w, outcome.Response)
	}
	return true
}

func (c *progressCoalescer) advanceDrainLocked() {
	if c.state != progressCoalescerQuiescing || c.drain == nil || c.admissions != 0 {
		return
	}
	c.state = progressCoalescerDraining
	for key, entry := range c.entries {
		c.forceQueuedBatchesLocked(entry)
		c.advanceEntryLocked(key, entry)
	}
	c.completeDrainLocked()
}

func (c *progressCoalescer) completeDrainLocked() {
	if c.state != progressCoalescerDraining || c.drain == nil || c.admissions != 0 {
		return
	}
	for _, entry := range c.entries {
		if entry.activeBatch != nil || entry.activeBarrier != nil || len(entry.queue) != 0 {
			return
		}
	}
	cycle := c.drain
	c.drain = nil
	if cycle.err == nil {
		c.state = progressCoalescerDrained
	} else {
		c.state = progressCoalescerOpen
	}
	close(cycle.done)
}

func (c *progressCoalescer) Drain(ctx context.Context) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	switch c.state {
	case progressCoalescerClosed, progressCoalescerDrained:
		c.mu.Unlock()
		return nil
	case progressCoalescerQuiescing, progressCoalescerDraining:
		cycle := c.drain
		c.mu.Unlock()
		select {
		case <-cycle.done:
			return cycle.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	cycle := &progressDrainCycle{done: make(chan struct{})}
	c.state = progressCoalescerQuiescing
	c.drain = cycle
	c.advanceDrainLocked()
	c.mu.Unlock()

	select {
	case <-cycle.done:
		return cycle.err
	case <-ctx.Done():
		c.mu.Lock()
		if (c.state == progressCoalescerQuiescing || c.state == progressCoalescerDraining) && c.drain == cycle {
			c.state = progressCoalescerOpen
			c.drain = nil
		}
		c.mu.Unlock()
		return ctx.Err()
	}
}

func (c *progressCoalescer) Close() {
	if c == nil {
		return
	}
	c.cancel()
	c.mu.Lock()
	if c.state == progressCoalescerClosed {
		done := c.maintenanceDone
		c.mu.Unlock()
		<-done
		return
	}
	c.state = progressCoalescerClosed
	for key, entry := range c.entries {
		for _, work := range entry.queue {
			if work.batch != nil {
				work.batch.timerGeneration++
				if work.batch.timer != nil {
					work.batch.timer.Stop()
				}
				work.batch.request.release()
			}
		}
		delete(c.entries, key)
		c.global.releaseKey()
	}
	c.mu.Unlock()
	<-c.maintenanceDone
}

func (c *progressCoalescer) activeCounts() (keys, waiters int) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, entry := range c.entries {
		waiters += entry.waiters
	}
	return len(c.entries), waiters
}

const (
	pingCacheTTL          = 2 * time.Second
	pingCacheMaxBodyBytes = 64 << 10
	pingCacheMaxEntries   = 256
)

type pingCacheRoute uint8

const (
	pingCacheRouteSystem pingCacheRoute = iota + 1
	pingCacheRouteEmbySystem
)

type pingCacheRequestContextKey struct{}

func pingCacheRouteForRequest(r *http.Request) (pingCacheRoute, bool) {
	if r == nil || r.URL == nil || r.Method != http.MethodGet && r.Method != http.MethodHead || hasUpgradeIntent(r) {
		return 0, false
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || cacheRequestForcesRevalidation(r) {
		return 0, false
	}
	if cacheHeaderPresent(r.Header, "Range") || cacheHeaderPresent(r.Header, "If-Range") {
		return 0, false
	}
	if r.URL.EscapedPath() != r.URL.Path {
		return 0, false
	}
	switch r.URL.Path {
	case "/System/Ping":
		return pingCacheRouteSystem, true
	case "/emby/System/Ping":
		return pingCacheRouteEmbySystem, true
	default:
		return 0, false
	}
}

type pingCacheKey struct {
	siteID                      int64
	primaryAuthority            string
	route                       pingCacheRoute
	method                      string
	forceQuery                  bool
	representationQueryDigest   [sha256.Size]byte
	representationHeadersDigest [sha256.Size]byte
	credentialIdentityDigest    [sha256.Size]byte
}

type pingCacheEntry struct {
	key           pingCacheKey
	header        http.Header
	body          []byte
	contentLength int64
	responseAt    time.Time
	initialAge    time.Duration
	expiresAt     time.Time
}

type pingCacheFlight struct {
	done       chan struct{}
	generation uint64
	waiters    int
}

type pingCache struct {
	mu               sync.Mutex
	siteID           int64
	primaryAuthority string
	credentialKey    [sha256.Size]byte
	now              func() time.Time
	generation       uint64
	entries          map[pingCacheKey]*list.Element
	lru              list.List
	inflight         map[pingCacheKey]*pingCacheFlight
}

func newPingCache(siteID int64, primary *url.URL, now func() time.Time) (*pingCache, error) {
	authority := redirectHostKey(primary)
	if siteID <= 0 || authority == "" {
		return nil, fmt.Errorf("ping cache requires a site ID and normalized primary authority")
	}
	if now == nil {
		now = time.Now
	}
	cache := &pingCache{
		siteID:           siteID,
		primaryAuthority: authority,
		now:              now,
		entries:          make(map[pingCacheKey]*list.Element),
		inflight:         make(map[pingCacheKey]*pingCacheFlight),
	}
	if _, err := rand.Read(cache.credentialKey[:]); err != nil {
		return nil, fmt.Errorf("initialize ping cache credential key: %w", err)
	}
	return cache, nil
}

func (c *pingCache) requestKey(req *http.Request) (pingCacheKey, bool) {
	if c == nil || req == nil || req.URL == nil || req.Context().Err() != nil {
		return pingCacheKey{}, false
	}
	route, ok := req.Context().Value(pingCacheRequestContextKey{}).(pingCacheRoute)
	if !ok || route != pingCacheRouteSystem && route != pingCacheRouteEmbySystem ||
		req.Method != http.MethodGet && req.Method != http.MethodHead || redirectHostKey(req.URL) != c.primaryAuthority ||
		req.ContentLength != 0 || len(req.TransferEncoding) != 0 ||
		cacheRequestForcesRevalidation(req) || cacheHeaderPresent(req.Header, "Range") || cacheHeaderPresent(req.Header, "If-Range") {
		return pingCacheKey{}, false
	}
	representationQuery, credentialQuery, ok := splitCanonicalCacheQuery(req.URL.RawQuery)
	if !ok {
		return pingCacheKey{}, false
	}
	representationHeaders, ok := cacheHeaderDigest(req.Header,
		"Accept", "Accept-Charset", "Accept-Encoding", "Accept-Language", "Origin", "User-Agent",
		"X-Emby-Client", "X-Emby-Client-Version", "X-Emby-Device-Id", "X-Emby-Device-Name")
	if !ok {
		return pingCacheKey{}, false
	}
	credentialIdentity, ok := cacheCredentialDigest(c.credentialKey, credentialQuery, req.Header)
	if !ok {
		return pingCacheKey{}, false
	}
	return pingCacheKey{
		siteID:                      c.siteID,
		primaryAuthority:            c.primaryAuthority,
		route:                       route,
		method:                      req.Method,
		forceQuery:                  req.URL.ForceQuery,
		representationQueryDigest:   sha256.Sum256([]byte(representationQuery)),
		representationHeadersDigest: representationHeaders,
		credentialIdentityDigest:    credentialIdentity,
	}, true
}

func (c *pingCache) removeEntryLocked(element *list.Element) {
	if element == nil {
		return
	}
	if entry, ok := element.Value.(*pingCacheEntry); ok && entry != nil {
		delete(c.entries, entry.key)
	}
	c.lru.Remove(element)
}

func (c *pingCache) lookupLocked(key pingCacheKey, now time.Time) *pingCacheEntry {
	element := c.entries[key]
	if element == nil {
		return nil
	}
	entry, _ := element.Value.(*pingCacheEntry)
	if entry == nil || !now.Before(entry.expiresAt) {
		c.removeEntryLocked(element)
		return nil
	}
	c.lru.MoveToFront(element)
	return entry
}

func pingCacheResponseFromEntry(req *http.Request, entry *pingCacheEntry, now time.Time) *http.Response {
	body := io.ReadCloser(http.NoBody)
	if req.Method == http.MethodGet {
		body = io.NopCloser(bytes.NewReader(entry.body))
	}
	header := entry.header.Clone()
	header.Set("Age", cacheResponseAgeValue(entry.initialAge, entry.responseAt, now))
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Header:        header,
		Body:          body,
		ContentLength: entry.contentLength,
		Request:       req,
	}
}

func (c *pingCache) cachedResponse(key pingCacheKey, req *http.Request) (*http.Response, bool) {
	c.mu.Lock()
	now := c.now()
	entry := c.lookupLocked(key, now)
	if entry == nil {
		c.mu.Unlock()
		return nil, false
	}
	response := pingCacheResponseFromEntry(req, entry, now)
	c.mu.Unlock()
	return response, true
}

func pingCacheVarySafe(header http.Header) bool {
	values, ok := cacheHeaderValues(header, "Vary")
	if !ok {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		for _, raw := range strings.Split(value, ",") {
			switch strings.ToLower(strings.TrimSpace(raw)) {
			case "accept", "accept-charset", "accept-encoding", "accept-language", "origin", "user-agent",
				"x-emby-client", "x-emby-client-version", "x-emby-device-id", "x-emby-device-name":
			default:
				return false
			}
		}
	}
	return true
}

func pingCacheResponseHeadersSafe(resp *http.Response, method string) bool {
	if resp == nil || resp.StatusCode != http.StatusOK || cacheHeaderPresent(resp.Header, "Set-Cookie") ||
		cacheHeaderPresent(resp.Header, "Content-Range") || cacheHeaderPresent(resp.Header, "Trailer") ||
		len(resp.Trailer) != 0 || !pingCacheVarySafe(resp.Header) {
		return false
	}
	directives, ok := parseCacheControlDirectives(resp.Header, "Cache-Control")
	if !ok || cacheDirectivePresent(directives, "private") || cacheDirectivePresent(directives, "no-store") || cacheDirectivePresent(directives, "no-cache") || cachePragmaNoCache(resp.Header) {
		return false
	}
	return method == http.MethodHead || resp.ContentLength <= pingCacheMaxBodyBytes
}

func pingCacheReplayHeaders(header http.Header, contentLength int64) (http.Header, bool) {
	replay, _, ok := safeCachedResponseHeaders(header, []string{
		"Access-Control-Allow-Credentials", "Access-Control-Allow-Origin", "Access-Control-Expose-Headers",
		"Cache-Control", "Content-Encoding", "Content-Language", "Content-Type", "Date", "ETag", "Expires", "Last-Modified", "Vary",
	})
	if !ok {
		return nil, false
	}
	if contentLength >= 0 {
		replay.Set("Content-Length", strconv.FormatInt(contentLength, 10))
	}
	return replay, true
}

type pingCacheJoinedBody struct {
	io.Reader
	closer io.Closer
}

func (body *pingCacheJoinedBody) Close() error { return body.closer.Close() }

type pingCacheFailedBody struct {
	prefix *bytes.Reader
	err    error
}

func (body *pingCacheFailedBody) Read(p []byte) (int, error) {
	if body.prefix.Len() != 0 {
		return body.prefix.Read(p)
	}
	if body.err != nil {
		err := body.err
		body.err = nil
		return 0, err
	}
	return 0, io.EOF
}

func (*pingCacheFailedBody) Close() error { return nil }

// prepareResponse publishes only a complete EOF-backed body. Oversized bodies
// keep streaming through a bounded prefix plus the untouched remainder, while
// read failures replay the consumed prefix followed by the original error.
func (c *pingCache) prepareResponse(req *http.Request, resp *http.Response, responseAt time.Time) (*pingCacheEntry, *http.Response) {
	if !pingCacheResponseHeadersSafe(resp, req.Method) {
		return nil, resp
	}
	originalBody := resp.Body
	if originalBody == nil {
		originalBody = http.NoBody
	}
	originalLength := resp.ContentLength
	body, readErr := io.ReadAll(io.LimitReader(originalBody, pingCacheMaxBodyBytes+1))
	if readErr != nil {
		_ = originalBody.Close()
		resp.Body = &pingCacheFailedBody{prefix: bytes.NewReader(body), err: readErr}
		return nil, resp
	}
	if len(body) > pingCacheMaxBodyBytes {
		resp.Body = &pingCacheJoinedBody{Reader: io.MultiReader(bytes.NewReader(body), originalBody), closer: originalBody}
		return nil, resp
	}
	closeErr := originalBody.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	if req.Method == http.MethodGet {
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		if originalLength >= 0 && originalLength != int64(len(body)) {
			return nil, resp
		}
	} else if len(body) != 0 {
		return nil, resp
	}
	if closeErr != nil {
		return nil, resp
	}
	contentLength := resp.ContentLength
	if req.Method == http.MethodGet {
		contentLength = int64(len(body))
	}
	expiresAt, initialAge, fresh := cacheResponseFreshness(resp.Header, responseAt, pingCacheTTL)
	if !fresh {
		return nil, resp
	}
	header, ok := pingCacheReplayHeaders(resp.Header, contentLength)
	if !ok {
		return nil, resp
	}
	return &pingCacheEntry{
		header: header, body: body, contentLength: contentLength,
		responseAt: responseAt, initialAge: initialAge, expiresAt: expiresAt,
	}, resp
}

func (c *pingCache) finishFlight(key pingCacheKey, flight *pingCacheFlight, entry *pingCacheEntry) {
	c.mu.Lock()
	if c.inflight[key] == flight {
		if entry != nil && flight.generation == c.generation && c.now().Before(entry.expiresAt) {
			entry.key = key
			if previous := c.entries[key]; previous != nil {
				c.removeEntryLocked(previous)
			}
			c.entries[key] = c.lru.PushFront(entry)
			for len(c.entries) > pingCacheMaxEntries {
				c.removeEntryLocked(c.lru.Back())
			}
		}
		delete(c.inflight, key)
		close(flight.done)
	}
	c.mu.Unlock()
}

func (c *pingCache) roundTrip(req *http.Request, upstream http.RoundTripper) (*http.Response, error) {
	key, ok := c.requestKey(req)
	if !ok {
		return upstream.RoundTrip(req)
	}
	if response, hit := c.cachedResponse(key, req); hit {
		return response, nil
	}
	c.mu.Lock()
	now := c.now()
	if entry := c.lookupLocked(key, now); entry != nil {
		response := pingCacheResponseFromEntry(req, entry, now)
		c.mu.Unlock()
		return response, nil
	}
	if flight := c.inflight[key]; flight != nil {
		flight.waiters++
		done := flight.done
		c.mu.Unlock()
		select {
		case <-done:
			if response, hit := c.cachedResponse(key, req); hit {
				return response, nil
			}
			if err := req.Context().Err(); err != nil {
				return nil, err
			}
			return upstream.RoundTrip(req)
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	flight := &pingCacheFlight{done: make(chan struct{}), generation: c.generation}
	c.inflight[key] = flight
	c.mu.Unlock()

	resp, err := upstream.RoundTrip(req)
	if err != nil {
		c.finishFlight(key, flight, nil)
		return nil, err
	}
	responseAt := c.now()
	entry, prepared := c.prepareResponse(req, resp, responseAt)
	c.finishFlight(key, flight, entry)
	return prepared, nil
}

func (c *pingCache) invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.generation++
	for element := c.lru.Front(); element != nil; {
		next := element.Next()
		c.removeEntryLocked(element)
		element = next
	}
	c.mu.Unlock()
}

type pingCacheTransport struct {
	base  http.RoundTripper
	cache *pingCache
}

func (transport *pingCacheTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if transport == nil || transport.base == nil {
		return nil, fmt.Errorf("ping cache transport is not configured")
	}
	if transport.cache == nil {
		return transport.base.RoundTrip(req)
	}
	return transport.cache.roundTrip(req, transport.base)
}

type ProxyInstance struct {
	Site      Site
	handler   http.Handler
	server    *http.Server
	listener  net.Listener
	transport *http.Transport
	startedAt time.Time
	ctx       context.Context
	cancel    context.CancelFunc
	// lifecycleMu closes the gate before activeRequests.Wait begins, so no Add
	// can race a drain. Hijacked WebSocket connections are tracked separately
	// because net/http no longer owns them after Hijack.
	lifecycleMu     sync.Mutex
	closing         bool
	activeRequests  sync.WaitGroup
	hijackedConns   map[net.Conn]struct{}
	portServing     atomic.Bool
	portServeFailed atomic.Bool
	// trafficMu serializes this instance's traffic state transitions: flush,
	// single-site history snapshot and the live overlay in global snapshots.
	// Lock order is pm.mu -> trafficMu; helpers that take trafficMu (e.g.
	// flushProxyTraffic) must never be called from code that already holds it.
	trafficMu            sync.Mutex
	bytesIn              atomic.Int64
	bytesOut             atomic.Int64
	reqCount             atomic.Int64
	activeTrafficMeters  atomic.Int64
	flushBytesIn         int64
	flushBytesOut        int64
	pendingMinuteTraffic map[int64]trafficMinuteDelta
	persistedTraffic     atomic.Int64
	trustedProxies       []*net.IPNet
	dynamicState         *dynamicSiteState
	progress             *progressCoalescer
	pingCache            *pingCache
	imageCache           *imageCacheSite
}

func (inst *ProxyInstance) drainProgress(ctx context.Context) error {
	if inst == nil || inst.progress == nil {
		return nil
	}
	return inst.progress.Drain(ctx)
}

func (inst *ProxyInstance) closeProgress() {
	if inst != nil && inst.progress != nil {
		inst.progress.Close()
	}
}

type ProxyManager struct {
	mu                      sync.RWMutex
	lifecycleMu             sync.Mutex
	proxies                 map[int64]*ProxyInstance
	publicHosts             map[string]int64
	publicHostModes         map[string]string
	upstreamHeaderKey       []byte
	trustedProxies          []*net.IPNet
	hostOnlyIngressSafe     bool
	shutdownStarted         atomic.Bool
	database                *DB
	dynamicRuntime          *dynamicRuntime
	progressRuntime         *progressGlobalRuntime
	imageCacheRuntime       *imageCacheRuntime
	dynamicRouteKey         []byte
	dynamicTransportFactory dynamicTransportFactory
	dynamicAvailable        bool
	dynamicPanelHost        string
	dynamicPanelPort        int
	dynamicInterfaceAddrs   dynamicInterfaceAddrsFunc
}

// siteIngressClosedError means StopSite passed the irreversible boundary: new
// requests are rejected and listeners are closed, but draining and/or the final
// traffic checkpoint did not finish. Callers must not leave the DB row enabled
// as if the proxy were still serving.
type siteIngressClosedError struct {
	siteID   int64
	drainErr error
	flushErr error
}

func (e *siteIngressClosedError) Error() string {
	switch {
	case e.drainErr != nil && e.flushErr != nil:
		return fmt.Sprintf("site %d ingress closed; drain failed: %v; final traffic flush failed: %v", e.siteID, e.drainErr, e.flushErr)
	case e.drainErr != nil:
		return fmt.Sprintf("site %d ingress closed; drain failed: %v", e.siteID, e.drainErr)
	default:
		return fmt.Sprintf("site %d ingress closed; final traffic flush failed: %v", e.siteID, e.flushErr)
	}
}

func isSiteIngressClosedError(err error) bool {
	var closedErr *siteIngressClosedError
	return errors.As(err, &closedErr)
}

func (inst *ProxyInstance) beginRequest() bool {
	inst.lifecycleMu.Lock()
	defer inst.lifecycleMu.Unlock()
	if inst.closing {
		return false
	}
	inst.activeRequests.Add(1)
	return true
}

func (inst *ProxyInstance) endRequest() {
	inst.activeRequests.Done()
}

func (inst *ProxyInstance) isAccepting() bool {
	inst.lifecycleMu.Lock()
	defer inst.lifecycleMu.Unlock()
	return !inst.closing
}

// isOperational distinguishes an open lifecycle gate from a usable ingress.
// Host-capable instances remain reachable through the shared panel listener;
// port-only instances are operational only while their dedicated Serve loop is
// actually alive.
func (inst *ProxyInstance) isOperational() bool {
	if !inst.isAccepting() {
		return false
	}
	return ingressUsesHost(inst.Site.IngressMode) || !inst.portServeFailed.Load()
}

func (inst *ProxyInstance) trackHijackedConn(conn net.Conn) bool {
	inst.lifecycleMu.Lock()
	defer inst.lifecycleMu.Unlock()
	if inst.closing {
		return false
	}
	if inst.hijackedConns == nil {
		inst.hijackedConns = make(map[net.Conn]struct{})
	}
	inst.hijackedConns[conn] = struct{}{}
	return true
}

func (inst *ProxyInstance) untrackHijackedConn(conn net.Conn) {
	inst.lifecycleMu.Lock()
	delete(inst.hijackedConns, conn)
	inst.lifecycleMu.Unlock()
}

func (inst *ProxyInstance) shutdown(ctx context.Context) error {
	inst.lifecycleMu.Lock()
	if !inst.closing {
		inst.closing = true
		if inst.cancel != nil {
			inst.cancel()
		}
	}
	connections := make([]net.Conn, 0, len(inst.hijackedConns))
	for conn := range inst.hijackedConns {
		connections = append(connections, conn)
	}
	inst.lifecycleMu.Unlock()
	inst.pingCache.invalidate()
	inst.imageCache.close()

	if inst.listener != nil {
		_ = inst.listener.Close()
	}
	if inst.server != nil {
		_ = inst.server.Close()
	}
	if inst.transport != nil {
		inst.transport.CloseIdleConnections()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}

	drained := make(chan struct{})
	go func() {
		inst.activeRequests.Wait()
		close(drained)
	}()
	select {
	case <-drained:
		inst.dynamicState.close()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func NewProxyManager(db *DB, upstreamHeaderKey []byte) *ProxyManager {
	pm := &ProxyManager{
		proxies:           make(map[int64]*ProxyInstance),
		publicHosts:       make(map[string]int64),
		publicHostModes:   make(map[string]string),
		dynamicRuntime:    newDynamicRuntime(),
		progressRuntime:   newProgressGlobalRuntime(progressMaxGlobalKeys, progressMaxGlobalWaiters),
		imageCacheRuntime: newImageCacheRuntime(upstreamHeaderKey),
		database:          db,
	}
	pm.upstreamHeaderKey = append([]byte(nil), upstreamHeaderKey...)
	return pm
}

func (pm *ProxyManager) DynamicDiscoveryAvailable() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.dynamicAvailable
}

func (pm *ProxyManager) buildDynamicSelfTargetPolicy() (*dynamicSelfTargetPolicy, error) {
	pm.mu.RLock()
	available := pm.dynamicAvailable
	panelHost := pm.dynamicPanelHost
	panelPort := pm.dynamicPanelPort
	interfaceAddrs := pm.dynamicInterfaceAddrs
	pm.mu.RUnlock()
	if !available {
		return nil, nil
	}
	if pm.database == nil {
		return nil, fmt.Errorf("dynamic self-target policy requires proxy manager database state")
	}
	sites, err := pm.database.ListSites()
	if err != nil {
		return nil, fmt.Errorf("snapshot configured sites for dynamic self-target policy: %w", err)
	}
	return newDynamicSelfTargetPolicy(panelHost, panelPort, sites, interfaceAddrs)
}

func (pm *ProxyManager) ConfigureDynamicDiscovery(dynamicKey []byte, panelHost string, panelPort int, interfaceAddrs dynamicInterfaceAddrsFunc) error {
	pm.lifecycleMu.Lock()
	defer pm.lifecycleMu.Unlock()
	if len(dynamicKey) != 0 && len(dynamicKey) != sha256.Size {
		return fmt.Errorf("resolved DYNAMIC_ROUTE_KEY has an invalid length")
	}
	pm.mu.Lock()
	pm.dynamicAvailable = len(dynamicKey) == sha256.Size
	pm.dynamicRouteKey = append(pm.dynamicRouteKey[:0], dynamicKey...)
	pm.dynamicPanelHost = panelHost
	pm.dynamicPanelPort = panelPort
	pm.dynamicInterfaceAddrs = interfaceAddrs
	pm.mu.Unlock()
	policy, err := pm.buildDynamicSelfTargetPolicy()
	if err != nil {
		pm.dynamicRuntime.selfTargets.Store(nil)
		pm.mu.Lock()
		pm.dynamicAvailable = false
		pm.mu.Unlock()
		return err
	}
	pm.dynamicRuntime.selfTargets.Store(policy)
	return nil
}

func (pm *ProxyManager) SetTrustedProxies(networks []*net.IPNet) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.trustedProxies = append([]*net.IPNet(nil), networks...)
}

func (pm *ProxyManager) SetHostOnlyIngressSafe(safe bool) {
	pm.mu.Lock()
	pm.hostOnlyIngressSafe = safe
	pm.mu.Unlock()
}

func (pm *ProxyManager) HostOnlyIngressSafe() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.hostOnlyIngressSafe
}

func (pm *ProxyManager) UpstreamHeadersAvailable() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.upstreamHeaderKey) == 32
}

func (pm *ProxyManager) validateIngressSafety(mode string) error {
	if mode != ingressModeHost {
		return nil
	}
	pm.mu.RLock()
	safe := pm.hostOnlyIngressSafe
	pm.mu.RUnlock()
	if !safe {
		return errUnsafeHostOnlyIngress
	}
	return nil
}

func (pm *ProxyManager) registerSiteHostLocked(site Site) error {
	desiredHost := ""
	if ingressUsesHost(site.IngressMode) {
		desiredHost = site.PublicHost
		if existing, ok := pm.publicHosts[desiredHost]; ok && existing != site.ID {
			return fmt.Errorf("public_host %s is already assigned to another site", desiredHost)
		}
	}
	for host, id := range pm.publicHosts {
		if id == site.ID && host != desiredHost {
			delete(pm.publicHosts, host)
			delete(pm.publicHostModes, host)
		}
	}
	if desiredHost == "" {
		return nil
	}
	pm.publicHosts[desiredHost] = site.ID
	pm.publicHostModes[desiredHost] = site.IngressMode
	return nil
}

func (pm *ProxyManager) RegisterSiteHost(site Site) error {
	pm.lifecycleMu.Lock()
	defer pm.lifecycleMu.Unlock()
	if pm.shutdownStarted.Load() {
		return errProxyManagerShuttingDown
	}
	publicHost, err := normalizePublicHost(site.PublicHost)
	if err != nil {
		return err
	}
	site.PublicHost = publicHost
	site.IngressMode, err = normalizeIngressMode(site.IngressMode, site.PublicHost)
	if err != nil {
		return err
	}
	nextSelfTargets, snapshotErr := pm.buildDynamicSelfTargetPolicy()
	pm.mu.Lock()
	err = pm.registerSiteHostLocked(site)
	if err == nil {
		if snapshotErr != nil {
			pm.dynamicRuntime.selfTargets.Store(nil)
		} else {
			pm.dynamicRuntime.selfTargets.Store(nextSelfTargets)
		}
	}
	pm.mu.Unlock()
	if err != nil {
		return err
	}
	if snapshotErr != nil {
		log.Printf("dynamic discovery disabled until the next lifecycle refresh: %v", snapshotErr)
	}
	return nil
}

func (pm *ProxyManager) UnregisterSiteHost(siteID int64) {
	pm.lifecycleMu.Lock()
	defer pm.lifecycleMu.Unlock()
	nextSelfTargets, snapshotErr := pm.buildDynamicSelfTargetPolicy()
	pm.mu.Lock()
	for host, id := range pm.publicHosts {
		if id == siteID {
			delete(pm.publicHosts, host)
			delete(pm.publicHostModes, host)
		}
	}
	if snapshotErr != nil {
		pm.dynamicRuntime.selfTargets.Store(nil)
	} else {
		pm.dynamicRuntime.selfTargets.Store(nextSelfTargets)
	}
	pm.mu.Unlock()
	if snapshotErr != nil {
		log.Printf("dynamic discovery disabled until the next lifecycle refresh: %v", snapshotErr)
	}
}

func (pm *ProxyManager) PublicHostHandler(host string) (http.Handler, bool) {
	handler, configured, _ := pm.PublicHostRoute(host)
	return handler, configured
}

func (pm *ProxyManager) PublicHostRoute(host string) (http.Handler, bool, string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	id, configured := pm.publicHosts[host]
	if !configured {
		return nil, false, ""
	}
	mode := pm.publicHostModes[host]
	inst := pm.proxies[id]
	if inst == nil {
		return nil, true, mode
	}
	return inst.handler, true, mode
}

func (pm *ProxyManager) PublicHostSiteID(host string) (int64, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	id, ok := pm.publicHosts[host]
	return id, ok
}

// requestTrafficMeter keeps ordinary HTTP bytes request-local until completion,
// while global pending totals continue to update on every read/write. A request
// promotes to streaming on Flush or a UTC-minute crossing; promoted traffic is
// aggregated immediately by occurrence minute so long-lived streams and
// WebSockets do not disappear until they close.
type requestTrafficMeter struct {
	inst          *ProxyInstance
	mu            sync.Mutex
	startedMinute int64
	localIn       int64
	localOut      int64
	streaming     bool
	finished      bool
}

func newRequestTrafficMeter(inst *ProxyInstance) *requestTrafficMeter {
	return newRequestTrafficMeterAt(inst, time.Now())
}

func newRequestTrafficMeterAt(inst *ProxyInstance, at time.Time) *requestTrafficMeter {
	inst.trafficMu.Lock()
	inst.activeTrafficMeters.Add(1)
	inst.trafficMu.Unlock()
	return &requestTrafficMeter{inst: inst, startedMinute: trafficMinuteStart(at)}
}

func (inst *ProxyInstance) addMinuteTraffic(minuteStart, bytesIn, bytesOut, requests int64, addGlobal bool) {
	if bytesIn == 0 && bytesOut == 0 && requests == 0 {
		return
	}
	inst.trafficMu.Lock()
	defer inst.trafficMu.Unlock()
	if addGlobal {
		inst.bytesIn.Add(bytesIn)
		inst.bytesOut.Add(bytesOut)
	}
	if inst.pendingMinuteTraffic == nil {
		inst.pendingMinuteTraffic = make(map[int64]trafficMinuteDelta)
	}
	delta := inst.pendingMinuteTraffic[minuteStart]
	delta.BytesIn += bytesIn
	delta.BytesOut += bytesOut
	delta.Requests += requests
	inst.pendingMinuteTraffic[minuteStart] = delta
	inst.flushBytesIn += bytesIn
	inst.flushBytesOut += bytesOut
}

func (m *requestTrafficMeter) promoteLocked() {
	if m.streaming {
		return
	}
	m.streaming = true
	if m.localIn != 0 || m.localOut != 0 {
		m.inst.addMinuteTraffic(m.startedMinute, m.localIn, m.localOut, 0, false)
		m.localIn = 0
		m.localOut = 0
	}
}

func (m *requestTrafficMeter) promote() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.promoteLocked()
}

func (m *requestTrafficMeter) add(bytesIn, bytesOut int64, at time.Time) {
	if m == nil || (bytesIn == 0 && bytesOut == 0) {
		return
	}
	minuteStart := trafficMinuteStart(at)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.finished {
		return
	}
	if !m.streaming && minuteStart == m.startedMinute {
		m.inst.bytesIn.Add(bytesIn)
		m.inst.bytesOut.Add(bytesOut)
		m.localIn += bytesIn
		m.localOut += bytesOut
		return
	}
	if !m.streaming {
		m.promoteLocked()
	}
	m.inst.addMinuteTraffic(minuteStart, bytesIn, bytesOut, 0, true)
}

func (m *requestTrafficMeter) addIn(n int64) {
	m.add(n, 0, time.Now())
}

func (m *requestTrafficMeter) addOut(n int64) {
	m.add(0, n, time.Now())
}

// finish attributes an ordinary request's bytes and every request count to the
// completion minute. Stream bytes were already attributed by occurrence time.
func (m *requestTrafficMeter) finish(at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.finished {
		m.mu.Unlock()
		return
	}
	m.finished = true
	minuteStart := trafficMinuteStart(at)
	if m.streaming {
		m.inst.addMinuteTraffic(minuteStart, 0, 0, 1, false)
	} else {
		m.inst.addMinuteTraffic(minuteStart, m.localIn, m.localOut, 1, false)
		m.localIn = 0
		m.localOut = 0
	}
	m.inst.reqCount.Add(1)
	m.mu.Unlock()
	m.inst.activeTrafficMeters.Add(-1)
}

func addMeteredBytes(counter *atomic.Int64, meter *requestTrafficMeter, inbound bool, n int64) {
	if n <= 0 {
		return
	}
	if meter != nil {
		if inbound {
			meter.addIn(n)
		} else {
			meter.addOut(n)
		}
		return
	}
	if counter != nil {
		counter.Add(n)
	}
}

// metered response writer
type meteredWriter struct {
	http.ResponseWriter
	written *atomic.Int64
	meter   *requestTrafficMeter
}

func (m *meteredWriter) Write(b []byte) (int, error) {
	n, err := m.ResponseWriter.Write(b)
	addMeteredBytes(m.written, m.meter, false, int64(n))
	return n, err
}

// Flush support for streaming
func (m *meteredWriter) Flush() {
	m.meter.promote()
	if f, ok := m.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack support for WebSocket upgrade
func (m *meteredWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := m.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}

// metered request body reader
type meteredReader struct {
	io.ReadCloser
	read  *atomic.Int64
	meter *requestTrafficMeter
}

func (m *meteredReader) Read(p []byte) (int, error) {
	n, err := m.ReadCloser.Read(p)
	addMeteredBytes(m.read, m.meter, true, int64(n))
	return n, err
}

type rateLimitedWriter struct {
	http.ResponseWriter
	bytesPerSec    int64
	written        *atomic.Int64
	meter          *requestTrafficMeter
	requestWritten int64
	start          time.Time
}

func (w *rateLimitedWriter) Write(b []byte) (int, error) {
	if w.bytesPerSec <= 0 {
		n, err := w.ResponseWriter.Write(b)
		addMeteredBytes(w.written, w.meter, false, int64(n))
		return n, err
	}
	totalWritten := 0
	for len(b) > 0 {
		elapsed := time.Since(w.start).Seconds()
		if elapsed < 0.001 {
			elapsed = 0.001
		}
		allowed := int64(elapsed*float64(w.bytesPerSec)) - w.requestWritten
		if allowed <= 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		chunk := b
		if int64(len(chunk)) > allowed {
			chunk = b[:allowed]
		}
		n, err := w.ResponseWriter.Write(chunk)
		addMeteredBytes(w.written, w.meter, false, int64(n))
		w.requestWritten += int64(n)
		totalWritten += n
		b = b[n:]
		if err != nil {
			return totalWritten, err
		}
		if n == 0 {
			return totalWritten, io.ErrNoProgress
		}
	}
	return totalWritten, nil
}

func (w *rateLimitedWriter) Flush() {
	w.meter.promote()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *rateLimitedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}

// tunnelWriter meters, and optionally paces, bytes copied through a hijacked
// WebSocket tunnel. Its request meter is promoted before the tunnel starts, so
// every chunk reaches an occurrence-minute bucket while the connection is live.
type tunnelWriter struct {
	dst         io.Writer
	counter     *atomic.Int64
	meter       *requestTrafficMeter
	inbound     bool
	bytesPerSec int64
	written     int64
	start       time.Time
}

func (t *tunnelWriter) Write(b []byte) (int, error) {
	if t.bytesPerSec <= 0 {
		n, err := t.dst.Write(b)
		addMeteredBytes(t.counter, t.meter, t.inbound, int64(n))
		return n, err
	}
	total := 0
	for len(b) > 0 {
		elapsed := time.Since(t.start).Seconds()
		if elapsed < 0.001 {
			elapsed = 0.001
		}
		allowed := int64(elapsed*float64(t.bytesPerSec)) - t.written
		if allowed <= 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		chunk := b
		if int64(len(chunk)) > allowed {
			chunk = b[:allowed]
		}
		n, err := t.dst.Write(chunk)
		addMeteredBytes(t.counter, t.meter, t.inbound, int64(n))
		t.written += int64(n)
		total += n
		b = b[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

// headerHasToken reports whether a comma-separated header such as Connection
// carries the given token, which is how RFC 9110 requires these be compared.
func headerHasToken(header http.Header, name, token string) bool {
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// isWebSocketUpgrade reports whether the request is a real RFC 6455 handshake.
// A bare "Upgrade: websocket" header is not enough to qualify: routing an
// ordinary request into the hijacked tunnel would skip the metering and
// speed-limit wrappers that the normal proxy path installs, and would relay raw
// bytes to an upstream that never agreed to switch protocols. Any request with
// upgrade intent that fails this check is rejected before ReverseProxy, because
// its generic 101 tunnel would bypass Meridian's traffic accounting and limits.
func isWebSocketUpgrade(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		headerHasToken(r.Header, "Connection", "upgrade") &&
		r.Header.Get("Sec-WebSocket-Key") != ""
}

func hasUpgradeIntent(r *http.Request) bool {
	return strings.TrimSpace(r.Header.Get("Upgrade")) != "" ||
		headerHasToken(r.Header, "Connection", "upgrade")
}

var dynamicForbiddenPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func containsDynamicUnsafeRune(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) >= 0
}

// normalizeDynamicHost applies the IDNA Lookup profile used by DNS resolvers.
// The returned host is lower-case ASCII without a trailing dot; IP literals
// are returned in netip canonical form and reported through isIP.
func normalizeDynamicHostSyntax(value string) (host string, isIP bool, err error) {
	value = strings.TrimSpace(value)
	if value == "" || containsDynamicUnsafeRune(value) {
		return "", false, fmt.Errorf("host is empty or contains whitespace/control characters")
	}
	if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
		if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
			return "", false, fmt.Errorf("host contains mismatched brackets")
		}
		value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
		if net.ParseIP(value) == nil || !strings.Contains(value, ":") {
			return "", false, fmt.Errorf("only IPv6 literals may use brackets")
		}
	}
	if strings.ContainsAny(value, "/\\@?#") || strings.Contains(value, "%") {
		return "", false, fmt.Errorf("host contains URL syntax or an IPv6 zone")
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return "", false, fmt.Errorf("host is empty")
	}
	if parsedIP := net.ParseIP(value); parsedIP != nil {
		addr, ok := netip.AddrFromSlice(parsedIP)
		if !ok {
			return "", false, fmt.Errorf("host contains an invalid IP address")
		}
		return addr.Unmap().String(), true, nil
	}

	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", false, fmt.Errorf("host is not valid IDNA: %w", err)
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if ascii == "" || len(ascii) > 253 {
		return "", false, fmt.Errorf("host must be 1-253 ASCII bytes")
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false, fmt.Errorf("host contains an invalid DNS label")
		}
		for i := range len(label) {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false, fmt.Errorf("host contains an invalid DNS label")
			}
		}
	}
	return ascii, false, nil
}

func normalizeDynamicHost(value string) (host string, isIP bool, err error) {
	host, isIP, err = normalizeDynamicHostSyntax(value)
	if err != nil || isIP {
		return host, isIP, err
	}
	publicSuffix, icann := publicsuffix.PublicSuffix(host)
	if publicSuffix == "" || (!icann && !strings.Contains(publicSuffix, ".")) {
		return "", false, fmt.Errorf("host must use a recognized public suffix")
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(host); err != nil {
		return "", false, fmt.Errorf("host must be below a public suffix")
	}
	return host, false, nil
}

func dynamicURLDecodedComponentIsSafe(value string, query bool) bool {
	if value == "" {
		return true
	}
	var decoded string
	var err error
	if query {
		decoded, err = url.QueryUnescape(value)
	} else {
		decoded, err = url.PathUnescape(value)
	}
	if err != nil {
		return false
	}
	// Raw whitespace is rejected before parsing. Percent-encoded spaces and
	// query '+' remain escaped on the wire and are valid URL data; decoded
	// controls and backslashes remain forbidden to prevent request ambiguity.
	return strings.IndexFunc(decoded, unicode.IsControl) < 0 && !strings.Contains(decoded, `\`)
}
func dynamicURLPathHasDotSegments(value string) bool {
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return true
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// normalizeDynamicURL is deliberately separate from normalizeTargetURL: the
// latter preserves v1.7's manual-site conveniences, while future discovered
// targets use this strict, canonical security boundary.
func normalizeDynamicURL(value string) (*url.URL, error) {
	if value == "" {
		return nil, fmt.Errorf("dynamic URL is required")
	}
	if len(value) > maxDynamicTargetURLBytes {
		return nil, fmt.Errorf("dynamic URL must not exceed %d bytes", maxDynamicTargetURLBytes)
	}
	if value != strings.TrimSpace(value) || containsDynamicUnsafeRune(value) {
		return nil, fmt.Errorf("dynamic URL contains whitespace or control characters")
	}
	if strings.Contains(value, `\`) {
		return nil, fmt.Errorf("dynamic URL must not contain backslashes")
	}
	if strings.Contains(value, "#") {
		return nil, fmt.Errorf("dynamic URL must not contain a fragment")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse dynamic URL: %w", err)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("dynamic URL scheme must be http or https")
	}
	if parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("dynamic URL must be an absolute hierarchical URL")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("dynamic URL must not contain userinfo")
	}
	if parsed.Fragment != "" || parsed.RawFragment != "" {
		return nil, fmt.Errorf("dynamic URL must not contain a fragment")
	}
	if strings.Contains(parsed.Host, "%") {
		return nil, fmt.Errorf("dynamic URL must not contain an IPv6 zone or escaped host")
	}
	if strings.HasPrefix(parsed.Host, "[") {
		if ip := net.ParseIP(parsed.Hostname()); ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("dynamic URL brackets require an IPv6 literal")
		}
	}
	if !dynamicURLDecodedComponentIsSafe(parsed.EscapedPath(), false) || !dynamicURLDecodedComponentIsSafe(parsed.RawQuery, true) {
		return nil, fmt.Errorf("dynamic URL contains an escaped whitespace or control character")
	}
	if dynamicURLPathHasDotSegments(parsed.EscapedPath()) {
		return nil, fmt.Errorf("dynamic URL must not contain dot path segments")
	}

	host, isIP, err := normalizeDynamicHost(parsed.Hostname())
	if err != nil {
		return nil, fmt.Errorf("invalid dynamic URL host: %w", err)
	}
	if isIP {
		if _, err := validateDynamicResolvedIPs([]net.IP{net.ParseIP(host)}); err != nil {
			return nil, fmt.Errorf("invalid dynamic URL host: %w", err)
		}
	}
	port := 80
	if parsed.Scheme == "https" {
		port = 443
	}
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("dynamic URL contains an invalid port")
		}
	} else if strings.HasSuffix(parsed.Host, ":") {
		return nil, fmt.Errorf("dynamic URL contains an invalid port")
	}
	parsed.Host = net.JoinHostPort(host, strconv.Itoa(port))
	return parsed, nil
}

func dynamicIPIsPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, prefix := range dynamicForbiddenPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// validateDynamicResolvedIPs rejects an entire DNS result if any answer is
// non-public. That all-or-nothing rule prevents mixed-answer rebinding from
// succeeding merely because one public address was returned first.
func validateDynamicResolvedIPs(ips []net.IP) ([]net.IP, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("dynamic target resolved to no IP addresses")
	}
	validated := make([]net.IP, 0, len(ips))
	seen := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, fmt.Errorf("dynamic target returned an invalid IP address")
		}
		addr = addr.Unmap()
		if !dynamicIPIsPublic(addr) {
			return nil, fmt.Errorf("dynamic target returned a non-public or special IP address")
		}
		if seen[addr] {
			continue
		}
		seen[addr] = true
		validated = append(validated, net.IP(addr.AsSlice()))
	}
	return validated, nil
}

var errDynamicSelfTarget = errors.New("dynamic target refers to Meridian or a local interface")

type dynamicInterfaceAddrsFunc func() ([]net.Addr, error)

// dynamicSelfTargetPolicy keeps immutable configured-host and baseline-interface
// snapshots, plus a live interface enumerator used again at resolution,
// transport construction, and immediately before each pinned dial.
type dynamicSelfTargetPolicy struct {
	deniedHosts    map[string]struct{}
	localIPs       map[netip.Addr]struct{}
	interfaceAddrs dynamicInterfaceAddrsFunc
}

func dynamicInterfaceAddrIP(value net.Addr) (netip.Addr, error) {
	if value == nil {
		return netip.Addr{}, fmt.Errorf("local interface returned a nil address")
	}
	var ip net.IP
	switch typed := value.(type) {
	case *net.IPNet:
		ip = typed.IP
	case *net.IPAddr:
		ip = typed.IP
	default:
		raw := value.String()
		if parsed, _, err := net.ParseCIDR(raw); err == nil {
			ip = parsed
		} else {
			if zone := strings.LastIndex(raw, "%"); zone >= 0 {
				raw = raw[:zone]
			}
			ip = net.ParseIP(raw)
		}
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("local interface returned an invalid IP address %q", value.String())
	}
	return addr.Unmap(), nil
}

func snapshotDynamicInterfaceIPs(interfaceAddrs dynamicInterfaceAddrsFunc) (map[netip.Addr]struct{}, error) {
	if interfaceAddrs == nil {
		interfaceAddrs = net.InterfaceAddrs
	}
	addresses, err := interfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("snapshot local interface addresses: %w", err)
	}
	localIPs := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		ip, err := dynamicInterfaceAddrIP(address)
		if err != nil {
			return nil, fmt.Errorf("snapshot local interface addresses: %w", err)
		}
		localIPs[ip] = struct{}{}
	}
	return localIPs, nil
}

func newDynamicSelfTargetPolicy(panelHost string, panelPort int, sites []Site, interfaceAddrs dynamicInterfaceAddrsFunc) (*dynamicSelfTargetPolicy, error) {
	if panelPort < 1 || panelPort > 65535 {
		return nil, fmt.Errorf("panel listener port must be between 1 and 65535")
	}
	panelHost, err := normalizePublicHost(panelHost)
	if err != nil {
		return nil, fmt.Errorf("invalid panel authority for dynamic self-target policy: %w", err)
	}
	if interfaceAddrs == nil {
		interfaceAddrs = net.InterfaceAddrs
	}
	localIPs, err := snapshotDynamicInterfaceIPs(interfaceAddrs)
	if err != nil {
		return nil, err
	}
	policy := &dynamicSelfTargetPolicy{
		deniedHosts:    make(map[string]struct{}, len(sites)+1),
		localIPs:       localIPs,
		interfaceAddrs: interfaceAddrs,
	}
	if panelHost != "" {
		policy.deniedHosts[panelHost] = struct{}{}
	}
	for _, site := range sites {
		publicHost, err := normalizePublicHost(site.PublicHost)
		if err != nil {
			return nil, fmt.Errorf("site %d has an invalid dynamic self-target authority: %w", site.ID, err)
		}
		mode, err := normalizeIngressMode(site.IngressMode, publicHost)
		if err != nil {
			return nil, fmt.Errorf("site %d has invalid ingress for dynamic self-target policy: %w", site.ID, err)
		}
		if publicHost != "" {
			policy.deniedHosts[publicHost] = struct{}{}
		}
		if ingressUsesPort(mode) && (site.ListenPort < 1 || site.ListenPort > 65535) {
			return nil, fmt.Errorf("site %d has an invalid listener port", site.ID)
		}
	}
	return policy, nil
}

func (p *dynamicSelfTargetPolicy) validateNormalizedTarget(target *url.URL) error {
	if p == nil {
		return fmt.Errorf("dynamic self-target policy snapshot is required")
	}
	if target == nil {
		return fmt.Errorf("dynamic target is required")
	}
	host, isIP, err := normalizeDynamicHost(target.Hostname())
	if err != nil {
		return fmt.Errorf("validate dynamic self-target authority: %w", err)
	}
	if _, denied := p.deniedHosts[host]; denied {
		return fmt.Errorf("%w: authority host %s is served by Meridian", errDynamicSelfTarget, host)
	}
	port := target.Port()
	if port == "" {
		return fmt.Errorf("validate dynamic self-target authority: target has no effective port")
	}
	if isIP {
		if err := p.validateIP(net.ParseIP(host)); err != nil {
			return fmt.Errorf("validate dynamic self-target literal: %w", err)
		}
	}
	return nil
}

func (p *dynamicSelfTargetPolicy) validateIPAgainst(ip net.IP, currentLocalIPs map[netip.Addr]struct{}) error {
	if p == nil {
		return fmt.Errorf("dynamic self-target policy snapshot is required")
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("dynamic target returned an invalid IP address")
	}
	addr = addr.Unmap()
	if _, denied := p.localIPs[addr]; denied {
		return fmt.Errorf("%w: resolved IP is assigned to a local interface", errDynamicSelfTarget)
	}
	if _, denied := currentLocalIPs[addr]; denied {
		return fmt.Errorf("%w: resolved IP is currently assigned to a local interface", errDynamicSelfTarget)
	}
	return nil
}

func (p *dynamicSelfTargetPolicy) validateIP(ip net.IP) error {
	if p == nil {
		return fmt.Errorf("dynamic self-target policy snapshot is required")
	}
	currentLocalIPs, err := snapshotDynamicInterfaceIPs(p.interfaceAddrs)
	if err != nil {
		return err
	}
	return p.validateIPAgainst(ip, currentLocalIPs)
}

func validateDynamicResolvedIPsWithPolicy(ips []net.IP, policy *dynamicSelfTargetPolicy) ([]net.IP, error) {
	if policy == nil {
		return nil, fmt.Errorf("dynamic self-target policy snapshot is required")
	}
	validated, err := validateDynamicResolvedIPs(ips)
	if err != nil {
		return nil, err
	}
	currentLocalIPs, err := snapshotDynamicInterfaceIPs(policy.interfaceAddrs)
	if err != nil {
		return nil, err
	}
	for _, ip := range validated {
		if err := policy.validateIPAgainst(ip, currentLocalIPs); err != nil {
			return nil, err
		}
	}
	return validated, nil
}

type dynamicIPResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

func resolveDynamicURLIPs(ctx context.Context, resolver dynamicIPResolver, target *url.URL, maxIPs int, policy *dynamicSelfTargetPolicy) ([]net.IP, error) {
	if policy == nil {
		return nil, fmt.Errorf("dynamic self-target policy snapshot is required")
	}
	if maxIPs < 1 || maxIPs > maxDynamicResolvedIPCount {
		return nil, fmt.Errorf("dynamic IP limit must be between 1 and %d", maxDynamicResolvedIPCount)
	}
	if target == nil {
		return nil, fmt.Errorf("dynamic target is required")
	}
	normalized, err := normalizeDynamicURL(target.String())
	if err != nil {
		return nil, err
	}
	if err := policy.validateNormalizedTarget(normalized); err != nil {
		return nil, err
	}
	if ip := net.ParseIP(normalized.Hostname()); ip != nil {
		return validateDynamicResolvedIPsWithPolicy([]net.IP{ip}, policy)
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	answers, err := resolver.LookupIPAddr(ctx, normalized.Hostname())
	if err != nil {
		return nil, fmt.Errorf("resolve dynamic target: %w", err)
	}
	if len(answers) > maxIPs {
		return nil, fmt.Errorf("dynamic target returned %d IP addresses, limit is %d", len(answers), maxIPs)
	}
	ips := make([]net.IP, 0, len(answers))
	for _, answer := range answers {
		if answer.Zone != "" {
			return nil, fmt.Errorf("dynamic target returned an IPv6 zone")
		}
		ips = append(ips, answer.IP)
	}
	return validateDynamicResolvedIPsWithPolicy(ips, policy)
}

type dynamicDialContextFunc func(context.Context, string, string) (net.Conn, error)

func newDynamicTransport(target *url.URL, pinnedIPs []net.IP, policy *dynamicSelfTargetPolicy) (*http.Transport, error) {
	if policy == nil {
		return nil, fmt.Errorf("dynamic self-target policy snapshot is required")
	}
	if len(pinnedIPs) < 1 || len(pinnedIPs) > maxDynamicResolvedIPCount {
		return nil, fmt.Errorf("dynamic transport requires between 1 and %d pinned IP addresses", maxDynamicResolvedIPCount)
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: -1}
	return newDynamicTransportWithDialer(target, pinnedIPs, dialer.DialContext, policy)
}

func newDynamicTransportWithDialer(target *url.URL, pinnedIPs []net.IP, dial dynamicDialContextFunc, policy *dynamicSelfTargetPolicy) (*http.Transport, error) {
	return newDynamicTransportWithDialerTimeout(target, pinnedIPs, dial, policy, dynamicPinnedDialTimeout)
}

func newDynamicTransportWithDialerTimeout(target *url.URL, pinnedIPs []net.IP, dial dynamicDialContextFunc, policy *dynamicSelfTargetPolicy, totalDialTimeout time.Duration) (*http.Transport, error) {
	if policy == nil {
		return nil, fmt.Errorf("dynamic self-target policy snapshot is required")
	}
	if len(pinnedIPs) < 1 || len(pinnedIPs) > maxDynamicResolvedIPCount {
		return nil, fmt.Errorf("dynamic transport requires between 1 and %d pinned IP addresses", maxDynamicResolvedIPCount)
	}
	if target == nil || dial == nil {
		return nil, fmt.Errorf("dynamic transport requires a target and dialer")
	}
	if totalDialTimeout <= 0 {
		return nil, fmt.Errorf("dynamic transport requires a positive total dial timeout")
	}
	normalized, err := normalizeDynamicURL(target.String())
	if err != nil {
		return nil, err
	}
	if err := policy.validateNormalizedTarget(normalized); err != nil {
		return nil, err
	}
	validated, err := validateDynamicResolvedIPsWithPolicy(pinnedIPs, policy)
	if err != nil {
		return nil, err
	}
	expectedHost := normalized.Hostname()
	expectedPort := normalized.Port()
	if directIP := net.ParseIP(expectedHost); directIP != nil {
		for _, pinnedIP := range validated {
			if !pinnedIP.Equal(directIP) {
				return nil, fmt.Errorf("dynamic transport pins do not match the literal target IP")
			}
		}
	}
	pins := validated

	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		TLSClientConfig:       secureTLSConfig(expectedHost),
		DialContext:           nil,
		MaxIdleConns:          -1,
		MaxIdleConnsPerHost:   -1,
		MaxConnsPerHost:       1,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("dynamic transport received an invalid dial authority: %w", err)
		}
		host, _, err = normalizeDynamicHost(host)
		if err != nil || host != expectedHost || port != expectedPort {
			return nil, fmt.Errorf("dynamic transport refused unpinned authority")
		}
		if err := policy.validateNormalizedTarget(normalized); err != nil {
			return nil, err
		}
		dialCtx, cancel := context.WithTimeout(ctx, totalDialTimeout)
		defer cancel()
		var lastErr error
		for _, ip := range pins {
			if err := dialCtx.Err(); err != nil {
				lastErr = err
				break
			}
			if (network == "tcp4" && ip.To4() == nil) || (network == "tcp6" && ip.To4() != nil) {
				continue
			}
			if err := policy.validateIP(ip); err != nil {
				return nil, err
			}
			conn, dialErr := dial(dialCtx, network, net.JoinHostPort(ip.String(), expectedPort))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no pinned IP address supports network %s", network)
		}
		return nil, fmt.Errorf("dial dynamic target using pinned IPs: %w", lastErr)
	}
	return transport, nil
}

func normalizeTargetURL(addr string) (*url.URL, error) {
	addr = strings.TrimSpace(addr)
	addr = strings.ReplaceAll(addr, "：", ":")
	if addr == "" {
		return nil, fmt.Errorf("target URL is required")
	}
	if len(addr) > 2048 {
		return nil, fmt.Errorf("target URL is too long")
	}
	explicitScheme := strings.Contains(addr, "://")
	if !explicitScheme {
		addr = "http://" + addr
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if !explicitScheme && parsed.Port() == "443" {
		parsed.Scheme = "https"
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Hostname() == "" || parsed.Opaque != "" {
		return nil, fmt.Errorf("invalid target URL")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("target URL must not contain credentials")
	}
	if parsed.Fragment != "" {
		return nil, fmt.Errorf("target URL must not contain a fragment")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return nil, fmt.Errorf("target URL contains an invalid port")
		}
	}
	return parsed, nil
}

// redactUpstreamURL keeps operator logs useful without retaining credentials,
// paths, or signed query parameters from configured upstreams.
func redactUpstreamURL(target *url.URL) string {
	if target == nil || target.Scheme == "" || target.Host == "" {
		return "configured upstream"
	}
	return strings.ToLower(target.Scheme) + "://" + target.Host
}

func redirectHostKey(target *url.URL) string {
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	if host == "" {
		return ""
	}
	port := target.Port()
	scheme := strings.ToLower(target.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "" && !((scheme == "http" && port == "80") || (scheme == "https" && port == "443")) {
		authority = net.JoinHostPort(host, port)
	}
	return scheme + "://" + authority
}

// sameRedirectAuthority reports whether two URLs share scheme, host, and
// effective port. Redirects that stay within the same authority may keep the
// client's headers; anything else is a cross-origin hop.
func sameRedirectAuthority(from, to *url.URL) bool {
	return redirectHostKey(from) == redirectHostKey(to)
}

func singleJoiningSlash(a, b string) string {
	aSlash := strings.HasSuffix(a, "/")
	bSlash := strings.HasPrefix(b, "/")
	switch {
	case aSlash && bSlash:
		return a + b[1:]
	case !aSlash && !bSlash:
		return a + "/" + b
	default:
		return a + b
	}
}

func joinURLPath(base, request *url.URL) (joinedPath, joinedRawPath string) {
	if base.RawPath == "" && request.RawPath == "" {
		return singleJoiningSlash(base.Path, request.Path), ""
	}
	basePath := base.EscapedPath()
	requestPath := request.EscapedPath()
	baseSlash := strings.HasSuffix(basePath, "/")
	requestSlash := strings.HasPrefix(requestPath, "/")
	switch {
	case baseSlash && requestSlash:
		return base.Path + request.Path[1:], basePath + requestPath[1:]
	case !baseSlash && !requestSlash:
		return base.Path + "/" + request.Path, basePath + "/" + requestPath
	default:
		return base.Path + request.Path, basePath + requestPath
	}
}

func applyUpstreamURL(requestURL, upstream *url.URL) {
	requestURL.Scheme = upstream.Scheme
	requestURL.Host = upstream.Host
	requestURL.Path, requestURL.RawPath = joinURLPath(upstream, requestURL)
	switch {
	case upstream.RawQuery == "":
	case requestURL.RawQuery == "":
		requestURL.RawQuery = upstream.RawQuery
	default:
		requestURL.RawQuery = upstream.RawQuery + "&" + requestURL.RawQuery
	}
}

func normalizePublicHost(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", nil
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" || len(value) > 253 || !strings.Contains(value, ".") {
		return "", fmt.Errorf("public_host must be a fully-qualified DNS name")
	}
	if strings.ContainsAny(value, "/:*[]") || net.ParseIP(value) != nil {
		return "", fmt.Errorf("public_host must not contain a scheme, path, port, wildcard, or IP address")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("public_host contains an invalid DNS label")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("public_host must use ASCII DNS labels; encode international names as punycode")
			}
		}
	}
	return value, nil
}

func normalizeIngressMode(value, publicHost string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(value))
	if mode == "" {
		if publicHost != "" {
			mode = ingressModeHost
		} else {
			mode = ingressModePort
		}
	}
	switch mode {
	case ingressModePort:
		if publicHost != "" {
			return "", fmt.Errorf("public_host must be empty when ingress_mode is port")
		}
	case ingressModeHost, ingressModeBoth:
		if publicHost == "" {
			return "", fmt.Errorf("public_host is required when ingress_mode is %s", mode)
		}
	default:
		return "", fmt.Errorf("ingress_mode must be port, host, or both")
	}
	return mode, nil
}

func ingressUsesPort(mode string) bool {
	return mode == ingressModePort || mode == ingressModeBoth
}

func ingressUsesHost(mode string) bool {
	return mode == ingressModeHost || mode == ingressModeBoth
}

func isReservedDynamicRoute(requestPath string) bool {
	return requestPath == strings.TrimSuffix(dynamicRoutePrefix, "/") || strings.HasPrefix(requestPath, dynamicRoutePrefix)
}

const (
	imageCacheTTL               = time.Hour
	imageCacheMaxBodyBytes      = int64(8 << 20)
	imageCacheMaxSiteBytes      = int64(64 << 20)
	imageCacheMaxProcessBytes   = int64(256 << 20)
	maxCacheReplayHeaderBytes   = int64(64 << 10)
	imageCacheEntryOverhead     = int64(512)
	maxCanonicalCacheQueryBytes = 64 << 10
)

func cacheHeaderValues(header http.Header, name string) ([]string, bool) {
	var values []string
	found := false
	for key, candidate := range header {
		if !strings.EqualFold(key, name) {
			continue
		}
		if found {
			return nil, false
		}
		found = true
		values = candidate
	}
	return values, true
}

func cacheHeaderPresent(header http.Header, name string) bool {
	for key := range header {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

type cacheControlDirectives map[string][]string

func parseCacheControlDirectives(header http.Header, name string) (cacheControlDirectives, bool) {
	values, ok := cacheHeaderValues(header, name)
	if !ok {
		return nil, false
	}
	directives := make(cacheControlDirectives)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				return nil, false
			}
			key, directiveValue, hasValue := strings.Cut(part, "=")
			key = strings.TrimSpace(key)
			if key == "" {
				return nil, false
			}
			for i := 0; i < len(key); i++ {
				if !isHTTPTokenByte(key[i]) {
					return nil, false
				}
			}
			if hasValue {
				directiveValue = strings.TrimSpace(directiveValue)
			}
			key = strings.ToLower(key)
			directives[key] = append(directives[key], directiveValue)
		}
	}
	return directives, true
}

func cacheDirectivePresent(directives cacheControlDirectives, name string) bool {
	_, ok := directives[strings.ToLower(name)]
	return ok
}

func cacheDirectiveValue(directives cacheControlDirectives, name string) (string, bool, bool) {
	values, exists := directives[strings.ToLower(name)]
	if !exists {
		return "", false, true
	}
	if len(values) == 0 {
		return "", true, false
	}
	for _, value := range values[1:] {
		if value != values[0] {
			return "", true, false
		}
	}
	return values[0], true, true
}

func cachePragmaNoCache(header http.Header) bool {
	values, ok := cacheHeaderValues(header, "Pragma")
	if !ok {
		return true
	}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "no-cache") {
				return true
			}
		}
	}
	return false
}

func cacheRequestForcesRevalidation(r *http.Request) bool {
	if r == nil {
		return true
	}
	for _, name := range []string{"If-Match", "If-Modified-Since", "If-None-Match", "If-Unmodified-Since"} {
		if cacheHeaderPresent(r.Header, name) {
			return true
		}
	}
	directives, ok := parseCacheControlDirectives(r.Header, "Cache-Control")
	if !ok {
		return true
	}
	for _, name := range []string{"no-cache", "no-store", "max-age", "min-fresh", "max-stale", "only-if-cached"} {
		if cacheDirectivePresent(directives, name) {
			return true
		}
	}
	return cachePragmaNoCache(r.Header)
}

func cacheCredentialQueryName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch lower {
	case "api_key", "apikey", "access_token", "auth", "authorization", "key", "sig", "signature", "token",
		"x-emby-token", "x-mediabrowser-token", "x_emby_token", "x_mediabrowser_token",
		"x-amz-credential", "x-amz-security-token", "x-amz-signature", "x-goog-credential", "x-goog-signature":
		return true
	default:
		return strings.HasSuffix(lower, "_token") || strings.HasSuffix(lower, "-token")
	}
}

func splitCanonicalCacheQuery(rawQuery string) (string, string, bool) {
	if len(rawQuery) > maxCanonicalCacheQueryBytes {
		return "", "", false
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", "", false
	}
	representation := make(url.Values)
	credentials := make(url.Values)
	for name, original := range values {
		if cacheCredentialQueryName(name) {
			credentials[name] = original
		} else {
			representation[name] = original
		}
	}
	return representation.Encode(), credentials.Encode(), true
}

func writeCacheIdentityField(dst io.Writer, value string) {
	_, _ = io.WriteString(dst, strconv.Itoa(len(value)))
	_, _ = io.WriteString(dst, ":")
	_, _ = io.WriteString(dst, value)
}

func deriveCacheCredentialKey(master []byte, purpose string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, master)
	writeCacheIdentityField(mac, "meridian-memory-cache-v1")
	writeCacheIdentityField(mac, purpose)
	var key [sha256.Size]byte
	copy(key[:], mac.Sum(nil))
	return key
}

func cacheCredentialDigest(key [sha256.Size]byte, credentialQuery string, header http.Header) ([sha256.Size]byte, bool) {
	mac := hmac.New(sha256.New, key[:])
	writeCacheIdentityField(mac, credentialQuery)
	effective := header.Clone()
	stripCookieByName(effective, sessionCookieName)
	for _, name := range []string{"Authorization", "Cookie", "Proxy-Authorization", "X-Api-Key", "X-Emby-Authorization", "X-Emby-Token", "X-MediaBrowser-Token"} {
		values, ok := cacheHeaderValues(effective, name)
		if !ok {
			return [sha256.Size]byte{}, false
		}
		writeCacheIdentityField(mac, strings.ToLower(name))
		writeCacheIdentityField(mac, strconv.Itoa(len(values)))
		for _, value := range values {
			writeCacheIdentityField(mac, value)
		}
	}
	var digest [sha256.Size]byte
	copy(digest[:], mac.Sum(nil))
	return digest, true
}

func cacheHeaderDigest(header http.Header, names ...string) ([sha256.Size]byte, bool) {
	digest := sha256.New()
	for _, name := range names {
		values, ok := cacheHeaderValues(header, name)
		if !ok {
			return [sha256.Size]byte{}, false
		}
		writeCacheIdentityField(digest, strings.ToLower(name))
		writeCacheIdentityField(digest, strconv.Itoa(len(values)))
		for _, value := range values {
			writeCacheIdentityField(digest, value)
		}
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, true
}

func safeCachedResponseHeaders(header http.Header, allowed []string) (http.Header, int64, bool) {
	return safeCachedResponseHeadersWithin(header, allowed, maxCacheReplayHeaderBytes)
}

func safeCachedResponseHeadersWithin(header http.Header, allowed []string, maxBytes int64) (http.Header, int64, bool) {
	if maxBytes < 0 || maxBytes > maxCacheReplayHeaderBytes {
		return nil, 0, false
	}
	replay := make(http.Header)
	var retained int64
	for _, name := range allowed {
		values, ok := cacheHeaderValues(header, name)
		if !ok {
			return nil, 0, false
		}
		for _, value := range values {
			retained += int64(len(name) + len(value) + 16)
			if retained > maxBytes {
				return nil, 0, false
			}
			replay.Add(name, value)
		}
	}
	return replay, retained, true
}

type imageCacheKey struct {
	siteID             int64
	primaryAuthority   string
	canonicalPath      string
	canonicalQuery     string
	forceQuery         bool
	credentialIdentity [sha256.Size]byte
	representation     [sha256.Size]byte
}

const imageCacheContentLengthReservationBytes = int64(len("Content-Length") + 20 + 16)

func imageCacheKeyBytes(key imageCacheKey) int64 {
	return int64(len(key.primaryAuthority)) + int64(len(key.canonicalPath)) + int64(len(key.canonicalQuery))
}

func imageCacheMaximumFlightReservation(key imageCacheKey) int64 {
	return imageCacheMaxBodyBytes + maxCacheReplayHeaderBytes + imageCacheEntryOverhead + imageCacheKeyBytes(key)
}

type imageCacheEntry struct {
	key                    imageCacheKey
	owner                  *imageCacheSite
	header                 http.Header
	body                   []byte
	responseAt             time.Time
	initialAge             time.Duration
	expiresAt              time.Time
	cost                   int64
	globalPrev, globalNext *imageCacheEntry
	sitePrev, siteNext     *imageCacheEntry
}

type imageCacheFlight struct {
	done           chan struct{}
	stored         bool
	reservedBytes  int64
	captureStarted bool
}

type imageCacheRuntime struct {
	mu              sync.Mutex
	maxProcessBytes int64
	maxSiteBytes    int64
	ttl             time.Duration
	now             func() time.Time
	credentialKey   [sha256.Size]byte
	bytes           int64
	globalHead      *imageCacheEntry
	globalTail      *imageCacheEntry
}

type imageCacheSite struct {
	runtime *imageCacheRuntime
	siteID  int64
	closed  bool
	entries map[imageCacheKey]*imageCacheEntry
	flights map[imageCacheKey]*imageCacheFlight
	bytes   int64
	head    *imageCacheEntry
	tail    *imageCacheEntry
}

func newImageCacheRuntime(masterKey []byte) *imageCacheRuntime {
	return newImageCacheRuntimeWithLimits(imageCacheMaxProcessBytes, imageCacheMaxSiteBytes, imageCacheTTL, masterKey)
}

func newImageCacheRuntimeWithLimits(processBytes, siteBytes int64, ttl time.Duration, masterKey []byte) *imageCacheRuntime {
	return &imageCacheRuntime{
		maxProcessBytes: processBytes,
		maxSiteBytes:    siteBytes,
		ttl:             ttl,
		now:             time.Now,
		credentialKey:   deriveCacheCredentialKey(masterKey, "emby-image"),
	}
}

func (runtime *imageCacheRuntime) currentTime() time.Time {
	if runtime != nil && runtime.now != nil {
		return runtime.now()
	}
	return time.Now()
}

func (runtime *imageCacheRuntime) newSite(siteID int64) *imageCacheSite {
	if runtime == nil {
		return nil
	}
	return &imageCacheSite{
		runtime: runtime,
		siteID:  siteID,
		entries: make(map[imageCacheKey]*imageCacheEntry),
		flights: make(map[imageCacheKey]*imageCacheFlight),
	}
}

func (runtime *imageCacheRuntime) unlinkGlobal(entry *imageCacheEntry) {
	if entry.globalPrev != nil {
		entry.globalPrev.globalNext = entry.globalNext
	} else {
		runtime.globalHead = entry.globalNext
	}
	if entry.globalNext != nil {
		entry.globalNext.globalPrev = entry.globalPrev
	} else {
		runtime.globalTail = entry.globalPrev
	}
	entry.globalPrev, entry.globalNext = nil, nil
}

func (runtime *imageCacheRuntime) linkGlobalFront(entry *imageCacheEntry) {
	entry.globalNext = runtime.globalHead
	entry.globalPrev = nil
	if runtime.globalHead != nil {
		runtime.globalHead.globalPrev = entry
	} else {
		runtime.globalTail = entry
	}
	runtime.globalHead = entry
}

func (site *imageCacheSite) unlink(entry *imageCacheEntry) {
	if entry.sitePrev != nil {
		entry.sitePrev.siteNext = entry.siteNext
	} else {
		site.head = entry.siteNext
	}
	if entry.siteNext != nil {
		entry.siteNext.sitePrev = entry.sitePrev
	} else {
		site.tail = entry.sitePrev
	}
	entry.sitePrev, entry.siteNext = nil, nil
}

func (site *imageCacheSite) linkFront(entry *imageCacheEntry) {
	entry.siteNext = site.head
	entry.sitePrev = nil
	if site.head != nil {
		site.head.sitePrev = entry
	} else {
		site.tail = entry
	}
	site.head = entry
}

func (runtime *imageCacheRuntime) remove(entry *imageCacheEntry) {
	if entry == nil || entry.owner == nil || entry.owner.entries[entry.key] != entry {
		return
	}
	site := entry.owner
	delete(site.entries, entry.key)
	runtime.unlinkGlobal(entry)
	site.unlink(entry)
	runtime.bytes -= entry.cost
	site.bytes -= entry.cost
	if runtime.bytes < 0 {
		runtime.bytes = 0
	}
	if site.bytes < 0 {
		site.bytes = 0
	}
}

func (site *imageCacheSite) getLocked(key imageCacheKey, now time.Time) *imageCacheEntry {
	entry := site.entries[key]
	if entry == nil {
		return nil
	}
	if !now.Before(entry.expiresAt) {
		site.runtime.remove(entry)
		return nil
	}
	site.runtime.unlinkGlobal(entry)
	site.runtime.linkGlobalFront(entry)
	site.unlink(entry)
	site.linkFront(entry)
	return entry
}

func (site *imageCacheSite) storeLocked(key imageCacheKey, entry *imageCacheEntry, now time.Time) bool {
	runtime := site.runtime
	if site.closed || entry == nil || !now.Before(entry.expiresAt) || runtime.maxProcessBytes <= 0 || runtime.maxSiteBytes <= 0 {
		return false
	}
	entry.key, entry.owner = key, site
	entry.cost += imageCacheKeyBytes(key)
	if entry.cost > runtime.maxSiteBytes || entry.cost > runtime.maxProcessBytes {
		return false
	}
	if old := site.entries[key]; old != nil {
		runtime.remove(old)
	}
	site.entries[key] = entry
	site.linkFront(entry)
	runtime.linkGlobalFront(entry)
	site.bytes += entry.cost
	runtime.bytes += entry.cost
	for site.bytes > runtime.maxSiteBytes && site.tail != nil {
		runtime.remove(site.tail)
	}
	for runtime.bytes > runtime.maxProcessBytes && runtime.globalTail != nil {
		runtime.remove(runtime.globalTail)
	}
	return site.entries[key] == entry
}

func (site *imageCacheSite) reserveFlightLocked(key imageCacheKey) int64 {
	runtime := site.runtime
	if runtime.maxProcessBytes <= 0 || runtime.maxSiteBytes <= 0 {
		return 0
	}
	keyBytes := imageCacheKeyBytes(key)
	minimum := imageCacheEntryOverhead + keyBytes + imageCacheContentLengthReservationBytes
	target := imageCacheMaximumFlightReservation(key)
	if target > runtime.maxSiteBytes {
		target = runtime.maxSiteBytes
	}
	if target > runtime.maxProcessBytes {
		target = runtime.maxProcessBytes
	}
	if target <= minimum {
		return 0
	}
	for {
		siteAvailable := runtime.maxSiteBytes - site.bytes
		processAvailable := runtime.maxProcessBytes - runtime.bytes
		available := siteAvailable
		if processAvailable < available {
			available = processAvailable
		}
		if available > minimum {
			reservation := target
			if reservation > available {
				reservation = available
			}
			site.bytes += reservation
			runtime.bytes += reservation
			return reservation
		}
		if siteAvailable <= minimum {
			if site.tail == nil {
				return 0
			}
			runtime.remove(site.tail)
			continue
		}
		if processAvailable <= minimum {
			if runtime.globalTail == nil {
				return 0
			}
			runtime.remove(runtime.globalTail)
			continue
		}
		return 0
	}
}

func (site *imageCacheSite) releaseFlightReservationLocked(flight *imageCacheFlight) {
	if flight == nil || flight.reservedBytes <= 0 {
		return
	}
	reservation := flight.reservedBytes
	flight.reservedBytes = 0
	site.bytes -= reservation
	site.runtime.bytes -= reservation
	if site.bytes < 0 {
		site.bytes = 0
	}
	if site.runtime.bytes < 0 {
		site.runtime.bytes = 0
	}
}

func (site *imageCacheSite) lookup(key imageCacheKey, now time.Time) (*imageCacheEntry, *imageCacheFlight, bool) {
	if site == nil || site.runtime == nil {
		return nil, nil, false
	}
	site.runtime.mu.Lock()
	defer site.runtime.mu.Unlock()
	if site.closed {
		return nil, nil, false
	}
	return site.getLocked(key, now), site.flights[key], true
}

func (site *imageCacheSite) lookupOrBegin(key imageCacheKey, now time.Time) (*imageCacheEntry, *imageCacheFlight, bool, bool) {
	if site == nil || site.runtime == nil {
		return nil, nil, false, false
	}
	site.runtime.mu.Lock()
	defer site.runtime.mu.Unlock()
	if site.closed {
		return nil, nil, false, false
	}
	if entry := site.getLocked(key, now); entry != nil {
		return entry, nil, false, true
	}
	if flight := site.flights[key]; flight != nil {
		return nil, flight, false, true
	}
	reservation := site.reserveFlightLocked(key)
	if reservation <= 0 {
		return nil, nil, false, false
	}
	flight := &imageCacheFlight{done: make(chan struct{}), reservedBytes: reservation}
	site.flights[key] = flight
	return nil, flight, true, true
}

func (site *imageCacheSite) beginFlightCapture(key imageCacheKey, flight *imageCacheFlight) (int64, bool) {
	if site == nil || site.runtime == nil || flight == nil {
		return 0, false
	}
	site.runtime.mu.Lock()
	defer site.runtime.mu.Unlock()
	if site.closed || site.flights[key] != flight || flight.reservedBytes <= 0 {
		return 0, false
	}
	flight.captureStarted = true
	return flight.reservedBytes, true
}

func (site *imageCacheSite) finishFlight(key imageCacheKey, flight *imageCacheFlight, entry *imageCacheEntry, now time.Time) {
	if site == nil || site.runtime == nil || flight == nil {
		return
	}
	site.runtime.mu.Lock()
	defer site.runtime.mu.Unlock()
	if site.flights[key] != flight {
		site.releaseFlightReservationLocked(flight)
		return
	}
	keyBytes := imageCacheKeyBytes(key)
	entryFits := entry != nil && entry.cost <= flight.reservedBytes && keyBytes <= flight.reservedBytes-entry.cost
	site.releaseFlightReservationLocked(flight)
	if entryFits {
		flight.stored = site.storeLocked(key, entry, now)
	}
	delete(site.flights, key)
	close(flight.done)
}

func (site *imageCacheSite) close() {
	if site == nil || site.runtime == nil {
		return
	}
	site.runtime.mu.Lock()
	defer site.runtime.mu.Unlock()
	if site.closed {
		return
	}
	site.closed = true
	for site.tail != nil {
		site.runtime.remove(site.tail)
	}
	for key, flight := range site.flights {
		if !flight.captureStarted {
			site.releaseFlightReservationLocked(flight)
		}
		delete(site.flights, key)
		close(flight.done)
	}
}

func normalizeEmbyImageCachePath(requestURL *url.URL) (string, bool) {
	if requestURL == nil || requestURL.Opaque != "" || requestURL.Fragment != "" || requestURL.RawFragment != "" {
		return "", false
	}
	if requestURL.RawPath != "" {
		decoded, err := url.PathUnescape(requestURL.RawPath)
		if err != nil || decoded != requestURL.Path {
			return "", false
		}
	}
	escaped := requestURL.EscapedPath()
	if !strings.HasPrefix(escaped, "/") {
		return "", false
	}
	rawSegments := strings.Split(strings.TrimPrefix(escaped, "/"), "/")
	if len(rawSegments) < 4 {
		return "", false
	}
	segments := make([]string, len(rawSegments))
	for i, raw := range rawSegments {
		decoded, err := url.PathUnescape(raw)
		if err != nil || decoded == "" || decoded == "." || decoded == ".." || !utf8.ValidString(decoded) || strings.ContainsAny(decoded, "/\\") || strings.IndexFunc(decoded, unicode.IsControl) >= 0 {
			return "", false
		}
		segments[i] = decoded
	}
	base := 0
	if strings.EqualFold(segments[0], "emby") {
		if len(segments) < 5 {
			return "", false
		}
		segments[0] = "emby"
		base = 1
	}
	if !strings.EqualFold(segments[base], "Items") || !strings.EqualFold(segments[base+2], "Images") || len(segments) <= base+3 {
		return "", false
	}
	segments[base] = "Items"
	segments[base+2] = "Images"
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return "/" + strings.Join(segments, "/"), true
}

func imageCacheRequestKeyFor(site *imageCacheSite, primary *url.URL, r *http.Request) (imageCacheKey, bool) {
	if site == nil || site.runtime == nil || primary == nil || r == nil || r.URL == nil || r.Method != http.MethodGet && r.Method != http.MethodHead {
		return imageCacheKey{}, false
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 || r.Body != nil && r.Body != http.NoBody || hasUpgradeIntent(r) || isReservedDynamicRoute(r.URL.Path) || cacheRequestForcesRevalidation(r) {
		return imageCacheKey{}, false
	}
	if cacheHeaderPresent(r.Header, "Range") || cacheHeaderPresent(r.Header, "If-Range") {
		return imageCacheKey{}, false
	}
	canonicalRoute, ok := normalizeEmbyImageCachePath(r.URL)
	if !ok {
		return imageCacheKey{}, false
	}
	decodedRoute, err := url.PathUnescape(canonicalRoute)
	if err != nil {
		return imageCacheKey{}, false
	}
	upstreamURL := &url.URL{Path: decodedRoute, RawPath: canonicalRoute, RawQuery: r.URL.RawQuery, ForceQuery: r.URL.ForceQuery}
	applyUpstreamURL(upstreamURL, primary)
	representationQuery, credentialQuery, ok := splitCanonicalCacheQuery(upstreamURL.RawQuery)
	if !ok {
		return imageCacheKey{}, false
	}
	credentialIdentity, ok := cacheCredentialDigest(site.runtime.credentialKey, credentialQuery, r.Header)
	if !ok {
		return imageCacheKey{}, false
	}
	representation, ok := cacheHeaderDigest(r.Header, "Accept", "Accept-Encoding")
	if !ok {
		return imageCacheKey{}, false
	}
	authority := redirectHostKey(primary)
	if authority == "" {
		return imageCacheKey{}, false
	}
	return imageCacheKey{
		siteID: site.siteID, primaryAuthority: authority, canonicalPath: upstreamURL.EscapedPath(),
		canonicalQuery: representationQuery, forceQuery: upstreamURL.ForceQuery,
		credentialIdentity: credentialIdentity, representation: representation,
	}, true
}

var imageCacheReplayHeaderNames = []string{
	"Accept-Ranges", "Access-Control-Allow-Credentials", "Access-Control-Allow-Headers",
	"Access-Control-Allow-Methods", "Access-Control-Allow-Origin", "Access-Control-Expose-Headers",
	"Cache-Control", "Content-Disposition", "Content-Encoding", "Content-Language", "Content-Type", "Date",
	"Cross-Origin-Resource-Policy", "ETag", "Expires", "Last-Modified", "Timing-Allow-Origin", "Vary",
	"X-Content-Type-Options",
}

func imageCacheSafeVary(header http.Header) bool {
	values, ok := cacheHeaderValues(header, "Vary")
	if !ok {
		return false
	}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			name := strings.TrimSpace(part)
			if name == "" {
				return false
			}
			for i := 0; i < len(name); i++ {
				if !isHTTPTokenByte(name[i]) {
					return false
				}
			}
			if !strings.EqualFold(name, "Accept") && !strings.EqualFold(name, "Accept-Encoding") {
				return false
			}
		}
	}
	return true
}

func parseCacheDeltaSeconds(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	const maxSeconds = uint64((1<<63 - 1) / int64(time.Second))
	var seconds uint64
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
		digit := uint64(value[i] - '0')
		if seconds > (maxSeconds-digit)/10 {
			return 0, false
		}
		seconds = seconds*10 + digit
	}
	return time.Duration(seconds * uint64(time.Second)), true
}

func cacheResponseFreshness(header http.Header, now time.Time, ttl time.Duration) (time.Time, time.Duration, bool) {
	if ttl <= 0 {
		return time.Time{}, 0, false
	}
	directives, ok := parseCacheControlDirectives(header, "Cache-Control")
	if !ok {
		return time.Time{}, 0, false
	}
	for _, name := range []string{"private", "no-store", "no-cache"} {
		if cacheDirectivePresent(directives, name) {
			return time.Time{}, 0, false
		}
	}

	initialAge := time.Duration(0)
	ageValues, ok := cacheHeaderValues(header, "Age")
	if !ok || len(ageValues) > 1 {
		return time.Time{}, 0, false
	}
	if len(ageValues) == 1 {
		initialAge, ok = parseCacheDeltaSeconds(ageValues[0])
		if !ok {
			return time.Time{}, 0, false
		}
	}

	var dateValue time.Time
	hasDate := false
	dateValues, ok := cacheHeaderValues(header, "Date")
	if !ok || len(dateValues) > 1 {
		return time.Time{}, 0, false
	}
	if len(dateValues) == 1 {
		dateValue, _ = http.ParseTime(strings.TrimSpace(dateValues[0]))
		if dateValue.IsZero() {
			return time.Time{}, 0, false
		}
		hasDate = true
		if apparentAge := now.Sub(dateValue); apparentAge > initialAge {
			initialAge = apparentAge
		}
	}
	const maxAgeDuration = time.Duration(1<<63 - 1)
	if initialAge < 0 {
		initialAge = 0
	} else if initialAge == maxAgeDuration {
		return time.Time{}, 0, false
	}

	remaining := ttl
	maxAge, exists, valid := cacheDirectiveValue(directives, "s-maxage")
	if !exists {
		maxAge, exists, valid = cacheDirectiveValue(directives, "max-age")
	}
	if !valid {
		return time.Time{}, 0, false
	}
	if exists {
		freshnessLifetime, valid := parseCacheDeltaSeconds(maxAge)
		if !valid || freshnessLifetime <= initialAge {
			return time.Time{}, 0, false
		}
		if originRemaining := freshnessLifetime - initialAge; originRemaining < remaining {
			remaining = originRemaining
		}
	} else {
		expiresValues, valid := cacheHeaderValues(header, "Expires")
		if !valid || len(expiresValues) > 1 {
			return time.Time{}, 0, false
		}
		if len(expiresValues) == 1 {
			expiresValue, err := http.ParseTime(strings.TrimSpace(expiresValues[0]))
			if err != nil {
				return time.Time{}, 0, false
			}
			freshnessLifetime := expiresValue.Sub(now)
			if hasDate {
				freshnessLifetime = expiresValue.Sub(dateValue)
			}
			if freshnessLifetime <= initialAge {
				return time.Time{}, 0, false
			}
			if originRemaining := freshnessLifetime - initialAge; originRemaining < remaining {
				remaining = originRemaining
			}
		}
	}
	if remaining <= 0 {
		return time.Time{}, 0, false
	}
	return now.Add(remaining), initialAge, true
}

func cacheResponseAgeValue(initialAge time.Duration, responseAt, now time.Time) string {
	if initialAge < 0 {
		initialAge = 0
	}
	resident := now.Sub(responseAt)
	if resident < 0 {
		resident = 0
	}
	const maxAgeDuration = time.Duration(1<<63 - 1)
	if initialAge > maxAgeDuration-resident {
		initialAge = maxAgeDuration
	} else {
		initialAge += resident
	}
	seconds := int64(initialAge / time.Second)
	if initialAge%time.Second != 0 {
		seconds++
	}
	return strconv.FormatInt(seconds, 10)
}

type imageCacheMetadata struct {
	header            http.Header
	declaredLength    int64
	hasDeclaredLength bool
	expiresAt         time.Time
	initialAge        time.Duration
	replayHeaderBytes int64
}

func imageCacheResponseMetadata(header http.Header, status int, now time.Time, ttl time.Duration, maxHeaderBytes int64) (imageCacheMetadata, bool) {
	if status != http.StatusOK || cacheHeaderPresent(header, "Set-Cookie") || cacheHeaderPresent(header, "Content-Range") || cacheHeaderPresent(header, "Trailer") || cacheHeaderPresent(header, "Warning") || cachePragmaNoCache(header) || !imageCacheSafeVary(header) {
		return imageCacheMetadata{}, false
	}
	contentTypes, ok := cacheHeaderValues(header, "Content-Type")
	if !ok || len(contentTypes) != 1 {
		return imageCacheMetadata{}, false
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	mediaType = strings.ToLower(mediaType)
	if err != nil || !strings.HasPrefix(mediaType, "image/") || len(mediaType) <= len("image/") || strings.TrimPrefix(mediaType, "image/") == "*" {
		return imageCacheMetadata{}, false
	}
	for _, name := range []string{"Surrogate-Control", "CDN-Cache-Control"} {
		directives, valid := parseCacheControlDirectives(header, name)
		if !valid {
			return imageCacheMetadata{}, false
		}
		for _, forbidden := range []string{"private", "no-store", "no-cache"} {
			if cacheDirectivePresent(directives, forbidden) {
				return imageCacheMetadata{}, false
			}
		}
	}
	declaredLength := int64(0)
	hasDeclaredLength := false
	lengths, ok := cacheHeaderValues(header, "Content-Length")
	if !ok || len(lengths) > 1 {
		return imageCacheMetadata{}, false
	}
	if len(lengths) == 1 {
		declaredLength, err = strconv.ParseInt(strings.TrimSpace(lengths[0]), 10, 64)
		if err != nil || declaredLength < 0 || declaredLength > imageCacheMaxBodyBytes {
			return imageCacheMetadata{}, false
		}
		hasDeclaredLength = true
	}
	expiresAt, initialAge, fresh := cacheResponseFreshness(header, now, ttl)
	if !fresh {
		return imageCacheMetadata{}, false
	}
	replay, headerBytes, safe := safeCachedResponseHeadersWithin(header, imageCacheReplayHeaderNames, maxHeaderBytes)
	if !safe {
		return imageCacheMetadata{}, false
	}
	return imageCacheMetadata{
		header: replay, declaredLength: declaredLength, hasDeclaredLength: hasDeclaredLength,
		expiresAt: expiresAt, initialAge: initialAge, replayHeaderBytes: headerBytes,
	}, true
}

type imageCacheCaptureWriter struct {
	http.ResponseWriter
	runtime           *imageCacheRuntime
	reservedBytes     int64
	keyBytes          int64
	captureLimit      int64
	wroteFinal        bool
	sawInformational  bool
	cacheable         bool
	complete          bool
	declaredLength    int64
	hasDeclaredLength bool
	responseAt        time.Time
	initialAge        time.Duration
	expiresAt         time.Time
	replayHeader      http.Header
	replayHeaderBytes int64
	body              []byte
}

func newImageCacheCaptureWriter(w http.ResponseWriter, runtime *imageCacheRuntime, reservedBytes, keyBytes int64) *imageCacheCaptureWriter {
	return &imageCacheCaptureWriter{
		ResponseWriter: w, runtime: runtime, reservedBytes: reservedBytes, keyBytes: keyBytes, complete: true,
	}
}

func (w *imageCacheCaptureWriter) discard() {
	w.cacheable = false
	w.complete = false
	w.captureLimit = 0
	w.body = nil
	w.replayHeader = nil
}

func (w *imageCacheCaptureWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		w.sawInformational = true
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.wroteFinal {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.wroteFinal = true
	if w.runtime != nil {
		w.responseAt = w.runtime.currentTime()
		maxHeaderBytes := w.reservedBytes - w.keyBytes - imageCacheEntryOverhead - imageCacheContentLengthReservationBytes
		if maxHeaderBytes > maxCacheReplayHeaderBytes {
			maxHeaderBytes = maxCacheReplayHeaderBytes
		}
		metadata, cacheable := imageCacheResponseMetadata(w.Header(), status, w.responseAt, w.runtime.ttl, maxHeaderBytes)
		w.cacheable = cacheable && !w.sawInformational
		if w.cacheable {
			w.declaredLength = metadata.declaredLength
			w.hasDeclaredLength = metadata.hasDeclaredLength
			w.expiresAt = metadata.expiresAt
			w.initialAge = metadata.initialAge
			w.replayHeader = metadata.header
			w.replayHeaderBytes = metadata.replayHeaderBytes
			w.captureLimit = w.reservedBytes - w.keyBytes - imageCacheEntryOverhead - w.replayHeaderBytes - imageCacheContentLengthReservationBytes
			if w.captureLimit > imageCacheMaxBodyBytes {
				w.captureLimit = imageCacheMaxBodyBytes
			}
			if w.captureLimit < 0 || w.hasDeclaredLength && w.declaredLength > w.captureLimit {
				w.discard()
			} else {
				capacity := w.captureLimit
				if w.hasDeclaredLength {
					capacity = w.declaredLength
				}
				if capacity < 0 || capacity > imageCacheMaxBodyBytes {
					w.discard()
				} else if capacity > 0 {
					w.body = make([]byte, 0, int(capacity))
				}
			}
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *imageCacheCaptureWriter) Write(payload []byte) (int, error) {
	if !w.wroteFinal {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(payload)
	if w.cacheable {
		captured := int64(len(w.body)) + int64(n)
		if err != nil || n != len(payload) || captured > w.captureLimit || w.hasDeclaredLength && captured > w.declaredLength {
			w.discard()
		} else if n > 0 {
			w.body = append(w.body, payload[:n]...)
		}
	}
	return n, err
}

func (w *imageCacheCaptureWriter) Flush() {
	if !w.wroteFinal {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *imageCacheCaptureWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *imageCacheCaptureWriter) entry() *imageCacheEntry {
	if !w.wroteFinal || !w.cacheable || !w.complete || int64(len(w.body)) > w.captureLimit || w.hasDeclaredLength && int64(len(w.body)) != w.declaredLength || w.replayHeader == nil {
		return nil
	}
	w.replayHeader.Set("Content-Length", strconv.Itoa(len(w.body)))
	headerBytes := w.replayHeaderBytes + int64(len("Content-Length")+len(w.replayHeader.Get("Content-Length"))+16)
	if headerBytes > maxCacheReplayHeaderBytes {
		return nil
	}
	cost := int64(cap(w.body)) + headerBytes + imageCacheEntryOverhead
	if cost > w.reservedBytes || w.keyBytes > w.reservedBytes-cost {
		return nil
	}
	body := w.body
	w.body = nil
	header := w.replayHeader
	w.replayHeader = nil
	return &imageCacheEntry{
		header: header, body: body, responseAt: w.responseAt, initialAge: w.initialAge, expiresAt: w.expiresAt,
		cost: cost,
	}
}

func serveImageCacheEntry(w http.ResponseWriter, r *http.Request, entry *imageCacheEntry, now time.Time) {
	header := w.Header()
	for name := range header {
		delete(header, name)
	}
	for name, values := range entry.header {
		for _, value := range values {
			header.Add(name, value)
		}
	}
	header.Set("Age", cacheResponseAgeValue(entry.initialAge, entry.responseAt, now))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(entry.body)
	}
}

func (site *imageCacheSite) serve(w http.ResponseWriter, r *http.Request, primary *url.URL, next http.Handler) {
	key, eligible := imageCacheRequestKeyFor(site, primary, r)
	if !eligible {
		next.ServeHTTP(w, r)
		return
	}
	now := site.runtime.currentTime()
	if r.Method == http.MethodHead {
		entry, flight, available := site.lookup(key, now)
		if !available {
			next.ServeHTTP(w, r)
			return
		}
		if entry != nil {
			serveImageCacheEntry(w, r, entry, now)
			return
		}
		if flight != nil {
			select {
			case <-flight.done:
				hitNow := site.runtime.currentTime()
				if entry, _, available := site.lookup(key, hitNow); available && entry != nil {
					serveImageCacheEntry(w, r, entry, hitNow)
					return
				}
			case <-r.Context().Done():
			}
		}
		next.ServeHTTP(w, r)
		return
	}

	entry, flight, leader, available := site.lookupOrBegin(key, now)
	if !available {
		next.ServeHTTP(w, r)
		return
	}
	if entry != nil {
		serveImageCacheEntry(w, r, entry, now)
		return
	}
	if !leader {
		select {
		case <-flight.done:
			hitNow := site.runtime.currentTime()
			if entry, _, available := site.lookup(key, hitNow); available && entry != nil {
				serveImageCacheEntry(w, r, entry, hitNow)
				return
			}
		case <-r.Context().Done():
		}
		next.ServeHTTP(w, r)
		return
	}

	var candidate *imageCacheEntry
	defer func() {
		site.finishFlight(key, flight, candidate, site.runtime.currentTime())
	}()
	reservedBytes, captureAllowed := site.beginFlightCapture(key, flight)
	if !captureAllowed {
		next.ServeHTTP(w, r)
		return
	}
	capture := newImageCacheCaptureWriter(w, site.runtime, reservedBytes, imageCacheKeyBytes(key))
	next.ServeHTTP(capture, r)
	// Publication happens only after ReverseProxy returns from a complete body
	// copy. Panics, short writes, client disconnects and length mismatches leave
	// candidate nil and merely wake identical waiters.
	candidate = capture.entry()
}

func requestPublicHost(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" || strings.HasPrefix(hostport, "[") {
		return ""
	}
	host := hostport
	if parsedHost, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsedHost
	} else if strings.Contains(hostport, ":") {
		return ""
	}
	normalized, err := normalizePublicHost(host)
	if err != nil {
		return ""
	}
	return normalized
}

func validateSiteSettings(name string, listenPort int, targetURL, playbackTargetURL, playbackMode string, streamHosts []string, uaMode, customUserAgent, customClient, customVersion string, quota int64, speedLimit int) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 || strings.ContainsAny(name, "\r\n") {
		return fmt.Errorf("name must be 1-100 characters without line breaks")
	}
	if listenPort < 1 || listenPort > 65535 {
		return fmt.Errorf("listen_port must be between 1 and 65535")
	}
	if len(targetURL) > maxTargetURLLength {
		return fmt.Errorf("target_url must not exceed %d bytes", maxTargetURLLength)
	}
	if _, err := normalizeTargetURL(targetURL); err != nil {
		return fmt.Errorf("invalid target_url: %w", err)
	}
	if strings.TrimSpace(playbackTargetURL) != "" {
		if len(playbackTargetURL) > maxTargetURLLength {
			return fmt.Errorf("playback_target_url must not exceed %d bytes", maxTargetURLLength)
		}
		if _, err := normalizeTargetURL(playbackTargetURL); err != nil {
			return fmt.Errorf("invalid playback_target_url: %w", err)
		}
	}
	if playbackMode != "direct" && playbackMode != "redirect" {
		return fmt.Errorf("playback_mode must be direct or redirect")
	}
	if _, _, _, _, err := normalizeUAConfig(uaMode, customUserAgent, customClient, customVersion); err != nil {
		return err
	}
	if quota < 0 || speedLimit < 0 {
		return fmt.Errorf("traffic_quota and speed_limit must not be negative")
	}
	if speedLimit > maxSpeedLimitMbps {
		return fmt.Errorf("speed_limit must not exceed %d Mbps", maxSpeedLimitMbps)
	}
	playbackAddressCount := len(streamHosts)
	if strings.TrimSpace(playbackTargetURL) != "" {
		playbackAddressCount++
	}
	if playbackAddressCount > maxPlaybackAddresses {
		return fmt.Errorf("playback addresses must contain at most %d entries", maxPlaybackAddresses)
	}
	for _, host := range streamHosts {
		if len(host) > maxTargetURLLength {
			return fmt.Errorf("stream host must not exceed %d bytes", maxTargetURLLength)
		}
		if _, err := normalizeTargetURL(host); err != nil {
			return fmt.Errorf("invalid stream host %q: %w", host, err)
		}
	}
	return nil
}

func isPlaybackRequest(path string) bool {
	path = strings.ToLower(path)
	switch {
	case strings.HasPrefix(path, "/videos/"),
		strings.HasPrefix(path, "/emby/videos/"),
		strings.HasPrefix(path, "/audio/"),
		strings.HasPrefix(path, "/emby/audio/"),
		strings.HasPrefix(path, "/livetv/"),
		strings.HasPrefix(path, "/emby/livetv/"):
		return true
	case strings.HasPrefix(path, "/items/"),
		strings.HasPrefix(path, "/emby/items/"):
		return strings.Contains(path, "/download") || strings.Contains(path, "/file")
	default:
		return false
	}
}

func isPlaybackInfoRequest(path string) bool {
	parts := strings.Split(strings.ToLower(path), "/")
	if len(parts) == 4 {
		return parts[0] == "" && parts[1] == "items" && parts[2] != "" && parts[3] == "playbackinfo"
	}
	return len(parts) == 5 && parts[0] == "" && parts[1] == "emby" && parts[2] == "items" && parts[3] != "" && parts[4] == "playbackinfo"
}

func dynamicStructuredRequestSource(requestPath string) string {
	requestPath = strings.ToLower(requestPath)
	switch {
	case isPlaybackInfoRequest(requestPath):
		return dynamicDiscoverySourcePlaybackInfo
	case strings.HasSuffix(requestPath, ".m3u8"), strings.HasSuffix(requestPath, ".m3u"):
		return dynamicDiscoverySourceHLS
	case strings.HasSuffix(requestPath, ".mpd"):
		return dynamicDiscoverySourceDASH
	default:
		return ""
	}
}

func dynamicStructuredRequestIdentity(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	source := dynamicStructuredRequestSource(r.URL.Path)
	if !dynamicStructuredMethodAllowed(source, r.Method) {
		return ""
	}
	return source
}

func isDynamicRedirectEligibleRequest(r *http.Request) bool {
	if r == nil || r.Method != http.MethodGet && r.Method != http.MethodHead || hasUpgradeIntent(r) {
		return false
	}
	return isPlaybackRequest(r.URL.Path) || isPlaybackInfoRequest(r.URL.Path) || dynamicStructuredRequestSource(r.URL.Path) != ""
}

func isExtremeDynamicRedirectEligibleRequest(r *http.Request) bool {
	return r != nil && r.URL != nil && r.Method != http.MethodConnect && !hasUpgradeIntent(r) && !isReservedDynamicRoute(r.URL.Path)
}

func upstreamTargetForRequest(r *http.Request, apiTarget, playbackTarget *url.URL) *url.URL {
	if playbackTarget != nil && isPlaybackRequest(r.URL.Path) {
		return playbackTarget
	}
	return apiTarget
}

// resolvePlaybackConfiguration is the single interpretation of the persisted
// playback fields used by both runtime routing and diagnostics. The first
// stream_hosts entry becomes the effective playback target only when the
// dedicated playback_target_url is empty; every configured authority remains
// an allowed redirect destination.
func resolvePlaybackConfiguration(playbackTargetURL, streamHostsRaw string) (*url.URL, map[string]bool, error) {
	var playbackTarget *url.URL
	var err error
	if strings.TrimSpace(playbackTargetURL) != "" {
		playbackTarget, err = normalizeTargetURL(playbackTargetURL)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid playback target URL: %w", err)
		}
	}
	var extraHosts []string
	if strings.TrimSpace(streamHostsRaw) != "" {
		if err := json.Unmarshal([]byte(streamHostsRaw), &extraHosts); err != nil {
			return nil, nil, fmt.Errorf("invalid stream_hosts: %w", err)
		}
	}
	playbackHosts := make(map[string]bool, len(extraHosts)+1)
	if playbackTarget != nil {
		playbackHosts[redirectHostKey(playbackTarget)] = true
	}
	for _, raw := range extraHosts {
		parsed, err := normalizeTargetURL(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid stream host %q: %w", raw, err)
		}
		playbackHosts[redirectHostKey(parsed)] = true
		if playbackTarget == nil {
			playbackTarget = parsed
		}
	}
	return playbackTarget, playbackHosts, nil
}

func applyUAProfileHeaders(header http.Header, profile UAProfile) {
	header.Set("User-Agent", profile.UserAgent)
	rewriteEmbyAuthorizationHeaders(header, "X-Emby-Authorization", profile)
	rewriteEmbyAuthorizationHeaders(header, "Authorization", profile)
}

// applyUAHeaderPolicy applies a resolved UAHeaderPolicy to outbound headers.
// Rewrite mode sets the configured User-Agent and rewrites Emby Client/Version
// identity; passthrough leaves every inbound identity header untouched.
func applyUAHeaderPolicy(header http.Header, policy UAHeaderPolicy) {
	if !policy.Rewrite {
		return
	}
	applyUAProfileHeaders(header, policy.Profile)
}

func isManagedForwardingHeaderName(name string) bool {
	lowerName := strings.ToLower(name)
	if lowerName == "forwarded" || lowerName == "x-real-ip" || strings.HasPrefix(lowerName, "x-forwarded-") {
		return true
	}
	switch lowerName {
	case "cf-connecting-ip", "cf-connecting-ipv6", "fastly-client-ip", "fly-client-ip",
		"true-client-ip", "x-appengine-user-ip", "x-azure-clientip", "x-client-ip",
		"x-cluster-client-ip", "x-envoy-external-address", "x-original-forwarded-for":
		return true
	default:
		return false
	}
}

func removeClientForwardingHeaders(header http.Header) {
	for name := range header {
		if isManagedForwardingHeaderName(name) {
			delete(header, name)
		}
	}
}

func singleForwardedHeaderValue(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	value := strings.TrimSpace(values[0])
	if value == "" || strings.Contains(value, ",") {
		return "", false
	}
	return value, true
}

func setTrustedForwardingHeaders(header http.Header, inbound *http.Request, trustedProxies ...[]*net.IPNet) {
	removeClientForwardingHeaders(header)
	if inbound == nil {
		return
	}
	var configured []*net.IPNet
	if len(trustedProxies) > 0 {
		configured = trustedProxies[0]
	}
	peerIP := remoteAddressIP(inbound.RemoteAddr)
	clientIP := peerIP
	forwardedProto := "http"
	if inbound.TLS != nil {
		forwardedProto = "https"
	}
	if isTrustedProxy(peerIP, configured) {
		// Trust only the single value a configured edge proxy normalized. Never
		// relay an arbitrary inbound X-Forwarded-For chain to the upstream.
		if value, ok := singleForwardedHeaderValue(inbound.Header, "X-Real-IP"); ok {
			if forwardedIP := net.ParseIP(value); forwardedIP != nil {
				clientIP = forwardedIP
			}
		}
		if candidateProto, ok := singleForwardedHeaderValue(inbound.Header, "X-Forwarded-Proto"); ok {
			if strings.EqualFold(candidateProto, "http") || strings.EqualFold(candidateProto, "https") {
				forwardedProto = strings.ToLower(candidateProto)
			}
		}
	}
	if clientIP != nil {
		header.Set("X-Forwarded-For", clientIP.String())
		header.Set("X-Real-IP", clientIP.String())
	}
	header.Set("X-Forwarded-Proto", forwardedProto)
}

type publicHostIngressContextKey struct{}

func applySiteForwardedHost(header http.Header, inbound *http.Request, site Site) {
	header.Del("X-Forwarded-Host")
	if inbound == nil || !ingressUsesHost(site.IngressMode) {
		return
	}
	sharedIngress, _ := inbound.Context().Value(publicHostIngressContextKey{}).(bool)
	if sharedIngress && requestPublicHost(inbound.Host) == site.PublicHost {
		header.Set("X-Forwarded-Host", site.PublicHost)
	}
}

// stripCookieByName removes Meridian's management session before any site
// request leaves the process. Browser cookies are scoped by host, not port, so
// a panel session could otherwise ride along to a site listener on the same
// host. Malformed Cookie input is dropped in full rather than risk retaining a
// disguised management credential.
func stripCookieByName(header http.Header, name string) {
	var rawValues []string
	for key, values := range header {
		if strings.EqualFold(key, "Cookie") {
			rawValues = append(rawValues, values...)
			delete(header, key)
		}
	}
	if len(rawValues) == 0 {
		return
	}

	kept := make([]string, 0)
	for _, raw := range rawValues {
		cookies, err := http.ParseCookie(raw)
		if err != nil {
			return
		}
		for _, cookie := range cookies {
			if cookie.Name != name {
				kept = append(kept, cookie.String())
			}
		}
	}
	if len(kept) > 0 {
		header.Set("Cookie", strings.Join(kept, "; "))
	}
}

func prepareUpstreamHeaders(header http.Header, inbound *http.Request, policy UAHeaderPolicy, trustedProxies ...[]*net.IPNet) {
	stripCookieByName(header, sessionCookieName)
	setTrustedForwardingHeaders(header, inbound, trustedProxies...)
	applyUAHeaderPolicy(header, policy)
}

func prepareWebSocketUpstreamHeaders(inbound *http.Request, target *url.URL, policy UAHeaderPolicy, upstreamPolicies ...upstreamHeaderPolicy) http.Header {
	return prepareWebSocketUpstreamHeadersWithTrustedProxies(inbound, target, policy, nil, upstreamPolicies...)
}

func prepareWebSocketUpstreamHeadersWithTrustedProxies(inbound *http.Request, target *url.URL, policy UAHeaderPolicy, trustedProxies []*net.IPNet, upstreamPolicies ...upstreamHeaderPolicy) http.Header {
	header := inbound.Header.Clone()
	// RFC 9110 hop-by-hop: every header named by the inbound Connection header
	// is consumed by the first recipient and must not be forwarded. Delete them
	// all before rebuilding the upgrade headers below.
	for _, value := range inbound.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if token = strings.TrimSpace(token); token != "" {
				header.Del(token)
			}
		}
	}
	for _, name := range []string{
		// Content-Length must go with the other hop-by-hop headers: the upgrade
		// path never reads r.Body, so letting a length through would tell the
		// upstream to frame bytes as a body that this side never sends.
		"Content-Length",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
	header.Set("Connection", "Upgrade")
	header.Set("Upgrade", "websocket")
	header.Set("Host", target.Host)
	prepareUpstreamHeaders(header, inbound, policy, trustedProxies)
	if len(upstreamPolicies) > 0 {
		upstreamPolicies[0].apply(header, target)
	}
	return header
}

// stripPanelSessionSetCookies prevents an upstream site from overwriting the
// management session on a sibling port/route. Preserve valid application
// cookies verbatim; malformed individual values fail closed because browser
// parsers may otherwise interpret them more permissively than net/http.
func stripPanelSessionSetCookies(header http.Header) {
	values := header.Values("Set-Cookie")
	header.Del("Set-Cookie")
	for _, value := range values {
		cookie, err := http.ParseSetCookie(value)
		if err != nil || cookie.Name == sessionCookieName {
			continue
		}
		header.Add("Set-Cookie", value)
	}
}

// writeWebSocketGatewayError answers a hijacked client directly, since the
// http.ResponseWriter is no longer usable once the connection is taken over.
func writeWebSocketGatewayError(conn net.Conn) {
	const body = `{"error":"upstream refused websocket upgrade"}`
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request, target, primaryTarget *url.URL, policy UAHeaderPolicy, inst *ProxyInstance, speedLimitBytes int64, upstreamPolicies ...upstreamHeaderPolicy) {
	meter := newRequestTrafficMeter(inst)
	defer func() { meter.finish(time.Now()) }()
	handleWebSocketMetered(w, r, target, primaryTarget, policy, inst, meter, speedLimitBytes, upstreamPolicies...)
}

func handleWebSocketMetered(w http.ResponseWriter, r *http.Request, target, primaryTarget *url.URL, policy UAHeaderPolicy, inst *ProxyInstance, meter *requestTrafficMeter, speedLimitBytes int64, upstreamPolicies ...upstreamHeaderPolicy) {
	meter.promote()
	// Nothing on this path reads r.Body, so a body would be left sitting in the
	// hijacked buffer and relayed verbatim to the upstream.
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		http.Error(w, "websocket upgrade must not carry a body", http.StatusBadRequest)
		return
	}
	scheme := "ws"
	if target.Scheme == "https" {
		scheme = "wss"
	}
	// Hijack client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported", 500)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		log.Printf("[WS] hijack error: %v", err)
		return
	}
	defer clientConn.Close()
	if !inst.trackHijackedConn(clientConn) {
		return
	}
	defer inst.untrackHijackedConn(clientConn)

	// Connect to upstream
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var upstreamConn net.Conn
	port := target.Port()
	if port == "" {
		if scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}
	host := net.JoinHostPort(target.Hostname(), port)
	if scheme == "wss" {
		upstreamConn, err = tls.DialWithDialer(dialer, "tcp", host, secureTLSConfig(target.Hostname()))
	} else {
		upstreamConn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		log.Printf("[WS] upstream dial error: %v", err)
		writeWebSocketGatewayError(clientConn)
		return
	}
	defer upstreamConn.Close()

	// Send upgrade request to upstream
	if err := upstreamConn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("[WS] set handshake deadline: %v", err)
		return
	}
	upstreamURL := *r.URL
	applyUpstreamURL(&upstreamURL, target)
	reqLine := fmt.Sprintf("%s %s HTTP/1.1\r\n", r.Method, upstreamURL.RequestURI())
	if _, err := io.WriteString(upstreamConn, reqLine); err != nil { // #nosec G705 -- net/http rejects control characters in the parsed method and RequestURI.
		log.Printf("[WS] write request line: %v", err)
		return
	}
	upstreamHeader := prepareWebSocketUpstreamHeadersWithTrustedProxies(r, target, policy, inst.trustedProxies, upstreamPolicies...)
	if primaryTarget != nil && !sameRedirectAuthority(primaryTarget, target) {
		// A separately configured playback/CDN authority is a different trust
		// domain. Preserve only WebSocket negotiation fields and normalized client
		// identity; browser/API credentials must stay with the main origin.
		upstreamHeader = crossAuthorityWebSocketHeaders(upstreamHeader)
		upstreamHeader.Set("Host", target.Host)
	}
	applySiteForwardedHost(upstreamHeader, r, inst.Site)
	if err := upstreamHeader.Write(upstreamConn); err != nil {
		log.Printf("[WS] write request headers: %v", err)
		return
	}
	if _, err := io.WriteString(upstreamConn, "\r\n"); err != nil {
		log.Printf("[WS] finish request headers: %v", err)
		return
	}
	if err := upstreamConn.SetWriteDeadline(time.Time{}); err != nil {
		log.Printf("[WS] clear handshake deadline: %v", err)
		return
	}

	// Require a real protocol switch before relaying any raw bytes. Without this
	// check the tunnel starts regardless of what the upstream answered, so if the
	// upstream ignored the upgrade and stayed in HTTP keep-alive mode, whatever
	// the client sends next reaches it as requests that never passed through
	// removeClientForwardingHeaders/setTrustedForwardingHeaders/applyUAProfileHeaders.
	if err := upstreamConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("[WS] set handshake read deadline: %v", err)
		return
	}
	// Read through a buffered reader and keep using it below: ReadResponse may
	// consume bytes past the headers, and those belong to the tunnel.
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, r)
	if err != nil {
		log.Printf("[WS] read upstream handshake: %v", err)
		writeWebSocketGatewayError(clientConn)
		return
	}
	defer resp.Body.Close()
	if err := upstreamConn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("[WS] clear handshake read deadline: %v", err)
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		!headerHasToken(resp.Header, "Connection", "upgrade") {
		// The body is deliberately not relayed. An upstream that answers a
		// handshake with a normal response must not turn this path into an
		// unmetered, unthrottled transfer channel.
		log.Printf("[WS] upstream refused upgrade: status %d", resp.StatusCode)
		writeWebSocketGatewayError(clientConn)
		return
	}
	stripPanelSessionSetCookies(resp.Header)

	// Relay the switch verbatim; the client needs Sec-WebSocket-Accept.
	if _, err := io.WriteString(clientConn, "HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		log.Printf("[WS] write handshake response: %v", err)
		return
	}
	if err := resp.Header.Write(clientConn); err != nil {
		log.Printf("[WS] write handshake headers: %v", err)
		return
	}
	if _, err := io.WriteString(clientConn, "\r\n"); err != nil {
		log.Printf("[WS] finish handshake response: %v", err)
		return
	}

	log.Printf("[WS] tunnel established: client <-> %s", target.Host)

	// Bidirectional copy. Both directions are metered per chunk; only the
	// download direction is paced, matching rateLimitedWriter on the HTTP path.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(&tunnelWriter{dst: upstreamConn, counter: &inst.bytesIn, meter: meter, inbound: true, start: time.Now()}, clientBuf)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(&tunnelWriter{dst: clientConn, counter: &inst.bytesOut, meter: meter, bytesPerSec: speedLimitBytes, start: time.Now()}, upstreamReader)
		done <- struct{}{}
	}()
	// The first closed direction must tear down its counterpart, then both copy
	// goroutines must finish before the request leaves activeRequests. Otherwise
	// shutdown can perform its final traffic flush while the second goroutine is
	// still incrementing the old instance's counters.
	<-done
	_ = clientConn.Close()
	_ = upstreamConn.Close()
	<-done
}

func (pm *ProxyManager) StartSite(site Site) error {
	pm.lifecycleMu.Lock()
	defer pm.lifecycleMu.Unlock()
	if pm.shutdownStarted.Load() {
		return errProxyManagerShuttingDown
	}
	publicHost, err := normalizePublicHost(site.PublicHost)
	if err != nil {
		return fmt.Errorf("invalid public host: %w", err)
	}
	site.PublicHost = publicHost
	site.IngressMode, err = normalizeIngressMode(site.IngressMode, site.PublicHost)
	if err != nil {
		return fmt.Errorf("invalid ingress configuration: %w", err)
	}
	if err := pm.validateIngressSafety(site.IngressMode); err != nil {
		return err
	}
	target, err := normalizeTargetURL(site.TargetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	playbackTarget, playbackHostsSet, err := resolvePlaybackConfiguration(site.PlaybackTargetURL, site.StreamHosts)
	if err != nil {
		return err
	}

	policy, err := resolveUAHeaderPolicy(site)
	if err != nil {
		return fmt.Errorf("invalid UA profile: %w", err)
	}
	configuredHeaders, err := resolveUpstreamHeaderPolicy(site.StoredUpstreamHeaders, pm.upstreamHeaderKey, target)
	if err != nil {
		return fmt.Errorf("invalid upstream headers: %w", err)
	}
	redirectPolicy, err := newDynamicRedirectPolicy(site, pm.DynamicDiscoveryAvailable())
	if err != nil {
		return err
	}
	configuredAuthorities := make(map[string]bool, len(playbackHostsSet)+1)
	configuredAuthorities[redirectHostKey(target)] = true
	for authority := range playbackHostsSet {
		configuredAuthorities[authority] = true
	}
	var dynamicState *dynamicSiteState
	if redirectPolicy.configured {
		dynamicState = newDynamicSiteState(pm.dynamicRuntime, redirectPolicy.limits)
	}
	var dynamicIssuer *dynamicCapabilityIssuer
	if redirectPolicy.configured {
		dynamicIssuer = &dynamicCapabilityIssuer{
			key:                   append([]byte(nil), pm.dynamicRouteKey...),
			siteID:                site.ID,
			policyRevision:        site.DynamicPolicyRevision,
			policy:                redirectPolicy,
			state:                 dynamicState,
			database:              pm.database,
			transportFactory:      pm.dynamicTransportFactory,
			configuredAuthorities: configuredAuthorities,
			primaryAuthority:      redirectHostKey(target),
			site:                  site,
			trustedProxies:        append([]*net.IPNet(nil), pm.trustedProxies...),
			uaPolicy:              policy,
			upstreamHeaderPolicy:  configuredHeaders,
		}
	}
	var pingCacheState *pingCache
	if site.PingCacheEnabled {
		pingCacheState, err = newPingCache(site.ID, target, nil)
		if err != nil {
			return err
		}
	}
	var imageCacheState *imageCacheSite
	if site.ImageCacheEnabled && pm.imageCacheRuntime != nil {
		imageCacheState = pm.imageCacheRuntime.newSite(site.ID)
	}
	instanceCtx, instanceCancel := context.WithCancel(context.Background())
	inst := &ProxyInstance{
		Site:           site,
		startedAt:      time.Now(),
		ctx:            instanceCtx,
		cancel:         instanceCancel,
		hijackedConns:  make(map[net.Conn]struct{}),
		trustedProxies: append([]*net.IPNet(nil), pm.trustedProxies...),
		dynamicState:   dynamicState,
		pingCache:      pingCacheState,
		imageCache:     imageCacheState,
	}
	installed := false
	defer func() {
		if !installed {
			inst.closeProgress()
			inst.imageCache.close()
			instanceCancel()
			if dynamicState != nil {
				dynamicState.close()
			}
		}
	}()
	inst.persistedTraffic.Store(site.TrafficUsed)

	isRedirectMode := playbackTarget != nil && site.PlaybackMode == "redirect"
	proxyTransport := http.DefaultTransport.(*http.Transport).Clone()
	proxyTransport.TLSClientConfig = secureTLSConfig("")
	proxyTransport.ResponseHeaderTimeout = 30 * time.Second
	proxyTransport.MaxIdleConnsPerHost = 32
	inst.transport = proxyTransport
	baseTransport := http.RoundTripper(proxyTransport)
	if inst.pingCache != nil {
		baseTransport = &pingCacheTransport{base: baseTransport, cache: inst.pingCache}
	}
	if dynamicIssuer != nil {
		dynamicIssuer.configuredTransport = proxyTransport
	}

	proxy := &httputil.ReverseProxy{
		Transport: baseTransport,
		Rewrite: func(proxyReq *httputil.ProxyRequest) {
			if redirectPolicy.configured {
				eligible := isDynamicRedirectEligibleRequest(proxyReq.In)
				if redirectPolicy.profile == dynamicProfileExtreme {
					eligible = isExtremeDynamicRedirectEligibleRequest(proxyReq.In)
				}
				if eligible {
					ctx := context.WithValue(proxyReq.Out.Context(), dynamicRequestEligibleContextKey{}, true)
					proxyReq.Out = proxyReq.Out.WithContext(ctx)
				}
			}
			var upstream *url.URL
			if isRedirectMode {
				upstream = target
			} else {
				upstream = upstreamTargetForRequest(proxyReq.In, target, playbackTarget)
			}
			applyUpstreamURL(proxyReq.Out.URL, upstream)
			proxyReq.Out.Host = upstream.Host
			prepareUpstreamHeaders(proxyReq.Out.Header, proxyReq.In, policy, inst.trustedProxies)
			if !sameRedirectAuthority(target, upstream) {
				// Direct playback can target a separate CDN. Treat that authority like
				// a cross-origin redirect and rebuild from a narrow allowlist so client
				// cookies, bearer tokens, and arbitrary secret headers cannot follow it.
				proxyReq.Out.Header = crossAuthorityRedirectHeaders(proxyReq.Out.Header)
			}
			applySiteForwardedHost(proxyReq.Out.Header, proxyReq.In, site)
			configuredHeaders.apply(proxyReq.Out.Header, upstream)
			if source := dynamicStructuredRequestIdentity(proxyReq.In); source != "" {
				ctx := context.WithValue(proxyReq.Out.Context(), dynamicExpectedStructuredSourceContextKey{}, source)
				proxyReq.Out = proxyReq.Out.WithContext(ctx)
				if redirectPolicy.sourceEnabled(source) {
					proxyReq.Out.Header.Set("Accept-Encoding", "identity")
					for _, name := range []string{"Range", "If-Range", "If-Modified-Since", "If-None-Match"} {
						proxyReq.Out.Header.Del(name)
					}
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			dynamicResponse := responseIsDynamic(resp)
			expectedSource := dynamicResponseExpectedStructuredSource(resp)
			if err := rewriteDynamicStructuredResponseExpected(resp, dynamicIssuer, dynamicResponse, expectedSource, 0, false); err != nil {
				rollbackDynamicResponseAuthorities(resp)
				return err
			}
			if dynamicResponse && resp.StatusCode >= http.StatusBadRequest {
				sanitizeDynamicResourceErrorResponse(resp)
			}
			if resp.StatusCode < http.StatusBadRequest {
				commitDynamicResponseAuthorities(resp)
			} else {
				rollbackDynamicResponseAuthorities(resp)
			}
			if dynamicResponse {
				rebuildDynamicResponseHeaders(resp)
				return nil
			}
			stripPanelSessionSetCookies(resp.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			recordProgressDispatchError(r, err)
			var discoveryErr *dynamicProxyError
			if errors.As(err, &discoveryErr) {
				log.Printf("[%s] dynamic discovery denied: %s", site.Name, discoveryErr.reasonCode)
				discoveryErr.writeResponse(w)
				return
			}
			log.Printf("[%s] proxy error: %v", site.Name, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"upstream unavailable"}`))
		},
	}

	if isRedirectMode || redirectPolicy.configured {
		proxy.Transport = &redirectFollowTransport{
			base:                    baseTransport,
			playbackHosts:           playbackHostsSet,
			configuredAuthorities:   configuredAuthorities,
			disableLegacyRedirects:  !isRedirectMode,
			policy:                  policy,
			upstreamHeaderPolicy:    configuredHeaders,
			dynamicPolicy:           redirectPolicy,
			dynamicTransportFactory: pm.dynamicTransportFactory,
			dynamicState:            dynamicState,
			database:                pm.database,
			siteID:                  site.ID,
		}
	}

	if site.ProgressCoalescingEnabled {
		inst.progress = newProgressCoalescer(pm.progressRuntime, defaultProgressCoalescerConfig(), func(request *http.Request) (progressResponse, error) {
			capture := newProgressCaptureWriter()
			dispatchErrors := &progressDispatchErrorState{}
			request = request.WithContext(context.WithValue(request.Context(), progressDispatchErrorContextKey{}, dispatchErrors))
			proxy.ServeHTTP(capture, request) // #nosec G704 -- this uses the same validated, administrator-configured proxy as the ordinary request path.
			response, captureErr := capture.response()
			return response, errors.Join(captureErr, dispatchErrors.load())
		})
	}

	// Speed limit in bytes/sec (field is in Mbps, 0 = unlimited)
	speedLimitBytes := int64(site.SpeedLimit) * 125000 // Mbps -> bytes/sec

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !inst.beginRequest() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"site is stopping"}`))
			return
		}
		defer inst.endRequest()
		meter := newRequestTrafficMeter(inst)
		defer func() { meter.finish(time.Now()) }()
		requestCtx, requestCancel := context.WithCancel(r.Context())
		stopInstanceCancel := context.AfterFunc(inst.ctx, requestCancel)
		defer func() {
			stopInstanceCancel()
			requestCancel()
		}()
		r = r.WithContext(requestCtx)

		if site.TrafficQuota > 0 {
			currentUsed := inst.persistedTraffic.Load() + inst.bytesIn.Load() + inst.bytesOut.Load()
			if currentUsed >= site.TrafficQuota {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"traffic quota exceeded"}`))
				return
			}
		}
		if isReservedDynamicRoute(r.URL.Path) {
			var rw http.ResponseWriter
			if speedLimitBytes > 0 {
				rw = &rateLimitedWriter{
					ResponseWriter: w,
					bytesPerSec:    speedLimitBytes,
					written:        &inst.bytesOut,
					meter:          meter,
					start:          time.Now(),
				}
			} else {
				rw = &meteredWriter{ResponseWriter: w, written: &inst.bytesOut, meter: meter}
			}
			if dynamicIssuer == nil {
				writeDynamicCapabilityUnavailable(rw)
			} else {
				dynamicIssuer.serve(rw, r)
			}
			return
		}

		if hasUpgradeIntent(r) {
			if !isWebSocketUpgrade(r) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid websocket upgrade"}`))
				return
			}
			wsTarget := upstreamTargetForRequest(r, target, playbackTarget)
			if isRedirectMode {
				wsTarget = target
			}
			handleWebSocketMetered(w, r, wsTarget, target, policy, inst, meter, speedLimitBytes, configuredHeaders)
			return
		}

		if r.Body != nil && r.Body != http.NoBody {
			r.Body = &meteredReader{ReadCloser: r.Body, read: &inst.bytesIn, meter: meter}
		}
		if redirectPolicy.profile == dynamicProfileExtreme && isExtremeDynamicRedirectEligibleRequest(r) {
			releaseReplayBody, err := prepareExtremeRedirectReplayBody(r, dynamicState, redirectPolicy.limits.MaxBodyBytes)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid request body"}`))
				return
			}
			if releaseReplayBody != nil {
				defer releaseReplayBody()
			}
		}

		var rw http.ResponseWriter
		if speedLimitBytes > 0 {
			rw = &rateLimitedWriter{
				ResponseWriter: w,
				bytesPerSec:    speedLimitBytes,
				written:        &inst.bytesOut,
				meter:          meter,
				start:          time.Now(),
			}
		} else {
			rw = &meteredWriter{ResponseWriter: w, written: &inst.bytesOut, meter: meter}
		}
		if route, eligible := pingCacheRouteForRequest(r); eligible && inst.pingCache != nil {
			r = r.WithContext(context.WithValue(r.Context(), pingCacheRequestContextKey{}, route))
		}
		if inst.progress != nil && inst.progress.ServeHTTP(rw, r, proxy) {
			return
		}
		if inst.imageCache != nil {
			inst.imageCache.serve(rw, r, target, proxy)
			return
		}
		proxy.ServeHTTP(rw, r) // #nosec G704 -- forwarding to the administrator-configured, validated upstream is the product's purpose.
	})

	inst.handler = handler
	var listener net.Listener
	var server *http.Server
	if ingressUsesPort(site.IngressMode) {
		listenAddr := fmt.Sprintf(":%d", site.ListenPort)
		listener, err = net.Listen("tcp", listenAddr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", listenAddr, err)
		}
		listener = limitListener(listener, 2048)
		server = &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       0,
			WriteTimeout:      0,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    64 << 10,
		}
		inst.server = server
		inst.listener = listener
	}
	closeNewListener := func() {
		if listener != nil {
			_ = listener.Close()
		}
	}

	pm.mu.Lock()
	if ingressUsesHost(site.IngressMode) {
		if assignedID, ok := pm.publicHosts[site.PublicHost]; ok && assignedID != site.ID {
			pm.mu.Unlock()
			closeNewListener()
			return fmt.Errorf("public_host %s is already assigned to another site", site.PublicHost)
		}
	}
	existing := pm.proxies[site.ID]
	pm.mu.Unlock()
	if existing != nil {
		// Verify persistence before stopping the old instance. lifecycleMu pins the
		// selected instance while trafficMu serializes this flush, so the global
		// routing lock need not be held across a potentially slow SQLite write.
		if err := pm.flushProxyTraffic(existing); err != nil {
			closeNewListener()
			return fmt.Errorf("flush traffic of the instance being replaced: %w", err)
		}
	}

	if existing != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := existing.drainProgress(shutdownCtx); err != nil {
			shutdownCancel()
			closeNewListener()
			return fmt.Errorf("flush progress of the instance being replaced: %w", err)
		}
		shutdownErr := existing.shutdown(shutdownCtx)
		shutdownCancel()
		if shutdownErr != nil {
			closeNewListener()
			return fmt.Errorf("drain the instance being replaced: %w", shutdownErr)
		}
		// Account for bytes produced after the pre-stop flush. If this fails, keep
		// the closed instance in the map with its counters so a retry can persist
		// them rather than silently orphaning traffic.
		if err := pm.flushProxyTraffic(existing); err != nil {
			closeNewListener()
			return fmt.Errorf("final traffic flush of the instance being replaced: %w", err)
		}
		existing.closeProgress()
		if flushed := existing.Site.TrafficUsed; flushed > inst.persistedTraffic.Load() {
			inst.persistedTraffic.Store(flushed)
			inst.Site.TrafficUsed = flushed
		}
	}

	nextSelfTargets, snapshotErr := pm.buildDynamicSelfTargetPolicy()
	pm.mu.Lock()
	if err := pm.registerSiteHostLocked(site); err != nil {
		pm.mu.Unlock()
		closeNewListener()
		return err
	}
	if snapshotErr != nil {
		pm.dynamicRuntime.selfTargets.Store(nil)
	} else {
		pm.dynamicRuntime.selfTargets.Store(nextSelfTargets)
	}
	pm.proxies[site.ID] = inst
	pm.mu.Unlock()
	if snapshotErr != nil {
		log.Printf("dynamic discovery disabled until the next lifecycle refresh: %v", snapshotErr)
	}
	installed = true

	upstreamLogTarget := redactUpstreamURL(target)
	if server == nil {
		log.Printf("[%s] shared-host proxy %s -> %s (UA: %s)", site.Name, site.PublicHost, upstreamLogTarget, site.UAMode)
		return nil
	}
	inst.portServing.Store(true)
	go func() {
		defer inst.portServing.Store(false)
		if len(playbackHostsSet) > 0 {
			hosts := make([]string, 0, len(playbackHostsSet))
			for h := range playbackHostsSet {
				hosts = append(hosts, h)
			}
			log.Printf("[%s] proxy :%d -> %s (playback hosts: %s, mode: %s, UA: %s)", site.Name, site.ListenPort, upstreamLogTarget, strings.Join(hosts, ", "), site.PlaybackMode, site.UAMode)
		} else {
			log.Printf("[%s] proxy :%d -> %s (UA: %s)", site.Name, site.ListenPort, upstreamLogTarget, site.UAMode)
		}
		err := server.Serve(listener)
		if inst.isAccepting() {
			// A Serve loop that disappears while the lifecycle gate is still open
			// makes a port-only site unavailable even though its instance remains in
			// the map. Record that state for API/runtime diagnostics.
			inst.portServeFailed.Store(true)
			if err != nil && err != http.ErrServerClosed {
				log.Printf("[%s] server error: %v", site.Name, err)
			} else {
				log.Printf("[%s] server stopped unexpectedly", site.Name)
			}
		}
	}()

	return nil
}

func (pm *ProxyManager) StopSite(id int64) error {
	pm.lifecycleMu.Lock()
	defer pm.lifecycleMu.Unlock()
	pm.mu.RLock()
	inst, ok := pm.proxies[id]
	pm.mu.RUnlock()
	if !ok {
		return nil
	}
	// Check persistence before closing any listener or request context. A DB
	// failure therefore leaves a fully usable instance that can be retried.
	// lifecycleMu pins inst, and trafficMu protects its counters without blocking
	// shared-host routing on pm.mu.
	ingressAlreadyClosed := !inst.isAccepting()
	if err := pm.flushProxyTraffic(inst); err != nil {
		if ingressAlreadyClosed {
			return &siteIngressClosedError{siteID: id, flushErr: err}
		}
		return err
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := inst.drainProgress(shutdownCtx); err != nil {
		shutdownCancel()
		if ingressAlreadyClosed {
			return &siteIngressClosedError{siteID: id, drainErr: err}
		}
		return fmt.Errorf("flush pending progress updates: %w", err)
	}
	shutdownErr := inst.shutdown(shutdownCtx)
	shutdownCancel()
	finalFlushErr := pm.flushProxyTraffic(inst)
	if shutdownErr != nil || finalFlushErr != nil {
		// Keep the stopped instance and its pending counters addressable so a
		// subsequent StopSite/GracefulShutdown can retry the final persistence.
		return &siteIngressClosedError{siteID: id, drainErr: shutdownErr, flushErr: finalFlushErr}
	}
	inst.closeProgress()
	nextSelfTargets, snapshotErr := pm.buildDynamicSelfTargetPolicy()
	pm.mu.Lock()
	if pm.proxies[id] == inst {
		delete(pm.proxies, id)
	}
	if snapshotErr != nil {
		pm.dynamicRuntime.selfTargets.Store(nil)
	} else {
		pm.dynamicRuntime.selfTargets.Store(nextSelfTargets)
	}
	pm.mu.Unlock()
	if snapshotErr != nil {
		log.Printf("dynamic discovery disabled until the next lifecycle refresh: %v", snapshotErr)
	}
	return nil
}

func (pm *ProxyManager) IsRunning(id int64) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	inst, ok := pm.proxies[id]
	return ok && inst.isOperational()
}

func (pm *ProxyManager) StartAllEnabled() (int, error) {
	sites, err := pm.database.ListSites()
	if err != nil {
		return 0, err
	}
	for _, site := range sites {
		if err := pm.RegisterSiteHost(site); err != nil {
			return 0, err
		}
	}
	for _, s := range sites {
		if s.Enabled {
			if err := pm.StartSite(s); err != nil {
				if errors.Is(err, errUnsafeHostOnlyIngress) {
					return len(sites), fmt.Errorf("site %q: %w", s.Name, err)
				}
				log.Printf("[%s] failed to start: %v", s.Name, err)
			}
		}
	}
	return len(sites), nil
}

// FlushTraffic flushes every running instance's pending traffic to the DB. It
// is driven by the periodic ticker: a failed flush restores the pending
// counters and is logged here, so the next tick retries the same bytes.
func (pm *ProxyManager) FlushTraffic() {
	pm.mu.RLock()
	instances := make([]*ProxyInstance, 0, len(pm.proxies))
	for _, inst := range pm.proxies {
		instances = append(instances, inst)
	}
	pm.mu.RUnlock()
	for _, inst := range instances {
		if err := pm.flushProxyTraffic(inst); err != nil {
			log.Printf("[%s] failed to flush traffic: %v", inst.Site.Name, err)
		}
	}
}

// flushProxyTraffic persists only bytes that already have an in-memory minute
// attribution. Ordinary in-flight HTTP bytes stay in the global live counters
// until request completion; promoted streams attribute each chunk immediately.
// The caller must pin inst through lifecycleMu, a pm.mu snapshot, or another
// stable reference. Never call this while already holding inst.trafficMu.
func (pm *ProxyManager) flushProxyTraffic(inst *ProxyInstance) error {
	inst.trafficMu.Lock()
	defer inst.trafficMu.Unlock()
	return pm.flushProxyTrafficLocked(inst)
}

// flushProxyTrafficLocked commits the flushable byte counters and their exact
// minute buckets in one SQLite transaction. Nothing is cleared on failure, so
// a concurrent or later flush retries the same deltas exactly once.
func (pm *ProxyManager) flushProxyTrafficLocked(inst *ProxyInstance) error {
	in := inst.flushBytesIn
	out := inst.flushBytesOut
	buckets := inst.pendingMinuteTraffic

	// Keep direct counter users (including legacy integrations) working without
	// deriving real request buckets from globals: this fallback is allowed only
	// when no request meter is active and no attributed delta exists.
	if in == 0 && out == 0 && len(buckets) == 0 && inst.activeTrafficMeters.Load() == 0 {
		in = inst.bytesIn.Load()
		out = inst.bytesOut.Load()
		if in != 0 || out != 0 {
			buckets = map[int64]trafficMinuteDelta{
				trafficMinuteStart(time.Now()): {BytesIn: in, BytesOut: out},
			}
		}
	}
	if in == 0 && out == 0 && len(buckets) == 0 {
		return nil
	}
	now := time.Now()
	if err := pm.database.addTrafficMinuteBuckets(inst.Site.ID, in, out, buckets, now); err != nil {
		return err
	}

	inst.flushBytesIn = 0
	inst.flushBytesOut = 0
	clear(inst.pendingMinuteTraffic)
	inst.bytesIn.Add(-in)
	inst.bytesOut.Add(-out)
	delta := in + out
	inst.persistedTraffic.Add(delta)
	inst.Site.TrafficUsed += delta
	return nil
}

// sameTrafficHour reports whether a persisted recorded_at value falls in the
// same wall-clock hour as now. Stored rows are wall-clock values: legacy
// "2006-01-02 15:04:05" rows carry the writer's local time, and the modernc
// SQLite driver re-serializes DATETIME columns as RFC3339 with the stored
// wall clock in UTC (it attaches Z to whatever text was written). The
// year/month/day/hour components of the stored value are therefore compared
// against the current local wall clock, never the instants: an instant-based
// comparison would shift the bucket by the zone offset in non-UTC
// deployments. Values that parse as neither format never match, so a corrupt
// or foreign string cannot swallow pending bytes.
func sameTrafficHour(recordedAt string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, recordedAt)
	if err != nil {
		if t, err = time.ParseInLocation("2006-01-02 15:04:05", recordedAt, time.Local); err != nil {
			return false
		}
	}
	nowLocal := now.In(time.Local)
	y, m, d := t.Date()
	ny, nm, nd := nowLocal.Date()
	return y == ny && m == nm && d == nd && t.Hour() == nowLocal.Hour()
}

// mergePendingIntoLogs merges live pending bytes into the current-hour bucket
// of the returned log copy: it adds to the existing bucket when present, or
// appends a synthetic bucket with ID 0 when the hour has no bucket yet and
// pending bytes are non-zero. A zero pending pair is a no-op. The input slice
// must be a private copy (GetTrafficLogs always returns one). The current
// hour is matched by wall-clock semantics via sameTrafficHour, so rows
// persisted in either the RFC3339 form the SQLite driver returns or the
// legacy SQL layout merge correctly. The synthetic bucket is built from the
// current local wall hour stamped as UTC, exactly the representation the next
// addTraffic row will carry after the driver re-serializes it, with ID 0.
func mergePendingIntoLogs(logs []TrafficLog, siteID, pendingIn, pendingOut int64) []TrafficLog {
	if pendingIn == 0 && pendingOut == 0 {
		return logs
	}
	now := time.Now()
	for i := range logs {
		if sameTrafficHour(logs[i].RecordedAt, now) {
			logs[i].BytesIn += pendingIn
			logs[i].BytesOut += pendingOut
			return logs
		}
	}
	nowLocal := now.In(time.Local)
	return append(logs, TrafficLog{
		ID:         0,
		SiteID:     siteID,
		BytesIn:    pendingIn,
		BytesOut:   pendingOut,
		RecordedAt: time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day(), nowLocal.Hour(), 0, 0, 0, time.UTC).Format(time.RFC3339),
	})
}

// SiteTrafficHistory captures a single site's traffic history as a consistent
// point-in-time view: the DB log window plus live pending bytes merged into
// the returned copy's current-hour bucket, alongside the authoritative live
// state. For a running site the DB read and the live counters happen under
// inst.trafficMu (with pm.mu held read-only to pin the instance), so the view
// never interleaves with a concurrent flush.
func (pm *ProxyManager) SiteTrafficHistory(site Site, hours int) (*TrafficHistory, error) {
	snap := SiteTraffic{
		ID:               site.ID,
		Name:             site.Name,
		TrafficQuota:     site.TrafficQuota,
		PersistedTraffic: site.TrafficUsed,
		TrafficUsed:      site.TrafficUsed,
	}

	pm.mu.RLock()
	inst, present := pm.proxies[site.ID]
	if !present {
		pm.mu.RUnlock()
		logs, err := pm.database.GetTrafficLogs(site.ID, hours)
		if err != nil {
			return nil, err
		}
		return &TrafficHistory{Snapshot: snap, Logs: logs}, nil
	}
	// pm.mu -> trafficMu lock order. trafficMu stays held across the DB read
	// so the logs and the live counters describe the same instant.
	inst.trafficMu.Lock()
	defer inst.trafficMu.Unlock()
	defer pm.mu.RUnlock()

	logs, err := pm.database.GetTrafficLogs(site.ID, hours)
	if err != nil {
		return nil, err
	}
	snap.Running = inst.isOperational()
	snap.PersistedTraffic = inst.persistedTraffic.Load()
	snap.BytesIn = inst.bytesIn.Load()
	snap.BytesOut = inst.bytesOut.Load()
	snap.TrafficUsed = snap.PersistedTraffic + snap.BytesIn + snap.BytesOut
	snap.Requests = inst.reqCount.Load()
	logs = mergePendingIntoLogs(logs, site.ID, snap.BytesIn, snap.BytesOut)
	return &TrafficHistory{Snapshot: snap, Logs: logs}, nil
}

func mergePendingMinuteTraffic(timeline []TrafficMinuteLog, pending map[int64]trafficMinuteDelta) {
	if len(timeline) == 0 || len(pending) == 0 {
		return
	}
	start := timeline[0].MinuteStartUnix
	for minuteStart, delta := range pending {
		offset := minuteStart - start
		if offset < 0 || offset%trafficMinuteSeconds != 0 {
			continue
		}
		index := int(offset / trafficMinuteSeconds)
		if index >= len(timeline) {
			continue
		}
		timeline[index].BytesIn += delta.BytesIn
		timeline[index].BytesOut += delta.BytesOut
		timeline[index].Requests += delta.Requests
	}
}

// SiteTrafficTimeline captures persisted rows and unflushed completed/stream
// buckets under the same instance lock used by FlushTraffic. The dense return
// type contains no identity fields and is safe to serialize directly.
func (pm *ProxyManager) SiteTrafficTimeline(siteID int64, minutes int, now time.Time) ([]TrafficMinuteLog, error) {
	pm.mu.RLock()
	inst, present := pm.proxies[siteID]
	if !present {
		pm.mu.RUnlock()
		return pm.database.GetTrafficTimeline(siteID, minutes, now)
	}
	inst.trafficMu.Lock()
	defer inst.trafficMu.Unlock()
	defer pm.mu.RUnlock()
	timeline, err := pm.database.GetTrafficTimeline(siteID, minutes, now)
	if err != nil {
		return nil, err
	}
	mergePendingMinuteTraffic(timeline, inst.pendingMinuteTraffic)
	return timeline, nil
}

// overlaySiteTrafficLocked fills st with the authoritative live per-instance
// state for a running site: persistedTraffic + pending bytes, exactly the same
// merge every traffic view renders. The caller must hold pm.mu (read or
// write); inst.trafficMu is acquired here following the pm.mu -> trafficMu
// lock order, so the overlay never interleaves with a concurrent flush. This
// is the single per-site merge algorithm for all live traffic payloads.
func (pm *ProxyManager) overlaySiteTrafficLocked(s Site, st *SiteTraffic) {
	if inst, ok := pm.proxies[s.ID]; ok {
		inst.trafficMu.Lock()
		st.Running = inst.isOperational()
		st.PersistedTraffic = inst.persistedTraffic.Load()
		st.BytesIn = inst.bytesIn.Load()
		st.BytesOut = inst.bytesOut.Load()
		st.TrafficUsed = st.PersistedTraffic + st.BytesIn + st.BytesOut
		st.Requests = inst.reqCount.Load()
		inst.trafficMu.Unlock()
	}
}

// LiveSiteTraffic overlays the authoritative live traffic state (persisted
// baseline plus pending bytes, under each instance's trafficMu) onto the given
// DB sites and returns it as a map keyed by site ID. One pm.mu read lock is
// taken for the whole map, so the view is consistent and there is no N+1 lock
// churn; the lock order is pm.mu -> trafficMu.
func (pm *ProxyManager) LiveSiteTraffic(sites []Site) map[int64]SiteTraffic {
	live := make(map[int64]SiteTraffic, len(sites))
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for _, s := range sites {
		st := SiteTraffic{
			ID:               s.ID,
			Name:             s.Name,
			TrafficQuota:     s.TrafficQuota,
			PersistedTraffic: s.TrafficUsed,
			TrafficUsed:      s.TrafficUsed,
		}
		pm.overlaySiteTrafficLocked(s, &st)
		live[s.ID] = st
	}
	return live
}

// TrafficSnapshot builds the authoritative global traffic payload: every DB
// site, overlaid with live per-instance state for running sites. Dashboard,
// traffic overview and SSE events all render this single payload.
func (pm *ProxyManager) TrafficSnapshot() (*TrafficSnapshot, error) {
	sites, err := pm.database.ListSites()
	if err != nil {
		return nil, err
	}
	snap := &TrafficSnapshot{
		TotalSites: len(sites),
		LiveSites:  make([]SiteTraffic, 0, len(sites)),
	}
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for _, inst := range pm.proxies {
		if inst.isOperational() {
			snap.RunningSites++
		}
	}
	for _, s := range sites {
		st := SiteTraffic{
			ID:               s.ID,
			Name:             s.Name,
			TrafficQuota:     s.TrafficQuota,
			PersistedTraffic: s.TrafficUsed,
			TrafficUsed:      s.TrafficUsed,
		}
		if s.Enabled {
			snap.OnlineSites++
		}
		pm.overlaySiteTrafficLocked(s, &st)
		snap.TotalTraffic += st.TrafficUsed
		snap.TotalRequests += st.Requests
		snap.LiveSites = append(snap.LiveSites, st)
	}
	snap.UptimeSeconds = int64(time.Since(startTime).Seconds())
	return snap, nil
}

func (pm *ProxyManager) GetRunningCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	running := 0
	for _, inst := range pm.proxies {
		if inst.isOperational() {
			running++
		}
	}
	return running
}

func (pm *ProxyManager) GetSiteRuntime(id int64) (requests int64, startedAt time.Time, running, portListening bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	inst, ok := pm.proxies[id]
	if !ok {
		return 0, time.Time{}, false, false
	}
	return inst.reqCount.Load(), inst.startedAt, inst.isOperational(), inst.portServing.Load()
}

// GracefulShutdown stops all proxies gracefully
func (pm *ProxyManager) GracefulShutdown(ctx context.Context) {
	pm.lifecycleMu.Lock()
	defer pm.lifecycleMu.Unlock()
	pm.shutdownStarted.Store(true)
	pm.mu.RLock()
	instances := make(map[int64]*ProxyInstance, len(pm.proxies))
	for id, inst := range pm.proxies {
		instances[id] = inst
	}
	pm.mu.RUnlock()

	type shutdownResult struct {
		id   int64
		inst *ProxyInstance
		err  error
	}
	results := make(chan shutdownResult, len(instances))
	for id, inst := range instances {
		log.Printf("[%s] shutting down...", inst.Site.Name)
		go func(id int64, inst *ProxyInstance) {
			// shutdown closes the request gate and every listener/connection before
			// waiting, so launching all instances in parallel stops every ingress
			// promptly instead of spending the shared deadline site by site.
			progressErr := inst.drainProgress(ctx)
			shutdownErr := inst.shutdown(ctx)
			results <- shutdownResult{id: id, inst: inst, err: errors.Join(progressErr, shutdownErr)}
		}(id, inst)
	}

	// Capture an early best-effort checkpoint after all shutdowns have started.
	// The final pass below always runs, even when one or more drains time out.
	for _, inst := range instances {
		if err := pm.flushProxyTraffic(inst); err != nil {
			log.Printf("[%s] pre-shutdown traffic flush failed: %v", inst.Site.Name, err)
		}
	}

	drainErrors := make(map[int64]error, len(instances))
	for range instances {
		result := <-results
		drainErrors[result.id] = result.err
		if result.err != nil {
			log.Printf("[%s] shutdown drain failed: %v", result.inst.Site.Name, result.err)
		}
	}

	for id, inst := range instances {
		if err := pm.flushProxyTraffic(inst); err != nil {
			log.Printf("[%s] final shutdown traffic flush failed: %v", inst.Site.Name, err)
			continue
		}
		if drainErrors[id] != nil {
			// Keep a timed-out instance addressable: a caller that does not exit the
			// process may retry and persist counters produced by a late request.
			continue
		}
		pm.mu.Lock()
		if pm.proxies[id] == inst {
			delete(pm.proxies, id)
		}
		pm.mu.Unlock()
		inst.closeProgress()
	}
}

type DiagResult struct {
	Upstreams DiagUpstreams `json:"upstreams"`
	Health    DiagHealth    `json:"health"`
	TLS       DiagTLS       `json:"tls"`
	Headers   DiagHeaders   `json:"headers"`
	Proxy     DiagProxy     `json:"proxy"`
}

type DiagUpstreams struct {
	Primary  DiagUpstream `json:"primary"`
	Playback DiagUpstream `json:"playback"`
}

type DiagUpstream struct {
	Configured    bool       `json:"configured"`
	ConfiguredURL string     `json:"configured_url,omitempty"`
	EffectiveURL  string     `json:"effective_url"`
	UsingFallback bool       `json:"using_fallback"`
	SameAsPrimary bool       `json:"same_as_primary"`
	ShowHealth    bool       `json:"show_health"`
	ShowTLS       bool       `json:"show_tls"`
	Health        DiagHealth `json:"health"`
	TLS           DiagTLS    `json:"tls"`
}

type DiagProbe struct {
	Kind       string `json:"kind"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

type DiagHealth struct {
	Status    string    `json:"status"` // online, offline, error
	EmbyVer   string    `json:"emby_version"`
	LatencyMs int64     `json:"latency_ms"`
	Probe     DiagProbe `json:"probe"`
	Error     string    `json:"error,omitempty"`
}

type DiagTLS struct {
	Enabled   bool   `json:"enabled"`
	Valid     bool   `json:"valid"`
	Issuer    string `json:"issuer"`
	ExpiresAt string `json:"expires_at"`
	DaysLeft  int    `json:"days_left"`
	Error     string `json:"error,omitempty"`
}

type DiagHeaders struct {
	// Passthrough is the explicit marker for ua_mode passthrough: the client's
	// identity headers are preserved, so no configured identity is shown.
	Passthrough  bool   `json:"passthrough"`
	UAApplied    bool   `json:"ua_applied"`
	CurrentUA    string `json:"current_ua"`
	ClientField  string `json:"client_field"`
	VersionField string `json:"version_field"`
	ProfileError string `json:"profile_error,omitempty"`
}

type DiagProxy struct {
	Running       bool   `json:"running"`
	IngressMode   string `json:"ingress_mode"`
	PublicHost    string `json:"public_host,omitempty"`
	PortListening bool   `json:"port_listening"`
	ListenPort    int    `json:"listen_port"`
	TotalReqs     int64  `json:"total_requests"`
	Uptime        string `json:"uptime,omitempty"`
}

func tlsIssuerName(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if len(cert.Issuer.Organization) > 0 && cert.Issuer.Organization[0] != "" {
		return cert.Issuer.Organization[0]
	}
	if cert.Issuer.CommonName != "" {
		return cert.Issuer.CommonName
	}
	return cert.Issuer.String()
}

func canonicalTargetKey(target *url.URL) string {
	if target == nil {
		return ""
	}

	normalized := *target
	normalized.Scheme = strings.ToLower(normalized.Scheme)
	normalized.Host = strings.ToLower(normalized.Host)
	normalized.RawQuery = ""
	normalized.Fragment = ""

	cleanPath := path.Clean("/" + strings.Trim(normalized.Path, "/"))
	if cleanPath == "." || cleanPath == "/" {
		normalized.Path = ""
	} else {
		normalized.Path = cleanPath
	}

	return normalized.String()
}

func buildProbeURLs(target *url.URL, suffixes []string) []string {
	basePath := strings.TrimSpace(target.Path)
	seen := map[string]struct{}{}
	urls := make([]string, 0, len(suffixes))
	for _, suffix := range suffixes {
		probe := *target
		probe.RawQuery = ""
		probe.Fragment = ""
		if suffix == "" {
			cleanPath := path.Clean("/" + strings.Trim(basePath, "/"))
			if cleanPath == "." || cleanPath == "" {
				cleanPath = "/"
			}
			probe.Path = cleanPath
		} else {
			probe.Path = path.Clean("/" + path.Join(strings.Trim(basePath, "/"), suffix))
		}
		if _, ok := seen[probe.String()]; ok {
			continue
		}
		seen[probe.String()] = struct{}{}
		urls = append(urls, probe.String())
	}
	return urls
}

func healthProbeURLs(target *url.URL) []string {
	if strings.TrimSpace(target.Path) == "" || strings.TrimSpace(target.Path) == "/" {
		return buildProbeURLs(target, []string{"System/Info/Public", "emby/System/Info/Public", ""})
	}
	return buildProbeURLs(target, []string{"System/Info/Public", ""})
}

func playbackProbeURLs(target *url.URL) []string {
	return healthProbeURLs(target)
}

type diagProbePlan struct {
	BaseURL       string
	Kind          string
	Method        string
	CandidateURLs []string
	ParseVersion  bool
}

func resolveProbeKind(plan diagProbePlan, probeURL string) string {
	if plan.Kind != "metadata_api" {
		return plan.Kind
	}

	baseTarget, baseErr := normalizeTargetURL(plan.BaseURL)
	probeTarget, probeErr := normalizeTargetURL(probeURL)
	if baseErr != nil || probeErr != nil {
		return plan.Kind
	}

	basePath := strings.TrimSpace(baseTarget.Path)
	if basePath == "" {
		basePath = "/"
	}
	probePath := strings.TrimSpace(probeTarget.Path)
	if probePath == "" {
		probePath = "/"
	}
	if strings.TrimRight(probePath, "/") == strings.TrimRight(basePath, "/") {
		return "reachability_fallback"
	}

	return plan.Kind
}

func probeStatusRank(status int) int {
	switch {
	case status >= 200 && status < 300:
		return 4
	case status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusMethodNotAllowed:
		return 3
	case status == http.StatusNotFound:
		return 2
	case status > 0 && status < 500:
		return 1
	default:
		return 0
	}
}

// probeClient is shared by every diagnostics probe. Building a fresh
// http.Transport per call left idle keep-alive connections with a zero
// IdleConnTimeout, meaning they never expired, and CloseIdleConnections was never
// called, so each run stranded upstream sockets along with their read and write
// goroutines. DefaultTransport.Clone() brings a 90s IdleConnTimeout, matching
// what StartSite already does for the proxy transport.
var probeClient = func() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = secureTLSConfig("")
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		// Diagnostics must never become an internal scanner: a configured
		// upstream that answers with a redirect is only allowed to point back
		// at the same authority. Everything else stops the probe instead of
		// following the hop into private or third-party ranges.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("diagnostic probe followed too many redirects")
			}
			previous := via[len(via)-1]
			if !sameRedirectAuthority(previous.URL, req.URL) {
				return errors.New("diagnostic probe redirect to a different host is not allowed")
			}
			return nil
		},
	}
}()

func probeTargetHealth(plan diagProbePlan) DiagHealth {
	client := probeClient
	var bestReachable DiagHealth
	bestReachableRank := 0
	var serverError DiagHealth

	for _, probeURL := range plan.CandidateURLs {
		health := DiagHealth{
			Probe: DiagProbe{
				Kind:   resolveProbeKind(plan, probeURL),
				Method: plan.Method,
				URL:    probeURL,
			},
		}
		req, err := http.NewRequest(plan.Method, probeURL, nil)
		if err != nil {
			health.Status = "offline"
			health.Error = err.Error()
			return health
		}

		start := time.Now()
		resp, err := client.Do(req) // #nosec G704 -- diagnostics probe only the administrator-configured, validated upstream.
		latency := time.Since(start).Milliseconds()
		health.LatencyMs = latency
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			health.Status = "offline"
			health.Error = err.Error()
			return health
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		health.Probe.HTTPStatus = resp.StatusCode

		if resp.StatusCode >= 500 {
			if serverError.Error == "" {
				health.Status = "error"
				health.Error = fmt.Sprintf("probe returned HTTP %d", resp.StatusCode)
				serverError = health
			}
			continue
		}

		health.Status = "online"
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if plan.ParseVersion {
				var info map[string]interface{}
				if json.Unmarshal(body, &info) == nil {
					if v, ok := info["Version"]; ok {
						health.EmbyVer = fmt.Sprintf("%v", v)
					}
				}
			}
			return health
		}

		rank := probeStatusRank(resp.StatusCode)
		if rank > bestReachableRank {
			bestReachable = health
			bestReachableRank = rank
		}
		if plan.Kind == "playback_path" && rank >= 3 {
			return health
		}
	}

	if bestReachableRank > 0 {
		return bestReachable
	}
	if serverError.Error != "" {
		return serverError
	}
	return DiagHealth{
		Status: "offline",
		Probe: DiagProbe{
			Kind:   plan.Kind,
			Method: plan.Method,
			URL:    plan.BaseURL,
		},
		Error: "health probe failed",
	}
}

func probeSiteHealth(targetURL string) DiagHealth {
	target, err := normalizeTargetURL(targetURL)
	if err != nil {
		return DiagHealth{
			Status: "offline",
			Probe: DiagProbe{
				Kind:   "metadata_api",
				Method: http.MethodGet,
			},
			Error: err.Error(),
		}
	}
	return probeTargetHealth(diagProbePlan{
		BaseURL:       target.String(),
		Kind:          "metadata_api",
		Method:        http.MethodGet,
		CandidateURLs: healthProbeURLs(target),
		ParseVersion:  true,
	})
}

func probePlaybackHealth(targetURL string) DiagHealth {
	target, err := normalizeTargetURL(targetURL)
	if err != nil {
		return DiagHealth{
			Status: "offline",
			Probe: DiagProbe{
				Kind:   "metadata_api",
				Method: http.MethodGet,
			},
			Error: err.Error(),
		}
	}
	return probeTargetHealth(diagProbePlan{
		BaseURL:       target.String(),
		Kind:          "metadata_api",
		Method:        http.MethodGet,
		CandidateURLs: playbackProbeURLs(target),
		ParseVersion:  true,
	})
}

func probeSiteTLS(target *url.URL) DiagTLS {
	var result DiagTLS
	if target == nil || !strings.EqualFold(target.Scheme, "https") {
		return result
	}

	result.Enabled = true
	host := target.Hostname()
	port := target.Port()
	if port == "" {
		port = "443"
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		net.JoinHostPort(host, port),
		secureTLSConfig(host),
	)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return result
	}

	cert := certs[0]
	result.Valid = true
	result.Issuer = tlsIssuerName(cert)
	result.ExpiresAt = cert.NotAfter.Format("2006-01-02")
	result.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)

	return result
}

func secureTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}
}

func diagnoseUpstreamTarget(targetURL, probeKind string) (DiagUpstream, string) {
	trimmed := strings.TrimSpace(targetURL)
	result := DiagUpstream{
		Configured:    trimmed != "",
		ConfiguredURL: displayTargetURL(trimmed),
		EffectiveURL:  displayTargetURL(trimmed),
		ShowHealth:    true,
	}

	parsed, err := normalizeTargetURL(targetURL)
	if err != nil {
		result.Health = DiagHealth{Status: "offline", Error: err.Error()}
		return result, ""
	}

	result.ConfiguredURL = displayTargetURL(parsed.String())
	result.EffectiveURL = displayTargetURL(parsed.String())
	switch probeKind {
	case "playback_path":
		result.Health = probePlaybackHealth(parsed.String())
	default:
		result.Health = probeSiteHealth(parsed.String())
	}
	result.TLS = probeSiteTLS(parsed)
	result.ShowTLS = result.TLS.Enabled

	return result, canonicalTargetKey(parsed)
}

// displayTargetURL drops the query string before a configured upstream is
// shown in the panel: signed URLs and API keys in query parameters must not be
// rendered, because diagnostics output can be captured in screenshots or logs.
func displayTargetURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return raw
	}
	parsed.RawQuery = ""
	return parsed.String()
}

func diagnoseSite(site *Site, pm *ProxyManager) DiagResult {
	policy, profileErr := resolveUAHeaderPolicy(*site)
	primary, primaryKey := diagnoseUpstreamTarget(site.TargetURL, "metadata_api")
	primary.Configured = true
	primary.ShowHealth = true
	primary.ShowTLS = primary.TLS.Enabled

	playbackTarget, _, playbackConfigErr := resolvePlaybackConfiguration(site.PlaybackTargetURL, site.StreamHosts)
	playbackRaw := ""
	if playbackTarget != nil {
		playbackRaw = playbackTarget.String()
	}
	playback := primary
	playback.ConfiguredURL = ""
	playback.Configured = false
	playback.UsingFallback = true
	playback.SameAsPrimary = true
	playback.ShowHealth = false
	playback.ShowTLS = false

	if playbackConfigErr != nil {
		playback = DiagUpstream{
			Configured:    true,
			UsingFallback: false,
			SameAsPrimary: false,
			ShowHealth:    true,
			Health:        DiagHealth{Status: "offline", Error: playbackConfigErr.Error()},
		}
	} else if playbackRaw != "" {
		var playbackKey string
		playback, playbackKey = diagnoseUpstreamTarget(playbackRaw, "playback_path")
		playback.Configured = true
		playback.UsingFallback = false
		playback.SameAsPrimary = playbackKey != "" && playbackKey == primaryKey
		if playback.SameAsPrimary {
			playback.Health = primary.Health
			playback.TLS = primary.TLS
			playback.EffectiveURL = primary.EffectiveURL
			playback.ShowHealth = false
			playback.ShowTLS = false
		}
	}

	result := DiagResult{
		Upstreams: DiagUpstreams{
			Primary:  primary,
			Playback: playback,
		},
		Health: primary.Health,
		TLS:    primary.TLS,
	}

	// Headers
	if profileErr != nil {
		result.Headers = DiagHeaders{
			ProfileError: "invalid stored UA configuration",
		}
	} else if !policy.Rewrite {
		// Passthrough has no configured identity to show, and the real request
		// headers must never be rendered in diagnostics output.
		result.Headers = DiagHeaders{
			Passthrough: true,
			UAApplied:   false,
		}
	} else {
		result.Headers = DiagHeaders{
			UAApplied:    true,
			CurrentUA:    policy.Profile.UserAgent,
			ClientField:  policy.Profile.Client,
			VersionField: policy.Profile.Version,
		}
	}

	// Proxy status
	totalRequests, startedAt, running, portListening := pm.GetSiteRuntime(site.ID)
	uptime := ""
	if running && !startedAt.IsZero() {
		duration := time.Since(startedAt).Round(time.Second)
		if duration < 0 {
			duration = 0
		}
		uptime = duration.String()
	}
	result.Proxy = DiagProxy{
		Running:       running,
		IngressMode:   site.IngressMode,
		PublicHost:    site.PublicHost,
		PortListening: portListening,
		ListenPort:    site.ListenPort,
		TotalReqs:     totalRequests,
		Uptime:        uptime,
	}

	return result
}

type App struct {
	db                *DB
	pm                *ProxyManager
	siteLifecycleMu   sync.Mutex
	setupTokenMu      sync.Mutex
	setupToken        string
	loginLimiter      *loginRateLimiter
	loginLimiterOnce  sync.Once
	trustedProxies    []*net.IPNet
	panelHost         string
	panelBindLoopback bool
	panelListenPort   int
	dynamicRouteKey   []byte
}

func (pm *ProxyManager) snapshotDynamicSelfTargetPolicy(panelHost string, panelPort int, interfaceAddrs dynamicInterfaceAddrsFunc) (*dynamicSelfTargetPolicy, error) {
	if pm == nil || pm.database == nil {
		return nil, fmt.Errorf("dynamic self-target policy requires proxy manager database state")
	}
	sites, err := pm.database.ListSites()
	if err != nil {
		return nil, fmt.Errorf("snapshot configured sites for dynamic self-target policy: %w", err)
	}
	return newDynamicSelfTargetPolicy(panelHost, panelPort, sites, interfaceAddrs)
}

func (a *App) snapshotDynamicSelfTargetPolicy(interfaceAddrs dynamicInterfaceAddrsFunc) (*dynamicSelfTargetPolicy, error) {
	if a == nil || a.pm == nil {
		return nil, fmt.Errorf("dynamic self-target policy requires application proxy state")
	}
	a.siteLifecycleMu.Lock()
	defer a.siteLifecycleMu.Unlock()
	return a.pm.snapshotDynamicSelfTargetPolicy(a.panelHost, a.panelListenPort, interfaceAddrs)
}

func isLoopbackHealthProbe(r *http.Request) bool {
	if r == nil || r.Method != http.MethodGet || r.URL.Path != "/api/auth/check" {
		return false
	}
	for name := range r.Header {
		// A real local health probe arrives directly. If an edge proxy supplied
		// client-forwarding identity, a loopback transport peer alone must not
		// bypass strict PANEL_DOMAIN routing.
		if isManagedForwardingHeaderName(name) {
			return false
		}
	}
	peerIP := remoteAddressIP(r.RemoteAddr)
	if peerIP == nil || !peerIP.IsLoopback() {
		return false
	}
	host := strings.TrimSpace(r.Host)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	} else if strings.Count(host, ":") > 1 {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	hostIP := net.ParseIP(host)
	return hostIP != nil && hostIP.IsLoopback()
}

func (a *App) publicHostRouter(panel http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := requestPublicHost(r.Host)
		if host != "" {
			handler, configured, mode := a.pm.PublicHostRoute(host)
			if configured {
				if mode == ingressModeHost && !a.panelBindLoopback && !isTrustedProxy(remoteAddressIP(r.RemoteAddr), a.trustedProxies) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":"host-only ingress requires a configured proxy source"}`))
					return
				}
				if handler == nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`{"error":"site unavailable"}`))
					return
				}
				r = r.WithContext(context.WithValue(r.Context(), publicHostIngressContextKey{}, true))
				handler.ServeHTTP(w, r)
				return
			}
		}
		if a.panelHost == "" || host == a.panelHost || isLoopbackHealthProbe(r) {
			panel.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = w.Write([]byte(`{"error":"unrecognized host"}`))
	})
}

const (
	// 128 playback URLs at the per-entry limit plus site metadata fit below
	// this ceiling. Individual fields and list counts remain separately bounded.
	maxJSONBodyBytes = 512 << 10
	// speedLimitBytes multiplies this field by 125000, so an unbounded value
	// wraps int64 and silently disables the limit instead of tightening it.
	// 1000000 matches the max the site form already enforces.
	maxSpeedLimitMbps      = 1000000
	maxLoginFailures       = 5
	maxTrackedLoginClients = 10000
	loginFailureWindow     = 15 * time.Minute
	loginLockoutDuration   = 15 * time.Minute
)

type loginAttempt struct {
	failures     int
	firstFailure time.Time
	blockedUntil time.Time
	lastSeen     time.Time
}

type loginRateLimiter struct {
	mu         sync.Mutex
	attempts   map[string]loginAttempt
	maxEntries int
}

func newLoginRateLimiter() *loginRateLimiter {
	return newLoginRateLimiterWithLimit(maxTrackedLoginClients)
}

func newLoginRateLimiterWithLimit(maxEntries int) *loginRateLimiter {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &loginRateLimiter{
		attempts:   make(map[string]loginAttempt),
		maxEntries: maxEntries,
	}
}

func (l *loginRateLimiter) pruneExpired(now time.Time) {
	for client, attempt := range l.attempts {
		if now.Before(attempt.blockedUntil) {
			continue
		}
		if attempt.firstFailure.IsZero() || !now.Before(attempt.firstFailure.Add(loginFailureWindow)) {
			delete(l.attempts, client)
		}
	}
}

func (l *loginRateLimiter) evictLeastRecentlySeen() {
	var oldestClient string
	var oldestSeen time.Time
	for client, attempt := range l.attempts {
		seen := attempt.lastSeen
		if seen.IsZero() {
			seen = attempt.firstFailure
		}
		if oldestClient == "" || seen.Before(oldestSeen) {
			oldestClient = client
			oldestSeen = seen
		}
	}
	if oldestClient != "" {
		delete(l.attempts, oldestClient)
	}
}

func (l *loginRateLimiter) allow(client string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneExpired(now)
	attempt, ok := l.attempts[client]
	if !ok {
		return true, 0
	}
	attempt.lastSeen = now
	if now.Before(attempt.blockedUntil) {
		l.attempts[client] = attempt
		return false, attempt.blockedUntil.Sub(now)
	}
	l.attempts[client] = attempt
	return true, 0
}

func (l *loginRateLimiter) recordFailure(client string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneExpired(now)
	attempt, exists := l.attempts[client]
	if !exists && len(l.attempts) >= l.maxEntries {
		l.evictLeastRecentlySeen()
	}
	if attempt.firstFailure.IsZero() || now.Sub(attempt.firstFailure) >= loginFailureWindow {
		attempt = loginAttempt{firstFailure: now}
	}
	attempt.failures++
	attempt.lastSeen = now
	if attempt.failures >= maxLoginFailures {
		attempt.blockedUntil = now.Add(loginLockoutDuration)
	}
	l.attempts[client] = attempt
}

func (l *loginRateLimiter) reset(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, client)
}

func (a *App) limiter() *loginRateLimiter {
	a.loginLimiterOnce.Do(func() {
		if a.loginLimiter == nil {
			a.loginLimiter = newLoginRateLimiter()
		}
	})
	return a.loginLimiter
}

func parseTrustedProxyCIDRs(value string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid TRUSTED_PROXY_CIDRS entry %q: %w", raw, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func remoteAddressIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(remoteAddr)
}

func isTrustedProxy(ip net.IP, networks []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func requestClientKey(r *http.Request, trustedProxies []*net.IPNet) string {
	peerIP := remoteAddressIP(r.RemoteAddr)
	if isTrustedProxy(peerIP, trustedProxies) {
		// The trusted edge must normalize the client address into a single
		// X-Real-IP value. Never select from X-Forwarded-For: common
		// $proxy_add_x_forwarded_for configurations retain attacker-supplied
		// left-most values and would let clients rotate the login limiter key.
		if value, ok := singleForwardedHeaderValue(r.Header, "X-Real-IP"); ok {
			if forwarded := net.ParseIP(value); forwarded != nil {
				return forwarded.String()
			}
		}
	}
	if peerIP != nil {
		return peerIP.String()
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain one JSON object")
		}
		return err
	}
	return nil
}

func originMatchesRequestHost(origin string, r *http.Request) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func refererMatchesRequestHost(referer string, r *http.Request) bool {
	parsed, err := url.Parse(referer)
	if err != nil || parsed.User != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func requestHasSameOrigin(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		return originMatchesRequestHost(origin, r)
	}
	return refererMatchesRequestHost(r.Referer(), r)
}

func stateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if !originMatchesRequestHost(origin, r) {
				http.Error(w, "cross-origin request denied", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func panelBodyReadDeadline(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && (r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
			controller := http.NewResponseController(w)
			// Keep the deadline through net/http's post-handler request-body drain.
			// Clearing it when the handler returns lets a slow client keep dripping an
			// unread body indefinitely. The server installs the next request/idle
			// deadline before reusing a healthy keep-alive connection.
			_ = controller.SetReadDeadline(time.Now().Add(30 * time.Second))
		}
		next.ServeHTTP(w, r)
	})
}

func staticHandler(staticFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(staticFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		f, err := staticFS.Open(strings.TrimPrefix(path, "/"))
		if err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}

func (a *App) jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("write JSON response: %v", err)
	}
}

func (a *App) jsonOK(w http.ResponseWriter, data interface{}) {
	a.jsonResponse(w, http.StatusOK, data)
}

func (a *App) jsonErr(w http.ResponseWriter, status int, msg string) {
	a.jsonResponse(w, status, map[string]string{"error": msg})
}

func requestIsHTTPS(r *http.Request, trustedProxies []*net.IPNet) bool {
	if r.TLS != nil {
		return true
	}
	if !isTrustedProxy(remoteAddressIP(r.RemoteAddr), trustedProxies) {
		return false
	}
	forwardedProto, ok := singleForwardedHeaderValue(r.Header, "X-Forwarded-Proto")
	return ok && strings.EqualFold(forwardedProto, "https")
}

func (a *App) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	// #nosec G124 -- direct HTTP panel access is a documented compatibility mode;
	// requestIsHTTPS only accepts X-Forwarded-Proto from configured proxies.
	// CodeQL: Secure is conditional only for the documented direct-HTTP
	// compatibility mode; trusted proxy provenance is validated before
	// X-Forwarded-Proto can enable it.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(sessionDuration),
		MaxAge:   int(sessionDuration.Seconds()),
		Secure:   requestIsHTTPS(r, a.trustedProxies),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (a *App) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	// #nosec G124 -- must match setSessionCookie so HTTP sessions can be cleared.
	// CodeQL: deletion must use the same conditional Secure attribute as
	// creation or an HTTP compatibility session cannot be reliably cleared.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0),
		MaxAge:   -1,
		Secure:   requestIsHTTPS(r, a.trustedProxies),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func sessionIdentity(r *http.Request) (int64, string, error) {
	for _, cookie := range r.Cookies() {
		if cookie.Name != sessionCookieName || cookie.Value == "" {
			continue
		}
		userID, username, err := validateToken(cookie.Value)
		if err == nil {
			// Accept the signed management value even if an untrusted sibling
			// origin managed to prepend an invalid same-name cookie. The attacker
			// cannot forge a second valid token, so this avoids cookie-shadowing
			// logout/DoS without weakening authentication.
			return userID, username, nil
		}
	}
	return 0, "", errors.New("missing or invalid session")
}

func (a *App) csrfMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if stateChangingMethod(r.Method) && !requestHasSameOrigin(r) {
			a.jsonErr(w, http.StatusForbidden, "same-origin request required")
			return
		}
		next(w, r)
	}
}

func (a *App) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := sessionIdentity(r); err != nil {
			a.jsonErr(w, http.StatusUnauthorized, "session expired or invalid")
			return
		}
		if stateChangingMethod(r.Method) && !requestHasSameOrigin(r) {
			a.jsonErr(w, http.StatusForbidden, "same-origin request required")
			return
		}
		next(w, r)
	}
}

// POST /api/auth/setup
func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.jsonErr(w, 405, "method not allowed")
		return
	}
	client := requestClientKey(r, a.trustedProxies)
	if allowed, retryAfter := a.limiter().allow(client, time.Now()); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retryAfter.Seconds()+0.5))))
		a.jsonErr(w, http.StatusTooManyRequests, "too many setup attempts; try again later")
		return
	}
	a.setupTokenMu.Lock()
	defer a.setupTokenMu.Unlock()
	userCount, err := a.db.UserCount()
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "setup status unavailable")
		return
	}
	if userCount > 0 {
		a.jsonErr(w, 400, "admin user already exists")
		return
	}
	var req struct {
		Username   string `json:"username"`
		Password   string `json:"password"` // #nosec G117 -- request-only credential DTO; the value is never serialized or stored in plaintext.
		SetupToken string `json:"setup_token"`
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		a.jsonErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Username) > 64 || len(req.Password) < 12 || len(req.Password) > 72 {
		a.jsonErr(w, http.StatusBadRequest, "username must be 1-64 characters and password must be 12-72 bytes")
		return
	}
	if a.setupToken == "" || !setupTokenMatches(a.setupToken, req.SetupToken) {
		a.limiter().recordFailure(client, time.Now())
		a.jsonErr(w, http.StatusForbidden, "invalid setup token")
		return
	}
	id, err := a.db.CreateInitialUser(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, errAdminAlreadyExists) {
			a.limiter().recordFailure(client, time.Now())
			a.jsonErr(w, http.StatusConflict, errAdminAlreadyExists.Error())
			return
		}
		a.jsonErr(w, http.StatusInternalServerError, "unable to create admin user")
		return
	}
	a.limiter().reset(client)
	token, err := generateToken(id, req.Username)
	if err != nil {
		a.jsonErr(w, 500, err.Error())
		return
	}
	a.setupToken = ""
	w.Header().Set("Cache-Control", "no-store")
	a.setSessionCookie(w, r, token)
	a.jsonOK(w, map[string]interface{}{"username": req.Username})
}

// POST /api/auth/login
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.jsonErr(w, 405, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"` // #nosec G117 -- request-only credential DTO; the value is never serialized or stored in plaintext.
	}
	client := requestClientKey(r, a.trustedProxies)
	if allowed, retryAfter := a.limiter().allow(client, time.Now()); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retryAfter.Seconds()+0.5))))
		a.jsonErr(w, http.StatusTooManyRequests, "too many login attempts; try again later")
		return
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		a.limiter().recordFailure(client, time.Now())
		a.jsonErr(w, 400, "invalid request")
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" || len(username) > 64 || req.Password == "" || len(req.Password) > 72 {
		a.limiter().recordFailure(client, time.Now())
		a.jsonErr(w, http.StatusUnauthorized, errInvalidCredentials.Error())
		return
	}
	id, err := a.db.VerifyUser(username, req.Password)
	if err != nil {
		a.limiter().recordFailure(client, time.Now())
		if errors.Is(err, errInvalidCredentials) {
			a.jsonErr(w, http.StatusUnauthorized, errInvalidCredentials.Error())
			return
		}
		a.jsonErr(w, http.StatusInternalServerError, "authentication unavailable")
		return
	}
	a.limiter().reset(client)
	token, err := generateToken(id, username)
	if err != nil {
		a.jsonErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	a.setSessionCookie(w, r, token)
	a.jsonOK(w, map[string]interface{}{"username": username})
}

// POST /api/auth/logout
func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	a.clearSessionCookie(w, r)
	a.jsonOK(w, map[string]bool{"logged_out": true})
}

// GET /api/auth/check
func (a *App) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	userCount, err := a.db.UserCount()
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "setup status unavailable")
		return
	}
	needsSetup := userCount == 0
	authenticated := false
	username := ""
	if !needsSetup {
		if _, sessionUsername, err := sessionIdentity(r); err == nil {
			authenticated = true
			username = sessionUsername
		}
	}
	a.jsonOK(w, map[string]interface{}{
		"needs_setup":          needsSetup,
		"mode":                 "single_admin",
		"jwt_secret_ephemeral": jwtSecretEphemeral,
		"setup_token_required": needsSetup,
		"authenticated":        authenticated,
		"username":             username,
	})
}

// GET /api/dashboard
func (a *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	snap, err := a.pm.TrafficSnapshot()
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "dashboard unavailable")
		return
	}
	a.jsonOK(w, snap)
}

// GET /api/ingress-capabilities exposes only coarse deployment state so the
// site form can avoid proposing host-only mode when the backend must reject it.
func (a *App) handleIngressCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	a.jsonOK(w, map[string]interface{}{
		"host_only_available":        a.pm.HostOnlyIngressSafe(),
		"panel_bind_loopback":        a.panelBindLoopback,
		"trusted_proxy_configured":   len(a.trustedProxies) > 0,
		"upstream_headers_available": a.pm.UpstreamHeadersAvailable(),
		"max_playback_addresses":     maxPlaybackAddresses,
	})
}

// GET/POST /api/sites
func (a *App) handleSites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		sites, err := a.db.ListSites()
		if err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		// Overlay the authoritative live traffic state (persisted + pending)
		// for running sites, exactly the merge TrafficSnapshot renders; every
		// non-traffic field keeps its DB value. One pm.mu read lock covers the
		// whole map, so there is no N+1 lock handoff per site.
		live := a.pm.LiveSiteTraffic(sites)
		// Add running status
		type SiteWithStatus struct {
			Site
			Running bool `json:"running"`
		}
		result := make([]SiteWithStatus, len(sites))
		for i, s := range sites {
			st := live[s.ID]
			result[i] = SiteWithStatus{Site: s, Running: st.Running}
			result[i].TrafficUsed = st.TrafficUsed
		}
		a.jsonOK(w, result)

	case "POST":
		var req struct {
			Name                       string                `json:"name"`
			ListenPort                 int                   `json:"listen_port"`
			PublicHost                 string                `json:"public_host"`
			IngressMode                string                `json:"ingress_mode"`
			TargetURL                  string                `json:"target_url"`
			PlaybackTargetURL          string                `json:"playback_target_url"`
			PlaybackMode               string                `json:"playback_mode"`
			StreamHosts                []string              `json:"stream_hosts"`
			UAMode                     string                `json:"ua_mode"`
			CustomUserAgent            string                `json:"custom_user_agent"`
			CustomClient               string                `json:"custom_client"`
			CustomVersion              string                `json:"custom_version"`
			UpstreamHeaders            []UpstreamHeaderInput `json:"upstream_headers"`
			PingCacheEnabled           bool                  `json:"ping_cache_enabled"`
			ImageCacheEnabled          bool                  `json:"image_cache_enabled"`
			ProgressCoalescingEnabled  bool                  `json:"progress_coalescing_enabled"`
			DynamicDiscoveryEnabled    json.RawMessage       `json:"dynamic_discovery_enabled"`
			DynamicProfile             string                `json:"dynamic_profile"`
			DynamicDiscoverySources    json.RawMessage       `json:"dynamic_discovery_sources"`
			DynamicDomainRules         json.RawMessage       `json:"dynamic_domain_rules"`
			DynamicAllowHTTPSDowngrade bool                  `json:"dynamic_allow_https_downgrade"`
			Quota                      int64                 `json:"traffic_quota"`
			SpeedLimit                 int                   `json:"speed_limit"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			a.jsonErr(w, 400, "invalid request")
			return
		}
		dynamicEnabledValue, dynamicEnabledProvided, err := decodeOptionalBoolAPI(req.DynamicDiscoveryEnabled, "dynamic_discovery_enabled")
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		dynamicSources, dynamicSourcesProvided, err := decodeDynamicDiscoverySourcesAPI(req.DynamicDiscoverySources)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		dynamicRules, dynamicRulesProvided, err := decodeDynamicDomainRulesAPI(req.DynamicDomainRules)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if !dynamicRulesProvided {
			dynamicRules = []DynamicDomainRule{}
		}
		if req.Name == "" || req.ListenPort == 0 || req.TargetURL == "" {
			a.jsonErr(w, 400, "name, listen_port, and target_url are required")
			return
		}
		keyConfigured := len(a.dynamicRouteKey) == sha256.Size
		dynamicEnabled := keyConfigured
		if dynamicEnabledProvided {
			dynamicEnabled = dynamicEnabledValue
		}
		dynamicPolicy := Site{
			DynamicDiscoveryEnabled:    dynamicEnabled,
			DynamicProfile:             req.DynamicProfile,
			DynamicDiscoverySources:    dynamicSources,
			DynamicDomainRules:         dynamicRules,
			DynamicAllowHTTPSDowngrade: req.DynamicAllowHTTPSDowngrade,
		}
		if err := normalizeDynamicSitePolicy(&dynamicPolicy); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if dynamicSourcesProvided {
			if err := validateSelectableDynamicDiscoverySources(dynamicPolicy.DynamicProfile, dynamicPolicy.DynamicDiscoverySources); err != nil {
				a.jsonErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		if err := validateDynamicDiscoveryAPIEnablement(dynamicPolicy, keyConfigured, false); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.UAMode == "" {
			req.UAMode = "infuse"
		}
		if req.PlaybackMode == "" {
			req.PlaybackMode = "direct"
		}
		req.Name = strings.TrimSpace(req.Name)
		req.PlaybackMode = strings.ToLower(strings.TrimSpace(req.PlaybackMode))
		publicHost, err := normalizePublicHost(req.PublicHost)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if publicHost != "" && publicHost == a.panelHost {
			a.jsonErr(w, http.StatusBadRequest, "public_host must differ from PANEL_DOMAIN")
			return
		}
		req.PublicHost = publicHost
		req.IngressMode, err = normalizeIngressMode(req.IngressMode, req.PublicHost)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := a.pm.validateIngressSafety(req.IngressMode); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		normalizedMode, customUserAgent, customClient, customVersion, err := normalizeUAConfig(req.UAMode, req.CustomUserAgent, req.CustomClient, req.CustomVersion)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		req.UAMode = normalizedMode
		req.CustomUserAgent = customUserAgent
		req.CustomClient = customClient
		req.CustomVersion = customVersion
		if err := validateSiteSettings(req.Name, req.ListenPort, req.TargetURL, req.PlaybackTargetURL, req.PlaybackMode, req.StreamHosts, req.UAMode, req.CustomUserAgent, req.CustomClient, req.CustomVersion, req.Quota, req.SpeedLimit); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		streamHostsJSON, _ := json.Marshal(req.StreamHosts)
		if req.StreamHosts == nil {
			streamHostsJSON = []byte("[]")
		}
		storedHeaders, err := mergeUpstreamHeaders("[]", req.UpstreamHeaders, a.pm.upstreamHeaderKey, req.TargetURL)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		a.siteLifecycleMu.Lock()
		defer a.siteLifecycleMu.Unlock()
		if req.PublicHost != "" {
			if _, exists := a.pm.PublicHostSiteID(req.PublicHost); exists {
				a.jsonErr(w, http.StatusBadRequest, "public_host is already assigned to another site")
				return
			}
		}
		site, err := a.db.CreateSiteRecord(Site{
			Name:                          req.Name,
			ListenPort:                    req.ListenPort,
			PublicHost:                    req.PublicHost,
			IngressMode:                   req.IngressMode,
			TargetURL:                     req.TargetURL,
			PlaybackTargetURL:             req.PlaybackTargetURL,
			PlaybackMode:                  req.PlaybackMode,
			StreamHosts:                   string(streamHostsJSON),
			UAMode:                        req.UAMode,
			CustomUserAgent:               req.CustomUserAgent,
			CustomClient:                  req.CustomClient,
			CustomVersion:                 req.CustomVersion,
			StoredUpstreamHeaders:         storedHeaders,
			PingCacheEnabled:              req.PingCacheEnabled,
			ImageCacheEnabled:             req.ImageCacheEnabled,
			ProgressCoalescingEnabled:     req.ProgressCoalescingEnabled,
			DynamicDiscoveryEnabled:       dynamicPolicy.DynamicDiscoveryEnabled,
			DynamicProfile:                dynamicPolicy.DynamicProfile,
			StoredDynamicDiscoverySources: dynamicPolicy.StoredDynamicDiscoverySources,
			DynamicDiscoverySources:       dynamicPolicy.DynamicDiscoverySources,
			StoredDynamicDomainRules:      dynamicPolicy.StoredDynamicDomainRules,
			DynamicDomainRules:            dynamicPolicy.DynamicDomainRules,
			DynamicAllowHTTPSDowngrade:    dynamicPolicy.DynamicAllowHTTPSDowngrade,
			TrafficQuota:                  req.Quota,
			SpeedLimit:                    req.SpeedLimit,
		})
		if err != nil {
			if isSQLiteUniqueConstraintError(err) {
				a.jsonErr(w, http.StatusBadRequest, "listen_port or public_host is already assigned")
				return
			}
			log.Printf("create site record: %v", err)
			a.jsonErr(w, http.StatusInternalServerError, "create site failed")
			return
		}
		// Auto start
		if site.Enabled {
			if err := a.pm.StartSite(*site); err != nil {
				if deleteErr := a.db.DeleteSite(site.ID); deleteErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("start site: %v; rollback create: %v", err, deleteErr))
					return
				}
				a.pm.UnregisterSiteHost(site.ID)
				a.jsonErr(w, 500, err.Error())
				return
			}
		}
		a.jsonResponse(w, http.StatusCreated, site)

	default:
		a.jsonErr(w, 405, "method not allowed")
	}
}

// Site lifecycle, diagnostics, and dynamic-observation routes.
func (a *App) handleSiteByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/sites/")
	parts := strings.SplitN(path, "/", 2)
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		a.jsonErr(w, 400, "invalid site id")
		return
	}

	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch {
	case action == "dynamic-observations" && (r.Method == http.MethodGet || r.Method == http.MethodDelete):
		if _, err := a.db.GetSite(id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.jsonErr(w, http.StatusNotFound, "site not found")
			} else {
				a.jsonErr(w, http.StatusInternalServerError, "dynamic observations unavailable")
			}
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodDelete {
			if err := a.db.ClearDynamicObservations(id); err != nil {
				a.jsonErr(w, http.StatusInternalServerError, "clear dynamic observations failed")
				return
			}
			a.jsonOK(w, DynamicObservationsResponse{
				Observations:        make([]DynamicObservation, 0),
				DroppedObservations: a.db.DroppedDynamicObservations(),
			})
			return
		}
		observations, err := a.db.ListDynamicObservations(id)
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "dynamic observations unavailable")
			return
		}
		a.jsonOK(w, DynamicObservationsResponse{
			Observations:        observations,
			DroppedObservations: a.db.DroppedDynamicObservations(),
		})

	case action == "toggle" && r.Method == "POST":
		a.siteLifecycleMu.Lock()
		defer a.siteLifecycleMu.Unlock()
		site, err := a.db.GetSite(id)
		if err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		if site.Enabled {
			// A pre-close failure leaves the running instance usable and aborts the
			// toggle. A post-close failure is different: the listener is already gone,
			// so persist disabled and surface cleanup_pending instead of leaving an
			// enabled-but-offline row.
			stopErr := a.pm.StopSite(id)
			cleanupPending := isSiteIngressClosedError(stopErr)
			if stopErr != nil && !cleanupPending {
				a.jsonErr(w, http.StatusInternalServerError, stopErr.Error())
				return
			}
			if err := a.db.SetSiteEnabled(id, false); err != nil {
				if cleanupPending {
					a.jsonErr(w, http.StatusInternalServerError, fmt.Sprintf("%v; site ingress is closed but disabling the record failed: %v", stopErr, err))
					return
				}
				// The instance is stopped but the flag stayed on: restart it so the
				// DB and the running set stay consistent.
				if restarted, getErr := a.db.GetSite(id); getErr == nil {
					if startErr := a.pm.StartSite(*restarted); startErr == nil {
						a.jsonErr(w, 500, fmt.Sprintf("toggle off: %v", err))
						return
					}
				}
				a.jsonErr(w, 500, fmt.Sprintf("toggle off: %v; site stopped but flag update failed", err))
				return
			}
			result := map[string]interface{}{"enabled": false, "cleanup_pending": cleanupPending}
			if cleanupPending {
				result["warning"] = stopErr.Error()
			}
			a.jsonOK(w, result)
			return
		}
		// Turning on: flip the flag first so a failed start can roll it back.
		if err := a.db.SetSiteEnabled(id, true); err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		site, err = a.db.GetSite(id)
		if err != nil {
			if revertErr := a.db.SetSiteEnabled(id, false); revertErr != nil {
				a.jsonErr(w, 500, fmt.Sprintf("load site: %v; rollback toggle: %v", err, revertErr))
				return
			}
			a.jsonErr(w, 500, err.Error())
			return
		}
		if err := a.pm.StartSite(*site); err != nil {
			if revertErr := a.db.SetSiteEnabled(id, false); revertErr != nil {
				a.jsonErr(w, 500, fmt.Sprintf("start site: %v; rollback toggle: %v", err, revertErr))
				return
			}
			a.jsonErr(w, 500, err.Error())
			return
		}
		a.jsonOK(w, map[string]interface{}{"enabled": true})

	case action == "diag" && r.Method == "GET":
		site, err := a.db.GetSite(id)
		if err != nil {
			a.jsonErr(w, 404, "site not found")
			return
		}
		result := diagnoseSite(site, a.pm)
		a.jsonOK(w, result)

	case action == "" && r.Method == "PUT":
		a.siteLifecycleMu.Lock()
		defer a.siteLifecycleMu.Unlock()
		oldSite, err := a.db.GetSite(id)
		if err != nil {
			a.jsonErr(w, 404, "site not found")
			return
		}
		var req struct {
			Name                       string                 `json:"name"`
			ListenPort                 int                    `json:"listen_port"`
			PublicHost                 *string                `json:"public_host"`
			IngressMode                *string                `json:"ingress_mode"`
			TargetURL                  string                 `json:"target_url"`
			PlaybackTargetURL          *string                `json:"playback_target_url"`
			PlaybackMode               *string                `json:"playback_mode"`
			StreamHosts                *[]string              `json:"stream_hosts"`
			UAMode                     *string                `json:"ua_mode"`
			CustomUserAgent            *string                `json:"custom_user_agent"`
			CustomClient               *string                `json:"custom_client"`
			CustomVersion              *string                `json:"custom_version"`
			UpstreamHeaders            *[]UpstreamHeaderInput `json:"upstream_headers"`
			PingCacheEnabled           *bool                  `json:"ping_cache_enabled"`
			ImageCacheEnabled          *bool                  `json:"image_cache_enabled"`
			ProgressCoalescingEnabled  *bool                  `json:"progress_coalescing_enabled"`
			DynamicDiscoveryEnabled    json.RawMessage        `json:"dynamic_discovery_enabled"`
			DynamicProfile             *string                `json:"dynamic_profile"`
			DynamicDiscoverySources    json.RawMessage        `json:"dynamic_discovery_sources"`
			DynamicDomainRules         json.RawMessage        `json:"dynamic_domain_rules"`
			DynamicAllowHTTPSDowngrade *bool                  `json:"dynamic_allow_https_downgrade"`
			Quota                      *int64                 `json:"traffic_quota"`
			SpeedLimit                 *int                   `json:"speed_limit"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			a.jsonErr(w, 400, "invalid request")
			return
		}
		requestedDynamicEnabledValue, dynamicEnabledProvided, err := decodeOptionalBoolAPI(req.DynamicDiscoveryEnabled, "dynamic_discovery_enabled")
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		var requestedDynamicEnabled *bool
		if dynamicEnabledProvided {
			requestedDynamicEnabled = &requestedDynamicEnabledValue
		}
		requestedDynamicSources, dynamicSourcesProvided, err := decodeDynamicDiscoverySourcesAPI(req.DynamicDiscoverySources)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		requestedDynamicRules, dynamicRulesProvided, err := decodeDynamicDomainRulesAPI(req.DynamicDomainRules)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		playbackTargetURL := oldSite.PlaybackTargetURL
		if req.PlaybackTargetURL != nil {
			playbackTargetURL = *req.PlaybackTargetURL
		}
		playbackMode := oldSite.PlaybackMode
		if req.PlaybackMode != nil {
			playbackMode = *req.PlaybackMode
		}
		streamHosts := oldSite.StreamHosts
		if req.StreamHosts != nil {
			sh, _ := json.Marshal(*req.StreamHosts)
			streamHosts = string(sh)
		}
		speedLimit := oldSite.SpeedLimit
		if req.SpeedLimit != nil {
			speedLimit = *req.SpeedLimit
		}
		quota := oldSite.TrafficQuota
		if req.Quota != nil {
			quota = *req.Quota
		}
		publicHost := oldSite.PublicHost
		if req.PublicHost != nil {
			publicHost, err = normalizePublicHost(*req.PublicHost)
			if err != nil {
				a.jsonErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		if publicHost != "" && publicHost == a.panelHost {
			a.jsonErr(w, http.StatusBadRequest, "public_host must differ from PANEL_DOMAIN")
			return
		}
		ingressMode := oldSite.IngressMode
		if req.IngressMode != nil {
			ingressMode = *req.IngressMode
		} else if req.PublicHost != nil {
			// Backward-compatible updates that know only public_host inherit the
			// secure behavior: adding a host chooses host-only; removing it
			// chooses the legacy dedicated-port entry.
			if publicHost == "" {
				ingressMode = ingressModePort
			} else if oldSite.PublicHost == "" {
				ingressMode = ingressModeHost
			}
		}
		ingressMode, err = normalizeIngressMode(ingressMode, publicHost)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := a.pm.validateIngressSafety(ingressMode); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		oldTarget, oldTargetErr := normalizeTargetURL(oldSite.TargetURL)
		newTarget, newTargetErr := normalizeTargetURL(req.TargetURL)
		if newTargetErr != nil {
			a.jsonErr(w, http.StatusBadRequest, fmt.Sprintf("invalid target_url: %v", newTargetErr))
			return
		}
		if oldTargetErr != nil {
			a.jsonErr(w, http.StatusInternalServerError, "stored target_url is invalid")
			return
		}
		storedHeaders := oldSite.StoredUpstreamHeaders
		headerMergeBase := oldSite.StoredUpstreamHeaders
		if !sameRedirectAuthority(oldTarget, newTarget) {
			// Fixed upstream headers are origin secrets. Never carry ciphertext
			// across an authority change, even when the client omits this field.
			storedHeaders = "[]"
			headerMergeBase = "[]"
		}
		if req.UpstreamHeaders != nil {
			storedHeaders, err = mergeUpstreamHeaders(headerMergeBase, *req.UpstreamHeaders, a.pm.upstreamHeaderKey, req.TargetURL)
			if err != nil {
				a.jsonErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		uaMode, customUserAgent, customClient, customVersion, uaErr := mergeSiteUAConfig(*oldSite, req.UAMode, req.CustomUserAgent, req.CustomClient, req.CustomVersion)
		if uaErr != nil {
			a.jsonErr(w, http.StatusBadRequest, uaErr.Error())
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		playbackMode = strings.ToLower(strings.TrimSpace(playbackMode))
		var streamHostList []string
		if err := json.Unmarshal([]byte(streamHosts), &streamHostList); err != nil {
			a.jsonErr(w, http.StatusBadRequest, "invalid stream_hosts")
			return
		}
		candidate := *oldSite
		candidate.Name = req.Name
		candidate.ListenPort = req.ListenPort
		candidate.PublicHost = publicHost
		candidate.IngressMode = ingressMode
		candidate.TargetURL = req.TargetURL
		candidate.PlaybackTargetURL = playbackTargetURL
		candidate.PlaybackMode = playbackMode
		candidate.StreamHosts = streamHosts
		candidate.UAMode = uaMode
		candidate.CustomUserAgent = customUserAgent
		candidate.CustomClient = customClient
		candidate.CustomVersion = customVersion
		candidate.StoredUpstreamHeaders = storedHeaders
		if req.PingCacheEnabled != nil {
			candidate.PingCacheEnabled = *req.PingCacheEnabled
		}
		if req.ImageCacheEnabled != nil {
			candidate.ImageCacheEnabled = *req.ImageCacheEnabled
		}
		if req.ProgressCoalescingEnabled != nil {
			candidate.ProgressCoalescingEnabled = *req.ProgressCoalescingEnabled
		}
		candidate, err = mergeDynamicSitePolicyForAPI(candidate, requestedDynamicEnabled, req.DynamicProfile, requestedDynamicSources, dynamicSourcesProvided, requestedDynamicRules, dynamicRulesProvided, req.DynamicAllowHTTPSDowngrade)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := validateDynamicDiscoveryAPIEnablement(candidate, len(a.dynamicRouteKey) == sha256.Size, oldSite.DynamicDiscoveryEnabled); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		candidate.TrafficQuota = quota
		candidate.SpeedLimit = speedLimit
		if err := validateSiteSettings(candidate.Name, candidate.ListenPort, candidate.TargetURL, candidate.PlaybackTargetURL, candidate.PlaybackMode, streamHostList, candidate.UAMode, candidate.CustomUserAgent, candidate.CustomClient, candidate.CustomVersion, candidate.TrafficQuota, candidate.SpeedLimit); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if candidate.PublicHost != "" {
			if assignedID, exists := a.pm.PublicHostSiteID(candidate.PublicHost); exists && assignedID != candidate.ID {
				a.jsonErr(w, http.StatusBadRequest, "public_host is already assigned to another site")
				return
			}
		}
		needsPreStop := oldSite.Enabled && ingressUsesPort(oldSite.IngressMode) && ingressUsesPort(candidate.IngressMode) && oldSite.ListenPort == candidate.ListenPort && a.pm.IsRunning(id)
		if needsPreStop {
			// Stop before replacing a listener on the same port. A post-close drain
			// or final-checkpoint failure cannot restore that listener, so fail closed
			// by disabling the old record and let an operator retry cleanup/update.
			if stopErr := a.pm.StopSite(id); stopErr != nil {
				if isSiteIngressClosedError(stopErr) {
					if disableErr := a.db.SetSiteEnabled(id, false); disableErr != nil {
						a.jsonErr(w, http.StatusInternalServerError, fmt.Sprintf("%v; old ingress is closed and disabling the record failed: %v", stopErr, disableErr))
						return
					}
					a.jsonErr(w, http.StatusServiceUnavailable, fmt.Sprintf("update aborted; site disabled; cleanup pending: %v", stopErr))
					return
				}
				a.jsonErr(w, http.StatusInternalServerError, stopErr.Error())
				return
			}
		}
		if err := a.db.UpdateSiteRecord(candidate); err != nil {
			// A pre-stop is the normal reason the old runtime is absent here, but
			// recover from any enabled/non-operational state rather than keying the
			// invariant to one specific replacement path.
			restored, getErr := a.db.GetSite(id)
			if getErr != nil {
				a.jsonErr(w, 500, fmt.Sprintf("update site: %v; reload current site: %v", err, getErr))
				return
			}
			if restored.Enabled && !a.pm.IsRunning(id) {
				if restartErr := a.pm.StartSite(*restored); restartErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("update site: %v; restore instance: %v", err, restartErr))
					return
				}
			}
			if isSQLiteUniqueConstraintError(err) {
				a.jsonErr(w, http.StatusBadRequest, "listen_port or public_host is already assigned")
				return
			}
			a.jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		site, err := a.db.GetSite(id)
		if err != nil {
			// The record was already updated but cannot be reloaded for the
			// restart: roll the DB back to the old record so the enabled flag
			// never points at a configuration that never ran, then bring the
			// pre-stopped instance back from a fresh read. Any failure in the
			// rollback itself is reported explicitly.
			if rollbackErr := a.db.restoreSiteRecord(*oldSite); rollbackErr != nil {
				a.jsonErr(w, 500, fmt.Sprintf("reload updated site: %v; rollback update: %v", err, rollbackErr))
				return
			}
			restoredSite, getErr := a.db.GetSite(id)
			if getErr != nil {
				a.jsonErr(w, 500, fmt.Sprintf("reload updated site: %v; reload rollback site: %v", err, getErr))
				return
			}
			if restoredSite.Enabled && !a.pm.IsRunning(id) {
				if restartErr := a.pm.StartSite(*restoredSite); restartErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("reload updated site: %v; restored configuration is enabled but proxy is not running: %v", err, restartErr))
					return
				}
			}
			a.jsonErr(w, 500, err.Error())
			return
		}
		if site.Enabled {
			if err := a.pm.StartSite(*site); err != nil {
				if rollbackErr := a.db.restoreSiteRecord(*oldSite); rollbackErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("start updated site: %v; rollback update: %v", err, rollbackErr))
					return
				}
				restoredSite, getErr := a.db.GetSite(id)
				if getErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("start updated site: %v; reload rollback site: %v", err, getErr))
					return
				}
				if restoredSite.Enabled && !a.pm.IsRunning(id) {
					if restartErr := a.pm.StartSite(*restoredSite); restartErr != nil {
						a.jsonErr(w, 500, fmt.Sprintf("start updated site: %v; restored configuration is enabled but proxy is not running: %v", err, restartErr))
						return
					}
				}
				a.jsonErr(w, 500, err.Error())
				return
			}
		} else if err := a.pm.RegisterSiteHost(*site); err != nil {
			if rollbackErr := a.db.restoreSiteRecord(*oldSite); rollbackErr != nil {
				a.jsonErr(w, 500, fmt.Sprintf("register updated public host: %v; rollback update: %v", err, rollbackErr))
				return
			}
			a.jsonErr(w, 500, err.Error())
			return
		}
		a.jsonOK(w, site)

	case action == "" && r.Method == "DELETE":
		a.siteLifecycleMu.Lock()
		defer a.siteLifecycleMu.Unlock()
		// Only delete after a clean stop. If ingress already closed but drain or
		// final persistence failed, retain a disabled row as the retry handle.
		if stopErr := a.pm.StopSite(id); stopErr != nil {
			if isSiteIngressClosedError(stopErr) {
				if disableErr := a.db.SetSiteEnabled(id, false); disableErr != nil {
					a.jsonErr(w, http.StatusInternalServerError, fmt.Sprintf("%v; ingress is closed and disabling the record failed: %v", stopErr, disableErr))
					return
				}
				a.jsonErr(w, http.StatusServiceUnavailable, fmt.Sprintf("delete deferred; site disabled; cleanup pending: %v", stopErr))
				return
			}
			a.jsonErr(w, http.StatusInternalServerError, stopErr.Error())
			return
		}
		if err := a.db.DeleteSite(id); err != nil {
			// The row survived the delete, so an enabled site must not be left
			// without a running instance: restart it from a fresh read (which
			// includes the traffic StopSite flushed). Failures in the restore
			// are reported explicitly instead of claiming success.
			restored, getErr := a.db.GetSite(id)
			if getErr != nil {
				a.jsonErr(w, 500, fmt.Sprintf("delete site: %v; site stopped and reload failed: %v", err, getErr))
				return
			}
			if restored.Enabled {
				if restartErr := a.pm.StartSite(*restored); restartErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("delete site: %v; restore instance: %v", err, restartErr))
					return
				}
			}
			a.jsonErr(w, 500, err.Error())
			return
		}
		a.pm.UnregisterSiteHost(id)
		a.jsonOK(w, map[string]string{"status": "deleted"})

	default:
		a.jsonErr(w, 405, "method not allowed")
	}
}

// GET /api/traffic/{site_id}, /snapshot and /timeline
func (a *App) handleTraffic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/traffic/")

	if path == "overview" {
		snap, err := a.pm.TrafficSnapshot()
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "traffic overview unavailable")
			return
		}
		a.jsonOK(w, snap)
		return
	}

	timelineRequest := strings.HasSuffix(path, "/timeline")
	if timelineRequest {
		path = strings.TrimSuffix(path, "/timeline")
		if r.Method != http.MethodGet {
			a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
	}
	envelope := false
	if strings.HasSuffix(path, "/snapshot") {
		envelope = true
		path = strings.TrimSuffix(path, "/snapshot")
	}

	siteID, err := strconv.ParseInt(path, 10, 64)
	if err != nil || siteID <= 0 {
		a.jsonErr(w, http.StatusBadRequest, "invalid site id")
		return
	}

	if timelineRequest {
		minutes, err := strconv.Atoi(r.URL.Query().Get("minutes"))
		if err != nil || !validTrafficTimelineMinutes(minutes) {
			a.jsonErr(w, http.StatusBadRequest, "minutes must be one of 60, 360, 1440, 10080")
			return
		}
		if _, err := a.db.GetSite(siteID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.jsonErr(w, http.StatusNotFound, "site not found")
				return
			}
			a.jsonErr(w, http.StatusInternalServerError, "traffic timeline unavailable")
			return
		}
		buckets, err := a.pm.SiteTrafficTimeline(siteID, minutes, time.Now())
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "traffic timeline unavailable")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		a.jsonOK(w, buckets)
		return
	}

	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if v, err := strconv.Atoi(h); err == nil && v >= 1 && v <= 24*366 {
			hours = v
		} else {
			a.jsonErr(w, http.StatusBadRequest, "hours must be between 1 and 8784")
			return
		}
	}

	site, err := a.db.GetSite(siteID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if envelope {
				a.jsonErr(w, http.StatusNotFound, "site not found")
				return
			}
			// The legacy endpoint keeps returning an empty log array for
			// unknown sites.
			a.jsonOK(w, []TrafficLog{})
			return
		}
		a.jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	history, err := a.pm.SiteTrafficHistory(*site, hours)
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if envelope {
		a.jsonOK(w, history)
		return
	}
	a.jsonOK(w, history.Logs)
}

// GET /api/ua-profiles
func (a *App) handleUAProfiles(w http.ResponseWriter, r *http.Request) {
	profiles := make([]UAProfile, 0, len(uaProfiles))
	for _, p := range uaProfiles {
		profiles = append(profiles, p)
	}
	a.jsonOK(w, profiles)
}

// GET /api/dynamic-profiles reports deploy-time structured discovery availability
// without exposing dynamic route key material.
func (a *App) handleDynamicProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	readiness, err := a.db.DynamicRollbackReadiness()
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "dynamic policy readiness unavailable")
		return
	}
	keyConfigured := len(a.dynamicRouteKey) == sha256.Size
	a.jsonOK(w, DynamicProfilesResponse{
		Stage:               "structured-discovery",
		Available:           keyConfigured,
		KeyConfigured:       keyConfigured,
		DefaultPolicy:       dynamicDefaultPolicy(),
		EmptyRulesSemantics: "public_dns_https_443",
		RollbackReadiness:   readiness,
		Profiles:            dynamicProfilesCatalog(),
		GlobalLimits:        dynamicGlobalLimits(),
	})
}

func (a *App) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		a.jsonErr(w, 500, "SSE not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()

	// Send initial data immediately
	if err := a.sendSSEEvent(w, flusher); err != nil {
		log.Printf("send initial SSE event: %v", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.sendSSEEvent(w, flusher); err != nil {
				log.Printf("send SSE event: %v", err)
				return
			}
		}
	}
}

func (a *App) sendSSEEvent(w http.ResponseWriter, flusher http.Flusher) error {
	snap, err := a.pm.TrafficSnapshot()
	if err != nil {
		return err
	}

	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil { // #nosec G705 -- json.Marshal escapes control characters before the SSE frame is written.
		return err
	}
	flusher.Flush()
	return nil
}

var startTime = time.Now()

// appVersion is overridable at build time via -ldflags "-X main.appVersion=vX.Y.Z".
var appVersion = "v1.9.0"

func runCommandLine(args []string, input io.Reader, output io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "--version", "-v":
		if len(args) != 1 {
			return true, errors.New("version command does not accept arguments")
		}
		_, err := fmt.Fprintln(output, appVersion)
		return true, err
	case "admin":
		return true, runAdminCommand(args[1:], input, output)
	default:
		return false, nil
	}
}

func runAdminCommand(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 || args[0] != "reset-password" {
		return errors.New("usage: meridian admin reset-password --db <path> --password-stdin")
	}
	var dbPath string
	passwordStdin := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--db":
			if dbPath != "" || i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
				return errors.New("--db requires exactly one non-empty path")
			}
			dbPath = args[i+1]
			i++
		case "--password-stdin":
			if passwordStdin {
				return errors.New("--password-stdin may only be specified once")
			}
			passwordStdin = true
		default:
			return errors.New("unknown reset-password argument")
		}
	}
	if dbPath == "" || !passwordStdin {
		return errors.New("usage: meridian admin reset-password --db <path> --password-stdin")
	}

	password, err := readPasswordLine(input)
	if err != nil {
		return err
	}
	db, err := openDB(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	if err := db.ResetAdminPassword(password); err != nil {
		return fmt.Errorf("reset administrator password: %w", err)
	}
	_, err = fmt.Fprintln(output, "administrator password updated")
	return err
}

func readPasswordLine(input io.Reader) (string, error) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64), 74)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return "", errors.New("password input is empty")
	}
	password := strings.TrimSuffix(scanner.Text(), "\r")
	if scanner.Scan() {
		return "", errors.New("password input must contain exactly one line")
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if err := validateAdminPassword(password); err != nil {
		return "", err
	}
	return password, nil
}

func panelListenAddress(bindAddress string, port int) (string, error) {
	bindAddress = strings.TrimSpace(bindAddress)
	if bindAddress == "" {
		bindAddress = "0.0.0.0"
	}
	if net.ParseIP(bindAddress) == nil {
		return "", fmt.Errorf("PANEL_BIND_ADDR must be an IP address, got %q", bindAddress)
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("panel port must be between 1 and 65535, got %d", port)
	}
	return net.JoinHostPort(bindAddress, strconv.Itoa(port)), nil
}

func main() {
	if handled, err := runCommandLine(os.Args[1:], os.Stdin, os.Stdout); handled {
		if err != nil {
			fmt.Fprintf(os.Stderr, "meridian: %v\n", err)
			os.Exit(1)
		}
		return
	}

	port := 9090
	dbPath := "meridian.db"
	if jwtSecretEphemeral {
		log.Printf("JWT_SECRET not set; generated an ephemeral signing secret for this process. Set JWT_SECRET explicitly for stable sessions.")
	}

	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			port = p
		}
	}
	if v := os.Getenv("DB_PATH"); v != "" {
		dbPath = v
	}

	// Command line args
	for i, arg := range os.Args[1:] {
		switch arg {
		case "--port", "-p":
			if i+1 < len(os.Args)-1 {
				if p, err := strconv.Atoi(os.Args[i+2]); err == nil {
					port = p
				}
			}
		case "--db":
			if i+1 < len(os.Args)-1 {
				dbPath = os.Args[i+2]
			}
		}
	}
	addr, err := panelListenAddress(os.Getenv("PANEL_BIND_ADDR"), port)
	if err != nil {
		log.Fatalf("invalid panel listen address: %v", err)
	}
	panelBindHost, _, err := net.SplitHostPort(addr)
	if err != nil {
		log.Fatalf("invalid panel listen address: %v", err)
	}
	panelBindIP := net.ParseIP(panelBindHost)
	dynamicRouteKey, err := resolveDynamicRouteKey(os.Getenv("DYNAMIC_ROUTE_KEY"))
	if err != nil {
		log.Fatalf("invalid dynamic route key: %v", err)
	}
	upstreamHeaderKey, err := resolveUpstreamHeaderKey(os.Getenv("UPSTREAM_HEADER_KEY"))
	if err != nil {
		log.Fatalf("invalid upstream header key: %v", err)
	}
	if err := validateDynamicRouteKeySeparation(dynamicRouteKey, jwtSecret, upstreamHeaderKey); err != nil {
		log.Fatalf("invalid dynamic route key: %v", err)
	}

	db, err := openDB(dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	userCount, err := db.UserCount()
	if err != nil {
		log.Fatalf("failed to count users: %v", err)
	}
	setupToken, err := configuredSetupToken(userCount, os.Getenv("SETUP_TOKEN"))
	if err != nil {
		log.Fatalf("initial setup unavailable: %v", err)
	}

	trustedProxies, err := parseTrustedProxyCIDRs(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		log.Fatalf("invalid trusted proxy configuration: %v", err)
	}
	panelHost, err := normalizePublicHost(os.Getenv("PANEL_DOMAIN"))
	if err != nil {
		log.Fatalf("invalid PANEL_DOMAIN: %v", err)
	}
	pm := NewProxyManager(db, upstreamHeaderKey)
	pm.SetTrustedProxies(trustedProxies)
	pm.SetHostOnlyIngressSafe((panelBindIP != nil && panelBindIP.IsLoopback()) || len(trustedProxies) > 0)
	if err := pm.ConfigureDynamicDiscovery(dynamicRouteKey, panelHost, port, nil); err != nil {
		log.Fatalf("initialize dynamic discovery: %v", err)
	}
	loadedSiteCount, err := pm.StartAllEnabled()
	if err != nil {
		log.Fatalf("failed to load sites: %v", err)
	}

	// Traffic flush goroutine with context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				pm.FlushTraffic()
			case <-ctx.Done():
				return
			}
		}
	}()

	if panelHost != "" {
		if _, configured := pm.PublicHostHandler(panelHost); configured {
			log.Fatalf("PANEL_DOMAIN %s conflicts with a site's public_host", panelHost)
		}
	}
	app := &App{
		db:                db,
		pm:                pm,
		setupToken:        setupToken,
		loginLimiter:      newLoginRateLimiter(),
		trustedProxies:    trustedProxies,
		panelHost:         panelHost,
		panelBindLoopback: panelBindIP != nil && panelBindIP.IsLoopback(),
		panelListenPort:   port,
		dynamicRouteKey:   dynamicRouteKey,
	}

	mux := http.NewServeMux()

	// Public auth routes
	mux.HandleFunc("/api/auth/setup", cors(app.csrfMiddleware(app.handleSetup)))
	mux.HandleFunc("/api/auth/login", cors(app.csrfMiddleware(app.handleLogin)))
	mux.HandleFunc("/api/auth/logout", cors(app.csrfMiddleware(app.handleLogout)))
	mux.HandleFunc("/api/auth/check", cors(app.handleAuthCheck))

	// Protected routes
	mux.HandleFunc("/api/dashboard", cors(app.authMiddleware(app.handleDashboard)))
	mux.HandleFunc("/api/ingress-capabilities", cors(app.authMiddleware(app.handleIngressCapabilities)))
	mux.HandleFunc("/api/sites", cors(app.authMiddleware(app.handleSites)))
	mux.HandleFunc("/api/sites/", cors(app.authMiddleware(app.handleSiteByID)))
	mux.HandleFunc("/api/traffic/", cors(app.authMiddleware(app.handleTraffic)))
	mux.HandleFunc("/api/ua-profiles", cors(app.authMiddleware(app.handleUAProfiles)))
	mux.HandleFunc("/api/dynamic-profiles", cors(app.authMiddleware(app.handleDynamicProfiles)))
	mux.HandleFunc("/api/events", cors(app.authMiddleware(app.handleSSE)))
	mux.HandleFunc("/api/", cors(func(w http.ResponseWriter, _ *http.Request) {
		app.jsonErr(w, http.StatusNotFound, "API route not found")
	}))

	// Embedded static files
	staticFS, err := fs.Sub(web.StaticFiles, "static")
	if err != nil {
		log.Fatalf("failed to initialize embedded files: %v", err)
	}
	mux.Handle("/", staticHandler(staticFS))

	// HTTP server with graceful shutdown. Site listeners remain independently
	// bound by ProxyManager and are not affected by PANEL_BIND_ADDR.
	srv := &http.Server{
		Addr:              addr,
		Handler:           app.publicHostRouter(panelBodyReadDeadline(securityHeaders(mux))),
		ReadHeaderTimeout: 10 * time.Second,
		// Shared-host site traffic can include long-running uploads. Header and
		// per-endpoint body limits protect the panel without imposing a 30-second
		// whole-request deadline on media traffic routed by Host.
		ReadTimeout:    0,
		WriteTimeout:   0, // no write timeout for streaming
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 64 << 10,
	}

	log.Println("============================================================")
	log.Printf("  Meridian - Emby reverse proxy management panel %s", appVersion)
	log.Printf("  Listening on: http://%s", addr)
	log.Printf("  Sites loaded: %d (%d running)", loadedSiteCount, pm.GetRunningCount())
	log.Println("  Features: WebSocket proxy, structured backend discovery, TLS diagnostics, traffic limits")
	log.Println("============================================================")

	// Signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server failed: %v", err)
		}
	}()

	<-sigCh
	log.Println("\nReceived shutdown signal, stopping Meridian...")

	// Cancel background goroutines
	cancel()

	// Shutdown proxies (flushes traffic)
	proxyShutdownCtx, proxyShutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	pm.GracefulShutdown(proxyShutdownCtx)
	proxyShutdownCancel()

	// Give the management/shared-host server its own drain budget. A slow site
	// shutdown must not hand an already-expired context to the panel server.
	panelShutdownCtx, panelShutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := srv.Shutdown(panelShutdownCtx); err != nil {
		log.Printf("panel shutdown failed: %v", err)
	}
	panelShutdownCancel()

	// A request that exceeded the first proxy drain budget may finish while the
	// panel/shared listener is shutting down. Give retained instances one final
	// bounded drain/checkpoint pass so those tail counters are not abandoned just
	// before process exit, and retry any transient final SQLite write failure.
	finalProxyCtx, finalProxyCancel := context.WithTimeout(context.Background(), 2*time.Second)
	pm.GracefulShutdown(finalProxyCtx)
	finalProxyCancel()

	log.Println("Meridian stopped cleanly")
}
