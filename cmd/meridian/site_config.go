package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
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
	defaultAssetCacheTTL  = 24 * time.Hour
	defaultAssetCacheMax  = int64(512 << 20)
	maxAssetCacheObject   = int64(16 << 20)
	minAssetCacheTTLSec   = 60
	maxAssetCacheTTLSec   = 30 * 24 * 60 * 60
	maxAssetCacheMaxBytes = int64(20 << 30)
)

func normalizeAssetCacheConfig(site *Site) error {
	if site.AssetCacheTTLSec == 0 {
		site.AssetCacheTTLSec = int(defaultAssetCacheTTL / time.Second)
	}
	if site.AssetCacheMaxBytes == 0 {
		site.AssetCacheMaxBytes = defaultAssetCacheMax
	}
	if strings.TrimSpace(site.AssetCacheRules) == "" {
		site.AssetCacheRules = "*/file/*\n*/emby/Items/*/Images/*"
	}
	if site.AssetCacheTTLSec < minAssetCacheTTLSec || site.AssetCacheTTLSec > maxAssetCacheTTLSec {
		return fmt.Errorf("asset_cache_ttl_sec must be between %d and %d", minAssetCacheTTLSec, maxAssetCacheTTLSec)
	}
	if site.AssetCacheMaxBytes < 1<<20 || site.AssetCacheMaxBytes > maxAssetCacheMaxBytes {
		return fmt.Errorf("asset_cache_max_bytes must be between %d and %d", 1<<20, maxAssetCacheMaxBytes)
	}
	if len(site.AssetCacheRules) > 4096 {
		return fmt.Errorf("asset_cache_rules must not exceed 4096 bytes")
	}
	return nil
}

var errUnsafeHostOnlyIngress = errors.New("host-only ingress requires loopback PANEL_BIND_ADDR or a non-empty TRUSTED_PROXY_CIDRS source allowlist; use port/both only with the documented risk controls")
var errUnsetIngress = errors.New("站点入口尚未配置，请编辑站点并选择域名前缀、路径或独立端口后再启用")
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
