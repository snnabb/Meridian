package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var errInvalidSiteOrder = errors.New("invalid site order")

type Site struct {
	ID                            int64                `json:"id"`
	SortOrder                     int64                `json:"sort_order"`
	Name                          string               `json:"name"`
	ListenPort                    int                  `json:"listen_port"`
	PublicHost                    string               `json:"public_host"`
	PathPrefix                    string               `json:"path_prefix"`
	IngressMode                   string               `json:"ingress_mode"`
	TargetURL                     string               `json:"target_url"`
	PrimaryLineName               string               `json:"primary_line_name"`
	PlaybackTargetURL             string               `json:"playback_target_url"`
	PlaybackMode                  string               `json:"playback_mode"`
	MainVideoStreamMode           string               `json:"main_video_stream_mode"`
	FailoverTargets               string               `json:"-"`
	FailoverTargetList            []string             `json:"failover_targets"`
	StoredFailoverLines           string               `json:"-"`
	FailoverLines                 []FailoverLine       `json:"failover_lines"`
	StreamHosts                   string               `json:"-"`
	StreamHostList                []string             `json:"stream_hosts"`
	UAMode                        string               `json:"ua_mode"`
	CustomUserAgent               string               `json:"custom_user_agent"`
	CustomClient                  string               `json:"custom_client"`
	CustomVersion                 string               `json:"custom_version"`
	ClientIPMode                  string               `json:"client_ip_mode"`
	StoredUpstreamHeaders         string               `json:"-"`
	UpstreamHeaders               []UpstreamHeaderView `json:"upstream_headers"`
	DynamicDiscoveryEnabled       bool                 `json:"dynamic_discovery_enabled"`
	DynamicProfile                string               `json:"dynamic_profile"`
	StoredDynamicDiscoverySources string               `json:"-"`
	DynamicDiscoverySources       []string             `json:"dynamic_discovery_sources"`
	StoredDynamicDomainRules      string               `json:"-"`
	DynamicDomainRules            []DynamicDomainRule  `json:"dynamic_domain_rules"`
	DynamicAllowHTTPSDowngrade    bool                 `json:"dynamic_allow_https_downgrade"`
	DynamicPolicyRevision         int64                `json:"dynamic_policy_revision"`
	PingCacheEnabled              bool                 `json:"ping_cache_enabled"`
	ImageCacheEnabled             bool                 `json:"image_cache_enabled"`
	ProgressCoalescingEnabled     bool                 `json:"progress_coalescing_enabled"`
	AssetCacheEnabled             bool                 `json:"asset_cache_enabled"`
	AssetCacheTTLSec              int                  `json:"asset_cache_ttl_sec"`
	AssetCacheMaxBytes            int64                `json:"asset_cache_max_bytes"`
	AssetCacheRules               string               `json:"asset_cache_rules"`
	Enabled                       bool                 `json:"enabled"`
	TrafficQuota                  int64                `json:"traffic_quota"`
	TrafficUsed                   int64                `json:"traffic_used"`
	TrafficUsedIn                 int64                `json:"-"`
	TrafficUsedOut                int64                `json:"-"`
	SpeedLimit                    int                  `json:"speed_limit"`
	CreatedAt                     string               `json:"created_at"`
	UpdatedAt                     string               `json:"updated_at"`
}

func hydrateSiteConfiguration(site *Site, dynamicEnabled, dynamicDowngrade, pingCacheEnabled, imageCacheEnabled, progressCoalescingEnabled, assetCacheEnabled int) error {
	publicHost, err := normalizePublicHost(site.PublicHost)
	if err != nil {
		return err
	}
	site.PublicHost = publicHost
	pathPrefix, err := normalizePathPrefix(site.PathPrefix)
	if err != nil {
		return err
	}
	site.PathPrefix = pathPrefix
	site.PrimaryLineName, err = normalizePrimaryLineName(site.PrimaryLineName)
	if err != nil {
		return err
	}
	site.ClientIPMode, err = normalizeClientIPMode(site.ClientIPMode)
	if err != nil {
		return err
	}
	ingressMode, err := normalizeIngressMode(site.IngressMode, site.PublicHost)
	if err != nil {
		return err
	}
	site.IngressMode = ingressMode
	if site.IngressMode == ingressModePath && site.PathPrefix == "" {
		return fmt.Errorf("path_prefix is required when ingress_mode is path")
	}
	if site.IngressMode != ingressModePath && site.PathPrefix != "" {
		return fmt.Errorf("path_prefix must be empty when ingress_mode is %s", site.IngressMode)
	}
	if err := json.Unmarshal([]byte(site.StreamHosts), &site.StreamHostList); err != nil {
		return fmt.Errorf("invalid stored stream_hosts: %w", err)
	}
	if site.StreamHostList == nil {
		site.StreamHostList = []string{}
	}
	if err := json.Unmarshal([]byte(site.FailoverTargets), &site.FailoverTargetList); err != nil {
		return fmt.Errorf("invalid stored failover_targets: %w", err)
	}
	if site.FailoverTargetList == nil {
		site.FailoverTargetList = []string{}
	}
	lines, enabledTargets, err := decodeStoredFailoverLines(site.StoredFailoverLines, site.TargetURL, site.FailoverTargetList)
	if err != nil {
		return err
	}
	site.FailoverLines = lines
	site.FailoverTargetList = enabledTargets
	enabledJSON, _ := json.Marshal(enabledTargets)
	site.FailoverTargets = string(enabledJSON)
	views, err := upstreamHeaderViews(site.StoredUpstreamHeaders)
	if err != nil {
		return err
	}
	site.UpstreamHeaders = views
	if err := hydrateStoredDynamicSitePolicy(site, dynamicEnabled, dynamicDowngrade); err != nil {
		return err
	}
	site.PingCacheEnabled = pingCacheEnabled == 1
	site.ImageCacheEnabled = imageCacheEnabled == 1
	site.ProgressCoalescingEnabled = progressCoalescingEnabled == 1
	site.AssetCacheEnabled = assetCacheEnabled == 1
	if err := normalizeAssetCacheConfig(site); err != nil {
		return err
	}
	return nil
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

func (d *DB) ListSites() ([]Site, error) {
	rows, err := d.db.Query("SELECT id, sort_order, name, listen_port, public_host, path_prefix, ingress_mode, target_url, primary_line_name, playback_target_url, playback_mode, main_video_stream_mode, failover_targets, failover_lines, stream_hosts, ua_mode, custom_user_agent, custom_client, custom_version, client_ip_mode, upstream_headers, dynamic_discovery_enabled, dynamic_profile, dynamic_discovery_sources, dynamic_domain_rules, dynamic_allow_https_downgrade, dynamic_policy_revision, ping_cache_enabled, image_cache_enabled, progress_coalescing_enabled, asset_cache_enabled, asset_cache_ttl_sec, asset_cache_max_bytes, asset_cache_rules, enabled, traffic_quota, traffic_used, traffic_used_in, traffic_used_out, speed_limit, created_at, updated_at FROM sites ORDER BY sort_order, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sites []Site
	for rows.Next() {
		var s Site
		var enabled, dynamicEnabled, dynamicDowngrade, pingCacheEnabled, imageCacheEnabled, progressCoalescingEnabled, assetCacheEnabled int
		if err := rows.Scan(&s.ID, &s.SortOrder, &s.Name, &s.ListenPort, &s.PublicHost, &s.PathPrefix, &s.IngressMode, &s.TargetURL, &s.PrimaryLineName, &s.PlaybackTargetURL, &s.PlaybackMode, &s.MainVideoStreamMode, &s.FailoverTargets, &s.StoredFailoverLines, &s.StreamHosts, &s.UAMode, &s.CustomUserAgent, &s.CustomClient, &s.CustomVersion, &s.ClientIPMode, &s.StoredUpstreamHeaders, &dynamicEnabled, &s.DynamicProfile, &s.StoredDynamicDiscoverySources, &s.StoredDynamicDomainRules, &dynamicDowngrade, &s.DynamicPolicyRevision, &pingCacheEnabled, &imageCacheEnabled, &progressCoalescingEnabled, &assetCacheEnabled, &s.AssetCacheTTLSec, &s.AssetCacheMaxBytes, &s.AssetCacheRules, &enabled, &s.TrafficQuota, &s.TrafficUsed, &s.TrafficUsedIn, &s.TrafficUsedOut, &s.SpeedLimit, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		s.Enabled = enabled == 1
		if err := hydrateSiteConfiguration(&s, dynamicEnabled, dynamicDowngrade, pingCacheEnabled, imageCacheEnabled, progressCoalescingEnabled, assetCacheEnabled); err != nil {
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

func (d *DB) GetSite(id int64) (*Site, error) {
	var s Site
	var enabled, dynamicEnabled, dynamicDowngrade, pingCacheEnabled, imageCacheEnabled, progressCoalescingEnabled, assetCacheEnabled int
	err := d.db.QueryRow("SELECT id, sort_order, name, listen_port, public_host, path_prefix, ingress_mode, target_url, primary_line_name, playback_target_url, playback_mode, main_video_stream_mode, failover_targets, failover_lines, stream_hosts, ua_mode, custom_user_agent, custom_client, custom_version, client_ip_mode, upstream_headers, dynamic_discovery_enabled, dynamic_profile, dynamic_discovery_sources, dynamic_domain_rules, dynamic_allow_https_downgrade, dynamic_policy_revision, ping_cache_enabled, image_cache_enabled, progress_coalescing_enabled, asset_cache_enabled, asset_cache_ttl_sec, asset_cache_max_bytes, asset_cache_rules, enabled, traffic_quota, traffic_used, traffic_used_in, traffic_used_out, speed_limit, created_at, updated_at FROM sites WHERE id=?", id).
		Scan(&s.ID, &s.SortOrder, &s.Name, &s.ListenPort, &s.PublicHost, &s.PathPrefix, &s.IngressMode, &s.TargetURL, &s.PrimaryLineName, &s.PlaybackTargetURL, &s.PlaybackMode, &s.MainVideoStreamMode, &s.FailoverTargets, &s.StoredFailoverLines, &s.StreamHosts, &s.UAMode, &s.CustomUserAgent, &s.CustomClient, &s.CustomVersion, &s.ClientIPMode, &s.StoredUpstreamHeaders, &dynamicEnabled, &s.DynamicProfile, &s.StoredDynamicDiscoverySources, &s.StoredDynamicDomainRules, &dynamicDowngrade, &s.DynamicPolicyRevision, &pingCacheEnabled, &imageCacheEnabled, &progressCoalescingEnabled, &assetCacheEnabled, &s.AssetCacheTTLSec, &s.AssetCacheMaxBytes, &s.AssetCacheRules, &enabled, &s.TrafficQuota, &s.TrafficUsed, &s.TrafficUsedIn, &s.TrafficUsedOut, &s.SpeedLimit, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	s.Enabled = enabled == 1
	if err := hydrateSiteConfiguration(&s, dynamicEnabled, dynamicDowngrade, pingCacheEnabled, imageCacheEnabled, progressCoalescingEnabled, assetCacheEnabled); err != nil {
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
	var err error
	site.PrimaryLineName, err = normalizePrimaryLineName(site.PrimaryLineName)
	if err != nil {
		return nil, err
	}
	site.MainVideoStreamMode, err = normalizeMainVideoStreamMode(site.MainVideoStreamMode)
	if err != nil {
		return nil, err
	}
	if site.StreamHosts == "" {
		site.StreamHosts = "[]"
	}
	if site.FailoverTargets == "" {
		site.FailoverTargets = "[]"
	}
	var failoverTargetList []string
	if err := json.Unmarshal([]byte(site.FailoverTargets), &failoverTargetList); err != nil {
		return nil, fmt.Errorf("invalid failover_targets: %w", err)
	}
	lines, enabledTargets, err := decodeStoredFailoverLines(site.StoredFailoverLines, site.TargetURL, failoverTargetList)
	if err != nil {
		return nil, err
	}
	site.FailoverLines = lines
	failoverJSON, _ := json.Marshal(enabledTargets)
	site.FailoverTargets = string(failoverJSON)
	lineJSON, _ := json.Marshal(lines)
	site.StoredFailoverLines = string(lineJSON)
	if site.StoredUpstreamHeaders == "" {
		site.StoredUpstreamHeaders = "[]"
	}
	if strings.TrimSpace(site.UAMode) == "" {
		site.UAMode = passthroughUAMode
	}
	site.ClientIPMode, err = normalizeClientIPMode(site.ClientIPMode)
	if err != nil {
		return nil, err
	}
	if err := normalizeAssetCacheConfig(&site); err != nil {
		return nil, err
	}
	publicHost, err := normalizePublicHost(site.PublicHost)
	if err != nil {
		return nil, err
	}
	site.PublicHost = publicHost
	site.PathPrefix, err = normalizePathPrefix(site.PathPrefix)
	if err != nil {
		return nil, err
	}
	site.IngressMode, err = normalizeIngressMode(site.IngressMode, site.PublicHost)
	if err != nil {
		return nil, err
	}
	if site.IngressMode == ingressModePath && site.PathPrefix == "" {
		return nil, fmt.Errorf("path_prefix is required when ingress_mode is path")
	}
	if site.IngressMode != ingressModePath && site.PathPrefix != "" {
		return nil, fmt.Errorf("path_prefix must be empty when ingress_mode is %s", site.IngressMode)
	}
	if err := normalizeDynamicSitePolicy(&site); err != nil {
		return nil, err
	}
	site.DynamicPolicyRevision = 1
	res, err := d.db.Exec(
		"INSERT INTO sites (sort_order, name, listen_port, public_host, path_prefix, ingress_mode, target_url, primary_line_name, playback_target_url, playback_mode, main_video_stream_mode, failover_targets, failover_lines, stream_hosts, ua_mode, custom_user_agent, custom_client, custom_version, client_ip_mode, upstream_headers, dynamic_discovery_enabled, dynamic_profile, dynamic_discovery_sources, dynamic_domain_rules, dynamic_allow_https_downgrade, dynamic_policy_revision, ping_cache_enabled, image_cache_enabled, progress_coalescing_enabled, asset_cache_enabled, asset_cache_ttl_sec, asset_cache_max_bytes, asset_cache_rules, traffic_quota, speed_limit) VALUES ((SELECT COALESCE(MAX(sort_order), -1) + 1 FROM sites),?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		site.Name, site.ListenPort, site.PublicHost, site.PathPrefix, site.IngressMode, site.TargetURL, site.PrimaryLineName, site.PlaybackTargetURL, site.PlaybackMode, site.MainVideoStreamMode, site.FailoverTargets, site.StoredFailoverLines, site.StreamHosts, site.UAMode, site.CustomUserAgent, site.CustomClient, site.CustomVersion, site.ClientIPMode, site.StoredUpstreamHeaders, sqliteBool(site.DynamicDiscoveryEnabled), site.DynamicProfile, site.StoredDynamicDiscoverySources, site.StoredDynamicDomainRules, sqliteBool(site.DynamicAllowHTTPSDowngrade), site.DynamicPolicyRevision, sqliteBool(site.PingCacheEnabled), sqliteBool(site.ImageCacheEnabled), sqliteBool(site.ProgressCoalescingEnabled), sqliteBool(site.AssetCacheEnabled), site.AssetCacheTTLSec, site.AssetCacheMaxBytes, site.AssetCacheRules, site.TrafficQuota, site.SpeedLimit,
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

func (d *DB) ReorderSites(siteIDs []int64) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rows, err := tx.Query("SELECT id FROM sites")
	if err != nil {
		return err
	}
	stored := make(map[int64]struct{})
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		stored[id] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(siteIDs) != len(stored) {
		return fmt.Errorf("%w: site_ids must contain every site exactly once", errInvalidSiteOrder)
	}

	seen := make(map[int64]struct{}, len(siteIDs))
	for position, id := range siteIDs {
		if id <= 0 {
			return fmt.Errorf("%w: invalid site id", errInvalidSiteOrder)
		}
		if _, ok := stored[id]; !ok {
			return fmt.Errorf("%w: site %d does not exist", errInvalidSiteOrder, id)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("%w: site %d is duplicated", errInvalidSiteOrder, id)
		}
		seen[id] = struct{}{}
		if _, err := tx.Exec("UPDATE sites SET sort_order=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", position, id); err != nil {
			return err
		}
	}
	return tx.Commit()
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
	var err error
	site.PrimaryLineName, err = normalizePrimaryLineName(site.PrimaryLineName)
	if err != nil {
		return err
	}
	site.ClientIPMode, err = normalizeClientIPMode(site.ClientIPMode)
	if err != nil {
		return err
	}
	site.MainVideoStreamMode, err = normalizeMainVideoStreamMode(site.MainVideoStreamMode)
	if err != nil {
		return err
	}
	if site.StreamHosts == "" {
		site.StreamHosts = "[]"
	}
	if site.FailoverTargets == "" {
		site.FailoverTargets = "[]"
	}
	var failoverTargetList []string
	if err := json.Unmarshal([]byte(site.FailoverTargets), &failoverTargetList); err != nil {
		return fmt.Errorf("invalid failover_targets: %w", err)
	}
	lines, enabledTargets, err := decodeStoredFailoverLines(site.StoredFailoverLines, site.TargetURL, failoverTargetList)
	if err != nil {
		return err
	}
	failoverJSON, _ := json.Marshal(enabledTargets)
	site.FailoverTargets = string(failoverJSON)
	lineJSON, _ := json.Marshal(lines)
	site.StoredFailoverLines = string(lineJSON)
	if site.StoredUpstreamHeaders == "" {
		site.StoredUpstreamHeaders = "[]"
	}
	publicHost, err := normalizePublicHost(site.PublicHost)
	if err != nil {
		return err
	}
	site.PublicHost = publicHost
	site.PathPrefix, err = normalizePathPrefix(site.PathPrefix)
	if err != nil {
		return err
	}
	site.IngressMode, err = normalizeIngressMode(site.IngressMode, site.PublicHost)
	if err != nil {
		return err
	}
	if site.IngressMode == ingressModePath && site.PathPrefix == "" {
		return fmt.Errorf("path_prefix is required when ingress_mode is path")
	}
	if site.IngressMode != ingressModePath && site.PathPrefix != "" {
		return fmt.Errorf("path_prefix must be empty when ingress_mode is %s", site.IngressMode)
	}
	if err := normalizeDynamicSitePolicy(&site); err != nil {
		return err
	}
	if err := normalizeAssetCacheConfig(&site); err != nil {
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
	revisionExpression := "dynamic_policy_revision=dynamic_policy_revision+CASE WHEN dynamic_discovery_enabled<>? OR dynamic_profile<>? OR dynamic_discovery_sources<>? OR dynamic_domain_rules<>? OR dynamic_allow_https_downgrade<>? THEN 1 ELSE 0 END"
	args := []interface{}{
		site.Name, site.ListenPort, site.PublicHost, site.PathPrefix, site.IngressMode, site.TargetURL, site.PrimaryLineName,
		site.PlaybackTargetURL, site.PlaybackMode, site.MainVideoStreamMode, site.FailoverTargets, site.StoredFailoverLines, site.StreamHosts, site.UAMode,
		site.CustomUserAgent, site.CustomClient, site.CustomVersion, site.ClientIPMode, site.StoredUpstreamHeaders,
		dynamicEnabled, site.DynamicProfile, site.StoredDynamicDiscoverySources, site.StoredDynamicDomainRules, dynamicDowngrade,
	}
	if restoreRevision {
		revisionExpression = "dynamic_policy_revision=?"
		args = append(args, site.DynamicPolicyRevision)
	} else {
		args = append(args, dynamicEnabled, site.DynamicProfile, site.StoredDynamicDiscoverySources, site.StoredDynamicDomainRules, dynamicDowngrade)
	}
	args = append(args, sqliteBool(site.PingCacheEnabled), sqliteBool(site.ImageCacheEnabled), sqliteBool(site.ProgressCoalescingEnabled), sqliteBool(site.AssetCacheEnabled), site.AssetCacheTTLSec, site.AssetCacheMaxBytes, site.AssetCacheRules, site.TrafficQuota, site.SpeedLimit, site.ID)
	_, err = tx.Exec(
		"UPDATE sites SET name=?, listen_port=?, public_host=?, path_prefix=?, ingress_mode=?, target_url=?, primary_line_name=?, playback_target_url=?, playback_mode=?, main_video_stream_mode=?, failover_targets=?, failover_lines=?, stream_hosts=?, ua_mode=?, custom_user_agent=?, custom_client=?, custom_version=?, client_ip_mode=?, upstream_headers=?, dynamic_discovery_enabled=?, dynamic_profile=?, dynamic_discovery_sources=?, dynamic_domain_rules=?, dynamic_allow_https_downgrade=?, "+revisionExpression+", ping_cache_enabled=?, image_cache_enabled=?, progress_coalescing_enabled=?, asset_cache_enabled=?, asset_cache_ttl_sec=?, asset_cache_max_bytes=?, asset_cache_rules=?, traffic_quota=?, speed_limit=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
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
	if _, err := tx.Exec("DELETE FROM dynamic_observations WHERE site_id=?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM request_logs WHERE site_id=?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM traffic_minute_logs WHERE site_id=?", id); err != nil {
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
