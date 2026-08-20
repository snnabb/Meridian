package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func (a *App) handleUpstreamTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		TargetURL string `json:"target_url"`
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		a.jsonErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if strings.TrimSpace(req.TargetURL) == "" {
		a.jsonErr(w, http.StatusBadRequest, "target_url is required")
		return
	}
	if _, err := normalizeTargetURL(req.TargetURL); err != nil {
		a.jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	health := probeSiteHealth(req.TargetURL)
	a.jsonOK(w, map[string]interface{}{
		"status":        health.Status,
		"http_status":   health.Probe.HTTPStatus,
		"latency_ms":    health.LatencyMs,
		"effective_url": displayTargetURL(health.Probe.URL),
		"error":         health.Error,
	})
}

func (a *App) handleSites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.Header().Set("Cache-Control", "no-store")
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
		cacheSizes, _, err := a.pm.AssetCacheSizes()
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "cache statistics unavailable")
			return
		}
		// Add running status
		type SiteWithStatus struct {
			Site
			Running        bool  `json:"running"`
			CacheSizeBytes int64 `json:"cache_size_bytes"`
			MonthlyTraffic int64 `json:"monthly_traffic"`
		}
		result := make([]SiteWithStatus, len(sites))
		for i, s := range sites {
			st := live[s.ID]
			result[i] = SiteWithStatus{Site: s, Running: st.Running, CacheSizeBytes: cacheSizes[s.ID], MonthlyTraffic: st.MonthlyTraffic}
			result[i].TrafficUsed = st.TrafficUsed
		}
		a.jsonOK(w, result)

	case "POST":
		var req struct {
			Name                       string                `json:"name"`
			ListenPort                 int                   `json:"listen_port"`
			PublicHost                 string                `json:"public_host"`
			RoutePrefix                string                `json:"route_prefix"`
			PathPrefix                 string                `json:"path_prefix"`
			IngressMode                string                `json:"ingress_mode"`
			TargetURL                  string                `json:"target_url"`
			PrimaryLineName            string                `json:"primary_line_name"`
			PlaybackTargetURL          string                `json:"playback_target_url"`
			PlaybackMode               string                `json:"playback_mode"`
			MainVideoStreamMode        string                `json:"main_video_stream_mode"`
			FailoverTargets            []string              `json:"failover_targets"`
			FailoverLines              []FailoverLine        `json:"failover_lines"`
			StreamHosts                []string              `json:"stream_hosts"`
			UAMode                     string                `json:"ua_mode"`
			CustomUserAgent            string                `json:"custom_user_agent"`
			CustomClient               string                `json:"custom_client"`
			CustomVersion              string                `json:"custom_version"`
			ClientIPMode               string                `json:"client_ip_mode"`
			UpstreamHeaders            []UpstreamHeaderInput `json:"upstream_headers"`
			DynamicDiscoveryEnabled    optionalJSONBool      `json:"dynamic_discovery_enabled"`
			DynamicProfile             string                `json:"dynamic_profile"`
			DynamicDiscoverySources    json.RawMessage       `json:"dynamic_discovery_sources"`
			DynamicDomainRules         json.RawMessage       `json:"dynamic_domain_rules"`
			DynamicAllowHTTPSDowngrade bool                  `json:"dynamic_allow_https_downgrade"`
			PingCacheEnabled           bool                  `json:"ping_cache_enabled"`
			ImageCacheEnabled          bool                  `json:"image_cache_enabled"`
			ProgressCoalescingEnabled  bool                  `json:"progress_coalescing_enabled"`
			AssetCacheEnabled          bool                  `json:"asset_cache_enabled"`
			AssetCacheTTLSec           int                   `json:"asset_cache_ttl_sec"`
			AssetCacheMaxBytes         int64                 `json:"asset_cache_max_bytes"`
			AssetCacheRules            string                `json:"asset_cache_rules"`
			Quota                      int64                 `json:"traffic_quota"`
			SpeedLimit                 int                   `json:"speed_limit"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			a.jsonErr(w, 400, "invalid request")
			return
		}
		dynamicEnabled := false
		if req.DynamicDiscoveryEnabled.Present {
			if req.DynamicDiscoveryEnabled.Null {
				a.jsonErr(w, http.StatusBadRequest, "dynamic_discovery_enabled must be a JSON boolean, not null")
				return
			}
			dynamicEnabled = req.DynamicDiscoveryEnabled.Value
		}
		dynamicSources, _, err := decodeDynamicDiscoverySourcesAPI(req.DynamicDiscoverySources)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		dynamicRules, _, err := decodeDynamicDomainRulesAPI(req.DynamicDomainRules)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.Name == "" || req.TargetURL == "" {
			a.jsonErr(w, 400, "name and target_url are required")
			return
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
		if err := validateSelectableDynamicDiscoverySources(dynamicPolicy.DynamicProfile, dynamicPolicy.DynamicDiscoverySources); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := validateDynamicDiscoveryAPIEnablement(dynamicPolicy, len(a.dynamicRouteKey) == sha256.Size, false); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.UAMode == "" {
			req.UAMode = passthroughUAMode
		}
		if req.PlaybackMode == "" {
			req.PlaybackMode = "direct"
		}
		assetCacheConfig := Site{AssetCacheEnabled: req.AssetCacheEnabled, AssetCacheTTLSec: req.AssetCacheTTLSec, AssetCacheMaxBytes: req.AssetCacheMaxBytes, AssetCacheRules: req.AssetCacheRules}
		if err := normalizeAssetCacheConfig(&assetCacheConfig); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		req.PrimaryLineName, err = normalizePrimaryLineName(req.PrimaryLineName)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		req.PlaybackMode = strings.ToLower(strings.TrimSpace(req.PlaybackMode))
		if strings.TrimSpace(req.RoutePrefix) != "" {
			prefixHost, prefixErr := routeHostForPrefix(req.RoutePrefix, a.routeDomain)
			if prefixErr != nil {
				a.jsonErr(w, http.StatusBadRequest, prefixErr.Error())
				return
			}
			if strings.TrimSpace(req.PublicHost) != "" && !strings.EqualFold(strings.TrimSpace(req.PublicHost), prefixHost) {
				a.jsonErr(w, http.StatusBadRequest, "route_prefix does not match public_host")
				return
			}
			req.PublicHost = prefixHost
		}
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
		req.PathPrefix, err = normalizePathPrefix(req.PathPrefix)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		req.IngressMode, err = normalizeIngressMode(req.IngressMode, req.PublicHost)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.IngressMode == ingressModeUnset {
			a.jsonErr(w, http.StatusBadRequest, errUnsetIngress.Error())
			return
		}
		if req.IngressMode == ingressModePath && req.PathPrefix == "" {
			a.jsonErr(w, http.StatusBadRequest, "path_prefix is required for path ingress")
			return
		}
		if req.IngressMode != ingressModePath && req.PathPrefix != "" {
			a.jsonErr(w, http.StatusBadRequest, "path_prefix is only valid for path ingress")
			return
		}
		if err := a.pm.validateIngressSafety(req.IngressMode); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		a.siteLifecycleMu.Lock()
		defer a.siteLifecycleMu.Unlock()
		if req.ListenPort == 0 {
			if !ingressUsesPanel(req.IngressMode) {
				a.jsonErr(w, http.StatusBadRequest, "listen_port is required for dedicated-port ingress")
				return
			}
			sites, listErr := a.db.ListSites()
			if listErr != nil {
				a.jsonErr(w, http.StatusInternalServerError, "allocate internal site port failed")
				return
			}
			req.ListenPort, err = nextAvailableInternalSitePort(sites, a.panelListenPort)
			if err != nil {
				a.jsonErr(w, http.StatusServiceUnavailable, err.Error())
				return
			}
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
		req.ClientIPMode, err = normalizeClientIPMode(req.ClientIPMode)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		req.MainVideoStreamMode, err = normalizeMainVideoStreamMode(req.MainVideoStreamMode)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := validateSiteSettings(req.Name, req.ListenPort, req.TargetURL, req.PlaybackTargetURL, req.PlaybackMode, req.StreamHosts, req.UAMode, req.CustomUserAgent, req.CustomClient, req.CustomVersion, req.Quota, req.SpeedLimit); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		normalizedLines, enabledFailovers, err := normalizeFailoverLines(req.TargetURL, req.FailoverLines, req.FailoverTargets)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		req.FailoverLines = normalizedLines
		req.FailoverTargets = enabledFailovers
		streamHostsJSON, _ := json.Marshal(req.StreamHosts)
		if req.StreamHosts == nil {
			streamHostsJSON = []byte("[]")
		}
		failoverTargetsJSON, _ := json.Marshal(req.FailoverTargets)
		if req.FailoverTargets == nil {
			failoverTargetsJSON = []byte("[]")
		}
		failoverLinesJSON, _ := json.Marshal(req.FailoverLines)
		if req.FailoverLines == nil {
			failoverLinesJSON = []byte("[]")
		}
		storedHeaders, err := mergeUpstreamHeaders("[]", req.UpstreamHeaders, a.pm.upstreamHeaderKey, req.TargetURL)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if len(req.FailoverTargets) > 0 && storedHeaders != "[]" {
			a.jsonErr(w, http.StatusBadRequest, "failover_targets cannot be combined with fixed upstream headers")
			return
		}
		if req.PublicHost != "" {
			if _, exists := a.pm.PublicHostSiteID(req.PublicHost); exists {
				a.jsonErr(w, http.StatusBadRequest, "public_host is already assigned to another site")
				return
			}
		}
		if req.PathPrefix != "" {
			if _, exists := a.pm.PathPrefixSiteID(req.PathPrefix); exists {
				a.jsonErr(w, http.StatusBadRequest, "path_prefix is already assigned to another site")
				return
			}
		}
		site, err := a.db.CreateSiteRecord(Site{
			Name:                          req.Name,
			ListenPort:                    req.ListenPort,
			PublicHost:                    req.PublicHost,
			PathPrefix:                    req.PathPrefix,
			IngressMode:                   req.IngressMode,
			TargetURL:                     req.TargetURL,
			PrimaryLineName:               req.PrimaryLineName,
			PlaybackTargetURL:             req.PlaybackTargetURL,
			PlaybackMode:                  req.PlaybackMode,
			MainVideoStreamMode:           req.MainVideoStreamMode,
			FailoverTargets:               string(failoverTargetsJSON),
			StoredFailoverLines:           string(failoverLinesJSON),
			StreamHosts:                   string(streamHostsJSON),
			UAMode:                        req.UAMode,
			CustomUserAgent:               req.CustomUserAgent,
			CustomClient:                  req.CustomClient,
			CustomVersion:                 req.CustomVersion,
			ClientIPMode:                  req.ClientIPMode,
			StoredUpstreamHeaders:         storedHeaders,
			DynamicDiscoveryEnabled:       dynamicPolicy.DynamicDiscoveryEnabled,
			DynamicProfile:                dynamicPolicy.DynamicProfile,
			StoredDynamicDiscoverySources: dynamicPolicy.StoredDynamicDiscoverySources,
			DynamicDiscoverySources:       dynamicPolicy.DynamicDiscoverySources,
			StoredDynamicDomainRules:      dynamicPolicy.StoredDynamicDomainRules,
			DynamicDomainRules:            dynamicPolicy.DynamicDomainRules,
			DynamicAllowHTTPSDowngrade:    dynamicPolicy.DynamicAllowHTTPSDowngrade,
			PingCacheEnabled:              req.PingCacheEnabled,
			ImageCacheEnabled:             req.ImageCacheEnabled,
			ProgressCoalescingEnabled:     req.ProgressCoalescingEnabled,
			AssetCacheEnabled:             assetCacheConfig.AssetCacheEnabled,
			AssetCacheTTLSec:              assetCacheConfig.AssetCacheTTLSec,
			AssetCacheMaxBytes:            assetCacheConfig.AssetCacheMaxBytes,
			AssetCacheRules:               assetCacheConfig.AssetCacheRules,
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

func (a *App) handleSiteReorder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		SiteIDs []int64 `json:"site_ids"`
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		a.jsonErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	a.siteLifecycleMu.Lock()
	defer a.siteLifecycleMu.Unlock()
	if err := a.db.ReorderSites(req.SiteIDs); err != nil {
		if errors.Is(err, errInvalidSiteOrder) {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("reorder sites: %v", err)
		a.jsonErr(w, http.StatusInternalServerError, "save site order failed")
		return
	}
	a.jsonOK(w, map[string]interface{}{
		"site_ids": req.SiteIDs,
	})
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
				Observations:              make([]DynamicObservation, 0),
				DroppedObservations:       a.db.DroppedDynamicObservations(),
				DroppedObservationsGlobal: a.db.DroppedDynamicObservations(),
				RetentionDays:             dynamicObservationRetentionDays,
				PerSiteRowLimit:           dynamicObservationPerSiteRowLimit,
				GlobalRowLimit:            dynamicObservationGlobalRowLimit,
			})
			return
		}
		observations, err := a.db.ListDynamicObservations(id)
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "dynamic observations unavailable")
			return
		}
		a.jsonOK(w, DynamicObservationsResponse{
			Observations:              observations,
			DroppedObservations:       a.db.DroppedDynamicObservations(),
			DroppedObservationsGlobal: a.db.DroppedDynamicObservations(),
			RetentionDays:             dynamicObservationRetentionDays,
			PerSiteRowLimit:           dynamicObservationPerSiteRowLimit,
			GlobalRowLimit:            dynamicObservationGlobalRowLimit,
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
			RoutePrefix                *string                `json:"route_prefix"`
			PathPrefix                 *string                `json:"path_prefix"`
			IngressMode                *string                `json:"ingress_mode"`
			TargetURL                  string                 `json:"target_url"`
			PrimaryLineName            *string                `json:"primary_line_name"`
			PlaybackTargetURL          *string                `json:"playback_target_url"`
			PlaybackMode               *string                `json:"playback_mode"`
			MainVideoStreamMode        *string                `json:"main_video_stream_mode"`
			FailoverTargets            *[]string              `json:"failover_targets"`
			FailoverLines              *[]FailoverLine        `json:"failover_lines"`
			StreamHosts                *[]string              `json:"stream_hosts"`
			UAMode                     *string                `json:"ua_mode"`
			CustomUserAgent            *string                `json:"custom_user_agent"`
			CustomClient               *string                `json:"custom_client"`
			CustomVersion              *string                `json:"custom_version"`
			ClientIPMode               *string                `json:"client_ip_mode"`
			UpstreamHeaders            *[]UpstreamHeaderInput `json:"upstream_headers"`
			DynamicDiscoveryEnabled    optionalJSONBool       `json:"dynamic_discovery_enabled"`
			DynamicProfile             *string                `json:"dynamic_profile"`
			DynamicDiscoverySources    optionalJSONRaw        `json:"dynamic_discovery_sources"`
			DynamicDomainRules         optionalJSONRaw        `json:"dynamic_domain_rules"`
			DynamicAllowHTTPSDowngrade *bool                  `json:"dynamic_allow_https_downgrade"`
			PingCacheEnabled           *bool                  `json:"ping_cache_enabled"`
			ImageCacheEnabled          *bool                  `json:"image_cache_enabled"`
			ProgressCoalescingEnabled  *bool                  `json:"progress_coalescing_enabled"`
			AssetCacheEnabled          *bool                  `json:"asset_cache_enabled"`
			AssetCacheTTLSec           *int                   `json:"asset_cache_ttl_sec"`
			AssetCacheMaxBytes         *int64                 `json:"asset_cache_max_bytes"`
			AssetCacheRules            *string                `json:"asset_cache_rules"`
			Quota                      *int64                 `json:"traffic_quota"`
			SpeedLimit                 *int                   `json:"speed_limit"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			a.jsonErr(w, 400, "invalid request")
			return
		}
		dynamicEnabledValue := false
		dynamicEnabledProvided := req.DynamicDiscoveryEnabled.Present
		if req.DynamicDiscoveryEnabled.Present {
			if req.DynamicDiscoveryEnabled.Null {
				a.jsonErr(w, http.StatusBadRequest, "dynamic_discovery_enabled must be a JSON boolean, not null")
				return
			}
			dynamicEnabledValue = req.DynamicDiscoveryEnabled.Value
		}
		requestedDynamicSources := []string(nil)
		dynamicSourcesProvided := req.DynamicDiscoverySources.Present
		if dynamicSourcesProvided {
			if req.DynamicDiscoverySources.Null {
				a.jsonErr(w, http.StatusBadRequest, "dynamic_discovery_sources must be a JSON array, not null")
				return
			}
			requestedDynamicSources, _, err = decodeDynamicDiscoverySourcesAPI(req.DynamicDiscoverySources.Raw)
			if err != nil {
				a.jsonErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		playbackTargetURL := oldSite.PlaybackTargetURL
		if req.PlaybackTargetURL != nil {
			playbackTargetURL = *req.PlaybackTargetURL
		}
		playbackMode := oldSite.PlaybackMode
		if req.PlaybackMode != nil {
			playbackMode = *req.PlaybackMode
		}
		mainVideoStreamMode := oldSite.MainVideoStreamMode
		if req.MainVideoStreamMode != nil {
			mainVideoStreamMode, err = normalizeMainVideoStreamMode(*req.MainVideoStreamMode)
			if err != nil {
				a.jsonErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		streamHosts := oldSite.StreamHosts
		if req.StreamHosts != nil {
			sh, _ := json.Marshal(*req.StreamHosts)
			streamHosts = string(sh)
		}
		failoverTargets := oldSite.FailoverTargets
		failoverLines := oldSite.StoredFailoverLines
		if req.FailoverLines != nil {
			normalizedLines, enabledFailovers, normalizeErr := normalizeFailoverLines(req.TargetURL, *req.FailoverLines, nil)
			if normalizeErr != nil {
				a.jsonErr(w, http.StatusBadRequest, normalizeErr.Error())
				return
			}
			serialized, _ := json.Marshal(enabledFailovers)
			failoverTargets = string(serialized)
			serializedLines, _ := json.Marshal(normalizedLines)
			failoverLines = string(serializedLines)
		} else if req.FailoverTargets != nil {
			serialized, marshalErr := json.Marshal(*req.FailoverTargets)
			if marshalErr != nil {
				a.jsonErr(w, http.StatusBadRequest, "invalid failover_targets")
				return
			}
			failoverTargets = string(serialized)
			failoverLines = "[]"
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
		if req.RoutePrefix != nil {
			prefix := strings.TrimSpace(*req.RoutePrefix)
			if prefix == "" {
				publicHost = ""
			} else {
				prefixHost, prefixErr := routeHostForPrefix(prefix, a.routeDomain)
				if prefixErr != nil {
					a.jsonErr(w, http.StatusBadRequest, prefixErr.Error())
					return
				}
				if req.PublicHost != nil && strings.TrimSpace(*req.PublicHost) != "" && !strings.EqualFold(strings.TrimSpace(*req.PublicHost), prefixHost) {
					a.jsonErr(w, http.StatusBadRequest, "route_prefix does not match public_host")
					return
				}
				publicHost = prefixHost
			}
		}
		if req.PublicHost != nil {
			candidateHost := *req.PublicHost
			if req.RoutePrefix != nil && strings.TrimSpace(*req.RoutePrefix) != "" {
				candidateHost = publicHost
			}
			publicHost, err = normalizePublicHost(candidateHost)
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
		if ingressMode == ingressModeUnset {
			a.jsonErr(w, http.StatusBadRequest, errUnsetIngress.Error())
			return
		}
		pathPrefix := oldSite.PathPrefix
		if req.PathPrefix != nil {
			pathPrefix, err = normalizePathPrefix(*req.PathPrefix)
			if err != nil {
				a.jsonErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		if ingressMode == ingressModePath && pathPrefix == "" {
			a.jsonErr(w, http.StatusBadRequest, "path_prefix is required for path ingress")
			return
		}
		if ingressMode != ingressModePath {
			pathPrefix = ""
		}
		if err := a.pm.validateIngressSafety(ingressMode); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		listenPort := req.ListenPort
		if listenPort == 0 {
			if !ingressUsesPanel(ingressMode) {
				a.jsonErr(w, http.StatusBadRequest, "listen_port is required for dedicated-port ingress")
				return
			}
			if oldSite.ListenPort >= 1 && oldSite.ListenPort <= 65535 {
				listenPort = oldSite.ListenPort
			} else {
				sites, listErr := a.db.ListSites()
				if listErr != nil {
					a.jsonErr(w, http.StatusInternalServerError, "allocate internal site port failed")
					return
				}
				listenPort, err = nextAvailableInternalSitePort(sites, a.panelListenPort)
				if err != nil {
					a.jsonErr(w, http.StatusServiceUnavailable, err.Error())
					return
				}
			}
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
		var failoverTargetList []string
		if err := json.Unmarshal([]byte(failoverTargets), &failoverTargetList); err != nil {
			a.jsonErr(w, http.StatusBadRequest, "invalid failover_targets")
			return
		}
		if _, err := parseFailoverTargets(req.TargetURL, failoverTargetList); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if len(failoverTargetList) > 0 && storedHeaders != "[]" {
			a.jsonErr(w, http.StatusBadRequest, "failover_targets cannot be combined with fixed upstream headers")
			return
		}
		candidate := *oldSite
		candidate.Name = req.Name
		candidate.ListenPort = listenPort
		candidate.PublicHost = publicHost
		candidate.PathPrefix = pathPrefix
		candidate.IngressMode = ingressMode
		candidate.TargetURL = req.TargetURL
		if req.PrimaryLineName != nil {
			candidate.PrimaryLineName, err = normalizePrimaryLineName(*req.PrimaryLineName)
			if err != nil {
				a.jsonErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		candidate.PlaybackTargetURL = playbackTargetURL
		candidate.PlaybackMode = playbackMode
		candidate.MainVideoStreamMode = mainVideoStreamMode
		candidate.FailoverTargets = failoverTargets
		candidate.StoredFailoverLines = failoverLines
		candidate.StreamHosts = streamHosts
		candidate.UAMode = uaMode
		candidate.CustomUserAgent = customUserAgent
		candidate.CustomClient = customClient
		candidate.CustomVersion = customVersion
		if req.ClientIPMode != nil {
			candidate.ClientIPMode, err = normalizeClientIPMode(*req.ClientIPMode)
			if err != nil {
				a.jsonErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		candidate.StoredUpstreamHeaders = storedHeaders
		if dynamicEnabledProvided {
			candidate.DynamicDiscoveryEnabled = dynamicEnabledValue
		}
		if req.DynamicProfile != nil {
			candidate.DynamicProfile = *req.DynamicProfile
		}
		profileChanged := req.DynamicProfile != nil && strings.EqualFold(strings.TrimSpace(*req.DynamicProfile), oldSite.DynamicProfile) == false
		enabling := !oldSite.DynamicDiscoveryEnabled && candidate.DynamicDiscoveryEnabled
		if profileChanged && strings.EqualFold(strings.TrimSpace(candidate.DynamicProfile), dynamicProfileSafe) && req.DynamicAllowHTTPSDowngrade == nil {
			candidate.DynamicAllowHTTPSDowngrade = false
		}
		if (profileChanged || enabling) && !dynamicSourcesProvided {
			candidate.DynamicDiscoverySources, _ = dynamicDiscoverySourcesForProfile(candidate.DynamicProfile)
		}
		if dynamicSourcesProvided {
			candidate.DynamicDiscoverySources = requestedDynamicSources
		}
		if req.DynamicDomainRules.Present {
			if req.DynamicDomainRules.Null {
				a.jsonErr(w, http.StatusBadRequest, "dynamic_domain_rules must be a JSON array, not null")
				return
			}
			rules, _, decodeErr := decodeDynamicDomainRulesAPI(req.DynamicDomainRules.Raw)
			if decodeErr != nil {
				a.jsonErr(w, http.StatusBadRequest, decodeErr.Error())
				return
			}
			candidate.DynamicDomainRules = rules
		}
		if req.DynamicAllowHTTPSDowngrade != nil {
			candidate.DynamicAllowHTTPSDowngrade = *req.DynamicAllowHTTPSDowngrade
		}
		if req.PingCacheEnabled != nil {
			candidate.PingCacheEnabled = *req.PingCacheEnabled
		}
		if req.ImageCacheEnabled != nil {
			candidate.ImageCacheEnabled = *req.ImageCacheEnabled
		}
		if req.ProgressCoalescingEnabled != nil {
			candidate.ProgressCoalescingEnabled = *req.ProgressCoalescingEnabled
		}
		if req.AssetCacheEnabled != nil {
			candidate.AssetCacheEnabled = *req.AssetCacheEnabled
		}
		if req.AssetCacheTTLSec != nil {
			candidate.AssetCacheTTLSec = *req.AssetCacheTTLSec
		}
		if req.AssetCacheMaxBytes != nil {
			candidate.AssetCacheMaxBytes = *req.AssetCacheMaxBytes
		}
		if req.AssetCacheRules != nil {
			candidate.AssetCacheRules = *req.AssetCacheRules
		}
		if err := normalizeAssetCacheConfig(&candidate); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := normalizeDynamicSitePolicy(&candidate); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if dynamicSourcesProvided {
			if err := validateSelectableDynamicDiscoverySources(candidate.DynamicProfile, candidate.DynamicDiscoverySources); err != nil && !dynamicDiscoverySourcesEqual(candidate.DynamicDiscoverySources, oldSite.DynamicDiscoverySources) {
				a.jsonErr(w, http.StatusBadRequest, err.Error())
				return
			}
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
		if candidate.PathPrefix != "" {
			if assignedID, exists := a.pm.PathPrefixSiteID(candidate.PathPrefix); exists && assignedID != candidate.ID {
				a.jsonErr(w, http.StatusBadRequest, "path_prefix is already assigned to another site")
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
		if err := a.pm.ClearSiteAssetCache(id); err != nil {
			log.Printf("[%d] site asset cache cleanup failed: %v", id, err)
		}
		a.jsonOK(w, map[string]string{"status": "deleted"})

	default:
		a.jsonErr(w, 405, "method not allowed")
	}
}
