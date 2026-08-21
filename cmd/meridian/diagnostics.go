package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

type DiagResult struct {
	Upstreams DiagUpstreams `json:"upstreams"`
	Health    DiagHealth    `json:"health"`
	TLS       DiagTLS       `json:"tls"`
	Headers   DiagHeaders   `json:"headers"`
	Proxy     DiagProxy     `json:"proxy"`
}

type DiagUpstreams struct {
	Primary   DiagUpstream   `json:"primary"`
	Playback  DiagUpstream   `json:"playback"`
	Failovers []DiagUpstream `json:"failovers"`
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
	PathPrefix    string `json:"path_prefix"`
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
var probeClientMu sync.RWMutex

func newProbeClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = secureTLSConfig("")
	return &http.Client{
		Timeout:   timeout,
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
}

var probeClient = newProbeClient(5 * time.Second)

func configureProbeClient(timeout time.Duration) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	probeClientMu.Lock()
	previous := probeClient
	probeClient = newProbeClient(timeout)
	probeClientMu.Unlock()
	if previous != nil && previous.Transport != nil {
		if transport, ok := previous.Transport.(interface{ CloseIdleConnections() }); ok {
			transport.CloseIdleConnections()
		}
	}
}

func probeTargetHealth(plan diagProbePlan) DiagHealth {
	probeClientMu.RLock()
	client := probeClient
	probeClientMu.RUnlock()
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
		// codeql[go/request-forgery] -- diagnostics only probes the authenticated administrator's normalized site target; it is not derived from an unauthenticated request URL.
		resp, err := client.Do(req)
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
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func diagnoseSite(site *Site, pm *ProxyManager) DiagResult {
	policy, profileErr := resolveUAHeaderPolicy(*site)
	primary, primaryKey := diagnoseUpstreamTarget(site.TargetURL, "metadata_api")
	primary.Configured = true
	failovers := make([]DiagUpstream, 0, len(site.FailoverTargetList))
	if len(site.FailoverTargetList) > 0 {
		failovers = make([]DiagUpstream, len(site.FailoverTargetList))
		// Keep diagnostics responsive even when several backup lines are down.
		// The small bound avoids a scan creating an unbounded burst of dials.
		workers := make(chan struct{}, 2)
		var wait sync.WaitGroup
		for index, targetURL := range site.FailoverTargetList {
			wait.Add(1)
			go func(index int, targetURL string) {
				defer wait.Done()
				workers <- struct{}{}
				defer func() { <-workers }()
				upstream, _ := diagnoseUpstreamTarget(targetURL, "metadata_api")
				upstream.Configured = true
				failovers[index] = upstream
			}(index, targetURL)
		}
		wait.Wait()
	}
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
			Primary:   primary,
			Playback:  playback,
			Failovers: failovers,
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
		PathPrefix:    site.PathPrefix,
		PublicHost:    site.PublicHost,
		PortListening: portListening,
		ListenPort:    site.ListenPort,
		TotalReqs:     totalRequests,
		Uptime:        uptime,
	}

	return result
}
