package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultClientIPRegionEndpoint = "https://ipwho.is/{ip}?lang=zh-CN"
	clientIPRegionUnknown         = "未知"
	clientIPRegionLocal           = "内网/保留地址"
	clientIPRegionPending         = "查询中"
	clientIPRegionCacheTTL        = 24 * time.Hour
	clientIPRegionFailureTTL      = 10 * time.Minute
	clientIPRegionCacheLimit      = 4096
	clientIPRegionResponseLimit   = 64 << 10
)

type clientIPRegionCacheEntry struct {
	value     string
	expiresAt time.Time
}

type clientIPRegionResolver struct {
	endpoint string
	client   *http.Client

	mu       sync.Mutex
	cache    map[string]clientIPRegionCacheEntry
	inflight map[string]struct{}
	workers  chan struct{}
}

func newClientIPRegionResolver(endpoint string, client *http.Client) (*clientIPRegionResolver, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = "off"
	}
	if strings.EqualFold(endpoint, "off") || strings.EqualFold(endpoint, "disabled") {
		return nil, nil
	}
	if !strings.Contains(endpoint, "{ip}") {
		return nil, fmt.Errorf("CLIENT_IP_REGION_ENDPOINT must contain {ip}")
	}
	probe, err := url.Parse(strings.Replace(endpoint, "{ip}", "8.8.8.8", 1))
	if err != nil || probe.Hostname() == "" || probe.User != nil {
		return nil, fmt.Errorf("CLIENT_IP_REGION_ENDPOINT is invalid")
	}
	if probe.Scheme != "https" && !(probe.Scheme == "http" && (probe.Hostname() == "localhost" || dynamicIPIsLoopbackHost(probe.Hostname()))) {
		return nil, fmt.Errorf("CLIENT_IP_REGION_ENDPOINT must use HTTPS")
	}
	if client == nil {
		client = &http.Client{Timeout: 4 * time.Second}
	}
	return &clientIPRegionResolver{
		endpoint: endpoint,
		client:   client,
		cache:    make(map[string]clientIPRegionCacheEntry),
		inflight: make(map[string]struct{}),
		workers:  make(chan struct{}, 8),
	}, nil
}

func dynamicIPIsLoopbackHost(host string) bool {
	parsed, err := netip.ParseAddr(strings.TrimSpace(host))
	return err == nil && parsed.IsLoopback()
}

func clientIPRegionStatic(ip string) (string, string) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "", clientIPRegionUnknown
	}
	addr = addr.Unmap()
	if !dynamicIPIsPublic(addr) {
		return addr.String(), clientIPRegionLocal
	}
	return addr.String(), ""
}

func (r *clientIPRegionResolver) lookup(ip string) string {
	normalized, static := clientIPRegionStatic(ip)
	if static != "" {
		return static
	}
	if r == nil {
		return clientIPRegionUnknown
	}
	now := time.Now()
	r.mu.Lock()
	if entry, ok := r.cache[normalized]; ok {
		if entry.expiresAt.After(now) {
			r.mu.Unlock()
			return entry.value
		}
		delete(r.cache, normalized)
	}
	if _, ok := r.inflight[normalized]; ok {
		r.mu.Unlock()
		return clientIPRegionPending
	}
	r.inflight[normalized] = struct{}{}
	r.mu.Unlock()

	go r.resolve(normalized)
	return clientIPRegionPending
}

func (r *clientIPRegionResolver) resolve(ip string) {
	select {
	case r.workers <- struct{}{}:
		defer func() { <-r.workers }()
	default:
		r.finish(ip, clientIPRegionUnknown, clientIPRegionFailureTTL)
		return
	}

	value, err := r.fetch(ip)
	if err != nil || value == "" {
		r.finish(ip, clientIPRegionUnknown, clientIPRegionFailureTTL)
		return
	}
	r.finish(ip, value, clientIPRegionCacheTTL)
}

func (r *clientIPRegionResolver) fetch(ip string) (string, error) {
	target := strings.Replace(r.endpoint, "{ip}", url.PathEscape(ip), 1)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Meridian-IP-Region/1")
	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IP region service returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, clientIPRegionResponseLimit+1))
	if err != nil || len(body) > clientIPRegionResponseLimit {
		return "", fmt.Errorf("invalid IP region response")
	}
	var payload struct {
		Success bool   `json:"success"`
		Country string `json:"country"`
		Region  string `json:"region"`
		City    string `json:"city"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || !payload.Success {
		return "", fmt.Errorf("invalid IP region response")
	}
	parts := make([]string, 0, 3)
	for _, value := range []string{payload.Country, payload.Region, payload.City} {
		value = strings.TrimSpace(value)
		if value == "" || len(parts) > 0 && strings.EqualFold(parts[len(parts)-1], value) {
			continue
		}
		parts = append(parts, value)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("IP region response is empty")
	}
	return strings.Join(parts, " · "), nil
}

func (r *clientIPRegionResolver) finish(ip, value string, ttl time.Duration) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.inflight, ip)
	for key, entry := range r.cache {
		if !entry.expiresAt.After(now) {
			delete(r.cache, key)
		}
	}
	if len(r.cache) >= clientIPRegionCacheLimit {
		for key := range r.cache {
			delete(r.cache, key)
			break
		}
	}
	r.cache[ip] = clientIPRegionCacheEntry{value: value, expiresAt: now.Add(ttl)}
}

func (r *clientIPRegionResolver) enrich(logs []RequestLog) {
	for index := range logs {
		logs[index].ClientRegion = r.lookup(logs[index].ClientIP)
	}
}
