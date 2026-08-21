package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type App struct {
	db                *DB
	dbPath            string
	pm                *ProxyManager
	backupMu          sync.Mutex
	siteLifecycleMu   sync.Mutex
	setupTokenMu      sync.Mutex
	setupToken        string
	loginLimiter      *loginRateLimiter
	loginLimiterOnce  sync.Once
	trustedProxies    []*net.IPNet
	clientIPRegions   *clientIPRegionResolver
	panelHost         string
	routeDomain       string
	panelTLSEnabled   bool
	panelCertificates *panelCertificateManager
	panelBindLoopback bool
	panelListenPort   int
	dynamicRouteKey   []byte
	restartCh         chan struct{}
	restartOnce       sync.Once
}

func (a *App) requestRestart() {
	if a == nil || a.restartCh == nil {
		return
	}
	a.restartOnce.Do(func() {
		time.AfterFunc(500*time.Millisecond, func() { close(a.restartCh) })
	})
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
		directTLSHost := ""
		if a.panelTLSEnabled && r.TLS != nil && !isLoopbackHealthProbe(r) {
			directTLSHost = requestPublicHost(r.TLS.ServerName)
			if directTLSHost == "" || host == "" || directTLSHost != host {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusMisdirectedRequest)
				_, _ = w.Write([]byte(`{"error":"TLS server name does not match Host"}`))
				return
			}
		}
		if host != "" {
			handler, configured, mode := a.pm.PublicHostRoute(host)
			if configured {
				directTLS := a.panelTLSEnabled && directTLSHost == host
				if mode == ingressModeHost && !directTLS && !a.panelBindLoopback && !isTrustedProxy(remoteAddressIP(r.RemoteAddr), a.trustedProxies) {
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
			if handler, prefix, configured := a.pm.PathRoute(r.URL.Path); configured {
				if handler == nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`{"error":"site unavailable"}`))
					return
				}
				if r.URL.Path == prefix && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
					target := prefix + "/"
					if r.URL.RawQuery != "" {
						target += "?" + r.URL.RawQuery
					}
					http.Redirect(w, r, target, http.StatusPermanentRedirect) // #nosec G710 -- target is constructed solely from the matched local ingress prefix and original query.
					return
				}
				r = r.Clone(context.WithValue(r.Context(), pathIngressContextKey{}, prefix))
				normalizeEmbeddedIngressRequestPath(r.URL, prefix)
				stripIngressPathPrefix(r.URL, prefix)
				normalizeStrippedIngressRequestPath(r.URL, prefix)
				handler.ServeHTTP(w, r)
				return
			}
			panel.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = w.Write([]byte(`{"error":"unrecognized host"}`))
	})
}
