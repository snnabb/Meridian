package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

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
	drainDone       chan struct{}
	activeHTTP      map[*http.ResponseController]struct{}
	hijackedConns   map[net.Conn]struct{}
	portServing     atomic.Bool
	portServeFailed atomic.Bool
	// trafficMu serializes this instance's traffic state transitions: flush,
	// single-site history snapshot and the live overlay in global snapshots.
	// Lock order is pm.mu -> trafficMu; helpers that take trafficMu (e.g.
	// flushProxyTraffic) must never be called from code that already holds it.
	trafficMu            sync.Mutex
	quota                *trafficQuotaState
	bytesIn              atomic.Int64
	bytesOut             atomic.Int64
	cumulativeBytesIn    atomic.Int64
	cumulativeBytesOut   atomic.Int64
	persistedBytesIn     atomic.Int64
	persistedBytesOut    atomic.Int64
	reqCount             atomic.Int64
	pendingRequests      atomic.Int64
	persistedTraffic     atomic.Int64
	trafficCycleStart    time.Time
	trafficCycleMode     string
	trafficCycleUsage    int64
	activeTrafficMeters  atomic.Int64
	flushBytesIn         int64
	flushBytesOut        int64
	pendingMinuteTraffic map[int64]trafficMinuteDelta
	trustedProxies       []*net.IPNet
	dynamicState         *dynamicSiteState
	failoverState        *upstreamFailoverState
	progress             *progressCoalescer
	pingCache            *pingCache
	imageCache           *imageCacheSite
}

type ProxyManager struct {
	mu                      sync.RWMutex
	lifecycleMu             sync.Mutex
	proxies                 map[int64]*ProxyInstance
	publicHosts             map[string]int64
	publicHostModes         map[string]string
	pathPrefixes            map[string]int64
	upstreamHeaderKey       []byte
	trustedProxies          []*net.IPNet
	hostOnlyIngressSafe     bool
	shutdownStarted         atomic.Bool
	database                *DB
	dynamicRuntime          *dynamicRuntime
	dynamicRouteKey         []byte
	dynamicTransportFactory dynamicTransportFactory
	dynamicAvailable        bool
	dynamicPanelHost        string
	dynamicPanelPort        int
	dynamicInterfaceAddrs   dynamicInterfaceAddrsFunc
	assetCache              *assetCache
	siteTLSConfig           *tls.Config
	progressRuntime         *progressGlobalRuntime
	imageCacheRuntime       *imageCacheRuntime
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

func (e *siteIngressClosedError) Unwrap() error {
	if e == nil {
		return nil
	}
	if e.drainErr != nil && e.flushErr != nil {
		return errors.Join(e.drainErr, e.flushErr)
	}
	if e.drainErr != nil {
		return e.drainErr
	}
	return e.flushErr
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

func (inst *ProxyInstance) beginHTTPRequest(w http.ResponseWriter) (*http.ResponseController, bool) {
	controller := http.NewResponseController(w)
	inst.lifecycleMu.Lock()
	defer inst.lifecycleMu.Unlock()
	if inst.closing {
		return nil, false
	}
	if inst.activeHTTP == nil {
		inst.activeHTTP = make(map[*http.ResponseController]struct{})
	}
	inst.activeHTTP[controller] = struct{}{}
	inst.activeRequests.Add(1)
	return controller, true
}

func (inst *ProxyInstance) endHTTPRequest(controller *http.ResponseController) {
	inst.lifecycleMu.Lock()
	delete(inst.activeHTTP, controller)
	inst.lifecycleMu.Unlock()
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
	return ingressUsesPanel(inst.Site.IngressMode) || !inst.portServeFailed.Load()
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
	if err := inst.drainProgress(ctx); err != nil {
		return err
	}
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
	// Shared-host sites run on the panel server, so their listener/server cannot
	// be closed per site. Set deadlines while holding lifecycleMu: a handler
	// cannot unregister and let its connection be reused by another Host between
	// the active check and the deadline change.
	now := time.Now()
	for controller := range inst.activeHTTP {
		_ = controller.SetReadDeadline(now)
		_ = controller.SetWriteDeadline(now)
	}
	if inst.drainDone == nil {
		inst.drainDone = make(chan struct{})
		drainDone := inst.drainDone
		go func() {
			inst.activeRequests.Wait()
			close(drainDone)
		}()
	}
	drained := inst.drainDone
	inst.lifecycleMu.Unlock()

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

	select {
	case <-drained:
		if inst.dynamicState != nil {
			inst.dynamicState.close()
		}
		if inst.pingCache != nil {
			inst.pingCache.invalidate()
		}
		if inst.imageCache != nil {
			inst.imageCache.close()
		}
		inst.closeProgress()
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
		pathPrefixes:      make(map[string]int64),
		dynamicRuntime:    newDynamicRuntime(),
		progressRuntime:   newProgressGlobalRuntime(progressMaxGlobalKeys, progressMaxGlobalWaiters),
		imageCacheRuntime: newImageCacheRuntime(upstreamHeaderKey),
		database:          db,
	}
	pm.upstreamHeaderKey = append([]byte(nil), upstreamHeaderKey...)
	return pm
}

func (pm *ProxyManager) SetAssetCache(cache *assetCache) {
	pm.mu.Lock()
	pm.assetCache = cache
	pm.mu.Unlock()
}

// SetSiteTLSConfig enables TLS on dedicated site listeners when the panel TLS
// certificate is active. Shared-host ingress already uses the panel listener;
// port/both ingress must wrap its own listener as well so
// https://panel.example:PORT works consistently.
func (pm *ProxyManager) SetSiteTLSConfig(config *tls.Config) {
	pm.mu.Lock()
	if config == nil {
		pm.siteTLSConfig = nil
	} else {
		pm.siteTLSConfig = config.Clone()
	}
	pm.mu.Unlock()
}

func (pm *ProxyManager) siteTLSConfigSnapshot() *tls.Config {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if pm.siteTLSConfig == nil {
		return nil
	}
	return pm.siteTLSConfig.Clone()
}

func (pm *ProxyManager) AssetCacheSizes() (map[int64]int64, int64, error) {
	pm.mu.RLock()
	cache := pm.assetCache
	pm.mu.RUnlock()
	if cache == nil {
		return map[int64]int64{}, 0, nil
	}
	return cache.sizeBySite()
}

func (pm *ProxyManager) ClearAssetCache() error {
	pm.mu.RLock()
	cache := pm.assetCache
	pm.mu.RUnlock()
	if cache == nil {
		return nil
	}
	return cache.clear()
}

func (pm *ProxyManager) ClearSiteAssetCache(siteID int64) error {
	pm.mu.RLock()
	cache := pm.assetCache
	pm.mu.RUnlock()
	if cache == nil {
		return nil
	}
	return cache.clearSite(siteID)
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
	desiredPath := ""
	if ingressUsesPath(site.IngressMode) {
		desiredPath = site.PathPrefix
		if existing, ok := pm.pathPrefixes[desiredPath]; ok && existing != site.ID {
			return fmt.Errorf("path_prefix %s is already assigned to another site", desiredPath)
		}
	}
	for host, id := range pm.publicHosts {
		if id == site.ID && host != desiredHost {
			delete(pm.publicHosts, host)
			delete(pm.publicHostModes, host)
		}
	}
	if desiredHost != "" {
		pm.publicHosts[desiredHost] = site.ID
		pm.publicHostModes[desiredHost] = site.IngressMode
	}
	for pathPrefix, id := range pm.pathPrefixes {
		if id == site.ID && pathPrefix != desiredPath {
			delete(pm.pathPrefixes, pathPrefix)
		}
	}
	if desiredPath != "" {
		pm.pathPrefixes[desiredPath] = site.ID
	}
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
	for pathPrefix, id := range pm.pathPrefixes {
		if id == siteID {
			delete(pm.pathPrefixes, pathPrefix)
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

func (pm *ProxyManager) PathRoute(requestPath string) (http.Handler, string, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for prefix, id := range pm.pathPrefixes {
		if !ingressPathMatches(requestPath, prefix) && !embeddedIngressPathMatches(requestPath, prefix) {
			continue
		}
		inst := pm.proxies[id]
		if inst == nil {
			return nil, prefix, true
		}
		return inst.handler, prefix, true
	}
	return nil, "", false
}

func embeddedIngressPathMatches(requestPath, prefix string) bool {
	for _, appBase := range []string{"/emby", "/jellyfin"} {
		embedded := appBase + prefix
		if len(requestPath) >= len(embedded) && strings.EqualFold(requestPath[:len(embedded)], embedded) &&
			(len(requestPath) == len(embedded) || requestPath[len(embedded)] == '/') {
			return true
		}
	}
	return false
}

func (pm *ProxyManager) PathPrefixSiteID(prefix string) (int64, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	id, ok := pm.pathPrefixes[prefix]
	return id, ok
}
