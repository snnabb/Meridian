package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

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
	site.PathPrefix, err = normalizePathPrefix(site.PathPrefix)
	if err != nil {
		return fmt.Errorf("invalid path prefix: %w", err)
	}
	site.IngressMode, err = normalizeIngressMode(site.IngressMode, site.PublicHost)
	if err != nil {
		return fmt.Errorf("invalid ingress configuration: %w", err)
	}
	if site.IngressMode == ingressModeUnset {
		return errUnsetIngress
	}
	if site.IngressMode == ingressModePath && site.PathPrefix == "" {
		return fmt.Errorf("invalid ingress configuration: path_prefix is required when ingress_mode is path")
	}
	if err := pm.validateIngressSafety(site.IngressMode); err != nil {
		return err
	}
	target, err := normalizeTargetURL(site.TargetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	failoverTargets, err := parseFailoverTargets(site.TargetURL, site.FailoverTargetList)
	if err != nil {
		return fmt.Errorf("invalid failover targets: %w", err)
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
	for _, failoverTarget := range failoverTargets[1:] {
		configuredAuthorities[redirectHostKey(failoverTarget)] = true
	}
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
			pathPrefix:            site.PathPrefix,
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
		failoverState:  newUpstreamFailoverState(),
		progress:       nil,
		pingCache:      pingCacheState,
		imageCache:     imageCacheState,
	}
	installed := false
	defer func() {
		if !installed {
			if imageCacheState != nil {
				imageCacheState.close()
			}
			instanceCancel()
			if dynamicState != nil {
				dynamicState.close()
			}
		}
	}()
	inst.persistedTraffic.Store(site.TrafficUsed)
	inst.persistedBytesIn.Store(site.TrafficUsedIn)
	inst.persistedBytesOut.Store(site.TrafficUsedOut)
	if inst.persistedBytesIn.Load() == 0 && inst.persistedBytesOut.Load() == 0 && site.TrafficUsed > 0 {
		legacyIn, legacyOut := legacyTrafficDirections(site.TrafficUsed)
		inst.persistedBytesIn.Store(legacyIn)
		inst.persistedBytesOut.Store(legacyOut)
	}

	isRedirectMode := playbackTarget != nil && site.PlaybackMode == "redirect"
	proxyTransport := http.DefaultTransport.(*http.Transport).Clone()
	proxyTransport.TLSClientConfig = secureTLSConfig("")
	proxyTransport.ResponseHeaderTimeout = 30 * time.Second
	proxyTransport.MaxIdleConnsPerHost = 32
	inst.transport = proxyTransport
	baseTransport := http.RoundTripper(proxyTransport)
	if pingCacheState != nil {
		baseTransport = &pingCacheTransport{base: baseTransport, cache: pingCacheState}
	}
	if dynamicIssuer != nil {
		dynamicIssuer.configuredTransport = proxyTransport
	}

	proxy := &httputil.ReverseProxy{
		Transport: baseTransport,
		Rewrite: func(proxyReq *httputil.ProxyRequest) {
			ingressPrefix, _ := proxyReq.In.Context().Value(pathIngressContextKey{}).(string)
			if redirectPolicy.configured {
				eligible := isDynamicRedirectEligibleRequestForState(proxyReq.In, dynamicState)
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
			if tracker := backendAddressTrackerFromContext(proxyReq.Out.Context()); tracker != nil {
				tracker.SetURL(upstream)
			}
			originalURL := *proxyReq.Out.URL
			applyUpstreamURL(proxyReq.Out.URL, upstream)
			proxyReq.Out.Host = upstream.Host
			prepareUpstreamHeadersWithClientIPMode(proxyReq.Out.Header, proxyReq.In, policy, site.ClientIPMode, inst.trustedProxies)
			if !sameRedirectAuthority(target, upstream) {
				// Direct playback can target a separate CDN. Treat that authority like
				// a cross-origin redirect and rebuild from a narrow allowlist so client
				// cookies, bearer tokens, and arbitrary secret headers cannot follow it.
				proxyReq.Out.Header = crossAuthorityRedirectHeadersWithClientIPMode(proxyReq.Out.Header, site.ClientIPMode)
			}
			applySiteForwardedHost(proxyReq.Out.Header, proxyReq.In, site)
			configuredHeaders.apply(proxyReq.Out.Header, upstream)
			// Backup lines apply to the configured main upstream, including proxied
			// playback reads and replayable PlaybackInfo requests. Separate playback
			// targets, direct video, redirects and WebSockets keep their own routes.
			if len(failoverTargets) > 1 && upstreamTargetKey(upstream) == upstreamTargetKey(target) &&
				!isRedirectMode && site.MainVideoStreamMode != mainVideoStreamModeDirect && len(configuredHeaders.values) == 0 {
				proxyReq.Out = withFailoverRequestPlan(proxyReq.Out, &originalURL, failoverTargets, target, redirectPolicy.limits.MaxBodyBytes)
			}
			if source := dynamicStructuredRequestIdentity(proxyReq.In); source != "" {
				ctx := context.WithValue(proxyReq.Out.Context(), dynamicExpectedStructuredSourceContextKey{}, source)
				if source == dynamicDiscoverySourcePlaybackInfo && proxyReq.In != nil && proxyReq.In.URL != nil {
					clientBase := *proxyReq.In.URL
					if ingressPrefix != "" {
						clientBase.Path = addIngressPathPrefix(clientBase.Path, ingressPrefix)
						clientBase.RawPath = ""
					}
					clientBase.Scheme = ""
					clientBase.Host = ""
					clientBase.User = nil
					clientBase.RawQuery = ""
					clientBase.ForceQuery = false
					clientBase.Fragment = ""
					clientBase.RawFragment = ""
					ctx = context.WithValue(ctx, dynamicPlaybackInfoBaseContextKey{}, &clientBase)
				}
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
			rewriteRelative := ingressUsesPath(site.IngressMode) && dynamicIssuer != nil
			if err := rewriteDynamicStructuredResponseExpected(resp, dynamicIssuer, dynamicResponse || rewriteRelative, expectedSource, 0, false); err != nil {
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
				stripPanelSessionSetCookies(resp.Header)
				prefixPathIngressResponse(resp, site.PathPrefix, target.Path)
				return nil
			}
			stripPanelSessionSetCookies(resp.Header)
			prefixPathIngressResponse(resp, site.PathPrefix, target.Path)
			if err := prepareAssetCacheResponse(resp, pm.assetCache, site); err != nil {
				return err
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var discoveryErr *dynamicProxyError
			if errors.As(err, &discoveryErr) {
				log.Printf("[%s] dynamic discovery denied: %s", site.Name, discoveryErr.reasonCode)
				discoveryErr.writeResponse(w)
				return
			}
			if isClientRequestCancellation(originalRequestContext(r.Context()), err) {
				return
			}
			log.Printf("[%s] proxy error: %v", site.Name, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"upstream unavailable"}`))
		},
	}
	if isRedirectMode || redirectPolicy.configured || len(playbackHostsSet) > 0 {
		proxy.Transport = &redirectFollowTransport{
			base:                    proxy.Transport,
			playbackHosts:           playbackHostsSet,
			configuredAuthorities:   configuredAuthorities,
			disableLegacyRedirects:  !isRedirectMode && len(playbackHostsSet) == 0,
			followUnknownRedirects:  redirectPolicy.configured,
			policy:                  policy,
			clientIPMode:            site.ClientIPMode,
			upstreamHeaderPolicy:    configuredHeaders,
			dynamicPolicy:           redirectPolicy,
			dynamicTransportFactory: pm.dynamicTransportFactory,
			dynamicState:            dynamicState,
			capabilityIssuer:        dynamicIssuer,
			mainVideoDirect:         site.MainVideoStreamMode == mainVideoStreamModeDirect,
			database:                pm.database,
			siteID:                  site.ID,
		}
	}
	if len(failoverTargets) > 1 {
		proxy.Transport = &failoverTransport{base: proxy.Transport, state: inst.failoverState}
	}
	if site.ProgressCoalescingEnabled {
		inst.progress = newProgressCoalescer(pm.progressRuntime, defaultProgressCoalescerConfig(), func(request *http.Request) (progressResponse, error) {
			capture := newProgressCaptureWriter()
			dispatchErrors := &progressDispatchErrorState{}
			request = request.WithContext(context.WithValue(request.Context(), progressDispatchErrorContextKey{}, dispatchErrors))
			proxy.ServeHTTP(capture, request)
			response, captureErr := capture.response()
			return response, errors.Join(captureErr, dispatchErrors.load())
		})
	}

	// Speed limit in bytes/sec (field is in Mbps, 0 = unlimited)
	speedLimitBytes := int64(site.SpeedLimit) * 125000 // Mbps -> bytes/sec

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestController, accepted := inst.beginHTTPRequest(w)
		if !accepted {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"site is stopping"}`))
			return
		}
		defer inst.endHTTPRequest(requestController)
		normalizeEmbeddedDynamicCapabilityRequestPath(r.URL)
		clientRequestContext := r.Context()
		requestLogWriter := &requestLogResponseWriter{ResponseWriter: w}
		requestLogEntry := newRequestLogEvent(site, r, inst.trustedProxies, policy)
		defer func() {
			requestLogEntry.StatusCode = requestLogWriter.StatusCode()
			if errors.Is(clientRequestContext.Err(), context.Canceled) {
				requestLogEntry.StatusCode = clientClosedRequestStatus
			}
			requestLogEntry.OutboundColo = requestLogColo(requestLogWriter.Header().Get("CF-Ray"))
			if tracker := backendAddressTrackerFromContext(r.Context()); tracker != nil {
				requestLogEntry.BackendAddress = tracker.Get()
			}
			pm.database.EnqueueRequestLog(requestLogEntry)
		}()
		w = requestLogWriter
		requestCtx, requestCancel := context.WithCancel(r.Context())
		requestCtx = context.WithValue(requestCtx, originalRequestContextKey{}, clientRequestContext)
		backendTracker := &backendAddressTracker{}
		initialBackend := target
		if !isRedirectMode {
			initialBackend = upstreamTargetForRequest(r, target, playbackTarget)
		}
		backendTracker.SetURL(initialBackend)
		requestCtx = context.WithValue(requestCtx, backendAddressContextKey{}, backendTracker)
		stopInstanceCancel := context.AfterFunc(inst.ctx, requestCancel)
		defer func() {
			stopInstanceCancel()
			requestCancel()
		}()
		r = r.WithContext(requestCtx)
		inst.reqCount.Add(1)
		inst.pendingRequests.Add(1)

		if site.TrafficQuota > 0 {
			currentUsed, usageErr := pm.currentTrafficCycleUsage(inst, time.Now())
			if usageErr != nil {
				log.Printf("[%s] failed to calculate current traffic cycle usage: %v", site.Name, usageErr)
			} else if currentUsed >= site.TrafficQuota {
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
					cumulative:     &inst.cumulativeBytesOut,
					start:          time.Now(),
					ctx:            r.Context(),
				}
			} else {
				rw = &meteredWriter{ResponseWriter: w, written: &inst.bytesOut, cumulative: &inst.cumulativeBytesOut}
			}
			if dynamicIssuer == nil {
				writeDynamicCapabilityUnavailable(rw)
			} else {
				dynamicIssuer.serve(rw, r)
			}
			return
		}

		if site.MainVideoStreamMode == mainVideoStreamModeDirect && isMainVideoStreamRequest(r) {
			directUpstream := target
			if !isRedirectMode {
				directUpstream = upstreamTargetForRequest(r, target, playbackTarget)
			}
			directTarget := mainVideoDirectTarget(r, directUpstream)
			if tracker := backendAddressTrackerFromContext(r.Context()); tracker != nil {
				tracker.SetURL(directTarget)
			}
			r = r.WithContext(context.WithValue(r.Context(), mainVideoDirectFallbackContextKey{}, directTarget))
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
			handleWebSocket(w, r, wsTarget, target, policy, inst, speedLimitBytes, configuredHeaders)
			return
		}

		if route, eligible := pingCacheRouteForRequest(r); eligible && inst.pingCache != nil {
			r = r.WithContext(context.WithValue(r.Context(), pingCacheRequestContextKey{}, route))
		}
		cacheTarget := upstreamTargetForRequest(r, target, playbackTarget)
		if isRedirectMode {
			cacheTarget = target
		}

		if isRedirectMode {
			cacheTarget = target
		}
		if cacheReq := pm.assetCache.request(site, r, assetCacheTargetURL(r, cacheTarget)); cacheReq != nil {
			if hit, err := pm.assetCache.read(cacheReq, time.Now()); err == nil && hit != nil {
				var cacheWriter http.ResponseWriter
				if speedLimitBytes > 0 {
					cacheWriter = &rateLimitedWriter{ResponseWriter: w, bytesPerSec: speedLimitBytes, written: &inst.bytesOut, cumulative: &inst.cumulativeBytesOut, start: time.Now(), ctx: r.Context()}
				} else {
					cacheWriter = &meteredWriter{ResponseWriter: w, written: &inst.bytesOut, cumulative: &inst.cumulativeBytesOut}
				}
				serveAssetCacheHit(cacheWriter, r, hit)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), assetCacheContextKey{}, cacheReq))
		}

		if r.Body != nil {
			r.Body = &meteredReader{ReadCloser: r.Body, read: &inst.bytesIn, cumulative: &inst.cumulativeBytesIn}
		}
		if len(failoverTargets) > 1 {
			if err := prepareFailoverPlaybackInfoBody(r, redirectPolicy.limits.MaxBodyBytes); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid request body"}`))
				return
			}
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
				cumulative:     &inst.cumulativeBytesOut,
				start:          time.Now(),
				ctx:            r.Context(),
			}
		} else {
			rw = &meteredWriter{ResponseWriter: w, written: &inst.bytesOut, cumulative: &inst.cumulativeBytesOut}
		}
		finalProxy := http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			proxy.ServeHTTP(responseWriter, request)
		})
		if inst.imageCache != nil {
			finalProxy = http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
				inst.imageCache.serve(responseWriter, request, cacheTarget, http.HandlerFunc(func(nextWriter http.ResponseWriter, nextRequest *http.Request) {
					proxy.ServeHTTP(nextWriter, nextRequest)
				}))
			})
		}
		if inst.progress != nil && inst.progress.ServeHTTP(rw, r, finalProxy) {
			return
		}
		finalProxy.ServeHTTP(rw, r)
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
		if siteTLSConfig := pm.siteTLSConfigSnapshot(); siteTLSConfig != nil {
			listener = tls.NewListener(listener, siteTLSConfig)
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
	if ingressUsesPath(site.IngressMode) {
		if assignedID, ok := pm.pathPrefixes[site.PathPrefix]; ok && assignedID != site.ID {
			pm.mu.Unlock()
			closeNewListener()
			return fmt.Errorf("path_prefix %s is already assigned to another site", site.PathPrefix)
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
		if flushed := existing.Site.TrafficUsed; flushed > inst.persistedTraffic.Load() {
			inst.persistedTraffic.Store(flushed)
			inst.persistedBytesIn.Store(existing.Site.TrafficUsedIn)
			inst.persistedBytesOut.Store(existing.Site.TrafficUsedOut)
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
		if ingressUsesPath(site.IngressMode) {
			log.Printf("[%s] shared-path proxy %s -> %s (UA: %s)", site.Name, site.PathPrefix, upstreamLogTarget, site.UAMode)
		} else {
			log.Printf("[%s] shared-host proxy %s -> %s (UA: %s)", site.Name, site.PublicHost, upstreamLogTarget, site.UAMode)
		}
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
			protocol := "http"
			if pm.siteTLSConfigSnapshot() != nil {
				protocol = "https"
			}
			log.Printf("[%s] %s :%d -> %s (UA: %s)", site.Name, protocol, site.ListenPort, upstreamLogTarget, site.UAMode)
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
