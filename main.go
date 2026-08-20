package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/fs"
	"log"
	"meridian/web"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

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

var startTime = time.Now()

// appVersion is overridable at build time via -ldflags "-X main.appVersion=vX.Y.Z".
var appVersion = "v1.12.0"

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
	if err := validateCredentialKeySeparation(meridianSecretKey, meridianSecretKeyConfigured, jwtSecret, dynamicRouteKey, upstreamHeaderKey); err != nil {
		log.Fatalf("invalid credential key: %v", err)
	}

	restoreState, err := applyPendingRestore(dbPath)
	if err != nil {
		log.Fatalf("apply pending restore: %v", err)
	}
	db, err := openDB(dbPath)
	if err != nil && restoreState != nil {
		log.Printf("restored database failed to open; rolling back: %v", err)
		if rollbackErr := rollbackAppliedRestore(dbPath, restoreState); rollbackErr != nil {
			log.Fatalf("restored database failed and rollback failed: %v (original error: %v)", rollbackErr, err)
		}
		db, err = openDB(dbPath)
	}
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	if err := migrateStoredCredentialCiphertexts(db); err != nil {
		log.Fatalf("migrate stored credentials: %v", err)
	}
	if restoreState != nil {
		if err := db.InvalidateAllSessions(); err != nil {
			log.Fatalf("invalidate sessions after database restore: %v", err)
		}
	}
	defer db.Close()
	panelSettings, err := db.BootstrapPanelSettings(os.Getenv("PANEL_DOMAIN"), os.Getenv("PANEL_ROUTE_DOMAIN"), envBool("PANEL_TLS_ENABLED"), port)
	if err != nil {
		log.Fatalf("invalid panel settings: %v", err)
	}
	port = panelSettings.ListenPort
	if marker := panelPortMarkerPath(dbPath); marker != "" {
		if err := writePrivateFileAtomic(marker, []byte(strconv.Itoa(port)+"\n")); err != nil {
			log.Fatalf("write panel port marker: %v", err)
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
	panelHost := panelSettings.PanelDomain
	routeDomain := panelSettings.RouteDomain
	panelCertificates := newPanelCertificateManager(dbPath, nil)
	if disabled, err := disableExpiredPanelTLSIfNeeded(db, panelCertificates); err != nil {
		log.Fatalf("check panel TLS certificate: %v", err)
	} else if disabled {
		panelSettings, err = db.PanelSettings()
		if err != nil {
			log.Fatalf("reload panel settings after HTTPS fallback: %v", err)
		}
	}
	panelTLSConfig, panelTLSEnabled, err := panelCertificates.tlsConfig(panelSettings.TLSEnabled)
	if err != nil {
		log.Fatalf("invalid panel TLS configuration: %v", err)
	}
	if !panelTLSEnabled && panelBindIP != nil && !panelBindIP.IsLoopback() {
		if !envBool("ALLOW_INSECURE_HTTP") {
			log.Fatalf("refusing to expose the management panel over plain HTTP on %s; set ALLOW_INSECURE_HTTP=true only for a deliberate temporary compatibility deployment, or bind PANEL_BIND_ADDR=127.0.0.1 behind an HTTPS reverse proxy", panelBindIP.String())
		}
		log.Printf("SECURITY WARNING: ALLOW_INSECURE_HTTP is enabled; panel sessions are exposed over plain HTTP on %s", panelBindIP.String())
	}
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
	clientIPRegions, err := newClientIPRegionResolver(os.Getenv("CLIENT_IP_REGION_ENDPOINT"), nil)
	if err != nil {
		log.Fatalf("invalid client IP region configuration: %v", err)
	}
	pm := NewProxyManager(db, upstreamHeaderKey)
	if panelTLSEnabled {
		pm.SetSiteTLSConfig(panelTLSConfig)
	}
	assetCacheDir := strings.TrimSpace(os.Getenv("ASSET_CACHE_DIR"))
	if assetCacheDir == "" && dbPath != ":memory:" && !strings.HasPrefix(dbPath, "file:") {
		assetCacheDir = filepath.Join(filepath.Dir(dbPath), "asset-cache")
	}
	pm.SetAssetCache(newAssetCache(assetCacheDir))
	pm.SetTrustedProxies(trustedProxies)
	pm.SetHostOnlyIngressSafe(panelTLSEnabled || (panelBindIP != nil && panelBindIP.IsLoopback()) || len(trustedProxies) > 0)
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
	go runTelegramReportScheduler(ctx, db)

	if panelHost != "" {
		if _, configured := pm.PublicHostHandler(panelHost); configured {
			log.Fatalf("PANEL_DOMAIN %s conflicts with a site's public_host", panelHost)
		}
	}
	app := &App{
		db:                db,
		dbPath:            dbPath,
		pm:                pm,
		setupToken:        setupToken,
		loginLimiter:      newLoginRateLimiter(),
		trustedProxies:    trustedProxies,
		clientIPRegions:   clientIPRegions,
		panelHost:         panelHost,
		routeDomain:       routeDomain,
		panelTLSEnabled:   panelTLSEnabled,
		panelCertificates: panelCertificates,
		panelBindLoopback: panelBindIP != nil && panelBindIP.IsLoopback(),
		panelListenPort:   port,
		dynamicRouteKey:   dynamicRouteKey,
		restartCh:         make(chan struct{}),
	}
	go runPanelCertificateRenewalScheduler(ctx, db, panelCertificates, app.requestRestart)

	mux := http.NewServeMux()

	// Public auth routes
	mux.HandleFunc("/api/auth/setup", cors(app.csrfMiddleware(app.handleSetup)))
	mux.HandleFunc("/api/auth/login", cors(app.csrfMiddleware(app.handleLogin)))
	mux.HandleFunc("/api/auth/logout", cors(app.csrfMiddleware(app.handleLogout)))
	mux.HandleFunc("/api/auth/check", cors(app.handleAuthCheck))

	// Protected routes
	mux.HandleFunc("/api/account", cors(app.authMiddleware(app.handleAccount)))
	mux.HandleFunc("/api/dashboard", cors(app.authMiddleware(app.handleDashboard)))
	mux.HandleFunc("/api/dashboard-insights", cors(app.authMiddleware(app.handleDashboardInsights)))
	mux.HandleFunc("/api/dashboard-trends", cors(app.authMiddleware(app.handleDashboardTrends)))
	mux.HandleFunc("/api/system-settings", cors(app.authMiddleware(app.handleSystemSettings)))
	mux.HandleFunc("/api/ingress-capabilities", cors(app.authMiddleware(app.handleIngressCapabilities)))
	mux.HandleFunc("/api/panel-certificate", cors(app.authMiddleware(app.handlePanelCertificate)))
	mux.HandleFunc("/api/panel-settings", cors(app.authMiddleware(app.handlePanelSettings)))
	mux.HandleFunc("/api/panel-certificate/issue", cors(app.authMiddleware(app.handlePanelCertificateIssue)))
	mux.HandleFunc("/api/system/restart", cors(app.authMiddleware(app.handleSystemRestart)))
	mux.HandleFunc("/api/backup/export", cors(app.authMiddleware(app.handleBackupExport)))
	mux.HandleFunc("/api/backup/restore", cors(app.authMiddleware(app.handleBackupRestore)))
	mux.HandleFunc("/api/sites", cors(app.authMiddleware(app.handleSites)))
	mux.HandleFunc("/api/sites/reorder", cors(app.authMiddleware(app.handleSiteReorder)))
	mux.HandleFunc("/api/sites/", cors(app.authMiddleware(app.handleSiteByID)))
	mux.HandleFunc("/api/upstream-test", cors(app.authMiddleware(app.handleUpstreamTest)))
	mux.HandleFunc("/api/traffic/", cors(app.authMiddleware(app.handleTraffic)))
	mux.HandleFunc("/api/asset-cache", cors(app.authMiddleware(app.handleAssetCache)))
	mux.HandleFunc("/api/request-logs", cors(app.authMiddleware(app.handleRequestLogs)))
	mux.HandleFunc("/api/telegram-report", cors(app.authMiddleware(app.handleTelegramReport)))
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

	// HTTP/HTTPS server with graceful shutdown. Site listeners remain independently
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
	panelListeners, listenerFailures, err := listenPanel(os.Getenv("PANEL_BIND_ADDR"), port)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	for _, failure := range listenerFailures {
		log.Printf("panel %s listener unavailable on %s: %v", failure.spec.network, failure.spec.address, failure.err)
	}
	if panelTLSEnabled {
		for i, listener := range panelListeners {
			panelListeners[i] = tls.NewListener(listener, panelTLSConfig)
		}
	}
	// Keep the rollback marker until the restored database, TLS configuration,
	// proxy sites, and panel listener have all initialized successfully. A fatal
	// startup before this point leaves the marker for the next process to roll
	// back automatically.
	if restoreState != nil {
		if err := finalizeAppliedRestore(dbPath); err != nil {
			for _, listener := range panelListeners {
				_ = listener.Close()
			}
			log.Fatalf("finalize restored data: %v", err)
		}
	}

	log.Println("============================================================")
	log.Printf("  Meridian - Emby reverse proxy management panel %s", appVersion)
	panelScheme := "http"
	if panelTLSEnabled {
		panelScheme = "https"
	}
	for _, listener := range panelListeners {
		log.Printf("  Listening on: %s://%s", panelScheme, listener.Addr())
	}
	if routeDomain != "" {
		log.Printf("  Domain-prefix ingress: *.%s", routeDomain)
	}
	log.Printf("  Sites loaded: %d (%d running)", loadedSiteCount, pm.GetRunningCount())
	log.Println("  Features: WebSocket proxy, structured backend discovery, TLS diagnostics, traffic limits")
	log.Println("============================================================")

	// Signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	serveErrors := make(chan error, len(panelListeners))
	for _, listener := range panelListeners {
		go func(listener net.Listener) {
			if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
				serveErrors <- err
			}
		}(listener)
	}

	restartRequested := false
	select {
	case <-sigCh:
		log.Println("\nReceived shutdown signal, stopping Meridian...")
	case <-app.restartCh:
		restartRequested = true
		log.Println("\nPanel restart requested, stopping Meridian...")
	case err := <-serveErrors:
		log.Fatalf("server failed: %v", err)
	}

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
	if restartRequested {
		db.Close()
		os.Exit(75)
	}
}
