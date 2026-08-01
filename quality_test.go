package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestValidateSiteSettingsBoundsSpeedLimit(t *testing.T) {
	settings := func(speedLimit int) error {
		return validateSiteSettings("site", 19091, "http://127.0.0.1:8096", "", "direct",
			nil, "infuse", "", "", "", 0, speedLimit)
	}
	if err := settings(maxSpeedLimitMbps); err != nil {
		t.Fatalf("speed_limit %d must be accepted: %v", maxSpeedLimitMbps, err)
	}
	err := settings(maxSpeedLimitMbps + 1)
	if err == nil {
		t.Fatal("speed_limit above the cap must be rejected")
	}
	if !strings.Contains(err.Error(), "speed_limit") {
		t.Fatalf("error = %q, want it to name speed_limit", err)
	}
	// Kept within int32 so the test compiles on 32-bit targets too.
	if err := settings(1 << 30); err == nil {
		t.Fatal("an absurd speed_limit must be rejected before the bytes/sec conversion")
	}
}

func TestProbeClientReusesConnectionsWithAnIdleTimeout(t *testing.T) {
	transport, ok := probeClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("probe transport = %T, want *http.Transport", probeClient.Transport)
	}
	// A zero IdleConnTimeout is what stranded sockets: idle keep-alive
	// connections would never expire and nothing closed them.
	if transport.IdleConnTimeout == 0 {
		t.Fatal("probe transport must set IdleConnTimeout so idle connections expire")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion == 0 {
		t.Fatal("probe transport must keep the hardened TLS config")
	}
	if probeClient.Timeout == 0 {
		t.Fatal("probe client must keep its request timeout")
	}
}

func TestStartSiteFlushesTrafficWhenReplacingRunningInstance(t *testing.T) {
	// Changing a running site's listen_port is the one update path that does not
	// pre-stop, so StartSite has to flush the instance it displaces.
	app := newTestApp(t)
	site, err := app.db.CreateSite("replace", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	releasePort(site.ListenPort)
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("StartSite: %v", err)
	}
	t.Cleanup(func() { app.pm.StopSite(site.ID) })

	app.pm.mu.RLock()
	inst := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if inst == nil {
		t.Fatal("site did not register a proxy instance")
	}
	// Traffic accumulated since the last flush tick.
	inst.bytesIn.Store(700)
	inst.bytesOut.Store(300)

	moved, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	moved.ListenPort = freePort(t)
	releasePort(moved.ListenPort)
	if err := app.pm.StartSite(*moved); err != nil {
		t.Fatalf("StartSite on the new port: %v", err)
	}

	after, err := app.db.GetSite(site.ID)
	if err != nil {
		t.Fatalf("GetSite after replace: %v", err)
	}
	if after.TrafficUsed != 1000 {
		t.Fatalf("traffic_used = %d, want the 1000 pending bytes persisted", after.TrafficUsed)
	}

	app.pm.mu.RLock()
	replacement := app.pm.proxies[site.ID]
	app.pm.mu.RUnlock()
	if replacement == nil {
		t.Fatal("replacement instance missing")
	}
	if got := replacement.persistedTraffic.Load(); got != 1000 {
		t.Fatalf("replacement baseline = %d, want 1000 so the quota gate stays accurate", got)
	}
}
