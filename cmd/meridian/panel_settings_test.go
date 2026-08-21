package main

import (
	"path/filepath"
	"testing"
)

func TestNormalizeManagedPanelSettings(t *testing.T) {
	settings, err := normalizeManagedPanelSettings("Panel.Example.com.", "Example.com.")
	if err != nil {
		t.Fatalf("normalize managed settings: %v", err)
	}
	if settings.PanelDomain != "panel.example.com" || settings.RouteDomain != "example.com" || !settings.TLSEnabled {
		t.Fatalf("unexpected settings: %+v", settings)
	}
	for _, tc := range [][2]string{
		{"example.com", "example.com"},
		{"a.b.example.com", "example.com"},
		{"panel.example.com", ""},
	} {
		if _, err := normalizeManagedPanelSettings(tc[0], tc[1]); err == nil {
			t.Fatalf("normalizeManagedPanelSettings(%q, %q) unexpectedly succeeded", tc[0], tc[1])
		}
	}
}

func TestNormalizeManagedPanelPrefixAcceptsWildcardForm(t *testing.T) {
	settings, err := normalizeManagedPanelPrefix("panel", "*.example.com")
	if err != nil {
		t.Fatalf("normalize panel prefix: %v", err)
	}
	if settings.PanelDomain != "panel.example.com" || settings.RouteDomain != "example.com" {
		t.Fatalf("unexpected normalized wildcard settings: %+v", settings)
	}
	if got := wildcardDomainForSettings(settings); got != "*.example.com" {
		t.Fatalf("wildcard domain = %q", got)
	}
}

func TestBootstrapPanelSettingsImportsEnvironmentOnlyOnce(t *testing.T) {
	db, err := openDB(":memory:")
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()
	first, err := db.BootstrapPanelSettings("panel.example.com", "example.com", false, 9090)
	if err != nil {
		t.Fatalf("bootstrap settings: %v", err)
	}
	second, err := db.BootstrapPanelSettings("other.example.net", "example.net", true, 8080)
	if err != nil {
		t.Fatalf("second bootstrap settings: %v", err)
	}
	if first != second || second.PanelDomain != "panel.example.com" || second.RouteDomain != "example.com" || second.TLSEnabled {
		t.Fatalf("environment settings were not imported once: first=%+v second=%+v", first, second)
	}
}

func TestBootstrapPanelSettingsInitializesPortWithoutDomains(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "panel-settings-port.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	first, err := db.BootstrapPanelSettings("", "", false, 9090)
	if err != nil {
		t.Fatalf("bootstrap empty settings: %v", err)
	}
	if first.Configured || first.PanelDomain != "" || first.RouteDomain != "" || first.TLSEnabled {
		t.Fatalf("empty bootstrap unexpectedly configured domains or TLS: %#v", first)
	}
	if first.ListenPort != 9090 {
		t.Fatalf("empty bootstrap listen_port=%d, want 9090", first.ListenPort)
	}

	persisted, err := db.PanelSettings()
	if err != nil {
		t.Fatalf("read persisted settings: %v", err)
	}
	if persisted.ListenPort != 9090 || persisted.Configured {
		t.Fatalf("persisted empty bootstrap=%#v, want port-only initialization", persisted)
	}

	second, err := db.BootstrapPanelSettings("", "", false, 8080)
	if err != nil {
		t.Fatalf("second empty bootstrap: %v", err)
	}
	if second.ListenPort != 9090 {
		t.Fatalf("second empty bootstrap overwrote listen_port=%d, want 9090", second.ListenPort)
	}
}

func TestSaveManagedPanelSettingsMigratesPrefixHosts(t *testing.T) {
	db, err := openDB(":memory:")
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()
	if _, err := db.db.Exec(`INSERT INTO sites (name, listen_port, public_host, target_url) VALUES (?, ?, ?, ?)`, "One", 19001, "one.old.example.com", "http://127.0.0.1:8096"); err != nil {
		t.Fatalf("insert site: %v", err)
	}
	if _, err := db.BootstrapPanelSettings("panel.old.example.com", "old.example.com", false, 9090); err != nil {
		t.Fatalf("bootstrap old settings: %v", err)
	}
	settings, migrated, err := db.SaveManagedPanelSettings("panel.example.com", "example.com", 9090, false)
	if err != nil {
		t.Fatalf("save managed settings: %v", err)
	}
	if migrated != 1 || settings.PanelDomain != "panel.example.com" {
		t.Fatalf("unexpected migration result: settings=%+v migrated=%d", settings, migrated)
	}
	var host string
	if err := db.db.QueryRow("SELECT public_host FROM sites WHERE name=?", "One").Scan(&host); err != nil {
		t.Fatalf("read migrated site: %v", err)
	}
	if host != "one.example.com" {
		t.Fatalf("migrated site host = %q, want one.example.com", host)
	}
}

func TestSaveManagedPanelSettingsPreservesACMECredentials(t *testing.T) {
	db, err := openDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.SavePanelACMECredentials("admin@example.com", "cloudflare", "v1:ciphertext", true); err != nil {
		t.Fatal(err)
	}
	settings, _, err := db.SaveManagedPanelSettings("panel.example.com", "example.com", 9443, true)
	if err != nil {
		t.Fatal(err)
	}
	if settings.ACMEEmail != "admin@example.com" || settings.ACMEDNSProvider != "cloudflare" || settings.ACMETokenCiphertext != "v1:ciphertext" || !settings.ACMEStaging {
		t.Fatalf("ACME credentials changed while saving panel settings: %+v", settings)
	}
}
