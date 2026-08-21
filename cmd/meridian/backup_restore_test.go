package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestValidateEphemeralRestoreCredentials(t *testing.T) {
	original := jwtSecretEphemeral
	t.Cleanup(func() { jwtSecretEphemeral = original })
	jwtSecretEphemeral = true
	if err := validateEphemeralRestoreCredentials(false, nil); err != nil {
		t.Fatalf("empty ephemeral restore rejected: %v", err)
	}
	if err := validateEphemeralRestoreCredentials(true, nil); err == nil {
		t.Fatal("backup credentials were accepted with an ephemeral JWT secret")
	}
	if err := validateEphemeralRestoreCredentials(false, &backupPanelSettings{ACMETokenCiphertext: "ciphertext"}); err == nil {
		t.Fatal("preserved ACME credentials were accepted with an ephemeral JWT secret")
	}
	jwtSecretEphemeral = false
	if err := validateEphemeralRestoreCredentials(true, &backupPanelSettings{ACMETokenCiphertext: "ciphertext"}); err != nil {
		t.Fatalf("stable restore rejected: %v", err)
	}
}
func TestBackupEncryptionRejectsWrongPasswordAndTampering(t *testing.T) {
	plain := []byte("private meridian backup")
	sealed, err := sealBackup(plain, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openBackup(sealed, "correct horse battery staple")
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatalf("round trip = %q, %v", opened, err)
	}
	if _, err := openBackup(sealed, "wrong password long enough"); err == nil {
		t.Fatal("wrong password was accepted")
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	if _, err := openBackup(tampered, "correct horse battery staple"); err == nil {
		t.Fatal("tampered backup was accepted")
	}
}

func testBackupArchive(t *testing.T, manifest backupManifest, files map[string][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	w := zip.NewWriter(&buffer)
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	all := map[string][]byte{backupManifestEntry: manifestData}
	for name, data := range files {
		all[name] = data
	}
	for name, data := range all {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestParseBackupArchiveRejectsUnknownAndTraversalEntries(t *testing.T) {
	base := backupManifest{Format: "meridian-backup", FormatVersion: 1, Files: []string{backupDatabaseEntry}}
	for _, name := range []string{"../meridian.db", "secrets.env"} {
		manifest := base
		manifest.Files = []string{backupDatabaseEntry, name}
		archive := testBackupArchive(t, manifest, map[string][]byte{backupDatabaseEntry: []byte("db"), name: []byte("bad")})
		if _, _, err := parseBackupArchive(archive); err == nil {
			t.Fatalf("entry %q was accepted", name)
		}
	}
}

func TestParseBackupArchiveEnforcesTLSManifestScope(t *testing.T) {
	withoutTLS := false
	manifest := backupManifest{
		Format:        "meridian-backup",
		FormatVersion: backupFormatVersion,
		Files:         []string{backupDatabaseEntry, backupTLSCertificate},
		IncludeTLS:    &withoutTLS,
	}
	archive := testBackupArchive(t, manifest, map[string][]byte{
		backupDatabaseEntry:  []byte("db"),
		backupTLSCertificate: []byte("certificate"),
	})
	if _, _, err := parseBackupArchive(archive); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("TLS data outside the declared scope was accepted: %v", err)
	}

	// Backups from before include_tls was introduced always included TLS.
	manifest.IncludeTLS = nil
	archive = testBackupArchive(t, manifest, map[string][]byte{
		backupDatabaseEntry:  []byte("db"),
		backupTLSCertificate: []byte("certificate"),
	})
	parsed, _, err := parseBackupArchive(archive)
	if err != nil || !manifestIncludesTLS(parsed) {
		t.Fatalf("legacy TLS backup rejected: include=%v err=%v", manifestIncludesTLS(parsed), err)
	}
}

func TestBuildBackupIncludesTLSOnlyWhenSelected(t *testing.T) {
	t.Setenv("PANEL_TLS_CERT_FILE", "")
	t.Setenv("PANEL_TLS_KEY_FILE", "")
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "meridian.db")
	db, err := openDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.db.Exec(`INSERT INTO users (username, password_hash) VALUES ('admin', 'hash')`); err != nil {
		t.Fatal(err)
	}
	tlsDir := filepath.Join(dir, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"fullchain.pem":    "certificate",
		"privkey.pem":      "private key",
		"enabled":          "true\n",
		"acme-account.pem": "account",
	} {
		if err := os.WriteFile(filepath.Join(tlsDir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	app := &App{db: db, dbPath: dbPath, pm: NewProxyManager(db, bytes.Repeat([]byte("h"), 32))}
	const password = "correct horse battery staple"

	withoutTLS, err := app.buildBackup(password, false)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := openBackup(withoutTLS, password)
	if err != nil {
		t.Fatal(err)
	}
	manifest, entries, err := parseBackupArchive(plain)
	if err != nil {
		t.Fatal(err)
	}
	if manifestIncludesTLS(manifest) {
		t.Fatal("backup unexpectedly declares TLS data")
	}
	for name := range entries {
		if strings.HasPrefix(name, "tls/") {
			t.Fatalf("backup unexpectedly contains %s", name)
		}
	}

	withTLS, err := app.buildBackup(password, true)
	if err != nil {
		t.Fatal(err)
	}
	plain, err = openBackup(withTLS, password)
	if err != nil {
		t.Fatal(err)
	}
	manifest, entries, err = parseBackupArchive(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !manifestIncludesTLS(manifest) {
		t.Fatal("selected TLS backup does not declare TLS data")
	}
	for _, name := range []string{backupTLSCertificate, backupTLSPrivateKey, backupTLSEnabled, backupACMEAccount} {
		if _, ok := entries[name]; !ok {
			t.Fatalf("selected TLS backup is missing %s", name)
		}
	}
}

func makeBackupDatabase(t *testing.T, path string, jwt, upstreamKey []byte) {
	t.Helper()
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	targetURL := "https://emby.example.com"
	authority := "https://emby.example.com"
	ciphertext, err := encryptUpstreamHeaderValue("X-Test-Key", "secret-value", authority, upstreamKey)
	if err != nil {
		t.Fatal(err)
	}
	if value, decryptErr := decryptUpstreamHeaderValue("X-Test-Key", ciphertext, authority, upstreamKey); decryptErr != nil || value != "secret-value" {
		t.Fatalf("fixture header encryption failed: %q, %v", value, decryptErr)
	}
	raw, _ := json.Marshal([]storedUpstreamHeader{{Name: "X-Test-Key", Ciphertext: ciphertext}})
	if _, err := db.db.Exec(`INSERT INTO sites (name, listen_port, target_url, upstream_headers) VALUES ('test', 19001, ?, ?)`, targetURL, string(raw)); err != nil {
		db.Close()
		t.Fatal(err)
	}
	token, err := encryptTelegramBotTokenWithSecret("123456:test-token", jwt)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`UPDATE telegram_report_settings SET bot_token_ciphertext=?, chat_id='123' WHERE id=1`, token); err != nil {
		db.Close()
		t.Fatal(err)
	}
	acmeToken, err := encryptPanelACMETokenWithSecret("cloudflare-backup-token-value", jwt)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`UPDATE panel_settings SET acme_email='admin@example.com', acme_dns_provider='cloudflare', acme_token_ciphertext=?, acme_staging=1 WHERE id=1`, acmeToken); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`INSERT INTO users (username, password_hash) VALUES ('admin', 'hash')`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
}

func TestReencryptRestoredSecrets(t *testing.T) {
	oldJWT := bytes.Repeat([]byte("j"), 32)
	newJWT := bytes.Repeat([]byte("n"), 32)
	oldHeader := sha256.Sum256([]byte("old-upstream-header-key-material"))
	newHeader := sha256.Sum256([]byte("new-upstream-header-key-material"))
	path := filepath.Join(t.TempDir(), "backup.db")
	makeBackupDatabase(t, path, oldJWT, oldHeader[:])
	before, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var beforeRaw string
	if err := before.QueryRow("SELECT upstream_headers FROM sites WHERE name='test'").Scan(&beforeRaw); err != nil {
		before.Close()
		t.Fatal(err)
	}
	before.Close()
	beforeStored, err := parseStoredUpstreamHeaders(beforeRaw)
	if err != nil {
		t.Fatal(err)
	}
	if value, decryptErr := decryptUpstreamHeaderValue(beforeStored[0].Name, beforeStored[0].Ciphertext, "https://emby.example.com", oldHeader[:]); decryptErr != nil || value != "secret-value" {
		t.Fatalf("stored fixture header failed: %q, %v (%s)", value, decryptErr, beforeRaw)
	}
	if err := reencryptRestoredSecrets(path, oldJWT, oldJWT, oldHeader[:], newJWT, newJWT, newHeader[:]); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw string
	if err := db.QueryRow("SELECT upstream_headers FROM sites WHERE name='test'").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	stored, err := parseStoredUpstreamHeaders(raw)
	if err != nil {
		t.Fatal(err)
	}
	value, err := decryptUpstreamHeaderValue(stored[0].Name, stored[0].Ciphertext, "https://emby.example.com", newHeader[:])
	if err != nil || value != "secret-value" {
		t.Fatalf("header = %q, %v", value, err)
	}
	if _, err := decryptUpstreamHeaderValue(stored[0].Name, stored[0].Ciphertext, "https://emby.example.com", oldHeader[:]); err == nil {
		t.Fatal("old upstream key still decrypts migrated header")
	}
	var telegramCiphertext string
	if err := db.QueryRow("SELECT bot_token_ciphertext FROM telegram_report_settings WHERE id=1").Scan(&telegramCiphertext); err != nil {
		t.Fatal(err)
	}
	value, err = decryptTelegramBotTokenWithSecret(telegramCiphertext, newJWT)
	if err != nil || value != "123456:test-token" {
		t.Fatalf("telegram token = %q, %v", value, err)
	}
	var acmeCiphertext string
	if err := db.QueryRow("SELECT acme_token_ciphertext FROM panel_settings WHERE id=1").Scan(&acmeCiphertext); err != nil {
		t.Fatal(err)
	}
	value, err = decryptPanelACMETokenWithSecret(acmeCiphertext, newJWT)
	if err != nil || value != "cloudflare-backup-token-value" {
		t.Fatalf("ACME token = %q, %v", value, err)
	}
	if _, err := decryptPanelACMETokenWithSecret(acmeCiphertext, oldJWT); err == nil {
		t.Fatal("old JWT secret still decrypts migrated ACME token")
	}
}

func TestReencryptRestoredSecretsWithDedicatedCredentialKey(t *testing.T) {
	oldJWT := bytes.Repeat([]byte("j"), 32)
	oldCredential := bytes.Repeat([]byte("c"), 32)
	newJWT := bytes.Repeat([]byte("n"), 32)
	newCredential := bytes.Repeat([]byte("d"), 32)
	oldHeader := sha256.Sum256([]byte("old-dedicated-header-key-material"))
	newHeader := sha256.Sum256([]byte("new-dedicated-header-key-material"))
	path := filepath.Join(t.TempDir(), "backup.db")
	makeBackupDatabase(t, path, oldJWT, oldHeader[:])

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var telegramCiphertext, acmeCiphertext string
	if err := db.QueryRow("SELECT bot_token_ciphertext FROM telegram_report_settings WHERE id=1").Scan(&telegramCiphertext); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT acme_token_ciphertext FROM panel_settings WHERE id=1").Scan(&acmeCiphertext); err != nil {
		db.Close()
		t.Fatal(err)
	}
	telegramToken, err := decryptTelegramBotTokenWithSecret(telegramCiphertext, oldJWT)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	telegramCiphertext, err = encryptTelegramBotTokenWithSecret(telegramToken, oldCredential)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	acmeToken, err := decryptPanelACMETokenWithSecret(acmeCiphertext, oldJWT)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	acmeCiphertext, err = encryptPanelACMETokenWithSecret(acmeToken, oldCredential)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE telegram_report_settings SET bot_token_ciphertext=? WHERE id=1", telegramCiphertext); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE panel_settings SET acme_token_ciphertext=? WHERE id=1", acmeCiphertext); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if err := reencryptRestoredSecrets(path, oldJWT, oldCredential, oldHeader[:], newJWT, newCredential, newHeader[:]); err != nil {
		t.Fatal(err)
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.QueryRow("SELECT bot_token_ciphertext FROM telegram_report_settings WHERE id=1").Scan(&telegramCiphertext); err != nil {
		t.Fatal(err)
	}
	if value, err := decryptTelegramBotTokenWithSecret(telegramCiphertext, newCredential); err != nil || value != "123456:test-token" {
		t.Fatalf("Telegram token = %q, %v", value, err)
	}
	if err := db.QueryRow("SELECT acme_token_ciphertext FROM panel_settings WHERE id=1").Scan(&acmeCiphertext); err != nil {
		t.Fatal(err)
	}
	if value, err := decryptPanelACMETokenWithSecret(acmeCiphertext, newCredential); err != nil || value != "cloudflare-backup-token-value" {
		t.Fatalf("ACME token = %q, %v", value, err)
	}
}
func TestApplyPendingRestoreAndRollback(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "meridian.db")
	if err := os.WriteFile(dbPath, []byte("old database"), 0o600); err != nil {
		t.Fatal(err)
	}
	tlsDir := filepath.Join(dir, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tlsDir, "fullchain.pem"), []byte("old cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	pending := dbPath + backupPendingSuffix
	if err := os.MkdirAll(filepath.Join(pending, "tls"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pending, backupDatabaseEntry), []byte("new database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pending, filepath.FromSlash(backupTLSCertificate)), []byte("new cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker, _ := json.Marshal(restoreMarker{Files: []string{backupDatabaseEntry, backupTLSCertificate}})
	if err := os.WriteFile(filepath.Join(pending, "restore.json"), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := applyPendingRestore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(dbPath)
	if string(data) != "new database" {
		t.Fatalf("applied database = %q", data)
	}
	if err := rollbackAppliedRestore(dbPath, state); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(dbPath)
	if string(data) != "old database" {
		t.Fatalf("rolled back database = %q", data)
	}
	data, _ = os.ReadFile(filepath.Join(tlsDir, "fullchain.pem"))
	if string(data) != "old cert" {
		t.Fatalf("rolled back cert = %q", data)
	}
}

func TestRestoreWithoutTLSPreservesTargetSettingsAndFiles(t *testing.T) {
	t.Setenv("PANEL_TLS_CERT_FILE", "")
	t.Setenv("PANEL_TLS_KEY_FILE", "")
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.db")
	targetDB, err := openDB(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := targetDB.db.Exec(`UPDATE panel_settings SET panel_domain='target.example.com', route_domain='route.target.example.com', listen_port=9443, tls_enabled=1, configured=1 WHERE id=1`); err != nil {
		targetDB.Close()
		t.Fatal(err)
	}
	targetJWT := bytes.Repeat([]byte("n"), 32)
	targetACME, err := encryptPanelACMETokenWithSecret("target-cloudflare-token-value", targetJWT)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := targetDB.db.Exec(`UPDATE panel_settings SET acme_email='target@example.com', acme_dns_provider='cloudflare', acme_token_ciphertext=?, acme_staging=1 WHERE id=1`, targetACME); err != nil {
		t.Fatal(err)
	}
	preserved, err := readBackupPanelSettings(targetDB.db)
	if err != nil {
		targetDB.Close()
		t.Fatal(err)
	}
	targetDB.Close()

	tlsDir := filepath.Join(dir, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(tlsDir, "fullchain.pem")
	if err := os.WriteFile(certPath, []byte("target certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldJWT := bytes.Repeat([]byte("j"), 32)
	newJWT := targetJWT
	oldHeader := bytes.Repeat([]byte("h"), 32)
	newHeader := bytes.Repeat([]byte("k"), 32)
	backupPath := filepath.Join(dir, "backup.db")
	makeBackupDatabase(t, backupPath, oldJWT, oldHeader)
	backupDB, err := sql.Open("sqlite", backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backupDB.Exec(`UPDATE panel_settings SET panel_domain='source.example.com', route_domain='route.source.example.com', listen_port=8443, tls_enabled=0, configured=1 WHERE id=1`); err != nil {
		backupDB.Close()
		t.Fatal(err)
	}
	backupDB.Close()
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	includeTLS := false
	manifest := backupManifest{
		Format:            "meridian-backup",
		FormatVersion:     backupFormatVersion,
		Files:             []string{backupDatabaseEntry},
		IncludeTLS:        &includeTLS,
		JWTSecret:         base64.RawStdEncoding.EncodeToString(oldJWT),
		UpstreamHeaderKey: base64.RawStdEncoding.EncodeToString(oldHeader),
	}
	if _, err := writeRestorePending(targetPath, manifest, map[string][]byte{backupDatabaseEntry: backupData}, newJWT, newJWT, newHeader, preserved, false); err != nil {
		t.Fatal(err)
	}
	state, err := applyPendingRestore(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil {
		t.Fatal("restore was not applied")
	}
	restoredDB, err := sql.Open("sqlite", targetPath)
	if err != nil {
		t.Fatal(err)
	}
	var panelDomain, routeDomain, acmeEmail, acmeCiphertext string
	var listenPort, tlsEnabled, configured, acmeStaging int
	if err := restoredDB.QueryRow(`SELECT panel_domain, route_domain, listen_port, tls_enabled, configured, acme_email, acme_token_ciphertext, acme_staging FROM panel_settings WHERE id=1`).Scan(&panelDomain, &routeDomain, &listenPort, &tlsEnabled, &configured, &acmeEmail, &acmeCiphertext, &acmeStaging); err != nil {
		restoredDB.Close()
		t.Fatal(err)
	}
	restoredDB.Close()
	if panelDomain != preserved.PanelDomain || routeDomain != preserved.RouteDomain || listenPort != preserved.ListenPort || tlsEnabled != preserved.TLSEnabled || configured != preserved.Configured {
		t.Fatalf("target panel settings were not preserved: %q %q %d %d %d", panelDomain, routeDomain, listenPort, tlsEnabled, configured)
	}
	if acmeEmail != "target@example.com" || acmeStaging != 1 {
		t.Fatalf("target ACME settings were not preserved: email=%q staging=%d", acmeEmail, acmeStaging)
	}
	if value, err := decryptPanelACMETokenWithSecret(acmeCiphertext, newJWT); err != nil || value != "target-cloudflare-token-value" {
		t.Fatalf("target ACME token was not preserved: %q %v", value, err)
	}
	cert, err := os.ReadFile(certPath)
	if err != nil || string(cert) != "target certificate" {
		t.Fatalf("target certificate changed after restore: %q %v", cert, err)
	}
	if err := rollbackAppliedRestore(targetPath, state); err != nil {
		t.Fatal(err)
	}
	cert, err = os.ReadFile(certPath)
	if err != nil || string(cert) != "target certificate" {
		t.Fatalf("target certificate changed after rollback: %q %v", cert, err)
	}
}

func addBackupIngressSites(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows := []struct {
		name       string
		port       int
		publicHost string
		pathPrefix string
		mode       string
	}{
		{"shared-host", 18001, "host.source.example.com", "", ingressModeHost},
		{"shared-both", 18002, "both.source.example.com", "", ingressModeBoth},
		{"dedicated-port", 18003, "", "", ingressModePort},
		{"shared-path", 18004, "", "/emby", ingressModePath},
	}
	for _, row := range rows {
		if _, err := db.Exec(`INSERT INTO sites (name, listen_port, public_host, path_prefix, ingress_mode, target_url, stream_hosts, ua_mode, enabled) VALUES (?, ?, ?, ?, ?, 'https://origin.example.com', '[]', 'passthrough', 1)`, row.name, row.port, row.publicHost, row.pathPrefix, row.mode); err != nil {
			t.Fatal(err)
		}
	}
}

func restoreIngressFixture(t *testing.T, targetHostIngressWithoutTLS bool, targetSettings backupPanelSettings) (string, int64) {
	t.Helper()
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.db")
	targetDB, err := openDB(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := targetDB.db.Exec(`UPDATE panel_settings SET panel_domain=?, route_domain=?, listen_port=?, tls_enabled=?, configured=? WHERE id=1`, targetSettings.PanelDomain, targetSettings.RouteDomain, targetSettings.ListenPort, targetSettings.TLSEnabled, targetSettings.Configured); err != nil {
		targetDB.Close()
		t.Fatal(err)
	}
	preserved, err := readBackupPanelSettings(targetDB.db)
	if err != nil {
		targetDB.Close()
		t.Fatal(err)
	}
	targetDB.Close()

	oldJWT := bytes.Repeat([]byte("j"), 32)
	newJWT := bytes.Repeat([]byte("n"), 32)
	oldHeader := bytes.Repeat([]byte("h"), 32)
	newHeader := bytes.Repeat([]byte("k"), 32)
	backupPath := filepath.Join(dir, "backup.db")
	makeBackupDatabase(t, backupPath, oldJWT, oldHeader)
	addBackupIngressSites(t, backupPath)
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	includeTLS := false
	manifest := backupManifest{
		Format:            "meridian-backup",
		FormatVersion:     backupFormatVersion,
		Files:             []string{backupDatabaseEntry},
		IncludeTLS:        &includeTLS,
		JWTSecret:         base64.RawStdEncoding.EncodeToString(oldJWT),
		UpstreamHeaderKey: base64.RawStdEncoding.EncodeToString(oldHeader),
	}
	resetCount, err := writeRestorePending(targetPath, manifest, map[string][]byte{backupDatabaseEntry: backupData}, newJWT, newJWT, newHeader, preserved, targetHostIngressWithoutTLS)
	if err != nil {
		t.Fatal(err)
	}
	state, err := applyPendingRestore(targetPath)
	if err != nil || state == nil {
		t.Fatalf("apply restore state=%#v err=%v", state, err)
	}
	return targetPath, resetCount
}

func TestRestoreClearsUnsupportedIngressAndKeepsSites(t *testing.T) {
	path, resetCount := restoreIngressFixture(t, false, backupPanelSettings{ListenPort: 9090})
	if resetCount != 2 {
		t.Fatalf("reset ingress count=%d, want 2", resetCount)
	}
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sites, err := db.ListSites()
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 5 { // makeBackupDatabase adds one dedicated-port fixture.
		t.Fatalf("restored sites=%d, want 5", len(sites))
	}
	for _, site := range sites {
		switch site.Name {
		case "shared-host", "shared-both":
			if site.IngressMode != ingressModeUnset || site.PublicHost != "" || site.Enabled {
				t.Fatalf("unsupported site %q ingress=%q host=%q enabled=%v", site.Name, site.IngressMode, site.PublicHost, site.Enabled)
			}
		case "dedicated-port":
			if site.IngressMode != ingressModePort || !site.Enabled {
				t.Fatalf("supported port site ingress=%q enabled=%v", site.IngressMode, site.Enabled)
			}
		case "shared-path":
			if site.IngressMode != ingressModePath || site.PathPrefix != "/emby" || !site.Enabled {
				t.Fatalf("supported path site ingress=%q path=%q enabled=%v", site.IngressMode, site.PathPrefix, site.Enabled)
			}
		}
	}
}

func TestRestorePreservesSupportedHostIngress(t *testing.T) {
	path, resetCount := restoreIngressFixture(t, true, backupPanelSettings{RouteDomain: "target.example.com", ListenPort: 9090, Configured: 1})
	if resetCount != 0 {
		t.Fatalf("reset ingress count=%d, want 0", resetCount)
	}
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sites, err := db.ListSites()
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range sites {
		if site.Name == "shared-host" && (site.IngressMode != ingressModeHost || site.PublicHost == "" || !site.Enabled) {
			t.Fatalf("supported host site changed: %#v", site)
		}
		if site.Name == "shared-both" && (site.IngressMode != ingressModeBoth || site.PublicHost == "" || !site.Enabled) {
			t.Fatalf("supported both site changed: %#v", site)
		}
	}
}

func TestInterruptedRestoreRollsBackAndDiscardsIncompleteStage(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "meridian.db")
	rollback := dbPath + backupRollbackSuffix
	pending := dbPath + backupPendingSuffix
	if err := os.MkdirAll(rollback, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pending, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, []byte("partial restored database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rollback, backupDatabaseEntry), []byte("original database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath+backupAppliedSuffix, []byte("pending validation\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := applyPendingRestore(dbPath)
	if err != nil || state != nil {
		t.Fatalf("apply interrupted restore = %#v, %v", state, err)
	}
	data, err := os.ReadFile(dbPath)
	if err != nil || string(data) != "original database" {
		t.Fatalf("database after automatic rollback = %q, %v", data, err)
	}
	if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("incomplete stage still exists: %v", err)
	}
}

func TestWriteRestorePendingRejectsCorruptSQLite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "target.db")
	manifest := backupManifest{
		Format:            "meridian-backup",
		FormatVersion:     1,
		Files:             []string{backupDatabaseEntry},
		JWTSecret:         base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte("j"), 32)),
		UpstreamHeaderKey: base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte("h"), 32)),
	}
	_, err := writeRestorePending(dbPath, manifest, map[string][]byte{backupDatabaseEntry: []byte("not sqlite")}, bytes.Repeat([]byte("n"), 32), bytes.Repeat([]byte("n"), 32), bytes.Repeat([]byte("k"), 32), nil, false)
	if err == nil || !strings.Contains(err.Error(), "SQLite") && !strings.Contains(strings.ToLower(err.Error()), "database") {
		t.Fatalf("corrupt database error = %v", err)
	}
}
