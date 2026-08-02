package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"meridian/web"
)

type UAProfile struct {
	Name      string `json:"name"`
	UserAgent string `json:"user_agent"`
	Client    string `json:"client"`
	Version   string `json:"version"`
}

var uaProfiles = map[string]UAProfile{
	"infuse": {Name: "Infuse", UserAgent: "Infuse/7.8.1", Client: "Infuse", Version: "7.8.1"},
	"web":    {Name: "Web", UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Emby Theater", Client: "Emby Web", Version: "4.9.0.42"},
	"client": {Name: "Client", UserAgent: "Emby-Theater/4.7.0", Client: "Emby Theater", Version: "4.7.0"},
}

const (
	customUAMode          = "custom"
	maxCustomUserAgentLen = 1024
	maxCustomClientLen    = 128
	maxCustomVersionLen   = 64
)

func getUAProfile(mode string) UAProfile {
	if p, ok := uaProfiles[strings.ToLower(mode)]; ok {
		return p
	}
	return uaProfiles["infuse"]
}

func validateCustomUAValue(field, value string, maxLen int, allowQuotes bool) error {
	if value == "" {
		return fmt.Errorf("custom %s is required", field)
	}
	if len(value) > maxLen {
		return fmt.Errorf("custom %s must be at most %d bytes", field, maxLen)
	}
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return fmt.Errorf("custom %s must contain printable ASCII characters only", field)
		}
		if !allowQuotes && (r == '"' || r == '\\') {
			return fmt.Errorf("custom %s must not contain quotes or backslashes", field)
		}
	}
	return nil
}

func normalizeUAConfig(mode, userAgent, client, version string) (string, string, string, string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != customUAMode {
		if _, ok := uaProfiles[mode]; !ok {
			return "", "", "", "", fmt.Errorf("unknown ua_mode")
		}
		return mode, "", "", "", nil
	}

	userAgent = strings.TrimSpace(userAgent)
	client = strings.TrimSpace(client)
	version = strings.TrimSpace(version)
	if err := validateCustomUAValue("user_agent", userAgent, maxCustomUserAgentLen, true); err != nil {
		return "", "", "", "", err
	}
	if err := validateCustomUAValue("client", client, maxCustomClientLen, false); err != nil {
		return "", "", "", "", err
	}
	if err := validateCustomUAValue("version", version, maxCustomVersionLen, false); err != nil {
		return "", "", "", "", err
	}
	return mode, userAgent, client, version, nil
}

func resolveSiteUAProfile(site Site) (UAProfile, error) {
	mode, userAgent, client, version, err := normalizeUAConfig(site.UAMode, site.CustomUserAgent, site.CustomClient, site.CustomVersion)
	if err != nil {
		return UAProfile{}, err
	}
	if mode == customUAMode {
		return UAProfile{Name: "Custom", UserAgent: userAgent, Client: client, Version: version}, nil
	}
	return uaProfiles[mode], nil
}

func mergeSiteUAConfig(old Site, requestedMode, requestedUserAgent, requestedClient, requestedVersion *string) (string, string, string, string, error) {
	hasCustomFields := requestedUserAgent != nil || requestedClient != nil || requestedVersion != nil
	if hasCustomFields && (requestedUserAgent == nil || requestedClient == nil || requestedVersion == nil) {
		return "", "", "", "", fmt.Errorf("custom User-Agent, Client, and Version must be provided together")
	}

	mode := old.UAMode
	userAgent := old.CustomUserAgent
	client := old.CustomClient
	version := old.CustomVersion
	if requestedMode != nil {
		mode = *requestedMode
	}
	if hasCustomFields {
		userAgent = *requestedUserAgent
		client = *requestedClient
		version = *requestedVersion
	}

	if requestedMode == nil && !hasCustomFields {
		return normalizeUAConfig(mode, userAgent, client, version)
	}

	normalizedMode := strings.ToLower(strings.TrimSpace(mode))
	if normalizedMode != customUAMode {
		if hasCustomFields && (strings.TrimSpace(userAgent) != "" || strings.TrimSpace(client) != "" || strings.TrimSpace(version) != "") {
			return "", "", "", "", fmt.Errorf("custom fields require ua_mode custom")
		}
		return normalizeUAConfig(normalizedMode, "", "", "")
	}
	if !hasCustomFields {
		return "", "", "", "", fmt.Errorf("custom ua_mode requires User-Agent, Client, and Version")
	}
	return normalizeUAConfig(normalizedMode, userAgent, client, version)
}

var jwtSecret []byte
var jwtSecretEphemeral bool

const (
	sessionCookieName = "meridian_session"
	sessionDuration   = 72 * time.Hour
)

func init() {
	var err error
	jwtSecret, jwtSecretEphemeral, err = resolveJWTSecret(os.Getenv("JWT_SECRET"))
	if err != nil {
		panic(err)
	}
}

func resolveJWTSecret(value string) ([]byte, bool, error) {
	if value != "" {
		if len(value) < 32 {
			return nil, false, fmt.Errorf("JWT_SECRET must be at least 32 bytes")
		}
		return []byte(value), false, nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, false, fmt.Errorf("generate JWT secret: %w", err)
	}
	return secret, true, nil
}

func generateToken(userID int64, username string) (string, error) {
	header := jwtHeaderEncoded
	payload, err := json.Marshal(struct {
		Sub  int64  `json:"sub"`
		Name string `json:"name"`
		Exp  int64  `json:"exp"`
	}{
		Sub:  userID,
		Name: username,
		Exp:  time.Now().Add(72 * time.Hour).Unix(),
	})
	if err != nil {
		return "", err
	}
	payloadEnc := base64url(payload)
	sig := hmacSHA256(header+"."+payloadEnc, jwtSecret)
	return header + "." + payloadEnc + "." + sig, nil
}

func validateToken(token string) (int64, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, "", fmt.Errorf("invalid token")
	}
	if parts[0] != jwtHeaderEncoded {
		return 0, "", fmt.Errorf("invalid token header")
	}
	expectedSig := hmacSHA256(parts[0]+"."+parts[1], jwtSecret)
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return 0, "", fmt.Errorf("invalid signature")
	}
	payload, err := base64urlDecode(parts[1])
	if err != nil {
		return 0, "", err
	}
	var claims struct {
		Sub  int64  `json:"sub"`
		Name string `json:"name"`
		Exp  int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, "", err
	}
	if time.Now().Unix() > claims.Exp {
		return 0, "", fmt.Errorf("token expired")
	}
	return claims.Sub, claims.Name, nil
}

var jwtHeaderEncoded = base64url([]byte(`{"alg":"HS256","typ":"JWT"}`))

func hmacSHA256(data string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return base64url(h.Sum(nil))
}

func base64url(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func base64urlDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func configuredSetupToken(userCount int, value string) (string, error) {
	if userCount > 0 {
		return "", nil
	}
	token := strings.TrimSpace(value)
	if token == "" {
		return "", errors.New("SETUP_TOKEN must be configured before creating the first administrator")
	}
	if len(token) < 32 {
		return "", errors.New("SETUP_TOKEN must be at least 32 bytes")
	}
	return token, nil
}

func setupTokenMatches(expected, provided string) bool {
	expectedHash := sha256.Sum256([]byte(expected))
	providedHash := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(expectedHash[:], providedHash[:]) == 1
}

type DB struct {
	db *sql.DB
}

func openDB(path string) (*DB, error) {
	setSecureFileCreationMask()
	sqlDB, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	d := &DB{db: sqlDB}
	if err := d.migrate(); err != nil {
		sqlDB.Close()
		return nil, err
	}
	if err := hardenDatabaseFilePermissions(path); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// warnUnenforcedFileModes keeps the platform warning to one line per process
// instead of one per openDB call.
var warnUnenforcedFileModes sync.Once

func hardenDatabaseFilePermissions(path string) error {
	if path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil
	}
	if !fileModesEnforced() {
		// Chmod would report success and change nothing, which is worse than not
		// trying: it would let the operator believe the database is protected.
		warnUnenforcedFileModes.Do(func() {
			log.Printf("This platform does not enforce POSIX file modes, so %s keeps whatever permissions it inherits from its directory. That file holds the administrator password hash and every configured upstream URL: restrict the directory yourself and do not leave it somewhere other local users can read.", path)
		})
		return nil
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		// #nosec G703 -- the database path is operator-controlled and never derived from a request.
		if err := os.Chmod(candidate, 0600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("secure database file %s: %w", candidate, err)
		}
	}
	return nil
}

func (d *DB) Close() { d.db.Close() }

const (
	migrationRetryDelay    = 25 * time.Millisecond
	migrationRetryDeadline = 5 * time.Second
)

func (d *DB) migrate() error {
	deadline := time.Now().Add(migrationRetryDeadline)
	for {
		err := d.migrateOnce()
		if err == nil || !isSQLiteBusyError(err) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(migrationRetryDelay)
	}
}

func isSQLiteBusyError(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	// SQLite encodes the primary result code in the low byte of extended errors.
	switch sqliteErr.Code() & 0xff {
	case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
		return true
	default:
		return false
	}
}

func (d *DB) migrateOnce() error {
	ctx := context.Background()
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	if _, err := conn.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS sites (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		listen_port INTEGER NOT NULL UNIQUE,
		target_url TEXT NOT NULL,
		playback_target_url TEXT NOT NULL DEFAULT '',
		playback_mode TEXT NOT NULL DEFAULT 'direct',
		stream_hosts TEXT NOT NULL DEFAULT '[]',
		ua_mode TEXT DEFAULT 'infuse',
		custom_user_agent TEXT NOT NULL DEFAULT '',
		custom_client TEXT NOT NULL DEFAULT '',
		custom_version TEXT NOT NULL DEFAULT '',
		enabled INTEGER DEFAULT 1,
		traffic_quota BIGINT DEFAULT 0,
		traffic_used BIGINT DEFAULT 0,
		speed_limit INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS traffic_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
		bytes_in BIGINT DEFAULT 0,
		bytes_out BIGINT DEFAULT 0,
		recorded_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_traffic_site_time ON traffic_logs(site_id, recorded_at);
	`); err != nil {
		return err
	}

	for _, migration := range []struct {
		column string
		sql    string
	}{
		{"playback_target_url", "ALTER TABLE sites ADD COLUMN playback_target_url TEXT NOT NULL DEFAULT ''"},
		{"playback_mode", "ALTER TABLE sites ADD COLUMN playback_mode TEXT NOT NULL DEFAULT 'direct'"},
		{"stream_hosts", "ALTER TABLE sites ADD COLUMN stream_hosts TEXT NOT NULL DEFAULT '[]'"},
		{"custom_user_agent", "ALTER TABLE sites ADD COLUMN custom_user_agent TEXT NOT NULL DEFAULT ''"},
		{"custom_client", "ALTER TABLE sites ADD COLUMN custom_client TEXT NOT NULL DEFAULT ''"},
		{"custom_version", "ALTER TABLE sites ADD COLUMN custom_version TEXT NOT NULL DEFAULT ''"},
	} {
		exists, err := sqliteColumnExists(ctx, conn, migration.column)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := conn.ExecContext(ctx, migration.sql); err != nil {
				return err
			}
		}
	}

	var hasHourlyIndex int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_traffic_site_hour'").Scan(&hasHourlyIndex); err != nil {
		return err
	}
	if hasHourlyIndex == 0 {
		if _, err := conn.ExecContext(ctx, `
			CREATE TABLE traffic_logs_dedup (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
				bytes_in BIGINT DEFAULT 0,
				bytes_out BIGINT DEFAULT 0,
				recorded_at DATETIME NOT NULL
			);
			INSERT INTO traffic_logs_dedup (site_id, bytes_in, bytes_out, recorded_at)
			SELECT site_id, SUM(bytes_in), SUM(bytes_out), recorded_at
			FROM traffic_logs
			GROUP BY site_id, recorded_at;
			DELETE FROM traffic_logs;
			INSERT INTO traffic_logs (site_id, bytes_in, bytes_out, recorded_at)
			SELECT site_id, bytes_in, bytes_out, recorded_at
			FROM traffic_logs_dedup;
			DROP TABLE traffic_logs_dedup;
			CREATE UNIQUE INDEX idx_traffic_site_hour ON traffic_logs(site_id, recorded_at);
		`); err != nil {
			return err
		}
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

func sqliteColumnExists(ctx context.Context, conn *sql.Conn, column string) (bool, error) {
	var count int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('sites') WHERE name=?", column).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

type Site struct {
	ID                int64  `json:"id"`
	Name              string `json:"name"`
	ListenPort        int    `json:"listen_port"`
	TargetURL         string `json:"target_url"`
	PlaybackTargetURL string `json:"playback_target_url"`
	PlaybackMode      string `json:"playback_mode"`
	StreamHosts       string `json:"stream_hosts"`
	UAMode            string `json:"ua_mode"`
	CustomUserAgent   string `json:"custom_user_agent"`
	CustomClient      string `json:"custom_client"`
	CustomVersion     string `json:"custom_version"`
	Enabled           bool   `json:"enabled"`
	TrafficQuota      int64  `json:"traffic_quota"`
	TrafficUsed       int64  `json:"traffic_used"`
	SpeedLimit        int    `json:"speed_limit"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type TrafficLog struct {
	ID         int64  `json:"id"`
	SiteID     int64  `json:"site_id"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	RecordedAt string `json:"recorded_at"`
}

// SiteTraffic is the authoritative per-site traffic state: the persisted
// baseline plus in-memory pending bytes. TrafficUsed is always
// PersistedTraffic + BytesIn + BytesOut (pending, not yet flushed).
type SiteTraffic struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	Running          bool   `json:"running"`
	TrafficQuota     int64  `json:"traffic_quota"`
	PersistedTraffic int64  `json:"persisted_traffic"`
	BytesIn          int64  `json:"bytes_in"`
	BytesOut         int64  `json:"bytes_out"`
	TrafficUsed      int64  `json:"traffic_used"`
	Requests         int64  `json:"requests"`
}

// TrafficSnapshot is the single authoritative global traffic payload shared by
// /api/dashboard, /api/traffic/overview and SSE events.
type TrafficSnapshot struct {
	TotalSites    int           `json:"total_sites"`
	OnlineSites   int           `json:"online_sites"`
	RunningSites  int           `json:"running_sites"`
	TotalTraffic  int64         `json:"total_traffic"`
	TotalRequests int64         `json:"total_requests"`
	UptimeSeconds int64         `json:"uptime_seconds"`
	LiveSites     []SiteTraffic `json:"live_sites"`
}

// TrafficHistory is the single-site envelope returned by
// /api/traffic/{id}/snapshot: an atomically captured live snapshot plus the
// log window with pending bytes merged into the current-hour bucket.
type TrafficHistory struct {
	Snapshot SiteTraffic  `json:"snapshot"`
	Logs     []TrafficLog `json:"logs"`
}

func (d *DB) UserCount() (int, error) {
	var n int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

var errAdminAlreadyExists = errors.New("admin user already exists")
var errInvalidCredentials = errors.New("invalid username or password")
var errAdminNotConfigured = errors.New("administrator is not configured")
var errMultipleAdmins = errors.New("multiple administrator accounts found")
var errInvalidAdminPassword = errors.New("password must be 12-72 bytes")

func validateAdminPassword(password string) error {
	if len(password) < 12 || len(password) > 72 {
		return errInvalidAdminPassword
	}
	return nil
}

func (d *DB) CreateInitialUser(username, password string) (int64, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	res, err := d.db.Exec(`
		INSERT INTO users (username, password_hash)
		SELECT ?, ?
		WHERE NOT EXISTS (SELECT 1 FROM users)
	`, username, string(hash))
	if err != nil {
		return 0, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if rows != 1 {
		return 0, errAdminAlreadyExists
	}
	return res.LastInsertId()
}

var invalidUserPasswordHash = func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("meridian-invalid-user"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return hash
}()

func (d *DB) VerifyUser(username, password string) (int64, error) {
	var id int64
	var hash string
	err := d.db.QueryRow("SELECT id, password_hash FROM users WHERE username=?", username).Scan(&id, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword(invalidUserPasswordHash, []byte(password))
		return 0, errInvalidCredentials
	}
	if err != nil {
		return 0, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return 0, errInvalidCredentials
	}
	return id, nil
}

func (d *DB) ResetAdminPassword(password string) error {
	if err := validateAdminPassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return err
	}
	switch {
	case count == 0:
		return errAdminNotConfigured
	case count != 1:
		return errMultipleAdmins
	}

	result, err := tx.Exec("UPDATE users SET password_hash=?", string(hash))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("updated %d administrator rows, want 1", rows)
	}
	return tx.Commit()
}

func (d *DB) ListSites() ([]Site, error) {
	rows, err := d.db.Query("SELECT id, name, listen_port, target_url, playback_target_url, playback_mode, stream_hosts, ua_mode, custom_user_agent, custom_client, custom_version, enabled, traffic_quota, traffic_used, speed_limit, created_at, updated_at FROM sites ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sites []Site
	for rows.Next() {
		var s Site
		var enabled int
		if err := rows.Scan(&s.ID, &s.Name, &s.ListenPort, &s.TargetURL, &s.PlaybackTargetURL, &s.PlaybackMode, &s.StreamHosts, &s.UAMode, &s.CustomUserAgent, &s.CustomClient, &s.CustomVersion, &enabled, &s.TrafficQuota, &s.TrafficUsed, &s.SpeedLimit, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		s.Enabled = enabled == 1
		sites = append(sites, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if sites == nil {
		sites = []Site{}
	}
	return sites, nil
}

func (d *DB) GetSite(id int64) (*Site, error) {
	var s Site
	var enabled int
	err := d.db.QueryRow("SELECT id, name, listen_port, target_url, playback_target_url, playback_mode, stream_hosts, ua_mode, custom_user_agent, custom_client, custom_version, enabled, traffic_quota, traffic_used, speed_limit, created_at, updated_at FROM sites WHERE id=?", id).
		Scan(&s.ID, &s.Name, &s.ListenPort, &s.TargetURL, &s.PlaybackTargetURL, &s.PlaybackMode, &s.StreamHosts, &s.UAMode, &s.CustomUserAgent, &s.CustomClient, &s.CustomVersion, &enabled, &s.TrafficQuota, &s.TrafficUsed, &s.SpeedLimit, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	s.Enabled = enabled == 1
	return &s, nil
}

func (d *DB) CreateSite(name string, port int, targetURL, playbackTargetURL, playbackMode, streamHosts, uaMode string, quota int64, speedLimit int) (*Site, error) {
	return d.CreateSiteWithCustomUA(name, port, targetURL, playbackTargetURL, playbackMode, streamHosts, uaMode, "", "", "", quota, speedLimit)
}

func (d *DB) CreateSiteWithCustomUA(name string, port int, targetURL, playbackTargetURL, playbackMode, streamHosts, uaMode, customUserAgent, customClient, customVersion string, quota int64, speedLimit int) (*Site, error) {
	return d.CreateSiteRecord(Site{
		Name:              name,
		ListenPort:        port,
		TargetURL:         targetURL,
		PlaybackTargetURL: playbackTargetURL,
		PlaybackMode:      playbackMode,
		StreamHosts:       streamHosts,
		UAMode:            uaMode,
		CustomUserAgent:   customUserAgent,
		CustomClient:      customClient,
		CustomVersion:     customVersion,
		TrafficQuota:      quota,
		SpeedLimit:        speedLimit,
	})
}

func (d *DB) CreateSiteRecord(site Site) (*Site, error) {
	if site.StreamHosts == "" {
		site.StreamHosts = "[]"
	}
	res, err := d.db.Exec(
		"INSERT INTO sites (name, listen_port, target_url, playback_target_url, playback_mode, stream_hosts, ua_mode, custom_user_agent, custom_client, custom_version, traffic_quota, speed_limit) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
		site.Name, site.ListenPort, site.TargetURL, site.PlaybackTargetURL, site.PlaybackMode, site.StreamHosts, site.UAMode, site.CustomUserAgent, site.CustomClient, site.CustomVersion, site.TrafficQuota, site.SpeedLimit,
	)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return d.GetSite(id)
}

func (d *DB) UpdateSite(id int64, name string, port int, targetURL, playbackTargetURL, playbackMode, streamHosts, uaMode string, quota int64, speedLimit int) error {
	return d.UpdateSiteWithCustomUA(id, name, port, targetURL, playbackTargetURL, playbackMode, streamHosts, uaMode, "", "", "", quota, speedLimit)
}

func (d *DB) UpdateSiteWithCustomUA(id int64, name string, port int, targetURL, playbackTargetURL, playbackMode, streamHosts, uaMode, customUserAgent, customClient, customVersion string, quota int64, speedLimit int) error {
	return d.UpdateSiteRecord(Site{
		ID:                id,
		Name:              name,
		ListenPort:        port,
		TargetURL:         targetURL,
		PlaybackTargetURL: playbackTargetURL,
		PlaybackMode:      playbackMode,
		StreamHosts:       streamHosts,
		UAMode:            uaMode,
		CustomUserAgent:   customUserAgent,
		CustomClient:      customClient,
		CustomVersion:     customVersion,
		TrafficQuota:      quota,
		SpeedLimit:        speedLimit,
	})
}

func (d *DB) UpdateSiteRecord(site Site) error {
	if site.StreamHosts == "" {
		site.StreamHosts = "[]"
	}
	_, err := d.db.Exec(
		"UPDATE sites SET name=?, listen_port=?, target_url=?, playback_target_url=?, playback_mode=?, stream_hosts=?, ua_mode=?, custom_user_agent=?, custom_client=?, custom_version=?, traffic_quota=?, speed_limit=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
		site.Name, site.ListenPort, site.TargetURL, site.PlaybackTargetURL, site.PlaybackMode, site.StreamHosts, site.UAMode, site.CustomUserAgent, site.CustomClient, site.CustomVersion, site.TrafficQuota, site.SpeedLimit, site.ID,
	)
	return err
}

func (d *DB) DeleteSite(id int64) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM traffic_logs WHERE site_id=?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM sites WHERE id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) ToggleSite(id int64) (bool, error) {
	var enabled int
	if err := d.db.QueryRow("SELECT enabled FROM sites WHERE id=?", id).Scan(&enabled); err != nil {
		return false, err
	}
	newVal := 1 - enabled
	_, err := d.db.Exec("UPDATE sites SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", newVal, id)
	return newVal == 1, err
}

func (d *DB) AddTraffic(siteID, bytesIn, bytesOut int64) {
	if err := d.addTraffic(siteID, bytesIn, bytesOut); err != nil {
		log.Printf("[traffic] failed to persist usage for site %d: %v", siteID, err)
	}
}

func (d *DB) addTraffic(siteID, bytesIn, bytesOut int64) error {
	hour := time.Now().Truncate(time.Hour).Format("2006-01-02 15:04:05")
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`INSERT INTO traffic_logs (site_id, bytes_in, bytes_out, recorded_at)
		 VALUES (?,?,?,?)
		 ON CONFLICT(site_id, recorded_at) DO UPDATE SET
		 	bytes_in = traffic_logs.bytes_in + excluded.bytes_in,
		 	bytes_out = traffic_logs.bytes_out + excluded.bytes_out`,
		siteID, bytesIn, bytesOut, hour,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(
		"UPDATE sites SET traffic_used=traffic_used+?+?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
		bytesIn, bytesOut, siteID,
	); err != nil {
		return err
	}

	return tx.Commit()
}

func (d *DB) GetTrafficLogs(siteID int64, hours int) ([]TrafficLog, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Format("2006-01-02 15:04:05")
	rows, err := d.db.Query(
		"SELECT id, site_id, bytes_in, bytes_out, recorded_at FROM traffic_logs WHERE site_id=? AND recorded_at>=? ORDER BY recorded_at",
		siteID, since,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []TrafficLog
	for rows.Next() {
		var l TrafficLog
		if err := rows.Scan(&l.ID, &l.SiteID, &l.BytesIn, &l.BytesOut, &l.RecordedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if logs == nil {
		logs = []TrafficLog{}
	}
	return logs, nil
}

type redirectFollowTransport struct {
	base          http.RoundTripper
	playbackHosts map[string]bool
	profile       UAProfile
}

func (t *redirectFollowTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return resp, nil
	}
	for i := 0; i < 3; i++ {
		if resp.StatusCode != 301 && resp.StatusCode != 302 && resp.StatusCode != 307 && resp.StatusCode != 308 {
			break
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			break
		}
		locURL, err := url.Parse(loc)
		if err != nil {
			break
		}
		locURL = req.URL.ResolveReference(locURL)
		locURL.Scheme = strings.ToLower(locURL.Scheme)
		if (locURL.Scheme != "http" && locURL.Scheme != "https") || !t.playbackHosts[redirectHostKey(locURL)] {
			break
		}
		resp.Body.Close()
		newReq, err := http.NewRequestWithContext(req.Context(), req.Method, locURL.String(), nil)
		if err != nil {
			break
		}
		for k, v := range req.Header {
			newReq.Header[k] = v
		}
		newReq.Host = locURL.Host
		if !sameRedirectAuthority(req.URL, locURL) {
			// A redirect to a different scheme/host/port is a new security
			// domain: the browser's cookies and the client's Emby access token
			// must not follow the hop to a playback or CDN host. The UA profile
			// is reapplied below, so identity rewriting stays consistent while
			// secrets stay behind.
			stripSensitiveRedirectHeaders(newReq.Header)
		}
		applyUAProfileHeaders(newReq.Header, t.profile)
		resp, err = t.base.RoundTrip(newReq)
		if err != nil {
			return nil, err
		}
		req = newReq
	}
	return resp, nil
}

type embyAuthAttribute struct {
	name       string
	valueStart int
	valueEnd   int
}

func isEmbyAuthWhitespace(value byte) bool {
	return value == ' ' || value == '\t'
}

func isEmbyAuthToken(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '-' || value == '_'
}

func parseEmbyAuthorizationAttributes(value string, offset int) ([]embyAuthAttribute, bool) {
	attributes := make([]embyAuthAttribute, 0, 4)
	for {
		for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
			offset++
		}
		nameStart := offset
		for offset < len(value) && isEmbyAuthToken(value[offset]) {
			offset++
		}
		if nameStart == offset {
			return nil, false
		}
		name := value[nameStart:offset]
		for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
			offset++
		}
		if offset >= len(value) || value[offset] != '=' {
			return nil, false
		}
		offset++
		for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
			offset++
		}
		if offset >= len(value) || value[offset] != '"' {
			return nil, false
		}
		offset++
		valueStart := offset
		for offset < len(value) && value[offset] != '"' {
			if value[offset] == '\\' || value[offset] < 0x20 || value[offset] == 0x7f {
				return nil, false
			}
			offset++
		}
		if offset >= len(value) {
			return nil, false
		}
		attributes = append(attributes, embyAuthAttribute{
			name:       name,
			valueStart: valueStart,
			valueEnd:   offset,
		})
		offset++
		for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
			offset++
		}
		if offset == len(value) {
			return attributes, true
		}
		if value[offset] != ',' {
			return nil, false
		}
		offset++
		if offset == len(value) {
			return nil, false
		}
	}
}

func rewriteEmbyAuthorizationValue(value string, profile UAProfile) string {
	offset := 0
	for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
		offset++
	}
	schemeStart := offset
	for offset < len(value) && isEmbyAuthToken(value[offset]) {
		offset++
	}
	if schemeStart == offset {
		return value
	}
	scheme := value[schemeStart:offset]
	if !strings.EqualFold(scheme, "MediaBrowser") && !strings.EqualFold(scheme, "Emby") {
		return value
	}
	if offset < len(value) && !isEmbyAuthWhitespace(value[offset]) {
		return value
	}
	for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
		offset++
	}
	if offset == len(value) {
		prefix := value
		if len(value) == schemeStart+len(scheme) {
			prefix += " "
		}
		return prefix + "Client=\"" + profile.Client + "\", Version=\"" + profile.Version + "\""
	}

	attributes, ok := parseEmbyAuthorizationAttributes(value, offset)
	if !ok {
		return value
	}
	clientIndex, versionIndex := -1, -1
	for index, attribute := range attributes {
		switch {
		case strings.EqualFold(attribute.name, "Client"):
			if clientIndex >= 0 {
				return value
			}
			clientIndex = index
		case strings.EqualFold(attribute.name, "Version"):
			if versionIndex >= 0 {
				return value
			}
			versionIndex = index
		}
	}

	type replacement struct {
		start int
		end   int
		value string
	}
	replacements := make([]replacement, 0, 2)
	if clientIndex >= 0 {
		attribute := attributes[clientIndex]
		replacements = append(replacements, replacement{attribute.valueStart, attribute.valueEnd, profile.Client})
	}
	if versionIndex >= 0 {
		attribute := attributes[versionIndex]
		replacements = append(replacements, replacement{attribute.valueStart, attribute.valueEnd, profile.Version})
	}

	if len(replacements) == 2 && replacements[0].start < replacements[1].start {
		replacements[0], replacements[1] = replacements[1], replacements[0]
	}
	rewritten := value
	for _, replacement := range replacements {
		rewritten = rewritten[:replacement.start] + replacement.value + rewritten[replacement.end:]
	}
	if clientIndex < 0 {
		rewritten += ", Client=\"" + profile.Client + "\""
	}
	if versionIndex < 0 {
		rewritten += ", Version=\"" + profile.Version + "\""
	}
	return rewritten
}

func rewriteEmbyAuthorizationHeaders(header http.Header, headerName string, profile UAProfile) {
	for name, values := range header {
		if !strings.EqualFold(name, headerName) {
			continue
		}
		for index, value := range values {
			values[index] = rewriteEmbyAuthorizationValue(value, profile)
		}
	}
}

// stripEmbyAuthorizationToken removes the Token attribute from an Emby
// authorization value, leaving every other attribute byte-identical. The
// boolean result reports whether the value is safe to forward: false means the
// value carries (or may carry) an access token that could not be stripped, and
// the caller must drop the entire header instead of forwarding it. Values
// without any recognizable Token attribute are returned unchanged with true.
func stripEmbyAuthorizationToken(value string) (string, bool) {
	offset := 0
	for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
		offset++
	}
	schemeStart := offset
	for offset < len(value) && isEmbyAuthToken(value[offset]) {
		offset++
	}
	if schemeStart == offset {
		// Empty or whitespace-only value: nothing to strip.
		return value, true
	}
	scheme := value[schemeStart:offset]
	if !strings.EqualFold(scheme, "MediaBrowser") && !strings.EqualFold(scheme, "Emby") {
		// Unknown scheme: it cannot be proven token-free, so fail closed.
		return value, false
	}
	if offset < len(value) && !isEmbyAuthWhitespace(value[offset]) {
		return value, false
	}
	for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
		offset++
	}
	if offset == len(value) {
		// A bare scheme carries no attributes and therefore no token.
		return value, true
	}
	attributes, ok := parseEmbyAuthorizationAttributes(value, offset)
	if !ok {
		return value, false
	}
	tokenIndex := -1
	for index, attribute := range attributes {
		if strings.EqualFold(attribute.name, "Token") {
			if tokenIndex >= 0 {
				// Duplicate Token attributes cannot be stripped without
				// guessing which one the server honors: fail closed.
				return value, false
			}
			tokenIndex = index
		}
	}
	if tokenIndex < 0 {
		return value, true
	}
	attribute := attributes[tokenIndex]
	return value[:attribute.valueStart] + value[attribute.valueEnd:], true
}

// stripSensitiveRedirectHeaders removes browser credentials and access tokens
// before a playback redirect crosses to a different authority. Only the Emby
// identity fields (Client/Version/Device/DeviceId) survive, and the UA profile
// is reapplied by the caller afterwards. Cross-authority protection is
// fail-closed: an X-Emby-Authorization value that may still carry a token is
// dropped together with the whole header rather than forwarded.
func stripSensitiveRedirectHeaders(header http.Header) {
	header.Del("Cookie")
	header.Del("Authorization")
	header.Del("Proxy-Authorization")
	// Dedicated token headers must not follow the hop either.
	header.Del("X-Emby-Token")
	header.Del("X-MediaBrowser-Token")
	for name, values := range header {
		if !strings.EqualFold(name, "X-Emby-Authorization") {
			continue
		}
		for index, value := range values {
			stripped, safe := stripEmbyAuthorizationToken(value)
			if !safe {
				header.Del(name)
				break
			}
			values[index] = stripped
		}
	}
}

type ProxyInstance struct {
	Site      Site
	server    *http.Server
	listener  net.Listener
	startedAt time.Time
	// trafficMu serializes this instance's traffic state transitions: flush,
	// single-site history snapshot and the live overlay in global snapshots.
	// Lock order is pm.mu -> trafficMu; helpers that take trafficMu (e.g.
	// flushProxyTraffic) must never be called from code that already holds it.
	trafficMu        sync.Mutex
	bytesIn          atomic.Int64
	bytesOut         atomic.Int64
	reqCount         atomic.Int64
	persistedTraffic atomic.Int64
}

type ProxyManager struct {
	mu       sync.RWMutex
	proxies  map[int64]*ProxyInstance
	database *DB
}

func NewProxyManager(db *DB) *ProxyManager {
	return &ProxyManager{
		proxies:  make(map[int64]*ProxyInstance),
		database: db,
	}
}

// metered response writer
type meteredWriter struct {
	http.ResponseWriter
	written *atomic.Int64
}

func (m *meteredWriter) Write(b []byte) (int, error) {
	n, err := m.ResponseWriter.Write(b)
	m.written.Add(int64(n))
	return n, err
}

// Flush support for streaming
func (m *meteredWriter) Flush() {
	if f, ok := m.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack support for WebSocket upgrade
func (m *meteredWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := m.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}

// metered request body reader
type meteredReader struct {
	io.ReadCloser
	read *atomic.Int64
}

func (m *meteredReader) Read(p []byte) (int, error) {
	n, err := m.ReadCloser.Read(p)
	m.read.Add(int64(n))
	return n, err
}

type rateLimitedWriter struct {
	http.ResponseWriter
	bytesPerSec    int64
	written        *atomic.Int64
	requestWritten int64
	start          time.Time
}

func (w *rateLimitedWriter) Write(b []byte) (int, error) {
	if w.bytesPerSec <= 0 {
		n, err := w.ResponseWriter.Write(b)
		w.written.Add(int64(n))
		return n, err
	}
	totalWritten := 0
	for len(b) > 0 {
		elapsed := time.Since(w.start).Seconds()
		if elapsed < 0.001 {
			elapsed = 0.001
		}
		allowed := int64(elapsed*float64(w.bytesPerSec)) - w.requestWritten
		if allowed <= 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		chunk := b
		if int64(len(chunk)) > allowed {
			chunk = b[:allowed]
		}
		n, err := w.ResponseWriter.Write(chunk)
		w.written.Add(int64(n))
		w.requestWritten += int64(n)
		totalWritten += n
		b = b[n:]
		if err != nil {
			return totalWritten, err
		}
		if n == 0 {
			return totalWritten, io.ErrNoProgress
		}
	}
	return totalWritten, nil
}

func (w *rateLimitedWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *rateLimitedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}

// tunnelWriter meters, and optionally paces, bytes copied through a hijacked
// WebSocket tunnel. Accounting has to happen per chunk rather than once the copy
// returns, otherwise a long-lived tunnel stays invisible to the quota gate and
// exempt from the site's speed limit for as long as it is open.
type tunnelWriter struct {
	dst         io.Writer
	counter     *atomic.Int64
	bytesPerSec int64
	written     int64
	start       time.Time
}

func (t *tunnelWriter) Write(b []byte) (int, error) {
	if t.bytesPerSec <= 0 {
		n, err := t.dst.Write(b)
		t.counter.Add(int64(n))
		return n, err
	}
	total := 0
	for len(b) > 0 {
		elapsed := time.Since(t.start).Seconds()
		if elapsed < 0.001 {
			elapsed = 0.001
		}
		allowed := int64(elapsed*float64(t.bytesPerSec)) - t.written
		if allowed <= 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		chunk := b
		if int64(len(chunk)) > allowed {
			chunk = b[:allowed]
		}
		n, err := t.dst.Write(chunk)
		t.counter.Add(int64(n))
		t.written += int64(n)
		total += n
		b = b[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

// headerHasToken reports whether a comma-separated header such as Connection
// carries the given token, which is how RFC 9110 requires these be compared.
func headerHasToken(header http.Header, name, token string) bool {
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// isWebSocketUpgrade reports whether the request is a real RFC 6455 handshake.
// A bare "Upgrade: websocket" header is not enough to qualify: routing an
// ordinary request into the hijacked tunnel would skip the metering and
// speed-limit wrappers that the normal proxy path installs, and would relay raw
// bytes to an upstream that never agreed to switch protocols. Requests that fail
// this check fall through to httputil.ReverseProxy, which negotiates protocol
// switches on its own.
func isWebSocketUpgrade(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		headerHasToken(r.Header, "Connection", "upgrade") &&
		r.Header.Get("Sec-WebSocket-Key") != ""
}

func normalizeTargetURL(addr string) (*url.URL, error) {
	addr = strings.TrimSpace(addr)
	addr = strings.ReplaceAll(addr, "：", ":")
	if addr == "" {
		return nil, fmt.Errorf("target URL is required")
	}
	if len(addr) > 2048 {
		return nil, fmt.Errorf("target URL is too long")
	}
	explicitScheme := strings.Contains(addr, "://")
	if !explicitScheme {
		addr = "http://" + addr
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if !explicitScheme && parsed.Port() == "443" {
		parsed.Scheme = "https"
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Hostname() == "" || parsed.Opaque != "" {
		return nil, fmt.Errorf("invalid target URL")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("target URL must not contain credentials")
	}
	if parsed.Fragment != "" {
		return nil, fmt.Errorf("target URL must not contain a fragment")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return nil, fmt.Errorf("target URL contains an invalid port")
		}
	}
	return parsed, nil
}

// redactUpstreamURL keeps operator logs useful without retaining credentials,
// paths, or signed query parameters from configured upstreams.
func redactUpstreamURL(target *url.URL) string {
	if target == nil || target.Scheme == "" || target.Host == "" {
		return "configured upstream"
	}
	return strings.ToLower(target.Scheme) + "://" + target.Host
}

func redirectHostKey(target *url.URL) string {
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	if host == "" {
		return ""
	}
	port := target.Port()
	scheme := strings.ToLower(target.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "" && !((scheme == "http" && port == "80") || (scheme == "https" && port == "443")) {
		authority = net.JoinHostPort(host, port)
	}
	return scheme + "://" + authority
}

// sameRedirectAuthority reports whether two URLs share scheme, host, and
// effective port. Redirects that stay within the same authority may keep the
// client's headers; anything else is a cross-origin hop.
func sameRedirectAuthority(from, to *url.URL) bool {
	return redirectHostKey(from) == redirectHostKey(to)
}

func singleJoiningSlash(a, b string) string {
	aSlash := strings.HasSuffix(a, "/")
	bSlash := strings.HasPrefix(b, "/")
	switch {
	case aSlash && bSlash:
		return a + b[1:]
	case !aSlash && !bSlash:
		return a + "/" + b
	default:
		return a + b
	}
}

func joinURLPath(base, request *url.URL) (joinedPath, joinedRawPath string) {
	if base.RawPath == "" && request.RawPath == "" {
		return singleJoiningSlash(base.Path, request.Path), ""
	}
	basePath := base.EscapedPath()
	requestPath := request.EscapedPath()
	baseSlash := strings.HasSuffix(basePath, "/")
	requestSlash := strings.HasPrefix(requestPath, "/")
	switch {
	case baseSlash && requestSlash:
		return base.Path + request.Path[1:], basePath + requestPath[1:]
	case !baseSlash && !requestSlash:
		return base.Path + "/" + request.Path, basePath + "/" + requestPath
	default:
		return base.Path + request.Path, basePath + requestPath
	}
}

func applyUpstreamURL(requestURL, upstream *url.URL) {
	requestURL.Scheme = upstream.Scheme
	requestURL.Host = upstream.Host
	requestURL.Path, requestURL.RawPath = joinURLPath(upstream, requestURL)
	switch {
	case upstream.RawQuery == "":
	case requestURL.RawQuery == "":
		requestURL.RawQuery = upstream.RawQuery
	default:
		requestURL.RawQuery = upstream.RawQuery + "&" + requestURL.RawQuery
	}
}

func validateSiteSettings(name string, listenPort int, targetURL, playbackTargetURL, playbackMode string, streamHosts []string, uaMode, customUserAgent, customClient, customVersion string, quota int64, speedLimit int) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 || strings.ContainsAny(name, "\r\n") {
		return fmt.Errorf("name must be 1-100 characters without line breaks")
	}
	if listenPort < 1 || listenPort > 65535 {
		return fmt.Errorf("listen_port must be between 1 and 65535")
	}
	if _, err := normalizeTargetURL(targetURL); err != nil {
		return fmt.Errorf("invalid target_url: %w", err)
	}
	if strings.TrimSpace(playbackTargetURL) != "" {
		if _, err := normalizeTargetURL(playbackTargetURL); err != nil {
			return fmt.Errorf("invalid playback_target_url: %w", err)
		}
	}
	if playbackMode != "direct" && playbackMode != "redirect" {
		return fmt.Errorf("playback_mode must be direct or redirect")
	}
	if _, _, _, _, err := normalizeUAConfig(uaMode, customUserAgent, customClient, customVersion); err != nil {
		return err
	}
	if quota < 0 || speedLimit < 0 {
		return fmt.Errorf("traffic_quota and speed_limit must not be negative")
	}
	if speedLimit > maxSpeedLimitMbps {
		return fmt.Errorf("speed_limit must not exceed %d Mbps", maxSpeedLimitMbps)
	}
	if len(streamHosts) > 128 {
		return fmt.Errorf("stream_hosts must contain at most 128 entries")
	}
	for _, host := range streamHosts {
		if _, err := normalizeTargetURL(host); err != nil {
			return fmt.Errorf("invalid stream host %q: %w", host, err)
		}
	}
	return nil
}

func isPlaybackRequest(path string) bool {
	path = strings.ToLower(path)
	switch {
	case strings.HasPrefix(path, "/videos/"),
		strings.HasPrefix(path, "/emby/videos/"),
		strings.HasPrefix(path, "/audio/"),
		strings.HasPrefix(path, "/emby/audio/"),
		strings.HasPrefix(path, "/livetv/"),
		strings.HasPrefix(path, "/emby/livetv/"):
		return true
	case strings.HasPrefix(path, "/items/"),
		strings.HasPrefix(path, "/emby/items/"):
		return strings.Contains(path, "/download") || strings.Contains(path, "/file")
	default:
		return false
	}
}

func upstreamTargetForRequest(r *http.Request, apiTarget, playbackTarget *url.URL) *url.URL {
	if playbackTarget != nil && isPlaybackRequest(r.URL.Path) {
		return playbackTarget
	}
	return apiTarget
}

func applyUAProfileHeaders(header http.Header, profile UAProfile) {
	header.Set("User-Agent", profile.UserAgent)
	rewriteEmbyAuthorizationHeaders(header, "X-Emby-Authorization", profile)
	rewriteEmbyAuthorizationHeaders(header, "Authorization", profile)
}

func removeClientForwardingHeaders(header http.Header) {
	for name := range header {
		lowerName := strings.ToLower(name)
		if lowerName == "forwarded" || lowerName == "x-real-ip" || strings.HasPrefix(lowerName, "x-forwarded-") {
			delete(header, name)
		}
	}
}

func setTrustedForwardingHeaders(header http.Header, inbound *http.Request) {
	removeClientForwardingHeaders(header)
	if inbound == nil {
		return
	}
	if peerIP := remoteAddressIP(inbound.RemoteAddr); peerIP != nil {
		header.Set("X-Forwarded-For", peerIP.String())
		header.Set("X-Real-IP", peerIP.String())
	}
	if inbound.Host != "" {
		header.Set("X-Forwarded-Host", inbound.Host)
	}
	forwardedProto := "http"
	if inbound.TLS != nil {
		forwardedProto = "https"
	}
	header.Set("X-Forwarded-Proto", forwardedProto)
}

func prepareUpstreamHeaders(header http.Header, inbound *http.Request, profile UAProfile) {
	setTrustedForwardingHeaders(header, inbound)
	applyUAProfileHeaders(header, profile)
}

func prepareWebSocketUpstreamHeaders(inbound *http.Request, target *url.URL, profile UAProfile) http.Header {
	header := inbound.Header.Clone()
	for _, name := range []string{
		// Content-Length must go with the other hop-by-hop headers: the upgrade
		// path never reads r.Body, so letting a length through would tell the
		// upstream to frame bytes as a body that this side never sends.
		"Content-Length",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
	header.Set("Connection", "Upgrade")
	header.Set("Upgrade", "websocket")
	header.Set("Host", target.Host)
	prepareUpstreamHeaders(header, inbound, profile)
	return header
}

// writeWebSocketGatewayError answers a hijacked client directly, since the
// http.ResponseWriter is no longer usable once the connection is taken over.
func writeWebSocketGatewayError(conn net.Conn) {
	const body = `{"error":"upstream refused websocket upgrade"}`
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request, target *url.URL, profile UAProfile, inst *ProxyInstance, speedLimitBytes int64) {
	// Nothing on this path reads r.Body, so a body would be left sitting in the
	// hijacked buffer and relayed verbatim to the upstream.
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		http.Error(w, "websocket upgrade must not carry a body", http.StatusBadRequest)
		return
	}
	scheme := "ws"
	if target.Scheme == "https" {
		scheme = "wss"
	}
	// Hijack client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported", 500)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		log.Printf("[WS] hijack error: %v", err)
		return
	}
	defer clientConn.Close()

	// Connect to upstream
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var upstreamConn net.Conn
	port := target.Port()
	if port == "" {
		if scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}
	host := net.JoinHostPort(target.Hostname(), port)
	if scheme == "wss" {
		upstreamConn, err = tls.DialWithDialer(dialer, "tcp", host, secureTLSConfig(target.Hostname()))
	} else {
		upstreamConn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		log.Printf("[WS] upstream dial error: %v", err)
		writeWebSocketGatewayError(clientConn)
		return
	}
	defer upstreamConn.Close()

	// Send upgrade request to upstream
	if err := upstreamConn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("[WS] set handshake deadline: %v", err)
		return
	}
	upstreamURL := *r.URL
	applyUpstreamURL(&upstreamURL, target)
	reqLine := fmt.Sprintf("%s %s HTTP/1.1\r\n", r.Method, upstreamURL.RequestURI())
	if _, err := io.WriteString(upstreamConn, reqLine); err != nil { // #nosec G705 -- net/http rejects control characters in the parsed method and RequestURI.
		log.Printf("[WS] write request line: %v", err)
		return
	}
	upstreamHeader := prepareWebSocketUpstreamHeaders(r, target, profile)
	if err := upstreamHeader.Write(upstreamConn); err != nil {
		log.Printf("[WS] write request headers: %v", err)
		return
	}
	if _, err := io.WriteString(upstreamConn, "\r\n"); err != nil {
		log.Printf("[WS] finish request headers: %v", err)
		return
	}
	if err := upstreamConn.SetWriteDeadline(time.Time{}); err != nil {
		log.Printf("[WS] clear handshake deadline: %v", err)
		return
	}

	// Require a real protocol switch before relaying any raw bytes. Without this
	// check the tunnel starts regardless of what the upstream answered, so if the
	// upstream ignored the upgrade and stayed in HTTP keep-alive mode, whatever
	// the client sends next reaches it as requests that never passed through
	// removeClientForwardingHeaders/setTrustedForwardingHeaders/applyUAProfileHeaders.
	if err := upstreamConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("[WS] set handshake read deadline: %v", err)
		return
	}
	// Read through a buffered reader and keep using it below: ReadResponse may
	// consume bytes past the headers, and those belong to the tunnel.
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, r)
	if err != nil {
		log.Printf("[WS] read upstream handshake: %v", err)
		writeWebSocketGatewayError(clientConn)
		return
	}
	defer resp.Body.Close()
	if err := upstreamConn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("[WS] clear handshake read deadline: %v", err)
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		!headerHasToken(resp.Header, "Connection", "upgrade") {
		// The body is deliberately not relayed. An upstream that answers a
		// handshake with a normal response must not turn this path into an
		// unmetered, unthrottled transfer channel.
		log.Printf("[WS] upstream refused upgrade: status %d", resp.StatusCode)
		writeWebSocketGatewayError(clientConn)
		return
	}

	// Relay the switch verbatim; the client needs Sec-WebSocket-Accept.
	if _, err := io.WriteString(clientConn, "HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		log.Printf("[WS] write handshake response: %v", err)
		return
	}
	if err := resp.Header.Write(clientConn); err != nil {
		log.Printf("[WS] write handshake headers: %v", err)
		return
	}
	if _, err := io.WriteString(clientConn, "\r\n"); err != nil {
		log.Printf("[WS] finish handshake response: %v", err)
		return
	}

	log.Printf("[WS] tunnel established: client <-> %s", target.Host)

	// Bidirectional copy. Both directions are metered per chunk; only the
	// download direction is paced, matching rateLimitedWriter on the HTTP path.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(&tunnelWriter{dst: upstreamConn, counter: &inst.bytesIn, start: time.Now()}, clientBuf)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(&tunnelWriter{dst: clientConn, counter: &inst.bytesOut, bytesPerSec: speedLimitBytes, start: time.Now()}, upstreamReader)
		done <- struct{}{}
	}()
	<-done
}

func (pm *ProxyManager) StartSite(site Site) error {
	target, err := normalizeTargetURL(site.TargetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	var playbackTarget *url.URL
	if strings.TrimSpace(site.PlaybackTargetURL) != "" {
		playbackTarget, err = normalizeTargetURL(site.PlaybackTargetURL)
		if err != nil {
			return fmt.Errorf("invalid playback target URL: %w", err)
		}
	}

	// Build playback hosts set from playback_target_url + stream_hosts
	playbackHostsSet := make(map[string]bool)
	if playbackTarget != nil {
		playbackHostsSet[redirectHostKey(playbackTarget)] = true
	}
	var extraHosts []string
	if strings.TrimSpace(site.StreamHosts) != "" {
		if err := json.Unmarshal([]byte(site.StreamHosts), &extraHosts); err != nil {
			return fmt.Errorf("invalid stream_hosts: %w", err)
		}
	}
	for _, raw := range extraHosts {
		parsed, err := normalizeTargetURL(raw)
		if err != nil {
			return fmt.Errorf("invalid stream host %q: %w", raw, err)
		}
		playbackHostsSet[redirectHostKey(parsed)] = true
		if playbackTarget == nil {
			playbackTarget = parsed
		}
	}

	profile, err := resolveSiteUAProfile(site)
	if err != nil {
		return fmt.Errorf("invalid UA profile: %w", err)
	}
	inst := &ProxyInstance{Site: site, startedAt: time.Now()}
	inst.persistedTraffic.Store(site.TrafficUsed)

	isRedirectMode := playbackTarget != nil && site.PlaybackMode == "redirect"
	proxyTransport := http.DefaultTransport.(*http.Transport).Clone()
	proxyTransport.TLSClientConfig = secureTLSConfig("")
	proxyTransport.ResponseHeaderTimeout = 30 * time.Second
	proxyTransport.MaxIdleConnsPerHost = 32

	proxy := &httputil.ReverseProxy{
		Transport: proxyTransport,
		Rewrite: func(proxyReq *httputil.ProxyRequest) {
			var upstream *url.URL
			if isRedirectMode {
				upstream = target
			} else {
				upstream = upstreamTargetForRequest(proxyReq.In, target, playbackTarget)
			}
			applyUpstreamURL(proxyReq.Out.URL, upstream)
			proxyReq.Out.Host = upstream.Host
			prepareUpstreamHeaders(proxyReq.Out.Header, proxyReq.In, profile)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[%s] proxy error: %v", site.Name, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error":"upstream unavailable"}`))
		},
	}

	if isRedirectMode {
		proxy.Transport = &redirectFollowTransport{
			base:          proxyTransport,
			playbackHosts: playbackHostsSet,
			profile:       profile,
		}
	}

	// Speed limit in bytes/sec (field is in Mbps, 0 = unlimited)
	speedLimitBytes := int64(site.SpeedLimit) * 125000 // Mbps -> bytes/sec

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inst.reqCount.Add(1)

		if site.TrafficQuota > 0 {
			currentUsed := inst.persistedTraffic.Load() + inst.bytesIn.Load() + inst.bytesOut.Load()
			if currentUsed >= site.TrafficQuota {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"traffic quota exceeded"}`))
				return
			}
		}

		if isWebSocketUpgrade(r) {
			wsTarget := upstreamTargetForRequest(r, target, playbackTarget)
			if isRedirectMode {
				wsTarget = target
			}
			handleWebSocket(w, r, wsTarget, profile, inst, speedLimitBytes)
			return
		}

		if r.Body != nil {
			r.Body = &meteredReader{ReadCloser: r.Body, read: &inst.bytesIn}
		}

		var rw http.ResponseWriter
		if speedLimitBytes > 0 {
			rw = &rateLimitedWriter{
				ResponseWriter: w,
				bytesPerSec:    speedLimitBytes,
				written:        &inst.bytesOut,
				start:          time.Now(),
			}
		} else {
			rw = &meteredWriter{ResponseWriter: w, written: &inst.bytesOut}
		}
		proxy.ServeHTTP(rw, r) // #nosec G704 -- forwarding to the administrator-configured, validated upstream is the product's purpose.
	})

	listenAddr := fmt.Sprintf(":%d", site.ListenPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	listener = limitListener(listener, 2048)

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	inst.server = server
	inst.listener = listener

	pm.mu.Lock()
	if existing, ok := pm.proxies[site.ID]; ok {
		// Flush before dropping the instance, the way StopSite does. This branch is
		// reached when a running site's listen_port changes, which is the one
		// update path handleSiteByID does not pre-stop, so without this everything
		// counted since the last 60s tick vanishes from traffic_logs and
		// sites.traffic_used.
		if err := pm.flushProxyTraffic(existing); err != nil {
			// Fail closed: keep the old instance and its pending bytes, release
			// the new instance's freshly bound listener, and leave the proxies
			// map untouched. The Serve goroutine below never starts, so closing
			// the raw listener is enough.
			pm.mu.Unlock()
			_ = listener.Close()
			return fmt.Errorf("flush traffic of the instance being replaced: %w", err)
		}
		// That flush moved bytes into the row `site` was read from, so carry the
		// authoritative total forward instead of the snapshot taken before it.
		if flushed := existing.Site.TrafficUsed; flushed > inst.persistedTraffic.Load() {
			inst.persistedTraffic.Store(flushed)
		}
		if existing.server != nil {
			existing.server.Close()
		}
		delete(pm.proxies, site.ID)
	}
	pm.proxies[site.ID] = inst
	pm.mu.Unlock()

	go func() {
		upstreamLogTarget := redactUpstreamURL(target)
		if len(playbackHostsSet) > 0 {
			hosts := make([]string, 0, len(playbackHostsSet))
			for h := range playbackHostsSet {
				hosts = append(hosts, h)
			}
			log.Printf("[%s] proxy :%d -> %s (playback hosts: %s, mode: %s, UA: %s)", site.Name, site.ListenPort, upstreamLogTarget, strings.Join(hosts, ", "), site.PlaybackMode, site.UAMode)
		} else {
			log.Printf("[%s] proxy :%d -> %s (UA: %s)", site.Name, site.ListenPort, upstreamLogTarget, site.UAMode)
		}
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[%s] server error: %v", site.Name, err)
		}
	}()

	return nil
}

func (pm *ProxyManager) StopSite(id int64) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	inst, ok := pm.proxies[id]
	if !ok {
		return nil
	}
	// Flush before dropping the instance so pending bytes reach the DB. If the
	// flush fails the instance stays running with its pending bytes intact and
	// the caller must abort (or retry) so instance and DB remain consistent.
	if err := pm.flushProxyTraffic(inst); err != nil {
		return err
	}
	if inst.server != nil {
		inst.server.Close()
	}
	delete(pm.proxies, id)
	return nil
}

func (pm *ProxyManager) IsRunning(id int64) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	_, ok := pm.proxies[id]
	return ok
}

func (pm *ProxyManager) StartAllEnabled() (int, error) {
	sites, err := pm.database.ListSites()
	if err != nil {
		return 0, err
	}
	for _, s := range sites {
		if s.Enabled {
			if err := pm.StartSite(s); err != nil {
				log.Printf("[%s] failed to start: %v", s.Name, err)
			}
		}
	}
	return len(sites), nil
}

// FlushTraffic flushes every running instance's pending traffic to the DB. It
// is driven by the periodic ticker: a failed flush restores the pending
// counters and is logged here, so the next tick retries the same bytes.
func (pm *ProxyManager) FlushTraffic() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for _, inst := range pm.proxies {
		if err := pm.flushProxyTraffic(inst); err != nil {
			log.Printf("[%s] failed to flush traffic: %v", inst.Site.Name, err)
		}
	}
}

// flushProxyTraffic persists inst's pending bytes into the DB and moves them
// into the persisted baseline. The caller must hold pm.mu (read or write);
// inst.trafficMu is acquired here. On failure the pending counters are fully
// restored so the next flush retries the same bytes. Never call this from
// code that already holds inst.trafficMu (no nested re-entry).
func (pm *ProxyManager) flushProxyTraffic(inst *ProxyInstance) error {
	inst.trafficMu.Lock()
	defer inst.trafficMu.Unlock()
	return pm.flushProxyTrafficLocked(inst)
}

// flushProxyTrafficLocked is the body of flushProxyTraffic and assumes
// inst.trafficMu is held. Order is swap -> DB -> persisted baseline: the
// pending counters are zeroed first, the baseline moves only after the DB
// transaction commits, and the counters are restored verbatim on any error.
func (pm *ProxyManager) flushProxyTrafficLocked(inst *ProxyInstance) error {
	in := inst.bytesIn.Swap(0)
	out := inst.bytesOut.Swap(0)
	if in == 0 && out == 0 {
		return nil
	}
	if err := pm.database.addTraffic(inst.Site.ID, in, out); err != nil {
		inst.bytesIn.Add(in)
		inst.bytesOut.Add(out)
		return err
	}
	delta := in + out
	inst.persistedTraffic.Add(delta)
	inst.Site.TrafficUsed += delta
	return nil
}

// sameTrafficHour reports whether a persisted recorded_at value falls in the
// same wall-clock hour as now. Stored rows are wall-clock values: legacy
// "2006-01-02 15:04:05" rows carry the writer's local time, and the modernc
// SQLite driver re-serializes DATETIME columns as RFC3339 with the stored
// wall clock in UTC (it attaches Z to whatever text was written). The
// year/month/day/hour components of the stored value are therefore compared
// against the current local wall clock, never the instants: an instant-based
// comparison would shift the bucket by the zone offset in non-UTC
// deployments. Values that parse as neither format never match, so a corrupt
// or foreign string cannot swallow pending bytes.
func sameTrafficHour(recordedAt string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, recordedAt)
	if err != nil {
		if t, err = time.ParseInLocation("2006-01-02 15:04:05", recordedAt, time.Local); err != nil {
			return false
		}
	}
	nowLocal := now.In(time.Local)
	y, m, d := t.Date()
	ny, nm, nd := nowLocal.Date()
	return y == ny && m == nm && d == nd && t.Hour() == nowLocal.Hour()
}

// mergePendingIntoLogs merges live pending bytes into the current-hour bucket
// of the returned log copy: it adds to the existing bucket when present, or
// appends a synthetic bucket with ID 0 when the hour has no bucket yet and
// pending bytes are non-zero. A zero pending pair is a no-op. The input slice
// must be a private copy (GetTrafficLogs always returns one). The current
// hour is matched by wall-clock semantics via sameTrafficHour, so rows
// persisted in either the RFC3339 form the SQLite driver returns or the
// legacy SQL layout merge correctly. The synthetic bucket is built from the
// current local wall hour stamped as UTC, exactly the representation the next
// addTraffic row will carry after the driver re-serializes it, with ID 0.
func mergePendingIntoLogs(logs []TrafficLog, siteID, pendingIn, pendingOut int64) []TrafficLog {
	if pendingIn == 0 && pendingOut == 0 {
		return logs
	}
	now := time.Now()
	for i := range logs {
		if sameTrafficHour(logs[i].RecordedAt, now) {
			logs[i].BytesIn += pendingIn
			logs[i].BytesOut += pendingOut
			return logs
		}
	}
	nowLocal := now.In(time.Local)
	return append(logs, TrafficLog{
		ID:         0,
		SiteID:     siteID,
		BytesIn:    pendingIn,
		BytesOut:   pendingOut,
		RecordedAt: time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day(), nowLocal.Hour(), 0, 0, 0, time.UTC).Format(time.RFC3339),
	})
}

// SiteTrafficHistory captures a single site's traffic history as a consistent
// point-in-time view: the DB log window plus live pending bytes merged into
// the returned copy's current-hour bucket, alongside the authoritative live
// state. For a running site the DB read and the live counters happen under
// inst.trafficMu (with pm.mu held read-only to pin the instance), so the view
// never interleaves with a concurrent flush.
func (pm *ProxyManager) SiteTrafficHistory(site Site, hours int) (*TrafficHistory, error) {
	snap := SiteTraffic{
		ID:               site.ID,
		Name:             site.Name,
		TrafficQuota:     site.TrafficQuota,
		PersistedTraffic: site.TrafficUsed,
		TrafficUsed:      site.TrafficUsed,
	}

	pm.mu.RLock()
	inst, running := pm.proxies[site.ID]
	if !running {
		pm.mu.RUnlock()
		logs, err := pm.database.GetTrafficLogs(site.ID, hours)
		if err != nil {
			return nil, err
		}
		return &TrafficHistory{Snapshot: snap, Logs: logs}, nil
	}
	// pm.mu -> trafficMu lock order. trafficMu stays held across the DB read
	// so the logs and the live counters describe the same instant.
	inst.trafficMu.Lock()
	defer inst.trafficMu.Unlock()
	defer pm.mu.RUnlock()

	logs, err := pm.database.GetTrafficLogs(site.ID, hours)
	if err != nil {
		return nil, err
	}
	snap.Running = true
	snap.PersistedTraffic = inst.persistedTraffic.Load()
	snap.BytesIn = inst.bytesIn.Load()
	snap.BytesOut = inst.bytesOut.Load()
	snap.TrafficUsed = snap.PersistedTraffic + snap.BytesIn + snap.BytesOut
	snap.Requests = inst.reqCount.Load()
	logs = mergePendingIntoLogs(logs, site.ID, snap.BytesIn, snap.BytesOut)
	return &TrafficHistory{Snapshot: snap, Logs: logs}, nil
}

// overlaySiteTrafficLocked fills st with the authoritative live per-instance
// state for a running site: persistedTraffic + pending bytes, exactly the same
// merge every traffic view renders. The caller must hold pm.mu (read or
// write); inst.trafficMu is acquired here following the pm.mu -> trafficMu
// lock order, so the overlay never interleaves with a concurrent flush. This
// is the single per-site merge algorithm for all live traffic payloads.
func (pm *ProxyManager) overlaySiteTrafficLocked(s Site, st *SiteTraffic) {
	if inst, ok := pm.proxies[s.ID]; ok {
		inst.trafficMu.Lock()
		st.Running = true
		st.PersistedTraffic = inst.persistedTraffic.Load()
		st.BytesIn = inst.bytesIn.Load()
		st.BytesOut = inst.bytesOut.Load()
		st.TrafficUsed = st.PersistedTraffic + st.BytesIn + st.BytesOut
		st.Requests = inst.reqCount.Load()
		inst.trafficMu.Unlock()
	}
}

// LiveSiteTraffic overlays the authoritative live traffic state (persisted
// baseline plus pending bytes, under each instance's trafficMu) onto the given
// DB sites and returns it as a map keyed by site ID. One pm.mu read lock is
// taken for the whole map, so the view is consistent and there is no N+1 lock
// churn; the lock order is pm.mu -> trafficMu.
func (pm *ProxyManager) LiveSiteTraffic(sites []Site) map[int64]SiteTraffic {
	live := make(map[int64]SiteTraffic, len(sites))
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for _, s := range sites {
		st := SiteTraffic{
			ID:               s.ID,
			Name:             s.Name,
			TrafficQuota:     s.TrafficQuota,
			PersistedTraffic: s.TrafficUsed,
			TrafficUsed:      s.TrafficUsed,
		}
		pm.overlaySiteTrafficLocked(s, &st)
		live[s.ID] = st
	}
	return live
}

// TrafficSnapshot builds the authoritative global traffic payload: every DB
// site, overlaid with live per-instance state for running sites. Dashboard,
// traffic overview and SSE events all render this single payload.
func (pm *ProxyManager) TrafficSnapshot() (*TrafficSnapshot, error) {
	sites, err := pm.database.ListSites()
	if err != nil {
		return nil, err
	}
	snap := &TrafficSnapshot{
		TotalSites: len(sites),
		LiveSites:  make([]SiteTraffic, 0, len(sites)),
	}
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	snap.RunningSites = len(pm.proxies)
	for _, s := range sites {
		st := SiteTraffic{
			ID:               s.ID,
			Name:             s.Name,
			TrafficQuota:     s.TrafficQuota,
			PersistedTraffic: s.TrafficUsed,
			TrafficUsed:      s.TrafficUsed,
		}
		if s.Enabled {
			snap.OnlineSites++
		}
		pm.overlaySiteTrafficLocked(s, &st)
		snap.TotalTraffic += st.TrafficUsed
		snap.TotalRequests += st.Requests
		snap.LiveSites = append(snap.LiveSites, st)
	}
	snap.UptimeSeconds = int64(time.Since(startTime).Seconds())
	return snap, nil
}

func (pm *ProxyManager) GetRunningCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.proxies)
}

func (pm *ProxyManager) GetSiteRuntime(id int64) (requests int64, startedAt time.Time, running bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	inst, ok := pm.proxies[id]
	if !ok {
		return 0, time.Time{}, false
	}
	return inst.reqCount.Load(), inst.startedAt, true
}

// GracefulShutdown stops all proxies gracefully
func (pm *ProxyManager) GracefulShutdown(ctx context.Context) {
	pm.FlushTraffic()
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for id, inst := range pm.proxies {
		log.Printf("[%s] shutting down...", inst.Site.Name)
		inst.server.Shutdown(ctx)
		delete(pm.proxies, id)
	}
}

type DiagResult struct {
	Upstreams DiagUpstreams `json:"upstreams"`
	Health    DiagHealth    `json:"health"`
	TLS       DiagTLS       `json:"tls"`
	Headers   DiagHeaders   `json:"headers"`
	Proxy     DiagProxy     `json:"proxy"`
}

type DiagUpstreams struct {
	Primary  DiagUpstream `json:"primary"`
	Playback DiagUpstream `json:"playback"`
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
	UAApplied    bool   `json:"ua_applied"`
	CurrentUA    string `json:"current_ua"`
	ClientField  string `json:"client_field"`
	VersionField string `json:"version_field"`
	ProfileError string `json:"profile_error,omitempty"`
}

type DiagProxy struct {
	Running    bool   `json:"running"`
	ListenPort int    `json:"listen_port"`
	TotalReqs  int64  `json:"total_requests"`
	Uptime     string `json:"uptime,omitempty"`
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
var probeClient = func() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = secureTLSConfig("")
	return &http.Client{
		Timeout:   5 * time.Second,
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
}()

func probeTargetHealth(plan diagProbePlan) DiagHealth {
	client := probeClient
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
		resp, err := client.Do(req) // #nosec G704 -- diagnostics probe only the administrator-configured, validated upstream.
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
	parsed.RawQuery = ""
	return parsed.String()
}

func diagnoseSite(site *Site, pm *ProxyManager) DiagResult {
	profile, profileErr := resolveSiteUAProfile(*site)
	primary, primaryKey := diagnoseUpstreamTarget(site.TargetURL, "metadata_api")
	primary.Configured = true
	primary.ShowHealth = true
	primary.ShowTLS = primary.TLS.Enabled

	playbackRaw := strings.TrimSpace(site.PlaybackTargetURL)
	playback := primary
	playback.ConfiguredURL = ""
	playback.Configured = false
	playback.UsingFallback = true
	playback.SameAsPrimary = true
	playback.ShowHealth = false
	playback.ShowTLS = false

	if playbackRaw != "" {
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
			Primary:  primary,
			Playback: playback,
		},
		Health: primary.Health,
		TLS:    primary.TLS,
	}

	// Headers
	if profileErr != nil {
		result.Headers = DiagHeaders{
			ProfileError: "invalid stored UA configuration",
		}
	} else {
		result.Headers = DiagHeaders{
			UAApplied:    true,
			CurrentUA:    profile.UserAgent,
			ClientField:  profile.Client,
			VersionField: profile.Version,
		}
	}

	// Proxy status
	totalRequests, startedAt, running := pm.GetSiteRuntime(site.ID)
	uptime := ""
	if running && !startedAt.IsZero() {
		duration := time.Since(startedAt).Round(time.Second)
		if duration < 0 {
			duration = 0
		}
		uptime = duration.String()
	}
	result.Proxy = DiagProxy{
		Running:    running,
		ListenPort: site.ListenPort,
		TotalReqs:  totalRequests,
		Uptime:     uptime,
	}

	return result
}

type App struct {
	db               *DB
	pm               *ProxyManager
	siteLifecycleMu  sync.Mutex
	setupTokenMu     sync.Mutex
	setupToken       string
	loginLimiter     *loginRateLimiter
	loginLimiterOnce sync.Once
	trustedProxies   []*net.IPNet
}

const (
	maxJSONBodyBytes = 64 << 10
	// speedLimitBytes multiplies this field by 125000, so an unbounded value
	// wraps int64 and silently disables the limit instead of tightening it.
	// 1000000 matches the max the site form already enforces.
	maxSpeedLimitMbps      = 1000000
	maxLoginFailures       = 5
	maxTrackedLoginClients = 10000
	loginFailureWindow     = 15 * time.Minute
	loginLockoutDuration   = 15 * time.Minute
)

type loginAttempt struct {
	failures     int
	firstFailure time.Time
	blockedUntil time.Time
	lastSeen     time.Time
}

type loginRateLimiter struct {
	mu         sync.Mutex
	attempts   map[string]loginAttempt
	maxEntries int
}

func newLoginRateLimiter() *loginRateLimiter {
	return newLoginRateLimiterWithLimit(maxTrackedLoginClients)
}

func newLoginRateLimiterWithLimit(maxEntries int) *loginRateLimiter {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &loginRateLimiter{
		attempts:   make(map[string]loginAttempt),
		maxEntries: maxEntries,
	}
}

func (l *loginRateLimiter) pruneExpired(now time.Time) {
	for client, attempt := range l.attempts {
		if now.Before(attempt.blockedUntil) {
			continue
		}
		if attempt.firstFailure.IsZero() || !now.Before(attempt.firstFailure.Add(loginFailureWindow)) {
			delete(l.attempts, client)
		}
	}
}

func (l *loginRateLimiter) evictLeastRecentlySeen() {
	var oldestClient string
	var oldestSeen time.Time
	for client, attempt := range l.attempts {
		seen := attempt.lastSeen
		if seen.IsZero() {
			seen = attempt.firstFailure
		}
		if oldestClient == "" || seen.Before(oldestSeen) {
			oldestClient = client
			oldestSeen = seen
		}
	}
	if oldestClient != "" {
		delete(l.attempts, oldestClient)
	}
}

func (l *loginRateLimiter) allow(client string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneExpired(now)
	attempt, ok := l.attempts[client]
	if !ok {
		return true, 0
	}
	attempt.lastSeen = now
	if now.Before(attempt.blockedUntil) {
		l.attempts[client] = attempt
		return false, attempt.blockedUntil.Sub(now)
	}
	l.attempts[client] = attempt
	return true, 0
}

func (l *loginRateLimiter) recordFailure(client string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneExpired(now)
	attempt, exists := l.attempts[client]
	if !exists && len(l.attempts) >= l.maxEntries {
		l.evictLeastRecentlySeen()
	}
	if attempt.firstFailure.IsZero() || now.Sub(attempt.firstFailure) >= loginFailureWindow {
		attempt = loginAttempt{firstFailure: now}
	}
	attempt.failures++
	attempt.lastSeen = now
	if attempt.failures >= maxLoginFailures {
		attempt.blockedUntil = now.Add(loginLockoutDuration)
	}
	l.attempts[client] = attempt
}

func (l *loginRateLimiter) reset(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, client)
}

func (a *App) limiter() *loginRateLimiter {
	a.loginLimiterOnce.Do(func() {
		if a.loginLimiter == nil {
			a.loginLimiter = newLoginRateLimiter()
		}
	})
	return a.loginLimiter
}

func parseTrustedProxyCIDRs(value string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid TRUSTED_PROXY_CIDRS entry %q: %w", raw, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func remoteAddressIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(remoteAddr)
}

func isTrustedProxy(ip net.IP, networks []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func requestClientKey(r *http.Request, trustedProxies []*net.IPNet) string {
	peerIP := remoteAddressIP(r.RemoteAddr)
	if isTrustedProxy(peerIP, trustedProxies) {
		if forwarded := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); forwarded != nil {
			return forwarded.String()
		}
		for _, raw := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
			if forwarded := net.ParseIP(strings.TrimSpace(raw)); forwarded != nil {
				return forwarded.String()
			}
		}
	}
	if peerIP != nil {
		return peerIP.String()
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain one JSON object")
		}
		return err
	}
	return nil
}

func originMatchesRequestHost(origin string, r *http.Request) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func refererMatchesRequestHost(referer string, r *http.Request) bool {
	parsed, err := url.Parse(referer)
	if err != nil || parsed.User != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func requestHasSameOrigin(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		return originMatchesRequestHost(origin, r)
	}
	return refererMatchesRequestHost(r.Referer(), r)
}

func stateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if !originMatchesRequestHost(origin, r) {
				http.Error(w, "cross-origin request denied", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func staticHandler(staticFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(staticFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		f, err := staticFS.Open(strings.TrimPrefix(path, "/"))
		if err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}

func (a *App) jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("write JSON response: %v", err)
	}
}

func (a *App) jsonOK(w http.ResponseWriter, data interface{}) {
	a.jsonResponse(w, http.StatusOK, data)
}

func (a *App) jsonErr(w http.ResponseWriter, status int, msg string) {
	a.jsonResponse(w, status, map[string]string{"error": msg})
}

func requestIsHTTPS(r *http.Request, trustedProxies []*net.IPNet) bool {
	if r.TLS != nil {
		return true
	}
	if !isTrustedProxy(remoteAddressIP(r.RemoteAddr), trustedProxies) {
		return false
	}
	forwardedProto := strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]
	return strings.EqualFold(strings.TrimSpace(forwardedProto), "https")
}

func (a *App) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	// #nosec G124 -- direct HTTP panel access is a documented compatibility mode;
	// requestIsHTTPS only accepts X-Forwarded-Proto from configured proxies.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(sessionDuration),
		MaxAge:   int(sessionDuration.Seconds()),
		Secure:   requestIsHTTPS(r, a.trustedProxies),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (a *App) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	// #nosec G124 -- must match setSessionCookie so HTTP sessions can be cleared.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0),
		MaxAge:   -1,
		Secure:   requestIsHTTPS(r, a.trustedProxies),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func sessionIdentity(r *http.Request) (int64, string, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return 0, "", errors.New("missing session")
	}
	return validateToken(cookie.Value)
}

func (a *App) csrfMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if stateChangingMethod(r.Method) && !requestHasSameOrigin(r) {
			a.jsonErr(w, http.StatusForbidden, "same-origin request required")
			return
		}
		next(w, r)
	}
}

func (a *App) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := sessionIdentity(r); err != nil {
			a.jsonErr(w, http.StatusUnauthorized, "session expired or invalid")
			return
		}
		if stateChangingMethod(r.Method) && !requestHasSameOrigin(r) {
			a.jsonErr(w, http.StatusForbidden, "same-origin request required")
			return
		}
		next(w, r)
	}
}

// POST /api/auth/setup
func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.jsonErr(w, 405, "method not allowed")
		return
	}
	client := requestClientKey(r, a.trustedProxies)
	if allowed, retryAfter := a.limiter().allow(client, time.Now()); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retryAfter.Seconds()+0.5))))
		a.jsonErr(w, http.StatusTooManyRequests, "too many setup attempts; try again later")
		return
	}
	a.setupTokenMu.Lock()
	defer a.setupTokenMu.Unlock()
	userCount, err := a.db.UserCount()
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "setup status unavailable")
		return
	}
	if userCount > 0 {
		a.jsonErr(w, 400, "admin user already exists")
		return
	}
	var req struct {
		Username   string `json:"username"`
		Password   string `json:"password"` // #nosec G117 -- request-only credential DTO; the value is never serialized or stored in plaintext.
		SetupToken string `json:"setup_token"`
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		a.jsonErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Username) > 64 || len(req.Password) < 12 || len(req.Password) > 72 {
		a.jsonErr(w, http.StatusBadRequest, "username must be 1-64 characters and password must be 12-72 bytes")
		return
	}
	if a.setupToken == "" || !setupTokenMatches(a.setupToken, req.SetupToken) {
		a.limiter().recordFailure(client, time.Now())
		a.jsonErr(w, http.StatusForbidden, "invalid setup token")
		return
	}
	id, err := a.db.CreateInitialUser(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, errAdminAlreadyExists) {
			a.limiter().recordFailure(client, time.Now())
			a.jsonErr(w, http.StatusConflict, errAdminAlreadyExists.Error())
			return
		}
		a.jsonErr(w, http.StatusInternalServerError, "unable to create admin user")
		return
	}
	a.limiter().reset(client)
	token, err := generateToken(id, req.Username)
	if err != nil {
		a.jsonErr(w, 500, err.Error())
		return
	}
	a.setupToken = ""
	w.Header().Set("Cache-Control", "no-store")
	a.setSessionCookie(w, r, token)
	a.jsonOK(w, map[string]interface{}{"username": req.Username})
}

// POST /api/auth/login
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.jsonErr(w, 405, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"` // #nosec G117 -- request-only credential DTO; the value is never serialized or stored in plaintext.
	}
	client := requestClientKey(r, a.trustedProxies)
	if allowed, retryAfter := a.limiter().allow(client, time.Now()); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retryAfter.Seconds()+0.5))))
		a.jsonErr(w, http.StatusTooManyRequests, "too many login attempts; try again later")
		return
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		a.limiter().recordFailure(client, time.Now())
		a.jsonErr(w, 400, "invalid request")
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" || len(username) > 64 || req.Password == "" || len(req.Password) > 72 {
		a.limiter().recordFailure(client, time.Now())
		a.jsonErr(w, http.StatusUnauthorized, errInvalidCredentials.Error())
		return
	}
	id, err := a.db.VerifyUser(username, req.Password)
	if err != nil {
		a.limiter().recordFailure(client, time.Now())
		if errors.Is(err, errInvalidCredentials) {
			a.jsonErr(w, http.StatusUnauthorized, errInvalidCredentials.Error())
			return
		}
		a.jsonErr(w, http.StatusInternalServerError, "authentication unavailable")
		return
	}
	a.limiter().reset(client)
	token, err := generateToken(id, username)
	if err != nil {
		a.jsonErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	a.setSessionCookie(w, r, token)
	a.jsonOK(w, map[string]interface{}{"username": username})
}

// POST /api/auth/logout
func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	a.clearSessionCookie(w, r)
	a.jsonOK(w, map[string]bool{"logged_out": true})
}

// GET /api/auth/check
func (a *App) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	userCount, err := a.db.UserCount()
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "setup status unavailable")
		return
	}
	needsSetup := userCount == 0
	authenticated := false
	username := ""
	if !needsSetup {
		if _, sessionUsername, err := sessionIdentity(r); err == nil {
			authenticated = true
			username = sessionUsername
		}
	}
	a.jsonOK(w, map[string]interface{}{
		"needs_setup":          needsSetup,
		"mode":                 "single_admin",
		"jwt_secret_ephemeral": jwtSecretEphemeral,
		"setup_token_required": needsSetup,
		"authenticated":        authenticated,
		"username":             username,
	})
}

// GET /api/dashboard
func (a *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	snap, err := a.pm.TrafficSnapshot()
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "dashboard unavailable")
		return
	}
	a.jsonOK(w, snap)
}

// GET/POST /api/sites
func (a *App) handleSites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
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
		// Add running status
		type SiteWithStatus struct {
			Site
			Running bool `json:"running"`
		}
		result := make([]SiteWithStatus, len(sites))
		for i, s := range sites {
			st := live[s.ID]
			result[i] = SiteWithStatus{Site: s, Running: st.Running}
			result[i].TrafficUsed = st.TrafficUsed
		}
		a.jsonOK(w, result)

	case "POST":
		var req struct {
			Name              string   `json:"name"`
			ListenPort        int      `json:"listen_port"`
			TargetURL         string   `json:"target_url"`
			PlaybackTargetURL string   `json:"playback_target_url"`
			PlaybackMode      string   `json:"playback_mode"`
			StreamHosts       []string `json:"stream_hosts"`
			UAMode            string   `json:"ua_mode"`
			CustomUserAgent   string   `json:"custom_user_agent"`
			CustomClient      string   `json:"custom_client"`
			CustomVersion     string   `json:"custom_version"`
			Quota             int64    `json:"traffic_quota"`
			SpeedLimit        int      `json:"speed_limit"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			a.jsonErr(w, 400, "invalid request")
			return
		}
		if req.Name == "" || req.ListenPort == 0 || req.TargetURL == "" {
			a.jsonErr(w, 400, "name, listen_port, and target_url are required")
			return
		}
		if req.UAMode == "" {
			req.UAMode = "infuse"
		}
		if req.PlaybackMode == "" {
			req.PlaybackMode = "direct"
		}
		req.Name = strings.TrimSpace(req.Name)
		req.PlaybackMode = strings.ToLower(strings.TrimSpace(req.PlaybackMode))
		normalizedMode, customUserAgent, customClient, customVersion, err := normalizeUAConfig(req.UAMode, req.CustomUserAgent, req.CustomClient, req.CustomVersion)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		req.UAMode = normalizedMode
		req.CustomUserAgent = customUserAgent
		req.CustomClient = customClient
		req.CustomVersion = customVersion
		if err := validateSiteSettings(req.Name, req.ListenPort, req.TargetURL, req.PlaybackTargetURL, req.PlaybackMode, req.StreamHosts, req.UAMode, req.CustomUserAgent, req.CustomClient, req.CustomVersion, req.Quota, req.SpeedLimit); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		streamHostsJSON, _ := json.Marshal(req.StreamHosts)
		if req.StreamHosts == nil {
			streamHostsJSON = []byte("[]")
		}
		a.siteLifecycleMu.Lock()
		defer a.siteLifecycleMu.Unlock()
		site, err := a.db.CreateSiteRecord(Site{
			Name:              req.Name,
			ListenPort:        req.ListenPort,
			TargetURL:         req.TargetURL,
			PlaybackTargetURL: req.PlaybackTargetURL,
			PlaybackMode:      req.PlaybackMode,
			StreamHosts:       string(streamHostsJSON),
			UAMode:            req.UAMode,
			CustomUserAgent:   req.CustomUserAgent,
			CustomClient:      req.CustomClient,
			CustomVersion:     req.CustomVersion,
			TrafficQuota:      req.Quota,
			SpeedLimit:        req.SpeedLimit,
		})
		if err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		// Auto start
		if site.Enabled {
			if err := a.pm.StartSite(*site); err != nil {
				if deleteErr := a.db.DeleteSite(site.ID); deleteErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("start site: %v; rollback create: %v", err, deleteErr))
					return
				}
				a.jsonErr(w, 500, err.Error())
				return
			}
		}
		a.jsonResponse(w, http.StatusCreated, site)

	default:
		a.jsonErr(w, 405, "method not allowed")
	}
}

// PUT/DELETE /api/sites/{id}, POST /api/sites/{id}/toggle, GET /api/sites/{id}/diag
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
	case action == "toggle" && r.Method == "POST":
		a.siteLifecycleMu.Lock()
		defer a.siteLifecycleMu.Unlock()
		site, err := a.db.GetSite(id)
		if err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		if site.Enabled {
			// Turning off: stop (and flush) before flipping the flag, so a failed
			// flush aborts with the instance still running and the flag still on
			// - instance and DB stay consistent.
			if err := a.pm.StopSite(id); err != nil {
				a.jsonErr(w, 500, err.Error())
				return
			}
			if _, err := a.db.ToggleSite(id); err != nil {
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
			a.jsonOK(w, map[string]interface{}{"enabled": false})
			return
		}
		// Turning on: flip the flag first so a failed start can roll it back.
		if _, err := a.db.ToggleSite(id); err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		site, err = a.db.GetSite(id)
		if err != nil {
			if _, revertErr := a.db.ToggleSite(id); revertErr != nil {
				a.jsonErr(w, 500, fmt.Sprintf("load site: %v; rollback toggle: %v", err, revertErr))
				return
			}
			a.jsonErr(w, 500, err.Error())
			return
		}
		if err := a.pm.StartSite(*site); err != nil {
			if _, revertErr := a.db.ToggleSite(id); revertErr != nil {
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
			Name              string    `json:"name"`
			ListenPort        int       `json:"listen_port"`
			TargetURL         string    `json:"target_url"`
			PlaybackTargetURL *string   `json:"playback_target_url"`
			PlaybackMode      *string   `json:"playback_mode"`
			StreamHosts       *[]string `json:"stream_hosts"`
			UAMode            *string   `json:"ua_mode"`
			CustomUserAgent   *string   `json:"custom_user_agent"`
			CustomClient      *string   `json:"custom_client"`
			CustomVersion     *string   `json:"custom_version"`
			Quota             *int64    `json:"traffic_quota"`
			SpeedLimit        *int      `json:"speed_limit"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			a.jsonErr(w, 400, "invalid request")
			return
		}
		playbackTargetURL := oldSite.PlaybackTargetURL
		if req.PlaybackTargetURL != nil {
			playbackTargetURL = *req.PlaybackTargetURL
		}
		playbackMode := oldSite.PlaybackMode
		if req.PlaybackMode != nil {
			playbackMode = *req.PlaybackMode
		}
		streamHosts := oldSite.StreamHosts
		if req.StreamHosts != nil {
			sh, _ := json.Marshal(*req.StreamHosts)
			streamHosts = string(sh)
		}
		speedLimit := oldSite.SpeedLimit
		if req.SpeedLimit != nil {
			speedLimit = *req.SpeedLimit
		}
		quota := oldSite.TrafficQuota
		if req.Quota != nil {
			quota = *req.Quota
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
		candidate := *oldSite
		candidate.Name = req.Name
		candidate.ListenPort = req.ListenPort
		candidate.TargetURL = req.TargetURL
		candidate.PlaybackTargetURL = playbackTargetURL
		candidate.PlaybackMode = playbackMode
		candidate.StreamHosts = streamHosts
		candidate.UAMode = uaMode
		candidate.CustomUserAgent = customUserAgent
		candidate.CustomClient = customClient
		candidate.CustomVersion = customVersion
		candidate.TrafficQuota = quota
		candidate.SpeedLimit = speedLimit
		if err := validateSiteSettings(candidate.Name, candidate.ListenPort, candidate.TargetURL, candidate.PlaybackTargetURL, candidate.PlaybackMode, streamHostList, candidate.UAMode, candidate.CustomUserAgent, candidate.CustomClient, candidate.CustomVersion, candidate.TrafficQuota, candidate.SpeedLimit); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		needsPreStop := oldSite.Enabled && oldSite.ListenPort == candidate.ListenPort && a.pm.IsRunning(id)
		if needsPreStop {
			// Stop (and flush) before the DB update, so a failed flush aborts with
			// the old config still in the DB and the old instance still running -
			// instance and DB stay consistent.
			if err := a.pm.StopSite(id); err != nil {
				a.jsonErr(w, 500, err.Error())
				return
			}
		}
		if err := a.db.UpdateSiteRecord(candidate); err != nil {
			if needsPreStop {
				// The instance is stopped; bring it back from a fresh read (which
				// includes the flushed traffic) so the DB flag and the running set
				// stay consistent. If even the reload fails, say so explicitly:
				// the enabled row must never silently sit without an instance.
				restored, getErr := a.db.GetSite(id)
				if getErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("update site: %v; site stopped and reload failed: %v", err, getErr))
					return
				}
				if restartErr := a.pm.StartSite(*restored); restartErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("update site: %v; restore instance: %v", err, restartErr))
					return
				}
			}
			a.jsonErr(w, 500, err.Error())
			return
		}
		site, err := a.db.GetSite(id)
		if err != nil {
			// The record was already updated but cannot be reloaded for the
			// restart: roll the DB back to the old record so the enabled flag
			// never points at a configuration that never ran, then bring the
			// pre-stopped instance back from a fresh read. Any failure in the
			// rollback itself is reported explicitly.
			if rollbackErr := a.db.UpdateSiteRecord(*oldSite); rollbackErr != nil {
				a.jsonErr(w, 500, fmt.Sprintf("reload updated site: %v; rollback update: %v", err, rollbackErr))
				return
			}
			restoredSite, getErr := a.db.GetSite(id)
			if getErr != nil {
				a.jsonErr(w, 500, fmt.Sprintf("reload updated site: %v; reload rollback site: %v", err, getErr))
				return
			}
			if needsPreStop {
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
				if rollbackErr := a.db.UpdateSiteRecord(*oldSite); rollbackErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("start updated site: %v; rollback update: %v", err, rollbackErr))
					return
				}
				restoredSite, getErr := a.db.GetSite(id)
				if getErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("start updated site: %v; reload rollback site: %v", err, getErr))
					return
				}
				if needsPreStop {
					if restartErr := a.pm.StartSite(*restoredSite); restartErr != nil {
						a.jsonErr(w, 500, fmt.Sprintf("start updated site: %v; restored configuration is enabled but proxy is not running: %v", err, restartErr))
						return
					}
				}
				a.jsonErr(w, 500, err.Error())
				return
			}
		}
		a.jsonOK(w, site)

	case action == "" && r.Method == "DELETE":
		a.siteLifecycleMu.Lock()
		defer a.siteLifecycleMu.Unlock()
		// Only delete the DB row after the instance stopped cleanly (flush
		// succeeded); a failed flush aborts with the instance and row intact.
		if err := a.pm.StopSite(id); err != nil {
			a.jsonErr(w, 500, err.Error())
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
		a.jsonOK(w, map[string]string{"status": "deleted"})

	default:
		a.jsonErr(w, 405, "method not allowed")
	}
}

// GET /api/traffic/{site_id} and GET /api/traffic/{site_id}/snapshot
func (a *App) handleTraffic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/traffic/")

	if path == "overview" {
		snap, err := a.pm.TrafficSnapshot()
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "traffic overview unavailable")
			return
		}
		a.jsonOK(w, snap)
		return
	}

	envelope := false
	if strings.HasSuffix(path, "/snapshot") {
		envelope = true
		path = strings.TrimSuffix(path, "/snapshot")
	}

	siteID, err := strconv.ParseInt(path, 10, 64)
	if err != nil {
		a.jsonErr(w, 400, "invalid site id")
		return
	}

	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if v, err := strconv.Atoi(h); err == nil && v >= 1 && v <= 24*366 {
			hours = v
		} else {
			a.jsonErr(w, http.StatusBadRequest, "hours must be between 1 and 8784")
			return
		}
	}

	site, err := a.db.GetSite(siteID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if envelope {
				a.jsonErr(w, http.StatusNotFound, "site not found")
				return
			}
			// The legacy endpoint keeps returning an empty log array for
			// unknown sites.
			a.jsonOK(w, []TrafficLog{})
			return
		}
		a.jsonErr(w, 500, err.Error())
		return
	}

	history, err := a.pm.SiteTrafficHistory(*site, hours)
	if err != nil {
		a.jsonErr(w, 500, err.Error())
		return
	}
	if envelope {
		a.jsonOK(w, history)
		return
	}
	a.jsonOK(w, history.Logs)
}

// GET /api/ua-profiles
func (a *App) handleUAProfiles(w http.ResponseWriter, r *http.Request) {
	profiles := make([]UAProfile, 0, len(uaProfiles))
	for _, p := range uaProfiles {
		profiles = append(profiles, p)
	}
	a.jsonOK(w, profiles)
}

func (a *App) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		a.jsonErr(w, 500, "SSE not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()

	// Send initial data immediately
	if err := a.sendSSEEvent(w, flusher); err != nil {
		log.Printf("send initial SSE event: %v", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.sendSSEEvent(w, flusher); err != nil {
				log.Printf("send SSE event: %v", err)
				return
			}
		}
	}
}

func (a *App) sendSSEEvent(w http.ResponseWriter, flusher http.Flusher) error {
	snap, err := a.pm.TrafficSnapshot()
	if err != nil {
		return err
	}

	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil { // #nosec G705 -- json.Marshal escapes control characters before the SSE frame is written.
		return err
	}
	flusher.Flush()
	return nil
}

var startTime = time.Now()

// appVersion is overridable at build time via -ldflags "-X main.appVersion=vX.Y.Z".
var appVersion = "v1.5.6"

func runCommandLine(args []string, input io.Reader, output io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "--version", "-v":
		if len(args) != 1 {
			return true, errors.New("version command does not accept arguments")
		}
		_, err := fmt.Fprintln(output, appVersion)
		return true, err
	case "admin":
		return true, runAdminCommand(args[1:], input, output)
	default:
		return false, nil
	}
}

func runAdminCommand(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 || args[0] != "reset-password" {
		return errors.New("usage: meridian admin reset-password --db <path> --password-stdin")
	}
	var dbPath string
	passwordStdin := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--db":
			if dbPath != "" || i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
				return errors.New("--db requires exactly one non-empty path")
			}
			dbPath = args[i+1]
			i++
		case "--password-stdin":
			if passwordStdin {
				return errors.New("--password-stdin may only be specified once")
			}
			passwordStdin = true
		default:
			return errors.New("unknown reset-password argument")
		}
	}
	if dbPath == "" || !passwordStdin {
		return errors.New("usage: meridian admin reset-password --db <path> --password-stdin")
	}

	password, err := readPasswordLine(input)
	if err != nil {
		return err
	}
	db, err := openDB(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	if err := db.ResetAdminPassword(password); err != nil {
		return fmt.Errorf("reset administrator password: %w", err)
	}
	_, err = fmt.Fprintln(output, "administrator password updated")
	return err
}

func readPasswordLine(input io.Reader) (string, error) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64), 74)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return "", errors.New("password input is empty")
	}
	password := strings.TrimSuffix(scanner.Text(), "\r")
	if scanner.Scan() {
		return "", errors.New("password input must contain exactly one line")
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if err := validateAdminPassword(password); err != nil {
		return "", err
	}
	return password, nil
}

func panelListenAddress(bindAddress string, port int) (string, error) {
	bindAddress = strings.TrimSpace(bindAddress)
	if bindAddress == "" {
		bindAddress = "0.0.0.0"
	}
	if net.ParseIP(bindAddress) == nil {
		return "", fmt.Errorf("PANEL_BIND_ADDR must be an IP address, got %q", bindAddress)
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("panel port must be between 1 and 65535, got %d", port)
	}
	return net.JoinHostPort(bindAddress, strconv.Itoa(port)), nil
}

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

	db, err := openDB(dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	userCount, err := db.UserCount()
	if err != nil {
		log.Fatalf("failed to count users: %v", err)
	}
	setupToken, err := configuredSetupToken(userCount, os.Getenv("SETUP_TOKEN"))
	if err != nil {
		log.Fatalf("initial setup unavailable: %v", err)
	}

	pm := NewProxyManager(db)
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

	trustedProxies, err := parseTrustedProxyCIDRs(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		log.Fatalf("invalid trusted proxy configuration: %v", err)
	}
	app := &App{
		db:             db,
		pm:             pm,
		setupToken:     setupToken,
		loginLimiter:   newLoginRateLimiter(),
		trustedProxies: trustedProxies,
	}

	mux := http.NewServeMux()

	// Public auth routes
	mux.HandleFunc("/api/auth/setup", cors(app.csrfMiddleware(app.handleSetup)))
	mux.HandleFunc("/api/auth/login", cors(app.csrfMiddleware(app.handleLogin)))
	mux.HandleFunc("/api/auth/logout", cors(app.csrfMiddleware(app.handleLogout)))
	mux.HandleFunc("/api/auth/check", cors(app.handleAuthCheck))

	// Protected routes
	mux.HandleFunc("/api/dashboard", cors(app.authMiddleware(app.handleDashboard)))
	mux.HandleFunc("/api/sites", cors(app.authMiddleware(app.handleSites)))
	mux.HandleFunc("/api/sites/", cors(app.authMiddleware(app.handleSiteByID)))
	mux.HandleFunc("/api/traffic/", cors(app.authMiddleware(app.handleTraffic)))
	mux.HandleFunc("/api/ua-profiles", cors(app.authMiddleware(app.handleUAProfiles)))
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

	// HTTP server with graceful shutdown. Site listeners remain independently
	// bound by ProxyManager and are not affected by PANEL_BIND_ADDR.
	addr, err := panelListenAddress(os.Getenv("PANEL_BIND_ADDR"), port)
	if err != nil {
		log.Fatalf("invalid panel listen address: %v", err)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // no write timeout for streaming
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	log.Println("============================================================")
	log.Printf("  Meridian - Emby reverse proxy management panel %s", appVersion)
	log.Printf("  Listening on: http://%s", addr)
	log.Printf("  Sites loaded: %d (%d running)", loadedSiteCount, pm.GetRunningCount())
	log.Println("  Features: WebSocket proxy, TLS diagnostics, traffic limits")
	log.Println("============================================================")

	// Signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server failed: %v", err)
		}
	}()

	<-sigCh
	log.Println("\nReceived shutdown signal, stopping Meridian...")

	// Cancel background goroutines
	cancel()

	// Shutdown proxies (flushes traffic)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	pm.GracefulShutdown(shutdownCtx)
	srv.Shutdown(shutdownCtx)

	log.Println("Meridian stopped cleanly")
}
