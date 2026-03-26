package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"

	"emby-panel/web"
)

// ═══════════════════════════════════════════════════════════════
// UA Profiles — only 3 modes
// ═══════════════════════════════════════════════════════════════

type UAProfile struct {
	Name      string `json:"name"`
	UserAgent string `json:"user_agent"`
	Client    string `json:"client"`
}

var uaProfiles = map[string]UAProfile{
	"infuse": {Name: "Infuse", UserAgent: "Infuse/7.8.1", Client: "Infuse"},
	"web":    {Name: "Web", UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Emby Theater", Client: "Emby Web"},
	"client": {Name: "客户端", UserAgent: "Emby-Theater/4.7.0", Client: "Emby Theater"},
}

func getUAProfile(mode string) UAProfile {
	if p, ok := uaProfiles[strings.ToLower(mode)]; ok {
		return p
	}
	return uaProfiles["infuse"]
}

// ═══════════════════════════════════════════════════════════════
// JWT helpers (simple HMAC-SHA256)
// ═══════════════════════════════════════════════════════════════

var jwtSecret []byte

func init() {
	s := os.Getenv("JWT_SECRET")
	if s == "" {
		s = "embyhub-default-secret-change-me"
	}
	jwtSecret = []byte(s)
}

// Minimal JWT — no external dependency
func generateToken(userID int64, username string) (string, error) {
	header := base64url([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := fmt.Sprintf(`{"sub":%d,"name":"%s","exp":%d}`, userID, username, time.Now().Add(72*time.Hour).Unix())
	payloadEnc := base64url([]byte(payload))
	sig := hmacSHA256(header+"."+payloadEnc, jwtSecret)
	return header + "." + payloadEnc + "." + sig, nil
}

func validateToken(token string) (int64, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, "", fmt.Errorf("invalid token")
	}
	expectedSig := hmacSHA256(parts[0]+"."+parts[1], jwtSecret)
	if parts[2] != expectedSig {
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


// ═══════════════════════════════════════════════════════════════
// Crypto helpers
// ═══════════════════════════════════════════════════════════════


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

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ═══════════════════════════════════════════════════════════════
// Database
// ═══════════════════════════════════════════════════════════════

type DB struct {
	db *sql.DB
}

func openDB(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	d := &DB{db: sqlDB}
	if err := d.migrate(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *DB) Close() { d.db.Close() }

func (d *DB) migrate() error {
	_, err := d.db.Exec(`
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
		ua_mode TEXT DEFAULT 'infuse',
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
	`)
	return err
}

// ═══════════════════════════════════════════════════════════════
// Models
// ═══════════════════════════════════════════════════════════════

type Site struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	ListenPort   int    `json:"listen_port"`
	TargetURL    string `json:"target_url"`
	UAMode       string `json:"ua_mode"`
	Enabled      bool   `json:"enabled"`
	TrafficQuota int64  `json:"traffic_quota"`
	TrafficUsed  int64  `json:"traffic_used"`
	SpeedLimit   int    `json:"speed_limit"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type TrafficLog struct {
	ID         int64  `json:"id"`
	SiteID     int64  `json:"site_id"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	RecordedAt string `json:"recorded_at"`
}

// ═══════════════════════════════════════════════════════════════
// DB operations
// ═══════════════════════════════════════════════════════════════

func (d *DB) UserCount() int {
	var n int
	d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n
}

func (d *DB) CreateUser(username, password string) (int64, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	res, err := d.db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, string(hash))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) VerifyUser(username, password string) (int64, error) {
	var id int64
	var hash string
	err := d.db.QueryRow("SELECT id, password_hash FROM users WHERE username=?", username).Scan(&id, &hash)
	if err != nil {
		return 0, fmt.Errorf("用户不存在")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return 0, fmt.Errorf("密码错误")
	}
	return id, nil
}

func (d *DB) ListSites() ([]Site, error) {
	rows, err := d.db.Query("SELECT id, name, listen_port, target_url, ua_mode, enabled, traffic_quota, traffic_used, speed_limit, created_at, updated_at FROM sites ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sites []Site
	for rows.Next() {
		var s Site
		var enabled int
		rows.Scan(&s.ID, &s.Name, &s.ListenPort, &s.TargetURL, &s.UAMode, &enabled, &s.TrafficQuota, &s.TrafficUsed, &s.SpeedLimit, &s.CreatedAt, &s.UpdatedAt)
		s.Enabled = enabled == 1
		sites = append(sites, s)
	}
	if sites == nil {
		sites = []Site{}
	}
	return sites, nil
}

func (d *DB) GetSite(id int64) (*Site, error) {
	var s Site
	var enabled int
	err := d.db.QueryRow("SELECT id, name, listen_port, target_url, ua_mode, enabled, traffic_quota, traffic_used, speed_limit, created_at, updated_at FROM sites WHERE id=?", id).
		Scan(&s.ID, &s.Name, &s.ListenPort, &s.TargetURL, &s.UAMode, &enabled, &s.TrafficQuota, &s.TrafficUsed, &s.SpeedLimit, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	s.Enabled = enabled == 1
	return &s, nil
}

func (d *DB) CreateSite(name string, port int, targetURL, uaMode string, quota int64, speedLimit int) (*Site, error) {
	res, err := d.db.Exec(
		"INSERT INTO sites (name, listen_port, target_url, ua_mode, traffic_quota, speed_limit) VALUES (?,?,?,?,?,?)",
		name, port, targetURL, uaMode, quota, speedLimit,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return d.GetSite(id)
}

func (d *DB) UpdateSite(id int64, name string, port int, targetURL, uaMode string, quota int64, speedLimit int) error {
	_, err := d.db.Exec(
		"UPDATE sites SET name=?, listen_port=?, target_url=?, ua_mode=?, traffic_quota=?, speed_limit=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
		name, port, targetURL, uaMode, quota, speedLimit, id,
	)
	return err
}

func (d *DB) DeleteSite(id int64) error {
	tx, _ := d.db.Begin()
	tx.Exec("DELETE FROM traffic_logs WHERE site_id=?", id)
	tx.Exec("DELETE FROM sites WHERE id=?", id)
	return tx.Commit()
}

func (d *DB) ToggleSite(id int64) (bool, error) {
	var enabled int
	d.db.QueryRow("SELECT enabled FROM sites WHERE id=?", id).Scan(&enabled)
	newVal := 1 - enabled
	_, err := d.db.Exec("UPDATE sites SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", newVal, id)
	return newVal == 1, err
}

func (d *DB) AddTraffic(siteID, bytesIn, bytesOut int64) {
	hour := time.Now().Truncate(time.Hour).Format("2006-01-02 15:04:05")
	d.db.Exec(
		"INSERT INTO traffic_logs (site_id, bytes_in, bytes_out, recorded_at) VALUES (?,?,?,?) ON CONFLICT DO NOTHING",
		siteID, bytesIn, bytesOut, hour,
	)
	// Try update first
	res, _ := d.db.Exec(
		"UPDATE traffic_logs SET bytes_in=bytes_in+?, bytes_out=bytes_out+? WHERE site_id=? AND recorded_at=?",
		bytesIn, bytesOut, siteID, hour,
	)
	if n, _ := res.RowsAffected(); n == 0 {
		d.db.Exec(
			"INSERT INTO traffic_logs (site_id, bytes_in, bytes_out, recorded_at) VALUES (?,?,?,?)",
			siteID, bytesIn, bytesOut, hour,
		)
	}
	d.db.Exec("UPDATE sites SET traffic_used=traffic_used+?+?, updated_at=CURRENT_TIMESTAMP WHERE id=?", bytesIn, bytesOut, siteID)
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
		rows.Scan(&l.ID, &l.SiteID, &l.BytesIn, &l.BytesOut, &l.RecordedAt)
		logs = append(logs, l)
	}
	if logs == nil {
		logs = []TrafficLog{}
	}
	return logs, nil
}

func (d *DB) DashboardStats() map[string]interface{} {
	var total, online int
	d.db.QueryRow("SELECT COUNT(*) FROM sites").Scan(&total)
	d.db.QueryRow("SELECT COUNT(*) FROM sites WHERE enabled=1").Scan(&online)
	var totalTraffic int64
	d.db.QueryRow("SELECT COALESCE(SUM(traffic_used),0) FROM sites").Scan(&totalTraffic)
	return map[string]interface{}{
		"total_sites":   total,
		"online_sites":  online,
		"total_traffic": totalTraffic,
	}
}

// ═══════════════════════════════════════════════════════════════
// Proxy Engine
// ═══════════════════════════════════════════════════════════════

var embyAuthClientRe = regexp.MustCompile(`(?i)(Client=")[^"]*"`)

type ProxyInstance struct {
	Site     Site
	server   *http.Server
	listener net.Listener
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
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

func (pm *ProxyManager) StartSite(site Site) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Stop existing if any
	if inst, ok := pm.proxies[site.ID]; ok {
		inst.server.Close()
		delete(pm.proxies, site.ID)
	}

	addr := site.TargetURL
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = "http://" + addr
	}
	target, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	profile := getUAProfile(site.UAMode)
	inst := &ProxyInstance{Site: site}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			req.Header.Set("User-Agent", profile.UserAgent)
			if auth := req.Header.Get("X-Emby-Authorization"); auth != "" {
				if embyAuthClientRe.MatchString(auth) {
					auth = embyAuthClientRe.ReplaceAllString(auth, `${1}`+profile.Client+`"`)
				}
				req.Header.Set("X-Emby-Authorization", auth)
			}
			if auth := req.Header.Get("Authorization"); auth != "" {
				if embyAuthClientRe.MatchString(auth) {
					auth = embyAuthClientRe.ReplaceAllString(auth, `${1}`+profile.Client+`"`)
				}
				req.Header.Set("Authorization", auth)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("X-Frame-Options")
			resp.Header.Del("Content-Security-Policy")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[%s] proxy error: %v", site.Name, err)
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error":"upstream unavailable"}`))
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Meter request body
		if r.Body != nil {
			r.Body = &meteredReader{ReadCloser: r.Body, read: &inst.bytesIn}
		}
		mw := &meteredWriter{ResponseWriter: w, written: &inst.bytesOut}
		proxy.ServeHTTP(mw, r)
	})

	listenAddr := fmt.Sprintf(":%d", site.ListenPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}

	server := &http.Server{
		Handler:      handler,
		ReadTimeout:  0,
		WriteTimeout: 0,
	}

	inst.server = server
	inst.listener = listener
	pm.proxies[site.ID] = inst

	go func() {
		log.Printf("[%s] proxy :%d → %s (UA: %s)", site.Name, site.ListenPort, site.TargetURL, site.UAMode)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[%s] server error: %v", site.Name, err)
		}
	}()

	return nil
}

func (pm *ProxyManager) StopSite(id int64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if inst, ok := pm.proxies[id]; ok {
		inst.server.Close()
		delete(pm.proxies, id)
	}
}

func (pm *ProxyManager) IsRunning(id int64) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	_, ok := pm.proxies[id]
	return ok
}

func (pm *ProxyManager) StartAllEnabled() {
	sites, _ := pm.database.ListSites()
	for _, s := range sites {
		if s.Enabled {
			if err := pm.StartSite(s); err != nil {
				log.Printf("[%s] failed to start: %v", s.Name, err)
			}
		}
	}
}

// Flush traffic counters to DB periodically
func (pm *ProxyManager) FlushTraffic() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for _, inst := range pm.proxies {
		in := inst.bytesIn.Swap(0)
		out := inst.bytesOut.Swap(0)
		if in > 0 || out > 0 {
			pm.database.AddTraffic(inst.Site.ID, in, out)
		}
	}
}

func (pm *ProxyManager) GetRunningCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.proxies)
}

// ═══════════════════════════════════════════════════════════════
// Diagnostics
// ═══════════════════════════════════════════════════════════════

type DiagResult struct {
	Health  DiagHealth  `json:"health"`
	TLS     DiagTLS     `json:"tls"`
	Headers DiagHeaders `json:"headers"`
	Proxy   DiagProxy   `json:"proxy"`
}

type DiagHealth struct {
	Status     string `json:"status"` // online, offline, error
	EmbyVer    string `json:"emby_version"`
	LatencyMs  int64  `json:"latency_ms"`
	Error      string `json:"error,omitempty"`
}

type DiagTLS struct {
	Enabled    bool   `json:"enabled"`
	Valid      bool   `json:"valid"`
	Issuer     string `json:"issuer"`
	ExpiresAt  string `json:"expires_at"`
	DaysLeft   int    `json:"days_left"`
	Error      string `json:"error,omitempty"`
}

type DiagHeaders struct {
	UAApplied    bool   `json:"ua_applied"`
	CurrentUA    string `json:"current_ua"`
	ClientField  string `json:"client_field"`
}

type DiagProxy struct {
	Running    bool  `json:"running"`
	ListenPort int   `json:"listen_port"`
	TotalReqs  int64 `json:"total_requests"`
}

func diagnoseSite(site *Site, pm *ProxyManager) DiagResult {
	result := DiagResult{}
	profile := getUAProfile(site.UAMode)

	// Health check
	addr := site.TargetURL
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}

	client := &http.Client{Timeout: 5 * time.Second}
	start := time.Now()
	resp, err := client.Get(addr + "/emby/System/Info/Public")
	latency := time.Since(start).Milliseconds()

	if err != nil {
		result.Health = DiagHealth{Status: "offline", LatencyMs: latency, Error: err.Error()}
	} else {
		defer resp.Body.Close()
		result.Health = DiagHealth{Status: "online", LatencyMs: latency}
		if resp.StatusCode >= 400 {
			result.Health.Status = "error"
		}
		var info map[string]interface{}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(body, &info) == nil {
			if v, ok := info["Version"]; ok {
				result.Health.EmbyVer = fmt.Sprintf("%v", v)
			}
		}
	}

	// TLS check
	parsed, _ := url.Parse(addr)
	if parsed != nil && parsed.Scheme == "https" {
		result.TLS.Enabled = true
		host := parsed.Hostname()
		port := parsed.Port()
		if port == "" {
			port = "443"
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host+":"+port, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			result.TLS.Error = err.Error()
		} else {
			defer conn.Close()
			certs := conn.ConnectionState().PeerCertificates
			if len(certs) > 0 {
				cert := certs[0]
				result.TLS.Valid = time.Now().Before(cert.NotAfter)
				result.TLS.Issuer = cert.Issuer.Organization[0]
				result.TLS.ExpiresAt = cert.NotAfter.Format("2006-01-02")
				result.TLS.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
			}
		}
	}

	// Headers
	result.Headers = DiagHeaders{
		UAApplied:   true,
		CurrentUA:   profile.UserAgent,
		ClientField: profile.Client,
	}

	// Proxy status
	result.Proxy = DiagProxy{
		Running:    pm.IsRunning(site.ID),
		ListenPort: site.ListenPort,
	}

	return result
}

// ═══════════════════════════════════════════════════════════════
// HTTP API
// ═══════════════════════════════════════════════════════════════

type App struct {
	db *DB
	pm *ProxyManager
}

func (a *App) jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (a *App) jsonErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (a *App) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			a.jsonErr(w, 401, "未登录")
			return
		}
		_, _, err := validateToken(strings.TrimPrefix(auth, "Bearer "))
		if err != nil {
			a.jsonErr(w, 401, "登录已过期")
			return
		}
		next(w, r)
	}
}

// POST /api/auth/setup
func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.jsonErr(w, 405, "method not allowed")
		return
	}
	if a.db.UserCount() > 0 {
		a.jsonErr(w, 400, "管理员已存在")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || len(req.Password) < 6 {
		a.jsonErr(w, 400, "用户名不能为空，密码至少 6 位")
		return
	}
	id, err := a.db.CreateUser(req.Username, req.Password)
	if err != nil {
		a.jsonErr(w, 500, err.Error())
		return
	}
	token, _ := generateToken(id, req.Username)
	a.jsonOK(w, map[string]interface{}{"token": token, "username": req.Username})
}

// POST /api/auth/login
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.jsonErr(w, 405, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.jsonErr(w, 400, "invalid request")
		return
	}
	id, err := a.db.VerifyUser(req.Username, req.Password)
	if err != nil {
		a.jsonErr(w, 401, err.Error())
		return
	}
	token, _ := generateToken(id, req.Username)
	a.jsonOK(w, map[string]interface{}{"token": token, "username": req.Username})
}

// GET /api/auth/check
func (a *App) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	a.jsonOK(w, map[string]interface{}{"needs_setup": a.db.UserCount() == 0})
}

// GET /api/dashboard
func (a *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	stats := a.db.DashboardStats()
	stats["running_sites"] = a.pm.GetRunningCount()
	a.jsonOK(w, stats)
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
		// Add running status
		type SiteWithStatus struct {
			Site
			Running bool `json:"running"`
		}
		result := make([]SiteWithStatus, len(sites))
		for i, s := range sites {
			result[i] = SiteWithStatus{Site: s, Running: a.pm.IsRunning(s.ID)}
		}
		a.jsonOK(w, result)

	case "POST":
		var req struct {
			Name       string `json:"name"`
			ListenPort int    `json:"listen_port"`
			TargetURL  string `json:"target_url"`
			UAMode     string `json:"ua_mode"`
			Quota      int64  `json:"traffic_quota"`
			SpeedLimit int    `json:"speed_limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			a.jsonErr(w, 400, "invalid request")
			return
		}
		if req.Name == "" || req.ListenPort == 0 || req.TargetURL == "" {
			a.jsonErr(w, 400, "名称、端口、回源地址不能为空")
			return
		}
		if req.UAMode == "" {
			req.UAMode = "infuse"
		}
		site, err := a.db.CreateSite(req.Name, req.ListenPort, req.TargetURL, req.UAMode, req.Quota, req.SpeedLimit)
		if err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		// Auto start
		if site.Enabled {
			a.pm.StartSite(*site)
		}
		w.WriteHeader(201)
		a.jsonOK(w, site)

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
		newState, err := a.db.ToggleSite(id)
		if err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		if newState {
			site, _ := a.db.GetSite(id)
			if site != nil {
				a.pm.StartSite(*site)
			}
		} else {
			a.pm.StopSite(id)
		}
		a.jsonOK(w, map[string]interface{}{"enabled": newState})

	case action == "diag" && r.Method == "GET":
		site, err := a.db.GetSite(id)
		if err != nil {
			a.jsonErr(w, 404, "站点不存在")
			return
		}
		result := diagnoseSite(site, a.pm)
		a.jsonOK(w, result)

	case action == "" && r.Method == "PUT":
		var req struct {
			Name       string `json:"name"`
			ListenPort int    `json:"listen_port"`
			TargetURL  string `json:"target_url"`
			UAMode     string `json:"ua_mode"`
			Quota      int64  `json:"traffic_quota"`
			SpeedLimit int    `json:"speed_limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			a.jsonErr(w, 400, "invalid request")
			return
		}
		if err := a.db.UpdateSite(id, req.Name, req.ListenPort, req.TargetURL, req.UAMode, req.Quota, req.SpeedLimit); err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		// Restart proxy with new config
		a.pm.StopSite(id)
		site, _ := a.db.GetSite(id)
		if site != nil && site.Enabled {
			a.pm.StartSite(*site)
		}
		a.jsonOK(w, site)

	case action == "" && r.Method == "DELETE":
		a.pm.StopSite(id)
		if err := a.db.DeleteSite(id); err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		a.jsonOK(w, map[string]string{"status": "deleted"})

	default:
		a.jsonErr(w, 405, "method not allowed")
	}
}

// GET /api/traffic/{site_id}
func (a *App) handleTraffic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/traffic/")

	if path == "overview" {
		stats := a.db.DashboardStats()
		a.jsonOK(w, stats)
		return
	}

	siteID, err := strconv.ParseInt(path, 10, 64)
	if err != nil {
		a.jsonErr(w, 400, "invalid site id")
		return
	}

	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if v, err := strconv.Atoi(h); err == nil {
			hours = v
		}
	}

	logs, err := a.db.GetTrafficLogs(siteID, hours)
	if err != nil {
		a.jsonErr(w, 500, err.Error())
		return
	}
	a.jsonOK(w, logs)
}

// GET /api/ua-profiles
func (a *App) handleUAProfiles(w http.ResponseWriter, r *http.Request) {
	profiles := make([]UAProfile, 0, len(uaProfiles))
	for _, p := range uaProfiles {
		profiles = append(profiles, p)
	}
	a.jsonOK(w, profiles)
}

// ═══════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════

func main() {
	port := 9090
	dbPath := "emby-panel.db"

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
		log.Fatalf("数据库初始化失败: %v", err)
	}
	defer db.Close()

	pm := NewProxyManager(db)
	pm.StartAllEnabled()

	// Traffic flush goroutine
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		for range ticker.C {
			pm.FlushTraffic()
		}
	}()

	app := &App{db: db, pm: pm}

	mux := http.NewServeMux()

	// CORS middleware wrapper
	cors := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
			if r.Method == "OPTIONS" {
				w.WriteHeader(204)
				return
			}
			h(w, r)
		}
	}

	// Public auth routes
	mux.HandleFunc("/api/auth/setup", cors(app.handleSetup))
	mux.HandleFunc("/api/auth/login", cors(app.handleLogin))
	mux.HandleFunc("/api/auth/check", cors(app.handleAuthCheck))

	// Protected routes
	mux.HandleFunc("/api/dashboard", cors(app.authMiddleware(app.handleDashboard)))
	mux.HandleFunc("/api/sites", cors(app.authMiddleware(app.handleSites)))
	mux.HandleFunc("/api/sites/", cors(app.authMiddleware(app.handleSiteByID)))
	mux.HandleFunc("/api/traffic/", cors(app.authMiddleware(app.handleTraffic)))
	mux.HandleFunc("/api/ua-profiles", cors(app.authMiddleware(app.handleUAProfiles)))

	// Embedded static files
	staticFS, err := fs.Sub(web.StaticFiles, "static")
	if err != nil {
		log.Fatalf("嵌入文件加载失败: %v", err)
	}
	fileServer := http.FileServer(http.FS(staticFS))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Try to serve static file
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		f, err := staticFS.Open(strings.TrimPrefix(path, "/"))
		if err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		// SPA fallback
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})

	addr := fmt.Sprintf(":%d", port)
	log.Println("═══════════════════════════════════════════")
	log.Println("  EmbyHub — Emby 反代控制面板")
	log.Printf("  管理面板: http://0.0.0.0%s", addr)
	log.Printf("  已加载 %d 个站点 (%d 运行中)", func() int { s, _ := db.ListSites(); return len(s) }(), pm.GetRunningCount())
	log.Println("═══════════════════════════════════════════")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}
