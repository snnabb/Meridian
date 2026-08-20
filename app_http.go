package main

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
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
		if requestIsHTTPS(r, nil) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func panelBodyReadDeadline(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && (r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
			controller := http.NewResponseController(w)
			// Keep the deadline through net/http's post-handler request-body drain.
			// Clearing it when the handler returns lets a slow client keep dripping an
			// unread body indefinitely. The server installs the next request/idle
			// deadline before reusing a healthy keep-alive connection.
			_ = controller.SetReadDeadline(time.Now().Add(30 * time.Second))
		}
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

func (a *App) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	// codeql[go/cookie-secure-not-set] -- documented HTTP panel compatibility; Secure is enabled automatically for HTTPS requests.
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
	// codeql[go/cookie-secure-not-set] -- documented HTTP panel compatibility; Secure is enabled automatically for HTTPS requests.
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
	for _, cookie := range r.Cookies() {
		if cookie.Name != sessionCookieName || cookie.Value == "" {
			continue
		}
		userID, username, err := validateToken(cookie.Value)
		if err == nil {
			// Accept the signed management value even if an untrusted sibling
			// origin managed to prepend an invalid same-name cookie. The attacker
			// cannot forge a second valid token, so this avoids cookie-shadowing
			// logout/DoS without weakening authentication.
			return userID, username, nil
		}
	}
	return 0, "", errors.New("missing or invalid session")
}

func (a *App) authenticatedSession(r *http.Request) (int64, string, error) {
	userID, username, err := sessionIdentity(r)
	if err != nil {
		return 0, "", err
	}
	if a == nil || a.db == nil {
		return 0, "", errors.New("session database unavailable")
	}
	account, err := a.db.AdminAccountByID(userID)
	if err != nil || account.Username != username {
		return 0, "", errors.New("session identity no longer valid")
	}
	return userID, username, nil
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
		if _, _, err := a.authenticatedSession(r); err != nil {
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
		a.jsonErr(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	id, err := a.db.VerifyUser(username, req.Password)
	if err != nil {
		a.limiter().recordFailure(client, time.Now())
		if errors.Is(err, errInvalidCredentials) {
			a.jsonErr(w, http.StatusUnauthorized, "用户名或密码错误")
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
		if _, sessionUsername, err := a.authenticatedSession(r); err == nil {
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

// GET/PUT /api/account
func (a *App) handleAccount(w http.ResponseWriter, r *http.Request) {
	userID, _, err := a.authenticatedSession(r)
	if err != nil {
		a.jsonErr(w, http.StatusUnauthorized, "session expired or invalid")
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	switch r.Method {
	case http.MethodGet:
		account, err := a.db.AdminAccountByID(userID)
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "account information unavailable")
			return
		}
		a.jsonOK(w, account)
	case http.MethodPut:
		var req struct {
			Username        string `json:"username"`
			CurrentPassword string `json:"current_password"` // #nosec G117 -- request-only credential DTO; the value is never serialized or stored in plaintext.
			NewPassword     string `json:"new_password"`     // #nosec G117 -- request-only credential DTO; the value is never serialized or stored in plaintext.
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			a.jsonErr(w, http.StatusBadRequest, "invalid request")
			return
		}
		account, err := a.db.UpdateAdminAccount(userID, req.CurrentPassword, req.Username, req.NewPassword)
		if err != nil {
			switch {
			case errors.Is(err, errInvalidCredentials):
				a.jsonErr(w, http.StatusForbidden, "current password is incorrect")
			case errors.Is(err, errInvalidAdminUsername), errors.Is(err, errInvalidAdminPassword), errors.Is(err, errNoAccountChanges):
				a.jsonErr(w, http.StatusBadRequest, err.Error())
			default:
				a.jsonErr(w, http.StatusInternalServerError, "unable to update account")
			}
			return
		}
		token, err := generateToken(userID, account.Username)
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "unable to refresh session")
			return
		}
		a.setSessionCookie(w, r, token)
		a.jsonOK(w, account)
	default:
		w.Header().Set("Allow", "GET, PUT")
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// GET /api/dashboard
