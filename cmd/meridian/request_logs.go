package main

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	requestLogQueueCapacity               = 4096
	requestLogBatchSize                   = 128
	requestLogGlobalRowLimit              = 20000
	requestLogRetention                   = 30 * 24 * time.Hour
	requestLogMaxSiteNameBytes            = 100
	requestLogMaxClientIPBytes            = 64
	requestLogMaxUserAgentBytes           = 512
	requestLogMaxPathBytes                = 1024
	requestLogCategoryPlayback            = "playback"
	requestLogCategoryPlaybackSync        = "playback_sync"
	requestLogCategoryVideo               = "video" // legacy grouped value retained for old rows and filters
	requestLogCategoryStream              = "stream"
	requestLogCategoryManifest            = "manifest"
	requestLogCategorySegment             = "segment"
	requestLogCategoryImage               = "image"
	requestLogCategoryMetadata            = "metadata"
	requestLogCategorySubtitle            = "subtitle"
	requestLogCategoryAsset               = "asset"
	requestLogCategoryWebSocket           = "websocket"
	requestLogCategoryAPI                 = "api"
	requestLogCategoryAuth                = "auth"
	clientClosedRequestStatus             = 499
	requestLogLegacyPlaybackSyncPredicate = `(lower(request_logs.path)='/sessions/playing' OR lower(request_logs.path) LIKE '/sessions/playing/%' OR lower(request_logs.path)='/emby/sessions/playing' OR lower(request_logs.path) LIKE '/emby/sessions/playing/%')`
)

// requestLogEvent is the bounded hot-path payload accepted from a site proxy.
// Query strings, request/response headers other than the sanitized User-Agent,
// cookies, tokens and bodies are deliberately excluded.
type requestLogEvent struct {
	SiteID            int64
	SiteName          string
	ResourceCategory  string
	StatusCode        int
	ClientIP          string
	InboundColo       string
	OutboundColo      string
	UserAgent         string
	UpstreamUserAgent string
	BackendAddress    string
	Method            string
	Path              string
}

type RequestLog struct {
	ID                int64  `json:"id"`
	SiteID            int64  `json:"site_id"`
	SiteName          string `json:"site_name"`
	ResourceCategory  string `json:"resource_category"`
	StatusCode        int    `json:"status_code"`
	ClientIP          string `json:"client_ip"`
	ClientRegion      string `json:"client_region"`
	InboundColo       string `json:"inbound_colo"`
	OutboundColo      string `json:"outbound_colo"`
	UserAgent         string `json:"user_agent"`
	UpstreamUserAgent string `json:"upstream_user_agent"`
	BackendAddress    string `json:"backend_address"`
	Method            string `json:"method"`
	Path              string `json:"path"`
	RecordedAtMS      int64  `json:"recorded_at_ms"`
}

type RequestLogFilter struct {
	FromMS      int64
	ToMS        int64
	Category    string
	StatusGroup string
	Query       string
	Limit       int
}

type RequestLogsResponse struct {
	Logs        []RequestLog `json:"logs"`
	DroppedLogs uint64       `json:"dropped_logs"`
}

type queuedRequestLog struct {
	event        requestLogEvent
	recordedAtMS int64
	timelineAtMS int64
}

func validRequestLogCategory(category string) bool {
	switch category {
	case requestLogCategoryPlayback, requestLogCategoryPlaybackSync, requestLogCategoryVideo, requestLogCategoryStream,
		requestLogCategoryManifest, requestLogCategorySegment, requestLogCategoryImage,
		requestLogCategoryMetadata, requestLogCategorySubtitle, requestLogCategoryAsset,
		requestLogCategoryWebSocket, requestLogCategoryAPI, requestLogCategoryAuth:
		return true
	default:
		return false
	}
}

// EnqueueRequestLog never waits for SQLite. Request logging is optional
// operator telemetry and must not add latency or backpressure to media traffic.
func (d *DB) EnqueueRequestLog(event requestLogEvent) {
	if d == nil {
		return
	}
	settings := d.currentSystemSettings()
	if !settings.LogEnabled || (settings.LogLevel == "error" && event.StatusCode < 400) ||
		(!settings.LogWriteImage && event.ResourceCategory == requestLogCategoryImage) ||
		(!settings.LogWritePlayback && (event.ResourceCategory == requestLogCategoryPlayback || event.ResourceCategory == requestLogCategoryPlaybackSync)) ||
		(!settings.LogWriteMetadata && event.ResourceCategory == requestLogCategoryMetadata) ||
		(!settings.LogWriteVideo && (event.ResourceCategory == requestLogCategoryVideo || event.ResourceCategory == requestLogCategoryStream || event.ResourceCategory == requestLogCategoryManifest || event.ResourceCategory == requestLogCategorySegment)) ||
		(!settings.LogWriteSubtitle && event.ResourceCategory == requestLogCategorySubtitle) ||
		(!settings.LogWriteAsset && event.ResourceCategory == requestLogCategoryAsset) ||
		(!settings.LogWriteWebSocket && event.ResourceCategory == requestLogCategoryWebSocket) ||
		(!settings.LogWriteAPI && event.ResourceCategory == requestLogCategoryAPI) ||
		(!settings.LogWriteAuth && event.ResourceCategory == requestLogCategoryAuth) {
		return
	}
	if !settings.LogWriteClientIP {
		event.ClientIP = ""
	}
	if !settings.LogWriteUA {
		event.UserAgent = ""
	}
	if !settings.LogWriteUpstreamUA {
		event.UpstreamUserAgent = ""
	}
	if !settings.LogWriteBackendAddress {
		event.BackendAddress = ""
	}
	if !settings.LogWriteNode {
		event.SiteName = ""
	}
	if !settings.LogWriteCategory {
		event.ResourceCategory = ""
	}
	if !settings.LogWriteStatus {
		event.StatusCode = 0
	}
	if !settings.LogWriteColo {
		event.InboundColo, event.OutboundColo = "", ""
	}
	if event.SiteID <= 0 || event.ResourceCategory != "" && !validRequestLogCategory(event.ResourceCategory) ||
		event.StatusCode != 0 && (event.StatusCode < 100 || event.StatusCode > 599) ||
		len(event.SiteName) > requestLogMaxSiteNameBytes || len(event.ClientIP) > requestLogMaxClientIPBytes ||
		len(event.UserAgent) > requestLogMaxUserAgentBytes || len(event.UpstreamUserAgent) > requestLogMaxUserAgentBytes || len(event.BackendAddress) > maxDynamicTargetURLBytes || event.Method == "" || len(event.Method) > 16 || event.Path == "" || len(event.Path) > requestLogMaxPathBytes {
		d.droppedRequestLogs.Add(1)
		return
	}
	nowMS := time.Now().UnixMilli()
	timelineAtMS := int64(0)
	if settings.LogWriteTimeline {
		timelineAtMS = nowMS
	}
	command := dynamicObservationCommand{
		kind: dynamicObservationCommandRequestLogWrite,
		requestLog: queuedRequestLog{
			event:        event,
			recordedAtMS: nowMS,
			timelineAtMS: timelineAtMS,
		},
	}
	if !d.dynamicObservationGate.TryRLock() {
		d.droppedRequestLogs.Add(1)
		return
	}
	defer d.dynamicObservationGate.RUnlock()
	if d.dynamicObservationClosed.Load() || d.dynamicObservationQueue == nil {
		d.droppedRequestLogs.Add(1)
		return
	}
	select {
	case d.dynamicObservationQueue <- command:
	default:
		d.droppedRequestLogs.Add(1)
	}
}

func (d *DB) DroppedRequestLogs() uint64 {
	if d == nil {
		return 0
	}
	return d.droppedRequestLogs.Load()
}

func (d *DB) ClearRequestLogs() error {
	return d.sendDynamicObservationControl(dynamicObservationCommandRequestLogClear, 0)
}

func (d *DB) ListRequestLogs(filter RequestLogFilter) ([]RequestLog, error) {
	if filter.FromMS < 0 || filter.ToMS < 0 || filter.FromMS > 0 && filter.ToMS > 0 && filter.FromMS > filter.ToMS {
		return nil, fmt.Errorf("invalid request log time range")
	}
	if filter.Category != "" && filter.Category != "all" && !validRequestLogCategory(filter.Category) {
		return nil, fmt.Errorf("invalid request log category")
	}
	switch filter.StatusGroup {
	case "", "all", "2xx", "3xx", "4xx", "5xx":
	default:
		return nil, fmt.Errorf("invalid request log status filter")
	}
	filter.Query = strings.TrimSpace(filter.Query)
	if len(filter.Query) > 200 {
		return nil, fmt.Errorf("request log search must not exceed 200 bytes")
	}
	if filter.Limit == 0 {
		filter.Limit = 200
	}
	if filter.Limit < 1 || filter.Limit > 500 {
		return nil, fmt.Errorf("request log limit must be between 1 and 500")
	}
	if err := d.flushDynamicObservations(); err != nil {
		return nil, err
	}

	conditions := make([]string, 0, 6)
	args := make([]interface{}, 0, 12)
	if filter.FromMS > 0 {
		conditions = append(conditions, "recorded_at_ms>=?")
		args = append(args, filter.FromMS)
	}
	if filter.ToMS > 0 {
		conditions = append(conditions, "recorded_at_ms<=?")
		args = append(args, filter.ToMS)
	}
	if filter.Category != "" && filter.Category != "all" {
		switch filter.Category {
		case requestLogCategoryVideo:
			conditions = append(conditions, "resource_category IN (?,?,?,?)")
			args = append(args, requestLogCategoryVideo, requestLogCategoryStream, requestLogCategoryManifest, requestLogCategorySegment)
		case requestLogCategoryPlaybackSync:
			conditions = append(conditions, "(resource_category=? OR (resource_category=? AND "+requestLogLegacyPlaybackSyncPredicate+"))")
			args = append(args, requestLogCategoryPlaybackSync, requestLogCategoryPlayback)
		case requestLogCategoryPlayback:
			conditions = append(conditions, "(resource_category=? AND NOT "+requestLogLegacyPlaybackSyncPredicate+")")
			args = append(args, requestLogCategoryPlayback)
		default:
			conditions = append(conditions, "resource_category=?")
			args = append(args, filter.Category)
		}
	}
	switch filter.StatusGroup {
	case "2xx":
		conditions = append(conditions, "status_code BETWEEN 200 AND 299")
	case "3xx":
		conditions = append(conditions, "status_code BETWEEN 300 AND 399")
	case "4xx":
		conditions = append(conditions, "status_code BETWEEN 400 AND 499")
	case "5xx":
		conditions = append(conditions, "status_code BETWEEN 500 AND 599")
	}
	if filter.Query != "" {
		conditions = append(conditions, `(instr(lower(request_logs.site_name), lower(?))>0 OR instr(lower(COALESCE(sites.name, '')), lower(?))>0 OR instr(lower(request_logs.client_ip), lower(?))>0 OR instr(lower(request_logs.user_agent), lower(?))>0 OR instr(lower(request_logs.upstream_user_agent), lower(?))>0 OR instr(lower(request_logs.backend_address), lower(?))>0 OR instr(lower(request_logs.path), lower(?))>0 OR CAST(request_logs.status_code AS TEXT)=?)`)
		for range 8 {
			args = append(args, filter.Query)
		}
	}
	query := `SELECT request_logs.id, request_logs.site_id, request_logs.site_name, request_logs.resource_category, request_logs.status_code, request_logs.client_ip, request_logs.user_agent, request_logs.upstream_user_agent, request_logs.backend_address, request_logs.method, request_logs.path, request_logs.timeline_at_ms, request_logs.inbound_colo, request_logs.outbound_colo FROM request_logs LEFT JOIN sites ON sites.id=request_logs.site_id`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ") // #nosec G202 -- conditions are fixed SQL fragments selected from validated filters; values remain parameters.
	}
	query += " ORDER BY request_logs.recorded_at_ms DESC, request_logs.id DESC LIMIT ?"
	args = append(args, filter.Limit)
	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	logs := make([]RequestLog, 0)
	for rows.Next() {
		var entry RequestLog
		if err := rows.Scan(&entry.ID, &entry.SiteID, &entry.SiteName, &entry.ResourceCategory, &entry.StatusCode, &entry.ClientIP, &entry.UserAgent, &entry.UpstreamUserAgent, &entry.BackendAddress, &entry.Method, &entry.Path, &entry.RecordedAtMS, &entry.InboundColo, &entry.OutboundColo); err != nil {
			return nil, err
		}
		if entry.ResourceCategory == requestLogCategoryPlayback && isRequestLogPlaybackActivityPath(entry.Path) {
			entry.ResourceCategory = requestLogCategoryPlaybackSync
		}
		logs = append(logs, entry)
	}
	settings := d.currentSystemSettings()
	for i := range logs {
		if !settings.LogDisplayClientIP {
			logs[i].ClientIP = "hidden"
		}
		if !settings.LogDisplayUA {
			logs[i].UserAgent = "hidden"
		}
		if !settings.LogDisplayUpstreamUA {
			logs[i].UpstreamUserAgent = "hidden"
		}
		if !settings.LogDisplayBackendAddress {
			logs[i].BackendAddress = "hidden"
		}
		if !settings.LogDisplayColo {
			logs[i].InboundColo, logs[i].OutboundColo = "hidden", "hidden"
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return logs, nil
}

func (d *DB) writeRequestLogBatch(batch []queuedRequestLog) (int, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	statement, err := tx.Prepare(`
		INSERT INTO request_logs
			(site_id, site_name, resource_category, status_code, client_ip, user_agent, upstream_user_agent, backend_address, inbound_colo, outbound_colo, method, path, recorded_at_ms, timeline_at_ms)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		WHERE EXISTS (SELECT 1 FROM sites WHERE id=?)`)
	if err != nil {
		return 0, err
	}
	defer statement.Close()
	skipped := 0
	for _, queued := range batch {
		event := queued.event
		result, err := statement.Exec(
			event.SiteID,
			event.SiteName,
			event.ResourceCategory,
			event.StatusCode,
			event.ClientIP,
			event.UserAgent,
			event.UpstreamUserAgent,
			event.BackendAddress,
			event.InboundColo,
			event.OutboundColo,
			event.Method,
			event.Path,
			queued.recordedAtMS,
			queued.timelineAtMS,
			event.SiteID,
		)
		if err != nil {
			return 0, err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		if rows == 0 {
			skipped++
		}
	}
	if err := pruneRequestLogsTx(tx, time.Now(), time.Duration(d.currentSystemSettings().LogRetentionDays)*24*time.Hour); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return skipped, nil
}

func pruneRequestLogsTx(tx *sql.Tx, now time.Time, retention time.Duration) error {
	cutoffMS := now.Add(-retention).UnixMilli()
	if _, err := tx.Exec("DELETE FROM request_logs WHERE recorded_at_ms<?", cutoffMS); err != nil {
		return err
	}
	_, err := tx.Exec(`
		DELETE FROM request_logs
		WHERE id IN (
			SELECT id FROM request_logs
			ORDER BY recorded_at_ms DESC, id DESC
			LIMIT -1 OFFSET ?
		)`, requestLogGlobalRowLimit)
	return err
}

func (d *DB) pruneRequestLogs() error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := pruneRequestLogsTx(tx, time.Now(), time.Duration(d.currentSystemSettings().LogRetentionDays)*24*time.Hour); err != nil {
		return err
	}
	return tx.Commit()
}

func requestLogSafeText(value string, maxBytes int) string {
	value = strings.ToValidUTF8(value, "")
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	for len(value) > maxBytes {
		_, size := utf8.DecodeLastRuneInString(value)
		if size <= 0 {
			return ""
		}
		value = value[:len(value)-size]
	}
	return value
}

func classifyRequestLogResource(r *http.Request) string {
	if r == nil || r.URL == nil {
		return requestLogCategoryAPI
	}
	path := strings.ToLower(r.URL.Path)
	switch {
	case hasUpgradeIntent(r):
		return requestLogCategoryWebSocket
	case strings.Contains(path, "/authenticate"), strings.Contains(path, "/quickconnect"):
		return requestLogCategoryAuth
	case isPlaybackInfoRequest(path):
		return requestLogCategoryPlayback
	case isRequestLogPlaybackActivityPath(path):
		return requestLogCategoryPlaybackSync
	case requestLogPathHasSuffix(path, ".m3u8", ".m3u", ".mpd"):
		return requestLogCategoryManifest
	case requestLogPathHasSuffix(path, ".ts", ".m4s"):
		return requestLogCategorySegment
	case strings.Contains(path, "/subtitles/"), strings.HasSuffix(path, "/subtitles"), strings.Contains(path, "/captions/"), requestLogPathHasSuffix(path, ".srt", ".ass", ".ssa", ".vtt", ".sub", ".idx", ".sup"):
		return requestLogCategorySubtitle
	case strings.Contains(path, "/images/"), strings.HasSuffix(path, "/images"), strings.Contains(path, "/image/"), strings.Contains(path, "/icons/"), strings.Contains(path, "/branding/"), strings.Contains(path, "/covers/"), requestLogPathHasSuffix(path, ".jpg", ".jpeg", ".gif", ".png", ".svg", ".ico", ".webp", ".avif"):
		return requestLogCategoryImage
	case requestLogPathHasSuffix(path, ".js", ".css", ".woff", ".woff2", ".ttf", ".otf", ".map", ".webmanifest"):
		return requestLogCategoryAsset
	case isPlaybackRequest(path), isPlaybackRedirectEndpoint(path), isReservedDynamicRoute(path), requestLogPathHasSuffix(path, ".mp4", ".m4v", ".ogv", ".webm", ".mkv", ".mov", ".avi", ".wmv", ".flv", ".mp3", ".m4a", ".aac", ".flac", ".wav", ".ogg", ".opus"):
		return requestLogCategoryStream
	case isRequestLogMetadataPath(path):
		return requestLogCategoryMetadata
	default:
		return requestLogCategoryAPI
	}
}

func requestLogPathHasSuffix(path string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func isRequestLogPlaybackActivityPath(path string) bool {
	path = strings.TrimSuffix(strings.ToLower(path), "/")
	return path == "/sessions/playing" || strings.HasPrefix(path, "/sessions/playing/") ||
		path == "/emby/sessions/playing" || strings.HasPrefix(path, "/emby/sessions/playing/")
}

func isRequestLogMetadataPath(path string) bool {
	parts := strings.Split(strings.Trim(strings.ToLower(path), "/"), "/")
	if len(parts) > 0 && parts[0] == "emby" {
		parts = parts[1:]
	}
	if len(parts) == 0 {
		return false
	}
	switch parts[0] {
	case "items", "shows", "movies", "users":
		return true
	default:
		return false
	}
}

func newRequestLogEvent(site Site, r *http.Request, trustedProxies []*net.IPNet, policies ...UAHeaderPolicy) requestLogEvent {
	path := "/"
	method := http.MethodGet
	userAgent := ""
	clientIP := "unknown"
	inboundColo := ""
	if r != nil {
		method = strings.ToUpper(strings.TrimSpace(r.Method))
		userAgent = r.Header.Get("User-Agent")
		inboundColo = requestLogColo(r.Header.Get("CF-Ray"))
		if r.URL != nil && r.URL.EscapedPath() != "" {
			path = r.URL.EscapedPath()
		}
		if ip := net.ParseIP(requestClientKey(r, trustedProxies)); ip != nil {
			clientIP = ip.String()
		}
	}
	if method == "" {
		method = http.MethodGet
	}
	upstreamUserAgent := userAgent
	if len(policies) > 0 && policies[0].Rewrite {
		upstreamUserAgent = policies[0].Profile.UserAgent
	}
	return requestLogEvent{
		SiteID:            site.ID,
		SiteName:          requestLogSafeText(site.Name, requestLogMaxSiteNameBytes),
		ResourceCategory:  classifyRequestLogResource(r),
		ClientIP:          clientIP,
		InboundColo:       inboundColo,
		UserAgent:         requestLogSafeText(userAgent, requestLogMaxUserAgentBytes),
		UpstreamUserAgent: requestLogSafeText(upstreamUserAgent, requestLogMaxUserAgentBytes),
		Method:            requestLogSafeText(method, 16),
		Path:              requestLogSafeText(path, requestLogMaxPathBytes),
	}
}

func requestLogColo(cfRay string) string {
	cfRay = strings.TrimSpace(cfRay)
	index := strings.LastIndexByte(cfRay, '-')
	if index < 0 || index == len(cfRay)-1 {
		return ""
	}
	colo := strings.ToUpper(strings.TrimSpace(cfRay[index+1:]))
	if len(colo) < 3 || len(colo) > 8 {
		return ""
	}
	for _, char := range colo {
		if char < 'A' || char > 'Z' {
			return ""
		}
	}
	return colo
}

type requestLogResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

type backendAddressContextKey struct{}

type backendAddressTracker struct {
	mu    sync.RWMutex
	value string
}

func (t *backendAddressTracker) SetURL(target *url.URL) {
	if t == nil || target == nil {
		return
	}
	value := dynamicCanonicalAuthority(target)
	if value == "" {
		value = redactUpstreamURL(target)
	}
	t.mu.Lock()
	t.value = value
	t.mu.Unlock()
}

func (t *backendAddressTracker) Get() string {
	if t == nil {
		return ""
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.value
}

func backendAddressTrackerFromContext(ctx context.Context) *backendAddressTracker {
	if ctx == nil {
		return nil
	}
	tracker, _ := ctx.Value(backendAddressContextKey{}).(*backendAddressTracker)
	return tracker
}

func (w *requestLogResponseWriter) WriteHeader(statusCode int) {
	if w.statusCode != 0 {
		return
	}
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *requestLogResponseWriter) Write(payload []byte) (int, error) {
	if w.statusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(payload)
}

func (w *requestLogResponseWriter) StatusCode() int {
	if w.statusCode == 0 {
		return http.StatusOK
	}
	return w.statusCode
}

func (w *requestLogResponseWriter) Flush() {
	if w.statusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *requestLogResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijack not supported")
	}
	conn, buffer, err := hijacker.Hijack()
	if err == nil && w.statusCode == 0 {
		w.statusCode = http.StatusSwitchingProtocols
	}
	return conn, buffer, err
}

func (w *requestLogResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *requestLogResponseWriter) Push(target string, options *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, options)
	}
	return http.ErrNotSupported
}

// GET/DELETE /api/request-logs
func (a *App) handleRequestLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		query := r.URL.Query()
		filter := RequestLogFilter{
			Category:    strings.ToLower(strings.TrimSpace(query.Get("category"))),
			StatusGroup: strings.ToLower(strings.TrimSpace(query.Get("status"))),
			Query:       query.Get("q"),
		}
		for name, target := range map[string]*int64{"from_ms": &filter.FromMS, "to_ms": &filter.ToMS} {
			if raw := strings.TrimSpace(query.Get(name)); raw != "" {
				value, err := strconv.ParseInt(raw, 10, 64)
				if err != nil || value < 0 {
					a.jsonErr(w, http.StatusBadRequest, name+" must be a non-negative Unix millisecond timestamp")
					return
				}
				*target = value
			}
		}
		if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil {
				a.jsonErr(w, http.StatusBadRequest, "limit must be an integer")
				return
			}
			filter.Limit = value
		}
		logs, err := a.db.ListRequestLogs(filter)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		a.clientIPRegions.enrich(logs)
		a.jsonOK(w, RequestLogsResponse{Logs: logs, DroppedLogs: a.db.DroppedRequestLogs()})
	case http.MethodDelete:
		if err := a.db.ClearRequestLogs(); err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "clear request logs failed")
			return
		}
		a.jsonOK(w, map[string]string{"status": "cleared"})
	default:
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
