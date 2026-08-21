package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	telegramReportDefaultTime        = "20:00"
	telegramReportDefaultWeekday     = 1
	telegramReportMaxMessageBytes    = 4096
	telegramReportCipherPrefix       = "v2:"
	telegramReportLegacyCipherPrefix = "v1:"
)

var telegramReportTimePattern = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)

var telegramReportHTTPClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type TelegramReportSettings struct {
	Enabled            bool   `json:"enabled"`
	Configured         bool   `json:"configured"`
	ChatID             string `json:"chat_id"`
	ScheduleTime       string `json:"schedule_time"`
	Frequency          string `json:"frequency"`
	Weekday            int    `json:"weekday"`
	LastSentKey        string `json:"last_sent_key,omitempty"`
	SecretStable       bool   `json:"secret_stable"`
	BotToken           string `json:"-"`
	BotTokenConfigured bool   `json:"bot_token_configured"`
}

type telegramReportStoredSettings struct {
	TelegramReportSettings
	BotTokenCiphertext string
}

type telegramReportInput struct {
	Enabled       *bool  `json:"enabled"`
	BotToken      string `json:"bot_token"`
	ClearBotToken bool   `json:"clear_bot_token"`
	ChatID        string `json:"chat_id"`
	ScheduleTime  string `json:"schedule_time"`
	Frequency     string `json:"frequency"`
	Weekday       *int   `json:"weekday"`
	Action        string `json:"action"`
}

type telegramReportSiteStat struct {
	Name     string
	Requests int64
	Traffic  int64
}

type telegramReportStats struct {
	GeneratedAt      time.Time
	UniqueClients    int64
	ActivePeak       int64
	Requests         int64
	VideoRequests    int64
	TodayTraffic     int64
	SevenDayTraffic  int64
	ThirtyDayTraffic int64
	HistoryTraffic   int64
	SiteCount        int
	RunningSiteCount int
	TopRequests      []telegramReportSiteStat
	TopTraffic       []telegramReportSiteStat
	TopUserAgents    []struct {
		Name  string
		Count int64
	}
}

func telegramReportKey() []byte {
	return telegramReportKeyForSecret(jwtSecret)
}

func telegramReportKeyForSecret(secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("meridian telegram report bot token v2\x00"))
	return mac.Sum(nil)
}

func legacyTelegramReportKeyForSecret(secret []byte) []byte {
	// codeql[go/weak-sensitive-data-hashing] -- legacy v1 ciphertext compatibility; new writes use HMAC-SHA256 v2.
	h := sha256.New()
	_, _ = h.Write([]byte("meridian telegram report bot token v1\x00"))
	_, _ = h.Write(secret)
	return h.Sum(nil)
}

func encryptTelegramBotToken(token string) (string, error) {
	return encryptTelegramBotTokenWithSecret(token, activeStoredCredentialSecret())
}

func encryptTelegramBotTokenWithSecret(token string, secret []byte) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, "\r\n\t ") || len(token) > 256 {
		return "", fmt.Errorf("invalid Telegram bot token")
	}
	block, err := aes.NewCipher(telegramReportKeyForSecret(secret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(token), []byte("meridian-telegram-report"))
	payload := append(nonce, sealed...)
	return telegramReportCipherPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func decryptTelegramBotToken(ciphertext string) (string, error) {
	var lastErr error
	for _, secret := range storedCredentialSecrets() {
		plain, err := decryptTelegramBotTokenWithSecret(ciphertext, secret)
		if err == nil {
			return plain, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func decryptTelegramBotTokenWithSecret(ciphertext string, secret []byte) (string, error) {
	keyForSecret := telegramReportKeyForSecret
	prefix := telegramReportCipherPrefix
	if strings.HasPrefix(ciphertext, telegramReportLegacyCipherPrefix) {
		keyForSecret = legacyTelegramReportKeyForSecret
		prefix = telegramReportLegacyCipherPrefix
	} else if !strings.HasPrefix(ciphertext, telegramReportCipherPrefix) {
		return "", fmt.Errorf("invalid Telegram bot token ciphertext")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(ciphertext, prefix))
	if err != nil {
		return "", fmt.Errorf("decode Telegram bot token: %w", err)
	}
	block, err := aes.NewCipher(keyForSecret(secret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(payload) < gcm.NonceSize()+gcm.Overhead() {
		return "", fmt.Errorf("invalid Telegram bot token ciphertext")
	}
	plain, err := gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], []byte("meridian-telegram-report"))
	if err != nil {
		return "", fmt.Errorf("decrypt Telegram bot token: %w", err)
	}
	return string(plain), nil
}

func normalizeTelegramReportSettings(settings TelegramReportSettings) (TelegramReportSettings, error) {
	settings.ScheduleTime = strings.TrimSpace(settings.ScheduleTime)
	if settings.ScheduleTime == "" {
		settings.ScheduleTime = telegramReportDefaultTime
	}
	if !telegramReportTimePattern.MatchString(settings.ScheduleTime) {
		return settings, fmt.Errorf("schedule_time must use HH:MM")
	}
	settings.Frequency = strings.ToLower(strings.TrimSpace(settings.Frequency))
	if settings.Frequency == "" {
		settings.Frequency = "daily"
	}
	if settings.Frequency != "daily" && settings.Frequency != "weekly" {
		return settings, fmt.Errorf("frequency must be daily or weekly")
	}
	if settings.Weekday < 0 || settings.Weekday > 6 {
		return settings, fmt.Errorf("weekday must be between 0 and 6")
	}
	return settings, nil
}

func (d *DB) telegramReportSettings() (telegramReportStoredSettings, error) {
	var stored telegramReportStoredSettings
	var enabled int
	err := d.db.QueryRow(`SELECT enabled, bot_token_ciphertext, chat_id, schedule_time, frequency, weekday, last_sent_key FROM telegram_report_settings WHERE id=1`).Scan(
		&enabled, &stored.BotTokenCiphertext, &stored.ChatID, &stored.ScheduleTime, &stored.Frequency, &stored.Weekday, &stored.LastSentKey,
	)
	if errors.Is(err, sql.ErrNoRows) {
		stored.ScheduleTime = telegramReportDefaultTime
		stored.Frequency = "daily"
		stored.Weekday = telegramReportDefaultWeekday
		return stored, nil
	}
	if err != nil {
		return stored, err
	}
	stored.Enabled = enabled == 1
	stored.Configured = stored.BotTokenCiphertext != "" && stored.ChatID != ""
	stored.SecretStable = !jwtSecretEphemeral
	stored.TelegramReportSettings, err = normalizeTelegramReportSettings(stored.TelegramReportSettings)
	return stored, err
}

func (d *DB) saveTelegramReportSettings(settings TelegramReportSettings, botTokenCiphertext string, replaceToken bool) error {
	settings, err := normalizeTelegramReportSettings(settings)
	if err != nil {
		return err
	}
	if settings.Enabled && (settings.ChatID == "" && !replaceToken) {
		// The caller validates the existing stored token and chat ID. This guard
		// only prevents accidentally enabling an empty destination.
		return fmt.Errorf("chat_id is required when Telegram reports are enabled")
	}
	var query string
	var args []any
	if replaceToken {
		query = `UPDATE telegram_report_settings SET
			last_sent_key=CASE WHEN enabled<>? OR bot_token_ciphertext<>? OR chat_id<>? OR schedule_time<>? OR frequency<>? OR weekday<>? THEN '' ELSE last_sent_key END,
			enabled=?, bot_token_ciphertext=?, chat_id=?, schedule_time=?, frequency=?, weekday=?, updated_at=CURRENT_TIMESTAMP WHERE id=1`
		args = []any{
			sqliteBool(settings.Enabled), botTokenCiphertext, settings.ChatID, settings.ScheduleTime, settings.Frequency, settings.Weekday,
			sqliteBool(settings.Enabled), botTokenCiphertext, settings.ChatID, settings.ScheduleTime, settings.Frequency, settings.Weekday,
		}
	} else {
		query = `UPDATE telegram_report_settings SET
			last_sent_key=CASE WHEN enabled<>? OR chat_id<>? OR schedule_time<>? OR frequency<>? OR weekday<>? THEN '' ELSE last_sent_key END,
			enabled=?, chat_id=?, schedule_time=?, frequency=?, weekday=?, updated_at=CURRENT_TIMESTAMP WHERE id=1`
		args = []any{
			sqliteBool(settings.Enabled), settings.ChatID, settings.ScheduleTime, settings.Frequency, settings.Weekday,
			sqliteBool(settings.Enabled), settings.ChatID, settings.ScheduleTime, settings.Frequency, settings.Weekday,
		}
	}
	_, err = d.db.Exec(query, args...)
	return err
}

func (d *DB) markTelegramReportSent(key string) error {
	_, err := d.db.Exec(`UPDATE telegram_report_settings SET last_sent_key=?, updated_at=CURRENT_TIMESTAMP WHERE id=1`, key)
	return err
}

func telegramReportPublicSettings(stored telegramReportStoredSettings) TelegramReportSettings {
	settings := stored.TelegramReportSettings
	settings.Configured = stored.BotTokenCiphertext != "" && settings.ChatID != ""
	settings.BotTokenConfigured = stored.BotTokenCiphertext != ""
	return settings
}

func parseTelegramReportTime(value string) (hour, minute int, err error) {
	if !telegramReportTimePattern.MatchString(value) {
		return 0, 0, fmt.Errorf("invalid schedule_time")
	}
	hour, _ = strconv.Atoi(value[:2])
	minute, _ = strconv.Atoi(value[3:])
	return hour, minute, nil
}

func telegramReportDue(now time.Time, settings telegramReportSettingsView) (string, bool) {
	now = now.In(timezoneLocationByName(settings.TimezoneName, settings.Timezone))
	hour, minute, err := parseTelegramReportTime(settings.ScheduleTime)
	if err != nil || !settings.Enabled || !settings.Configured {
		return "", false
	}
	if settings.Frequency == "weekly" && int(now.Weekday()) != settings.Weekday {
		return "", false
	}
	cutoff := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
	if now.Before(cutoff) {
		return "", false
	}
	if settings.Frequency == "weekly" {
		year, week := now.ISOWeek()
		return fmt.Sprintf("weekly:%04d-W%02d", year, week), true
	}
	return "daily:" + now.Format("2006-01-02"), true
}

type telegramReportSettingsView struct {
	Enabled      bool
	Configured   bool
	ScheduleTime string
	Frequency    string
	Weekday      int
	LastSentKey  string
	Timezone     int
	TimezoneName string
}

func (d *DB) telegramReportSettingsView() (telegramReportSettingsView, telegramReportStoredSettings, error) {
	stored, err := d.telegramReportSettings()
	if err != nil {
		return telegramReportSettingsView{}, stored, err
	}
	return telegramReportSettingsView{
		Enabled: stored.Enabled, Configured: stored.Configured, ScheduleTime: stored.ScheduleTime,
		Frequency: stored.Frequency, Weekday: stored.Weekday, LastSentKey: stored.LastSentKey,
		Timezone:     d.currentSystemSettings().ScheduleTimezone,
		TimezoneName: d.currentSystemSettings().ScheduleTimezoneName,
	}, stored, nil
}

func (d *DB) buildTelegramReportStats(now time.Time) (telegramReportStats, error) {
	settings := d.currentSystemSettings()
	location := timezoneLocationByName(settings.ScheduleTimezoneName, settings.ScheduleTimezone)
	billingMode := settings.TrafficBillingMode
	localNow := now.In(location)
	todayStart := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), 0, 0, 0, 0, location)
	tomorrow := todayStart.AddDate(0, 0, 1)
	stats := telegramReportStats{GeneratedAt: localNow}
	if err := d.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(enabled),0) FROM sites`).Scan(&stats.SiteCount, &stats.RunningSiteCount); err != nil {
		return stats, err
	}
	if err := d.db.QueryRow(`SELECT COUNT(DISTINCT client_ip), COALESCE(SUM(CASE WHEN resource_category IN ('video','stream','manifest','segment') THEN 1 ELSE 0 END),0) FROM request_logs WHERE recorded_at_ms>=? AND recorded_at_ms<?`, todayStart.UnixMilli(), tomorrow.UnixMilli()).Scan(&stats.UniqueClients, &stats.VideoRequests); err != nil {
		return stats, err
	}
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM request_logs WHERE recorded_at_ms>=? AND recorded_at_ms<?`, todayStart.UnixMilli(), tomorrow.UnixMilli()).Scan(&stats.Requests); err != nil {
		return stats, err
	}
	if err := d.db.QueryRow(`SELECT COALESCE(MAX(active_clients),0) FROM (SELECT COUNT(DISTINCT client_ip) AS active_clients FROM request_logs WHERE recorded_at_ms>=? AND recorded_at_ms<? GROUP BY CAST(recorded_at_ms/60000 AS INTEGER))`, todayStart.UnixMilli(), tomorrow.UnixMilli()).Scan(&stats.ActivePeak); err != nil {
		return stats, err
	}
	trafficSum := func(start time.Time) (int64, error) {
		var bytesIn, bytesOut sql.NullInt64
		err := d.db.QueryRow(`SELECT SUM(bytes_in), SUM(bytes_out) FROM traffic_logs WHERE recorded_at>=? AND recorded_at<?`, trafficMinuteBucket(start), trafficMinuteBucket(tomorrow)).Scan(&bytesIn, &bytesOut)
		if err != nil || !bytesIn.Valid || !bytesOut.Valid {
			return 0, err
		}
		return trafficBillableBytes(billingMode, bytesIn.Int64, bytesOut.Int64), nil
	}
	var err error
	if stats.TodayTraffic, err = trafficSum(todayStart); err != nil {
		return stats, err
	}
	if stats.SevenDayTraffic, err = trafficSum(todayStart.AddDate(0, 0, -6)); err != nil {
		return stats, err
	}
	if stats.ThirtyDayTraffic, err = trafficSum(todayStart.AddDate(0, 0, -29)); err != nil {
		return stats, err
	}
	var historyIn, historyOut int64
	if err := d.db.QueryRow(`SELECT COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0) FROM traffic_logs`).Scan(&historyIn, &historyOut); err != nil {
		return stats, err
	}
	stats.HistoryTraffic = trafficBillableBytes(billingMode, historyIn, historyOut)

	requestRows, err := d.db.Query(`SELECT site_id, site_name, COUNT(*) FROM request_logs WHERE recorded_at_ms>=? AND recorded_at_ms<? GROUP BY site_id, site_name`, todayStart.UnixMilli(), tomorrow.UnixMilli())
	if err != nil {
		return stats, err
	}
	requestBySite := make(map[int64]*telegramReportSiteStat)
	for requestRows.Next() {
		var id, requests int64
		var name string
		if err := requestRows.Scan(&id, &name, &requests); err != nil {
			requestRows.Close()
			return stats, err
		}
		requestBySite[id] = &telegramReportSiteStat{Name: name, Requests: requests}
	}
	if err := requestRows.Err(); err != nil {
		requestRows.Close()
		return stats, err
	}
	requestRows.Close()
	trafficRows, err := d.db.Query(`SELECT traffic_logs.site_id, COALESCE(NULLIF(sites.name,''), '站点 ' || traffic_logs.site_id), COALESCE(SUM(traffic_logs.bytes_in),0), COALESCE(SUM(traffic_logs.bytes_out),0) FROM traffic_logs LEFT JOIN sites ON sites.id=traffic_logs.site_id WHERE traffic_logs.recorded_at>=? AND traffic_logs.recorded_at<? GROUP BY traffic_logs.site_id, sites.name`, trafficMinuteBucket(todayStart), trafficMinuteBucket(tomorrow))
	if err != nil {
		return stats, err
	}
	for trafficRows.Next() {
		var id, bytesIn, bytesOut int64
		var name string
		if err := trafficRows.Scan(&id, &name, &bytesIn, &bytesOut); err != nil {
			trafficRows.Close()
			return stats, err
		}
		traffic := trafficBillableBytes(billingMode, bytesIn, bytesOut)
		if stat := requestBySite[id]; stat != nil {
			stat.Traffic = traffic
		} else {
			requestBySite[id] = &telegramReportSiteStat{Name: name, Traffic: traffic}
		}
	}
	if err := trafficRows.Err(); err != nil {
		trafficRows.Close()
		return stats, err
	}
	trafficRows.Close()
	for _, stat := range requestBySite {
		stats.TopRequests = append(stats.TopRequests, *stat)
		stats.TopTraffic = append(stats.TopTraffic, *stat)
	}
	sort.Slice(stats.TopRequests, func(i, j int) bool { return stats.TopRequests[i].Requests > stats.TopRequests[j].Requests })
	sort.Slice(stats.TopTraffic, func(i, j int) bool { return stats.TopTraffic[i].Traffic > stats.TopTraffic[j].Traffic })
	if len(stats.TopRequests) > 5 {
		stats.TopRequests = stats.TopRequests[:5]
	}
	if len(stats.TopTraffic) > 5 {
		stats.TopTraffic = stats.TopTraffic[:5]
	}
	uaRows, err := d.db.Query(`SELECT user_agent, COUNT(*) FROM request_logs WHERE recorded_at_ms>=? AND recorded_at_ms<? AND user_agent<>'' GROUP BY user_agent ORDER BY COUNT(*) DESC LIMIT 5`, todayStart.UnixMilli(), tomorrow.UnixMilli())
	if err != nil {
		return stats, err
	}
	for uaRows.Next() {
		var ua string
		var count int64
		if err := uaRows.Scan(&ua, &count); err != nil {
			uaRows.Close()
			return stats, err
		}
		stats.TopUserAgents = append(stats.TopUserAgents, struct {
			Name  string
			Count int64
		}{Name: ua, Count: count})
	}
	uaRows.Close()
	return stats, nil
}

func formatTelegramBytes(value int64) string {
	if value < 1024 {
		return fmt.Sprintf("%d B", value)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	f := float64(value)
	for _, unit := range units {
		f /= 1024
		if f < 1024 || unit == "TB" {
			return fmt.Sprintf("%.2f %s", f, unit)
		}
	}
	return fmt.Sprintf("%d B", value)
}

func buildTelegramReportMessage(stats telegramReportStats) string {
	var b strings.Builder
	fmt.Fprintf(&b, "📊 Meridian 日报\n统计时间：%s\n\n", stats.GeneratedAt.Format("2006-01-02 15:04"))
	fmt.Fprintf(&b, "✨ 今日概览\n• 独立客户端：%d\n• 活跃高峰：%d 个客户端/分钟\n• 请求总数：%d 次\n• 视频请求：%d 次\n• 媒体库节点：%d 个（启用 %d 个）\n\n", stats.UniqueClients, stats.ActivePeak, stats.Requests, stats.VideoRequests, stats.SiteCount, stats.RunningSiteCount)
	fmt.Fprintf(&b, "🌐 流量统计\n• 今日：%s\n• 近 7 日：%s\n• 近 30 日：%s\n• 历史累计：%s\n\n", formatTelegramBytes(stats.TodayTraffic), formatTelegramBytes(stats.SevenDayTraffic), formatTelegramBytes(stats.ThirtyDayTraffic), formatTelegramBytes(stats.HistoryTraffic))
	b.WriteString("🔥 今日请求量 TOP 5\n")
	if len(stats.TopRequests) == 0 {
		b.WriteString("• 暂无请求数据\n")
	} else {
		for i, item := range stats.TopRequests {
			fmt.Fprintf(&b, "%d. %s：%d 次\n", i+1, item.Name, item.Requests)
		}
	}
	b.WriteString("\n💾 今日流量 TOP 5\n")
	if len(stats.TopTraffic) == 0 {
		b.WriteString("• 暂无流量数据\n")
	} else {
		for i, item := range stats.TopTraffic {
			fmt.Fprintf(&b, "%d. %s：%s\n", i+1, item.Name, formatTelegramBytes(item.Traffic))
		}
	}
	b.WriteString("\n🧩 客户端分布\n")
	if len(stats.TopUserAgents) == 0 {
		b.WriteString("• 暂无客户端数据\n")
	} else {
		for _, item := range stats.TopUserAgents {
			fmt.Fprintf(&b, "• %s：%d 次\n", truncateTelegramText(item.Name, 72), item.Count)
		}
	}
	b.WriteString("\n✅ System Status: Operational")
	message := b.String()
	if len(message) > telegramReportMaxMessageBytes {
		message = truncateTelegramText(message, telegramReportMaxMessageBytes)
	}
	return message
}

func truncateTelegramText(value string, maxBytes int) string {
	value = strings.TrimSpace(value)
	if maxBytes < 4 || len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes-3]
	for len(value) > 0 && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value + "..."
}

func sendTelegramReport(ctx context.Context, botToken, chatID, message string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	botToken = strings.TrimSpace(botToken)
	chatID = strings.TrimSpace(chatID)
	if botToken == "" || chatID == "" {
		return fmt.Errorf("Telegram bot token and chat ID are required")
	}
	payload, err := json.Marshal(map[string]any{"chat_id": chatID, "text": message, "disable_web_page_preview": true})
	if err != nil {
		return err
	}
	endpoint := "https://api.telegram.org/bot" + url.PathEscape(botToken) + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// Telegram should never be able to redirect this credential-bearing request
	// to an attacker-controlled host. Treat redirects as terminal responses and
	// report them as an API failure below.
	resp, err := telegramReportHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("Telegram request failed: %w", err)
	}
	defer resp.Body.Close()
	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !result.OK {
		return fmt.Errorf("Telegram API rejected message: %s", result.Description)
	}
	return nil
}

func (a *App) handleTelegramReport(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		stored, err := a.db.telegramReportSettings()
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "failed to read Telegram report settings")
			return
		}
		a.jsonOK(w, telegramReportPublicSettings(stored))
	case http.MethodPost:
		var input telegramReportInput
		if err := decodeJSONBody(w, r, &input); err != nil {
			a.jsonErr(w, http.StatusBadRequest, "invalid Telegram report settings")
			return
		}
		stored, err := a.db.telegramReportSettings()
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "failed to read Telegram report settings")
			return
		}
		settings := stored.TelegramReportSettings
		if input.Enabled != nil {
			settings.Enabled = *input.Enabled
		}
		if input.ChatID != "" {
			settings.ChatID = strings.TrimSpace(input.ChatID)
		}
		if input.ScheduleTime != "" {
			settings.ScheduleTime = strings.TrimSpace(input.ScheduleTime)
		}
		if input.Frequency != "" {
			settings.Frequency = strings.TrimSpace(input.Frequency)
		}
		if input.Weekday != nil {
			if *input.Weekday < 0 || *input.Weekday > 6 {
				a.jsonErr(w, http.StatusBadRequest, "weekday must be between 0 and 6")
				return
			}
			settings.Weekday = *input.Weekday
		}
		settings, err = normalizeTelegramReportSettings(settings)
		if err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if len(settings.ChatID) > 128 {
			a.jsonErr(w, http.StatusBadRequest, "chat_id is too long")
			return
		}
		ciphertext := stored.BotTokenCiphertext
		replaceToken := false
		if input.ClearBotToken {
			ciphertext, replaceToken = "", true
		}
		if strings.TrimSpace(input.BotToken) != "" {
			if jwtSecretEphemeral {
				a.jsonErr(w, http.StatusConflict, "当前 JWT_SECRET 不是持久密钥，无法安全保存 Telegram Bot Token；请先配置稳定密钥")
				return
			}
			ciphertext, err = encryptTelegramBotToken(input.BotToken)
			if err != nil {
				a.jsonErr(w, http.StatusBadRequest, err.Error())
				return
			}
			replaceToken = true
		}
		if settings.Enabled && (ciphertext == "" || settings.ChatID == "") {
			a.jsonErr(w, http.StatusBadRequest, "启用日报前必须配置 Bot Token 和 Chat ID")
			return
		}
		if input.Action == "test" {
			if ciphertext == "" || settings.ChatID == "" {
				a.jsonErr(w, http.StatusBadRequest, "请先配置 Bot Token 和 Chat ID")
				return
			}
			token, decryptErr := decryptTelegramBotToken(ciphertext)
			if decryptErr != nil {
				a.jsonErr(w, http.StatusInternalServerError, "Telegram Bot Token 无法解密，请重新保存")
				return
			}
			stats, statsErr := a.db.buildTelegramReportStats(time.Now())
			if statsErr != nil {
				a.jsonErr(w, http.StatusInternalServerError, "failed to build daily report")
				return
			}
			if sendErr := sendTelegramReport(r.Context(), token, settings.ChatID, buildTelegramReportMessage(stats)); sendErr != nil {
				a.jsonErr(w, http.StatusBadGateway, sendErr.Error())
				return
			}
			a.jsonOK(w, map[string]any{"sent": true})
			return
		}
		if replaceToken && ciphertext == "" {
			settings.Enabled = false
		}
		if err := a.db.saveTelegramReportSettings(settings, ciphertext, replaceToken); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		fresh, err := a.db.telegramReportSettings()
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "failed to read Telegram report settings")
			return
		}
		a.jsonOK(w, telegramReportPublicSettings(fresh))
	default:
		w.Header().Set("Allow", "GET, POST")
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func runTelegramReportScheduler(ctx context.Context, db *DB) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			view, stored, err := db.telegramReportSettingsView()
			if err != nil || !view.Enabled || !view.Configured {
				continue
			}
			key, due := telegramReportDue(time.Now(), view)
			if !due || key == view.LastSentKey {
				continue
			}
			token, err := decryptTelegramBotToken(stored.BotTokenCiphertext)
			if err != nil {
				log.Printf("[telegram-report] bot token decrypt failed: %v", err)
				continue
			}
			stats, err := db.buildTelegramReportStats(time.Now())
			if err != nil {
				log.Printf("[telegram-report] build report failed: %v", err)
				continue
			}
			if err := sendTelegramReport(ctx, token, stored.ChatID, buildTelegramReportMessage(stats)); err != nil {
				log.Printf("[telegram-report] send failed: %v", err)
				continue
			}
			if err := db.markTelegramReportSent(key); err != nil {
				log.Printf("[telegram-report] mark sent failed: %v", err)
				continue
			}
			log.Printf("[telegram-report] sent %s", key)
		case <-ctx.Done():
			return
		}
	}
}
