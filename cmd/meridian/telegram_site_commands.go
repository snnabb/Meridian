package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

type siteCommandPreconditionKey struct{}
type siteCommandDryRunKey struct{}
type siteCommandImportKey struct{}

// Ignore live counters when detecting a concurrent edit, but include secret
// configuration even though normal Site JSON intentionally omits it.
func siteConfigurationFingerprint(site Site) string {
	site.TrafficUsed = 0
	site.TrafficUsedIn = 0
	site.TrafficUsedOut = 0
	site.UpdatedAt = ""
	data, _ := json.Marshal(struct {
		Site    Site
		Headers string
	}{site, site.StoredUpstreamHeaders})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
func (a *App) checkSiteCommandPrecondition(w http.ResponseWriter, r *http.Request, site *Site) bool {
	expected, _ := r.Context().Value(siteCommandPreconditionKey{}).(string)
	if expected == "" {
		expected = r.Header.Get("If-Match")
	}
	if expected != "" && (site == nil || expected != siteConfigurationFingerprint(*site)) {
		a.jsonErr(w, http.StatusConflict, "站点已被其他操作修改，请重新选择站点后再试")
		return false
	}
	return true
}

type siteCommandResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *siteCommandResponse) Header() http.Header { return w.header }
func (w *siteCommandResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *siteCommandResponse) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.body.Write(data)
}

// Authenticated Telegram commands enter the same validated lifecycle handlers
// as the panel. Only these four fixed operations are exposed, never arbitrary
// internal URLs or the authentication/session/backup endpoints.
func (a *App) executeTelegramSiteCommand(ctx context.Context, action string, id int64, payload map[string]any, expected string) (json.RawMessage, error) {
	method, path := http.MethodPost, "/api/sites"
	switch action {
	case "create":
	case "update":
		method = http.MethodPut
		path += "/" + strconv.FormatInt(id, 10)
	case "toggle":
		path += "/" + strconv.FormatInt(id, 10) + "/toggle"
	case "delete":
		method = http.MethodDelete
		path += "/" + strconv.FormatInt(id, 10)
	default:
		return nil, fmt.Errorf("不支持的站点操作")
	}
	if action != "create" && (id <= 0 || expected == "") {
		return nil, fmt.Errorf("站点确认信息已失效")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("站点配置无法解析")
	}
	ctx = context.WithValue(ctx, siteCommandPreconditionKey{}, expected)
	req, err := http.NewRequestWithContext(ctx, method, path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	result := &siteCommandResponse{header: make(http.Header)}
	if action == "create" {
		a.handleSites(result, req)
	} else {
		a.handleSiteByID(result, req)
	}
	if result.status < 200 || result.status >= 300 {
		var fail struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(result.body.Bytes(), &fail)
		if fail.Error == "" {
			fail.Error = "站点操作失败"
		}
		return nil, fmt.Errorf("%s", fail.Error)
	}
	return append(json.RawMessage(nil), result.body.Bytes()...), nil
}
