package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Templates contain only reusable policy. Origins, routing bindings, accounts,
// header secrets, traffic counters and discovered authorities are not copied.
func siteTemplateConfig(site Site) map[string]any {
	return map[string]any{
		"ua_mode": site.UAMode, "custom_user_agent": site.CustomUserAgent,
		"custom_client": site.CustomClient, "custom_version": site.CustomVersion,
		"client_ip_mode": site.ClientIPMode, "main_video_stream_mode": site.MainVideoStreamMode,
		"dynamic_discovery_enabled": site.DynamicDiscoveryEnabled, "dynamic_profile": site.DynamicProfile,
		"dynamic_discovery_sources":     site.DynamicDiscoverySources,
		"dynamic_allow_https_downgrade": site.DynamicAllowHTTPSDowngrade,
		"ping_cache_enabled":            site.PingCacheEnabled, "image_cache_enabled": site.ImageCacheEnabled,
		"progress_coalescing_enabled": site.ProgressCoalescingEnabled,
		"asset_cache_enabled":         site.AssetCacheEnabled, "asset_cache_ttl_sec": site.AssetCacheTTLSec,
		"asset_cache_max_bytes": site.AssetCacheMaxBytes, "asset_cache_rules": site.AssetCacheRules,
		"traffic_quota": site.TrafficQuota, "speed_limit": site.SpeedLimit, "total_speed_limit": site.TotalSpeedLimit,
	}
}

func (a *App) handleSiteTemplates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		rows, err := a.db.db.QueryContext(r.Context(), "SELECT id,name,config FROM site_templates ORDER BY id")
		if err != nil {
			a.jsonErr(w, 500, "读取模板失败")
			return
		}
		defer rows.Close()
		result := []map[string]any{}
		for rows.Next() {
			var id int64
			var name, config string
			if err := rows.Scan(&id, &name, &config); err != nil {
				a.jsonErr(w, 500, "读取模板失败")
				return
			}
			var policy map[string]any
			if json.Unmarshal([]byte(config), &policy) != nil {
				a.jsonErr(w, 500, "模板配置无效")
				return
			}
			result = append(result, map[string]any{"id": id, "name": name, "config": policy})
		}
		if rows.Err() != nil {
			a.jsonErr(w, 500, "读取模板失败")
			return
		}
		a.jsonOK(w, result)
	case http.MethodPost:
		var req struct {
			Name   string `json:"name"`
			SiteID int64  `json:"site_id"`
		}
		if decodeJSONBody(w, r, &req) != nil || strings.TrimSpace(req.Name) == "" || len([]rune(strings.TrimSpace(req.Name))) > 100 {
			a.jsonErr(w, 400, "请填写 1–100 个字符的模板名称")
			return
		}
		site, err := a.db.GetSite(req.SiteID)
		if err != nil {
			a.jsonErr(w, 404, "站点不存在")
			return
		}
		config, _ := json.Marshal(siteTemplateConfig(*site))
		_, err = a.db.db.ExecContext(r.Context(), "INSERT INTO site_templates(name,config) VALUES(?,?)", strings.TrimSpace(req.Name), string(config))
		if err != nil {
			a.jsonErr(w, 409, "保存失败，模板名称可能已存在")
			return
		}
		a.jsonOK(w, map[string]bool{"saved": true})
	case http.MethodDelete:
		id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		if err != nil || id <= 0 {
			a.jsonErr(w, 400, "无效模板")
			return
		}
		if _, err = a.db.db.ExecContext(r.Context(), "DELETE FROM site_templates WHERE id=?", id); err != nil {
			a.jsonErr(w, 500, "删除模板失败")
			return
		}
		a.jsonOK(w, map[string]bool{"deleted": true})
	default:
		a.jsonErr(w, 405, "method not allowed")
	}
}

type siteBulkRequest struct {
	SiteIDs    []int64 `json:"site_ids"`
	Action     string  `json:"action"`
	Quota      *int64  `json:"traffic_quota"`
	Speed      *int    `json:"speed_limit"`
	TotalSpeed *int    `json:"total_speed_limit"`
	Preview    bool    `json:"preview"`
	Token      string  `json:"preview_token"`
}
type siteBulkItem struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
	expected string
	payload  map[string]any
	action   string
}

func (a *App) handleSiteBulk(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		a.jsonErr(w, 405, "method not allowed")
		return
	}
	var req siteBulkRequest
	if decodeJSONBody(w, r, &req) != nil || len(req.SiteIDs) == 0 || len(req.SiteIDs) > 500 {
		a.jsonErr(w, 400, "请选择 1–500 个站点")
		return
	}
	if req.Action != "enable" && req.Action != "disable" && req.Action != "limits" {
		a.jsonErr(w, 400, "不支持的批量操作")
		return
	}
	if req.Action == "limits" && req.Quota == nil && req.Speed == nil && req.TotalSpeed == nil {
		a.jsonErr(w, 400, "请填写至少一项额度或限速")
		return
	}
	// Token binds the exact selection, operation, limits, and current configs.
	tokenReq := req
	tokenReq.Preview = false
	tokenReq.Token = ""
	encoded, _ := json.Marshal(tokenReq)
	hash := sha256.New()
	_, _ = hash.Write(encoded)
	items := []siteBulkItem{}
	seen := map[int64]bool{}
	valid := true
	for _, id := range req.SiteIDs {
		if id <= 0 || seen[id] {
			a.jsonErr(w, 400, "站点 ID 无效或重复")
			return
		}
		seen[id] = true
		item := siteBulkItem{ID: id, Status: "ready"}
		site, err := a.db.GetSite(id)
		if err != nil {
			item.Error = "站点不存在"
			valid = false
			items = append(items, item)
			continue
		}
		item.Name = site.Name
		item.expected = siteConfigurationFingerprint(*site)
		_, _ = fmt.Fprint(hash, id, ":", item.expected)
		if req.Action == "limits" {
			item.action = "update"
			item.payload = map[string]any{"name": site.Name, "target_url": site.TargetURL, "listen_port": site.ListenPort}
			if req.Quota != nil {
				item.payload["traffic_quota"] = *req.Quota
			}
			if req.Speed != nil {
				item.payload["speed_limit"] = *req.Speed
			}
			if req.TotalSpeed != nil {
				item.payload["total_speed_limit"] = *req.TotalSpeed
			}
			_, err = a.executeTelegramSiteCommand(context.WithValue(r.Context(), siteCommandDryRunKey{}, true), item.action, id, item.payload, item.expected)
			if err != nil {
				item.Error = err.Error()
				valid = false
			}
		} else if site.Enabled == (req.Action == "enable") {
			item.Status = "unchanged"
		} else {
			item.action = "toggle"
			if req.Action == "enable" && site.IngressMode == ingressModeUnset {
				item.Error = "请先配置站点入口"
				valid = false
			}
		}
		items = append(items, item)
	}
	token := fmt.Sprintf("%x", hash.Sum(nil))
	if req.Preview {
		a.jsonOK(w, map[string]any{"items": items, "valid": valid, "preview_token": token})
		return
	}
	if !valid || req.Token == "" || req.Token != token {
		a.jsonErr(w, 409, "配置已变化或预览有错误，请重新预览")
		return
	}
	for i := range items {
		item := &items[i]
		if item.Status == "unchanged" {
			continue
		}
		data, err := a.executeTelegramSiteCommand(r.Context(), item.action, item.ID, item.payload, item.expected)
		if err != nil {
			item.Status = "failed"
			item.Error = err.Error()
		} else {
			item.Status = "completed"
			var result struct {
				CleanupPending bool `json:"cleanup_pending"`
			}
			_ = json.Unmarshal(data, &result)
			if result.CleanupPending {
				item.Status = "warning"
				item.Error = "站点已停用，但流量清理尚未完成，请检查日志"
			}
		}
	}
	a.jsonOK(w, map[string]any{"items": items})
}
