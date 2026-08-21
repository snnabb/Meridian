package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var assetCacheBlockedExtensions = map[string]bool{
	".m3u8": true, ".m3u": true, ".mpd": true, ".ts": true, ".m4s": true,
	".mp4": true, ".m4v": true, ".mkv": true, ".webm": true, ".mov": true,
	".avi": true, ".flv": true, ".mp3": true, ".aac": true, ".m4a": true,
	".flac": true, ".ogg": true, ".opus": true, ".wav": true,
}

func assetCacheRuleMatches(rules string, target *url.URL) bool {
	if target == nil {
		return false
	}
	candidate := strings.ToLower(target.Host + target.EscapedPath())
	for _, line := range strings.Split(strings.ReplaceAll(rules, "\r\n", "\n"), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pattern := "^" + regexp.QuoteMeta(line) + "$"
		pattern = strings.ReplaceAll(pattern, `\*`, ".*")
		if matched, _ := regexp.MatchString(pattern, candidate); matched {
			return true
		}
	}
	return false
}

type assetCacheMeta struct {
	Status       int                 `json:"status"`
	Headers      map[string][]string `json:"headers"`
	CreatedAtMS  int64               `json:"created_at_ms"`
	ExpiresAtMS  int64               `json:"expires_at_ms"`
	AccessedAtMS int64               `json:"accessed_at_ms"`
	Size         int64               `json:"size"`
}

type assetCacheHit struct {
	meta assetCacheMeta
	body []byte
}

type assetCache struct {
	dir string
	mu  sync.Mutex
}

type assetCacheContextKey struct{}

type assetCacheRequest struct {
	key      string
	metaName string
	bodyName string
	metaPath string
	bodyPath string
	method   string
}

func newAssetCache(dir string) *assetCache {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil
	}
	return &assetCache{dir: dir}
}

func assetCacheTargetURL(r *http.Request, upstream *url.URL) *url.URL {
	if r == nil || r.URL == nil || upstream == nil {
		return nil
	}
	target := *r.URL
	applyUpstreamURL(&target, upstream)
	target.Fragment = ""
	target.RawFragment = ""
	return &target
}

func assetCacheRequestEligible(site Site, r *http.Request, target *url.URL) bool {
	if !site.AssetCacheEnabled || r == nil || target == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return false
	}
	if r.Header.Get("Range") != "" || hasUpgradeIntent(r) || isReservedDynamicRoute(r.URL.Path) || isPlaybackRedirectEndpoint(r.URL.Path) || isPlaybackInfoRequest(r.URL.Path) || dynamicStructuredRequestSource(r.URL.Path) != "" {
		return false
	}
	ext := strings.ToLower(filepath.Ext(target.Path))
	return !assetCacheBlockedExtensions[ext] && assetCacheRuleMatches(site.AssetCacheRules, target)
}

func assetCacheIdentity(r *http.Request) string {
	if r == nil {
		return ""
	}
	identity := strings.Join([]string{
		r.Header.Get("Authorization"),
		r.Header.Get("X-Emby-Authorization"),
		r.Header.Get("X-Emby-Token"),
		r.Header.Get("X-MediaBrowser-Token"),
		r.Header.Get("Cookie"),
	}, "\n")
	if identity == "\n\n\n\n" {
		return "anonymous"
	}
	digest := sha256.Sum256([]byte(identity))
	return fmt.Sprintf("%x", digest[:])
}

func (c *assetCache) request(site Site, r *http.Request, target *url.URL) *assetCacheRequest {
	if c == nil || !assetCacheRequestEligible(site, r, target) {
		return nil
	}
	raw := strings.Join([]string{
		strconv.FormatInt(site.ID, 10),
		target.String(),
		r.Header.Get("Accept"),
		r.Header.Get("Accept-Encoding"),
		assetCacheIdentity(r),
	}, "\n")
	digest := sha256.Sum256([]byte(raw))
	key := fmt.Sprintf("%x", digest[:])
	relDir := filepath.Join(strconv.FormatInt(site.ID, 10), key[:2])
	metaName := filepath.Join(relDir, key+".json")
	bodyName := filepath.Join(relDir, key+".body")
	return &assetCacheRequest{
		key:      key,
		method:   r.Method,
		metaName: metaName,
		bodyName: bodyName,
		metaPath: filepath.Join(c.dir, metaName),
		bodyPath: filepath.Join(c.dir, bodyName),
	}
}

func (c *assetCache) openRoot(create bool) (*os.Root, error) {
	if create {
		cleanDir, err := filepath.Abs(filepath.Clean(c.dir))
		if err != nil {
			return nil, err
		}
		parent := filepath.Dir(cleanDir)
		base := filepath.Base(cleanDir)
		parentRoot, err := os.OpenRoot(parent)
		if err != nil {
			return nil, err
		}
		err = parentRoot.Mkdir(base, 0700)
		_ = parentRoot.Close()
		if err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	return os.OpenRoot(c.dir)
}

// sizeBySite reports the bytes occupied by cached response bodies. Metadata
// files are intentionally excluded so the panel matches the configured cache
// budget, which is also enforced against response body sizes.
func (c *assetCache) sizeBySite() (map[int64]int64, int64, error) {
	sizes := make(map[int64]int64)
	if c == nil {
		return sizes, 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	root, err := c.openRoot(false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return sizes, 0, nil
		}
		return nil, 0, err
	}
	defer root.Close()

	var total int64
	err = fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".body") {
			return nil
		}
		parts := strings.SplitN(filepath.ToSlash(path), "/", 2)
		if len(parts) != 2 {
			return nil
		}
		siteID, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || siteID <= 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() < 0 {
			return fmt.Errorf("cache file %q has an invalid size", path)
		}
		sizes[siteID] += info.Size()
		total += info.Size()
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, 0, err
	}
	return sizes, total, nil
}

// clear removes only entries beneath the configured asset-cache root. The
// root directory itself remains available for subsequent cache writes.
func (c *assetCache) clear() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	root, err := c.openRoot(false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if err := root.RemoveAll(entry.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (c *assetCache) clearSite(siteID int64) error {
	if c == nil || siteID <= 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	root, err := c.openRoot(false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer root.Close()
	return root.RemoveAll(strconv.FormatInt(siteID, 10))
}

func (c *assetCache) read(req *assetCacheRequest, now time.Time) (*assetCacheHit, error) {
	if c == nil || req == nil {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	root, err := c.openRoot(false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer root.Close()
	metaBytes, err := root.ReadFile(req.metaName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var meta assetCacheMeta
	if json.Unmarshal(metaBytes, &meta) != nil || meta.ExpiresAtMS <= now.UnixMilli() || meta.Size < 0 || meta.Size > maxAssetCacheObject {
		_ = root.Remove(req.metaName)
		_ = root.Remove(req.bodyName)
		return nil, nil
	}
	body, err := root.ReadFile(req.bodyName)
	if err != nil || int64(len(body)) != meta.Size {
		_ = root.Remove(req.metaName)
		_ = root.Remove(req.bodyName)
		return nil, nil
	}
	meta.AccessedAtMS = now.UnixMilli()
	if updated, err := json.Marshal(meta); err == nil {
		_ = root.WriteFile(req.metaName, updated, 0600)
	}
	return &assetCacheHit{meta: meta, body: body}, nil
}

func assetCacheResponseEligible(resp *http.Response, body []byte) bool {
	if resp == nil || resp.StatusCode != http.StatusOK || len(body) == 0 || int64(len(body)) > maxAssetCacheObject || len(resp.Header.Values("Set-Cookie")) > 0 {
		return false
	}
	cacheControl := strings.ToLower(resp.Header.Get("Cache-Control"))
	if strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "no-cache") || strings.Contains(cacheControl, "private") {
		return false
	}
	vary := strings.ToLower(resp.Header.Get("Vary"))
	for _, name := range strings.Split(vary, ",") {
		name = strings.TrimSpace(name)
		if name != "" && name != "accept" && name != "accept-encoding" {
			return false
		}
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	mediaType = strings.ToLower(mediaType)
	if strings.HasPrefix(mediaType, "video/") || strings.HasPrefix(mediaType, "audio/") || strings.Contains(mediaType, "mpegurl") || mediaType == "application/dash+xml" {
		return false
	}
	return strings.HasPrefix(mediaType, "image/") || strings.HasPrefix(mediaType, "font/") || mediaType == "text/css" || strings.Contains(mediaType, "javascript") || mediaType == "application/wasm" || mediaType == "application/font-woff"
}

func cacheableResponseHeaders(header http.Header) map[string][]string {
	result := make(map[string][]string)
	for _, name := range []string{"Content-Type", "Content-Language", "Content-Encoding", "ETag", "Last-Modified", "Cache-Control", "Expires", "Vary"} {
		if values := header.Values(name); len(values) > 0 {
			result[name] = append([]string(nil), values...)
		}
	}
	return result
}

func (c *assetCache) write(site Site, req *assetCacheRequest, resp *http.Response, body []byte, now time.Time) error {
	if c == nil || req == nil || !assetCacheResponseEligible(resp, body) {
		return nil
	}
	meta := assetCacheMeta{
		Status:       resp.StatusCode,
		Headers:      cacheableResponseHeaders(resp.Header),
		CreatedAtMS:  now.UnixMilli(),
		ExpiresAtMS:  now.Add(time.Duration(site.AssetCacheTTLSec) * time.Second).UnixMilli(),
		AccessedAtMS: now.UnixMilli(),
		Size:         int64(len(body)),
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	root, err := c.openRoot(true)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll(filepath.Dir(req.bodyName), 0700); err != nil {
		return err
	}
	bodyTmp := req.bodyName + ".tmp"
	metaTmp := req.metaName + ".tmp"
	if err := root.WriteFile(bodyTmp, body, 0600); err != nil {
		return err
	}
	if err := root.WriteFile(metaTmp, metaBytes, 0600); err != nil {
		_ = root.Remove(bodyTmp)
		return err
	}
	if err := root.Rename(bodyTmp, req.bodyName); err != nil {
		_ = root.Remove(bodyTmp)
		_ = root.Remove(metaTmp)
		return err
	}
	if err := root.Rename(metaTmp, req.metaName); err != nil {
		_ = root.Remove(metaTmp)
		_ = root.Remove(req.bodyName)
		return err
	}
	return c.enforceBudgetLocked(root, site)
}

type assetCacheFile struct {
	metaName string
	bodyName string
	accessed int64
	size     int64
}

func (c *assetCache) enforceBudgetLocked(root *os.Root, site Site) error {
	siteDir := strconv.FormatInt(site.ID, 10)
	files := make([]assetCacheFile, 0)
	var total int64
	err := fs.WalkDir(root.FS(), siteDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		data, err := root.ReadFile(path)
		if err != nil {
			return nil
		}
		var meta assetCacheMeta
		if json.Unmarshal(data, &meta) != nil {
			return nil
		}
		bodyName := strings.TrimSuffix(path, ".json") + ".body"
		files = append(files, assetCacheFile{metaName: path, bodyName: bodyName, accessed: meta.AccessedAtMS, size: meta.Size})
		total += meta.Size
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].accessed < files[j].accessed })
	for _, file := range files {
		if total <= site.AssetCacheMaxBytes {
			break
		}
		_ = root.Remove(file.metaName)
		_ = root.Remove(file.bodyName)
		total -= file.size
	}
	return nil
}

func prepareAssetCacheResponse(resp *http.Response, cache *assetCache, site Site) error {
	cacheReq, _ := resp.Request.Context().Value(assetCacheContextKey{}).(*assetCacheRequest)
	if cacheReq == nil || resp.Body == nil {
		return nil
	}
	if cacheReq.method == http.MethodHead {
		return nil
	}
	if resp.ContentLength > maxAssetCacheObject {
		resp.Header.Set("X-Meridian-Cache", "BYPASS")
		return nil
	}
	originalBody := resp.Body
	body, err := io.ReadAll(io.LimitReader(originalBody, maxAssetCacheObject+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maxAssetCacheObject {
		// Unknown-length/chunked responses may still be cacheable. If the body is
		// larger than the object limit, put the bytes already read back in front
		// of the unread stream so the proxy never truncates the upstream response.
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), originalBody))
		resp.Header.Set("X-Meridian-Cache", "BYPASS")
		return nil
	}
	_ = originalBody.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	if int64(len(body)) <= maxAssetCacheObject {
		_ = cache.write(site, cacheReq, resp, body, time.Now())
	}
	resp.Header.Set("X-Meridian-Cache", "MISS")
	return nil
}

func serveAssetCacheHit(w http.ResponseWriter, r *http.Request, hit *assetCacheHit) {
	for name, values := range hit.meta.Headers {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.Header().Set("X-Meridian-Cache", "HIT")
	w.Header().Set("Age", strconv.FormatInt(max(0, (time.Now().UnixMilli()-hit.meta.CreatedAtMS)/1000), 10))
	w.Header().Set("Content-Length", strconv.Itoa(len(hit.body)))
	w.WriteHeader(hit.meta.Status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(hit.body) // #nosec G705 -- bytes are served only after cache metadata/content-type eligibility checks.
	}
}
