package main

import (
	"bytes"
	"container/list"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	pingCacheTTL          = 2 * time.Second
	pingCacheMaxBodyBytes = 64 << 10
	pingCacheMaxEntries   = 256
)

type pingCacheRoute uint8

const (
	pingCacheRouteSystem pingCacheRoute = iota + 1
	pingCacheRouteEmbySystem
)

type pingCacheRequestContextKey struct{}

func pingCacheRouteForRequest(r *http.Request) (pingCacheRoute, bool) {
	if r == nil || r.URL == nil || r.Method != http.MethodGet && r.Method != http.MethodHead || hasUpgradeIntent(r) {
		return 0, false
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || cacheRequestForcesRevalidation(r) {
		return 0, false
	}
	if cacheHeaderPresent(r.Header, "Range") || cacheHeaderPresent(r.Header, "If-Range") {
		return 0, false
	}
	if r.URL.EscapedPath() != r.URL.Path {
		return 0, false
	}
	switch r.URL.Path {
	case "/System/Ping":
		return pingCacheRouteSystem, true
	case "/emby/System/Ping":
		return pingCacheRouteEmbySystem, true
	default:
		return 0, false
	}
}

type pingCacheKey struct {
	siteID                      int64
	primaryAuthority            string
	route                       pingCacheRoute
	method                      string
	forceQuery                  bool
	representationQueryDigest   [sha256.Size]byte
	representationHeadersDigest [sha256.Size]byte
	credentialIdentityDigest    [sha256.Size]byte
}

type pingCacheEntry struct {
	key           pingCacheKey
	header        http.Header
	body          []byte
	contentLength int64
	responseAt    time.Time
	initialAge    time.Duration
	expiresAt     time.Time
}

type pingCacheFlight struct {
	done       chan struct{}
	generation uint64
	waiters    int
}

type pingCache struct {
	mu               sync.Mutex
	siteID           int64
	primaryAuthority string
	credentialKey    [sha256.Size]byte
	now              func() time.Time
	generation       uint64
	entries          map[pingCacheKey]*list.Element
	lru              list.List
	inflight         map[pingCacheKey]*pingCacheFlight
}

func newPingCache(siteID int64, primary *url.URL, now func() time.Time) (*pingCache, error) {
	authority := redirectHostKey(primary)
	if siteID <= 0 || authority == "" {
		return nil, fmt.Errorf("ping cache requires a site ID and normalized primary authority")
	}
	if now == nil {
		now = time.Now
	}
	cache := &pingCache{
		siteID:           siteID,
		primaryAuthority: authority,
		now:              now,
		entries:          make(map[pingCacheKey]*list.Element),
		inflight:         make(map[pingCacheKey]*pingCacheFlight),
	}
	if _, err := rand.Read(cache.credentialKey[:]); err != nil {
		return nil, fmt.Errorf("initialize ping cache credential key: %w", err)
	}
	return cache, nil
}

func (c *pingCache) requestKey(req *http.Request) (pingCacheKey, bool) {
	if c == nil || req == nil || req.URL == nil || req.Context().Err() != nil {
		return pingCacheKey{}, false
	}
	route, ok := req.Context().Value(pingCacheRequestContextKey{}).(pingCacheRoute)
	if !ok || route != pingCacheRouteSystem && route != pingCacheRouteEmbySystem ||
		req.Method != http.MethodGet && req.Method != http.MethodHead || redirectHostKey(req.URL) != c.primaryAuthority ||
		req.ContentLength != 0 || len(req.TransferEncoding) != 0 ||
		cacheRequestForcesRevalidation(req) || cacheHeaderPresent(req.Header, "Range") || cacheHeaderPresent(req.Header, "If-Range") {
		return pingCacheKey{}, false
	}
	representationQuery, credentialQuery, ok := splitCanonicalCacheQuery(req.URL.RawQuery)
	if !ok {
		return pingCacheKey{}, false
	}
	representationHeaders, ok := cacheHeaderDigest(req.Header,
		"Accept", "Accept-Charset", "Accept-Encoding", "Accept-Language", "Origin", "User-Agent",
		"X-Emby-Client", "X-Emby-Client-Version", "X-Emby-Device-Id", "X-Emby-Device-Name")
	if !ok {
		return pingCacheKey{}, false
	}
	credentialIdentity, ok := cacheCredentialDigest(c.credentialKey, credentialQuery, req.Header)
	if !ok {
		return pingCacheKey{}, false
	}
	return pingCacheKey{
		siteID:                      c.siteID,
		primaryAuthority:            c.primaryAuthority,
		route:                       route,
		method:                      req.Method,
		forceQuery:                  req.URL.ForceQuery,
		representationQueryDigest:   sha256.Sum256([]byte(representationQuery)),
		representationHeadersDigest: representationHeaders,
		credentialIdentityDigest:    credentialIdentity,
	}, true
}

func (c *pingCache) removeEntryLocked(element *list.Element) {
	if element == nil {
		return
	}
	if entry, ok := element.Value.(*pingCacheEntry); ok && entry != nil {
		delete(c.entries, entry.key)
	}
	c.lru.Remove(element)
}

func (c *pingCache) lookupLocked(key pingCacheKey, now time.Time) *pingCacheEntry {
	element := c.entries[key]
	if element == nil {
		return nil
	}
	entry, _ := element.Value.(*pingCacheEntry)
	if entry == nil || !now.Before(entry.expiresAt) {
		c.removeEntryLocked(element)
		return nil
	}
	c.lru.MoveToFront(element)
	return entry
}

func pingCacheResponseFromEntry(req *http.Request, entry *pingCacheEntry, now time.Time) *http.Response {
	body := io.ReadCloser(http.NoBody)
	if req.Method == http.MethodGet {
		body = io.NopCloser(bytes.NewReader(entry.body))
	}
	header := entry.header.Clone()
	header.Set("Age", cacheResponseAgeValue(entry.initialAge, entry.responseAt, now))
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Header:        header,
		Body:          body,
		ContentLength: entry.contentLength,
		Request:       req,
	}
}

func (c *pingCache) cachedResponse(key pingCacheKey, req *http.Request) (*http.Response, bool) {
	c.mu.Lock()
	now := c.now()
	entry := c.lookupLocked(key, now)
	if entry == nil {
		c.mu.Unlock()
		return nil, false
	}
	response := pingCacheResponseFromEntry(req, entry, now)
	c.mu.Unlock()
	return response, true
}

func pingCacheVarySafe(header http.Header) bool {
	values, ok := cacheHeaderValues(header, "Vary")
	if !ok {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		for _, raw := range strings.Split(value, ",") {
			switch strings.ToLower(strings.TrimSpace(raw)) {
			case "accept", "accept-charset", "accept-encoding", "accept-language", "origin", "user-agent",
				"x-emby-client", "x-emby-client-version", "x-emby-device-id", "x-emby-device-name":
			default:
				return false
			}
		}
	}
	return true
}

func pingCacheResponseHeadersSafe(resp *http.Response, method string) bool {
	if resp == nil || resp.StatusCode != http.StatusOK || cacheHeaderPresent(resp.Header, "Set-Cookie") ||
		cacheHeaderPresent(resp.Header, "Content-Range") || cacheHeaderPresent(resp.Header, "Trailer") ||
		len(resp.Trailer) != 0 || !pingCacheVarySafe(resp.Header) {
		return false
	}
	directives, ok := parseCacheControlDirectives(resp.Header, "Cache-Control")
	if !ok || cacheDirectivePresent(directives, "private") || cacheDirectivePresent(directives, "no-store") || cacheDirectivePresent(directives, "no-cache") || cachePragmaNoCache(resp.Header) {
		return false
	}
	return method == http.MethodHead || resp.ContentLength <= pingCacheMaxBodyBytes
}

func pingCacheReplayHeaders(header http.Header, contentLength int64) (http.Header, bool) {
	replay, _, ok := safeCachedResponseHeaders(header, []string{
		"Access-Control-Allow-Credentials", "Access-Control-Allow-Origin", "Access-Control-Expose-Headers",
		"Cache-Control", "Content-Encoding", "Content-Language", "Content-Type", "Date", "ETag", "Expires", "Last-Modified", "Vary",
	})
	if !ok {
		return nil, false
	}
	if contentLength >= 0 {
		replay.Set("Content-Length", strconv.FormatInt(contentLength, 10))
	}
	return replay, true
}

type pingCacheJoinedBody struct {
	io.Reader
	closer io.Closer
}

func (body *pingCacheJoinedBody) Close() error { return body.closer.Close() }

type pingCacheFailedBody struct {
	prefix *bytes.Reader
	err    error
}

func (body *pingCacheFailedBody) Read(p []byte) (int, error) {
	if body.prefix.Len() != 0 {
		return body.prefix.Read(p)
	}
	if body.err != nil {
		err := body.err
		body.err = nil
		return 0, err
	}
	return 0, io.EOF
}

func (*pingCacheFailedBody) Close() error { return nil }

// prepareResponse publishes only a complete EOF-backed body. Oversized bodies
// keep streaming through a bounded prefix plus the untouched remainder, while
// read failures replay the consumed prefix followed by the original error.
func (c *pingCache) prepareResponse(req *http.Request, resp *http.Response, responseAt time.Time) (*pingCacheEntry, *http.Response) {
	if !pingCacheResponseHeadersSafe(resp, req.Method) {
		return nil, resp
	}
	originalBody := resp.Body
	if originalBody == nil {
		originalBody = http.NoBody
	}
	originalLength := resp.ContentLength
	body, readErr := io.ReadAll(io.LimitReader(originalBody, pingCacheMaxBodyBytes+1))
	if readErr != nil {
		_ = originalBody.Close()
		resp.Body = &pingCacheFailedBody{prefix: bytes.NewReader(body), err: readErr}
		return nil, resp
	}
	if len(body) > pingCacheMaxBodyBytes {
		resp.Body = &pingCacheJoinedBody{Reader: io.MultiReader(bytes.NewReader(body), originalBody), closer: originalBody}
		return nil, resp
	}
	closeErr := originalBody.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	if req.Method == http.MethodGet {
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		if originalLength >= 0 && originalLength != int64(len(body)) {
			return nil, resp
		}
	} else if len(body) != 0 {
		return nil, resp
	}
	if closeErr != nil {
		return nil, resp
	}
	contentLength := resp.ContentLength
	if req.Method == http.MethodGet {
		contentLength = int64(len(body))
	}
	expiresAt, initialAge, fresh := cacheResponseFreshness(resp.Header, responseAt, pingCacheTTL)
	if !fresh {
		return nil, resp
	}
	header, ok := pingCacheReplayHeaders(resp.Header, contentLength)
	if !ok {
		return nil, resp
	}
	return &pingCacheEntry{
		header: header, body: body, contentLength: contentLength,
		responseAt: responseAt, initialAge: initialAge, expiresAt: expiresAt,
	}, resp
}

func (c *pingCache) finishFlight(key pingCacheKey, flight *pingCacheFlight, entry *pingCacheEntry) {
	c.mu.Lock()
	if c.inflight[key] == flight {
		if entry != nil && flight.generation == c.generation && c.now().Before(entry.expiresAt) {
			entry.key = key
			if previous := c.entries[key]; previous != nil {
				c.removeEntryLocked(previous)
			}
			c.entries[key] = c.lru.PushFront(entry)
			for len(c.entries) > pingCacheMaxEntries {
				c.removeEntryLocked(c.lru.Back())
			}
		}
		delete(c.inflight, key)
		close(flight.done)
	}
	c.mu.Unlock()
}

func (c *pingCache) roundTrip(req *http.Request, upstream http.RoundTripper) (*http.Response, error) {
	key, ok := c.requestKey(req)
	if !ok {
		return upstream.RoundTrip(req)
	}
	if response, hit := c.cachedResponse(key, req); hit {
		return response, nil
	}
	c.mu.Lock()
	now := c.now()
	if entry := c.lookupLocked(key, now); entry != nil {
		response := pingCacheResponseFromEntry(req, entry, now)
		c.mu.Unlock()
		return response, nil
	}
	if flight := c.inflight[key]; flight != nil {
		flight.waiters++
		done := flight.done
		c.mu.Unlock()
		select {
		case <-done:
			if response, hit := c.cachedResponse(key, req); hit {
				return response, nil
			}
			if err := req.Context().Err(); err != nil {
				return nil, err
			}
			return upstream.RoundTrip(req)
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	flight := &pingCacheFlight{done: make(chan struct{}), generation: c.generation}
	c.inflight[key] = flight
	c.mu.Unlock()

	resp, err := upstream.RoundTrip(req)
	if err != nil {
		c.finishFlight(key, flight, nil)
		return nil, err
	}
	responseAt := c.now()
	entry, prepared := c.prepareResponse(req, resp, responseAt)
	c.finishFlight(key, flight, entry)
	return prepared, nil
}

func (c *pingCache) invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.generation++
	for element := c.lru.Front(); element != nil; {
		next := element.Next()
		c.removeEntryLocked(element)
		element = next
	}
	c.mu.Unlock()
}

type pingCacheTransport struct {
	base  http.RoundTripper
	cache *pingCache
}

func (transport *pingCacheTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if transport == nil || transport.base == nil {
		return nil, fmt.Errorf("ping cache transport is not configured")
	}
	if transport.cache == nil {
		return transport.base.RoundTrip(req)
	}
	return transport.cache.roundTrip(req, transport.base)
}
