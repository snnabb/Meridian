package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"mime"
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
	imageCacheTTL               = time.Hour
	imageCacheMaxBodyBytes      = int64(8 << 20)
	imageCacheMaxSiteBytes      = int64(64 << 20)
	imageCacheMaxProcessBytes   = int64(256 << 20)
	maxCacheReplayHeaderBytes   = int64(64 << 10)
	imageCacheEntryOverhead     = int64(512)
	maxCanonicalCacheQueryBytes = 64 << 10
)

func cacheHeaderValues(header http.Header, name string) ([]string, bool) {
	var values []string
	found := false
	for key, candidate := range header {
		if !strings.EqualFold(key, name) {
			continue
		}
		if found {
			return nil, false
		}
		found = true
		values = candidate
	}
	return values, true
}

func cacheHeaderPresent(header http.Header, name string) bool {
	for key := range header {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

type cacheControlDirectives map[string][]string

func parseCacheControlDirectives(header http.Header, name string) (cacheControlDirectives, bool) {
	values, ok := cacheHeaderValues(header, name)
	if !ok {
		return nil, false
	}
	directives := make(cacheControlDirectives)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				return nil, false
			}
			key, directiveValue, hasValue := strings.Cut(part, "=")
			key = strings.TrimSpace(key)
			if key == "" {
				return nil, false
			}
			for i := 0; i < len(key); i++ {
				if !isHTTPTokenByte(key[i]) {
					return nil, false
				}
			}
			if hasValue {
				directiveValue = strings.TrimSpace(directiveValue)
			}
			key = strings.ToLower(key)
			directives[key] = append(directives[key], directiveValue)
		}
	}
	return directives, true
}

func cacheDirectivePresent(directives cacheControlDirectives, name string) bool {
	_, ok := directives[strings.ToLower(name)]
	return ok
}

func cacheDirectiveValue(directives cacheControlDirectives, name string) (string, bool, bool) {
	values, exists := directives[strings.ToLower(name)]
	if !exists {
		return "", false, true
	}
	if len(values) == 0 {
		return "", true, false
	}
	for _, value := range values[1:] {
		if value != values[0] {
			return "", true, false
		}
	}
	return values[0], true, true
}

func cachePragmaNoCache(header http.Header) bool {
	values, ok := cacheHeaderValues(header, "Pragma")
	if !ok {
		return false
	}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "no-cache") {
				return true
			}
		}
	}
	return false
}

func cacheRequestForcesRevalidation(r *http.Request) bool {
	if r == nil {
		return true
	}
	for _, name := range []string{"If-Match", "If-Modified-Since", "If-None-Match", "If-Unmodified-Since"} {
		if cacheHeaderPresent(r.Header, name) {
			return true
		}
	}
	directives, ok := parseCacheControlDirectives(r.Header, "Cache-Control")
	if !ok {
		return true
	}
	for _, name := range []string{"no-cache", "no-store", "max-age", "min-fresh", "max-stale", "only-if-cached"} {
		if cacheDirectivePresent(directives, name) {
			return true
		}
	}
	return cachePragmaNoCache(r.Header)
}

func cacheCredentialQueryName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch lower {
	case "api_key", "apikey", "access_token", "auth", "authorization", "key", "sig", "signature", "token",
		"x-emby-token", "x-mediabrowser-token", "x_emby_token", "x_mediabrowser_token",
		"x-amz-credential", "x-amz-security-token", "x-amz-signature", "x-goog-credential", "x-goog-signature":
		return true
	default:
		return strings.HasSuffix(lower, "_token") || strings.HasSuffix(lower, "-token")
	}
}

func splitCanonicalCacheQuery(rawQuery string) (string, string, bool) {
	if len(rawQuery) > maxCanonicalCacheQueryBytes {
		return "", "", false
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", "", false
	}
	representation := make(url.Values)
	credentials := make(url.Values)
	for name, original := range values {
		if cacheCredentialQueryName(name) {
			credentials[name] = original
		} else {
			representation[name] = original
		}
	}
	return representation.Encode(), credentials.Encode(), true
}

func writeCacheIdentityField(dst io.Writer, value string) {
	_, _ = io.WriteString(dst, strconv.Itoa(len(value)))
	_, _ = io.WriteString(dst, ":")
	_, _ = io.WriteString(dst, value)
}

func deriveCacheCredentialKey(master []byte, purpose string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, master)
	writeCacheIdentityField(mac, "meridian-memory-cache-v1")
	writeCacheIdentityField(mac, purpose)
	var key [sha256.Size]byte
	copy(key[:], mac.Sum(nil))
	return key
}

func cacheCredentialDigest(key [sha256.Size]byte, credentialQuery string, header http.Header) ([sha256.Size]byte, bool) {
	mac := hmac.New(sha256.New, key[:])
	writeCacheIdentityField(mac, credentialQuery)
	effective := header.Clone()
	stripCookieByName(effective, sessionCookieName)
	for _, name := range []string{"Authorization", "Cookie", "Proxy-Authorization", "X-Api-Key", "X-Emby-Authorization", "X-Emby-Token", "X-MediaBrowser-Token"} {
		values, ok := cacheHeaderValues(effective, name)
		if !ok {
			return [sha256.Size]byte{}, false
		}
		writeCacheIdentityField(mac, strings.ToLower(name))
		writeCacheIdentityField(mac, strconv.Itoa(len(values)))
		for _, value := range values {
			writeCacheIdentityField(mac, value)
		}
	}
	var digest [sha256.Size]byte
	copy(digest[:], mac.Sum(nil))
	return digest, true
}

func cacheHeaderDigest(header http.Header, names ...string) ([sha256.Size]byte, bool) {
	digest := sha256.New()
	for _, name := range names {
		values, ok := cacheHeaderValues(header, name)
		if !ok {
			return [sha256.Size]byte{}, false
		}
		writeCacheIdentityField(digest, strings.ToLower(name))
		writeCacheIdentityField(digest, strconv.Itoa(len(values)))
		for _, value := range values {
			writeCacheIdentityField(digest, value)
		}
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, true
}

func safeCachedResponseHeaders(header http.Header, allowed []string) (http.Header, int64, bool) {
	return safeCachedResponseHeadersWithin(header, allowed, maxCacheReplayHeaderBytes)
}

func safeCachedResponseHeadersWithin(header http.Header, allowed []string, maxBytes int64) (http.Header, int64, bool) {
	if maxBytes < 0 || maxBytes > maxCacheReplayHeaderBytes {
		return nil, 0, false
	}
	replay := make(http.Header)
	var retained int64
	for _, name := range allowed {
		values, ok := cacheHeaderValues(header, name)
		if !ok {
			return nil, 0, false
		}
		for _, value := range values {
			retained += int64(len(name) + len(value) + 16)
			if retained > maxBytes {
				return nil, 0, false
			}
			replay.Add(name, value)
		}
	}
	return replay, retained, true
}

type imageCacheKey struct {
	siteID             int64
	primaryAuthority   string
	canonicalPath      string
	canonicalQuery     string
	forceQuery         bool
	credentialIdentity [sha256.Size]byte
	representation     [sha256.Size]byte
}

const imageCacheContentLengthReservationBytes = int64(len("Content-Length") + 20 + 16)

func imageCacheKeyBytes(key imageCacheKey) int64 {
	return int64(len(key.primaryAuthority)) + int64(len(key.canonicalPath)) + int64(len(key.canonicalQuery))
}

func imageCacheMaximumFlightReservation(key imageCacheKey) int64 {
	return imageCacheMaxBodyBytes + maxCacheReplayHeaderBytes + imageCacheEntryOverhead + imageCacheKeyBytes(key)
}

type imageCacheEntry struct {
	key                    imageCacheKey
	owner                  *imageCacheSite
	header                 http.Header
	body                   []byte
	responseAt             time.Time
	initialAge             time.Duration
	expiresAt              time.Time
	cost                   int64
	globalPrev, globalNext *imageCacheEntry
	sitePrev, siteNext     *imageCacheEntry
}

type imageCacheFlight struct {
	done           chan struct{}
	stored         bool
	reservedBytes  int64
	captureStarted bool
}

type imageCacheRuntime struct {
	mu              sync.Mutex
	maxProcessBytes int64
	maxSiteBytes    int64
	ttl             time.Duration
	now             func() time.Time
	credentialKey   [sha256.Size]byte
	bytes           int64
	globalHead      *imageCacheEntry
	globalTail      *imageCacheEntry
}

type imageCacheSite struct {
	runtime *imageCacheRuntime
	siteID  int64
	closed  bool
	entries map[imageCacheKey]*imageCacheEntry
	flights map[imageCacheKey]*imageCacheFlight
	bytes   int64
	head    *imageCacheEntry
	tail    *imageCacheEntry
}

func newImageCacheRuntime(masterKey []byte) *imageCacheRuntime {
	return newImageCacheRuntimeWithLimits(imageCacheMaxProcessBytes, imageCacheMaxSiteBytes, imageCacheTTL, masterKey)
}

func newImageCacheRuntimeWithLimits(processBytes, siteBytes int64, ttl time.Duration, masterKey []byte) *imageCacheRuntime {
	return &imageCacheRuntime{
		maxProcessBytes: processBytes,
		maxSiteBytes:    siteBytes,
		ttl:             ttl,
		now:             time.Now,
		credentialKey:   deriveCacheCredentialKey(masterKey, "emby-image"),
	}
}

func (runtime *imageCacheRuntime) currentTime() time.Time {
	if runtime != nil && runtime.now != nil {
		return runtime.now()
	}
	return time.Now()
}

func (runtime *imageCacheRuntime) newSite(siteID int64) *imageCacheSite {
	if runtime == nil {
		return nil
	}
	return &imageCacheSite{
		runtime: runtime,
		siteID:  siteID,
		entries: make(map[imageCacheKey]*imageCacheEntry),
		flights: make(map[imageCacheKey]*imageCacheFlight),
	}
}

func (runtime *imageCacheRuntime) unlinkGlobal(entry *imageCacheEntry) {
	if entry.globalPrev != nil {
		entry.globalPrev.globalNext = entry.globalNext
	} else {
		runtime.globalHead = entry.globalNext
	}
	if entry.globalNext != nil {
		entry.globalNext.globalPrev = entry.globalPrev
	} else {
		runtime.globalTail = entry.globalPrev
	}
	entry.globalPrev, entry.globalNext = nil, nil
}

func (runtime *imageCacheRuntime) linkGlobalFront(entry *imageCacheEntry) {
	entry.globalNext = runtime.globalHead
	entry.globalPrev = nil
	if runtime.globalHead != nil {
		runtime.globalHead.globalPrev = entry
	} else {
		runtime.globalTail = entry
	}
	runtime.globalHead = entry
}

func (site *imageCacheSite) unlink(entry *imageCacheEntry) {
	if entry.sitePrev != nil {
		entry.sitePrev.siteNext = entry.siteNext
	} else {
		site.head = entry.siteNext
	}
	if entry.siteNext != nil {
		entry.siteNext.sitePrev = entry.sitePrev
	} else {
		site.tail = entry.sitePrev
	}
	entry.sitePrev, entry.siteNext = nil, nil
}

func (site *imageCacheSite) linkFront(entry *imageCacheEntry) {
	entry.siteNext = site.head
	entry.sitePrev = nil
	if site.head != nil {
		site.head.sitePrev = entry
	} else {
		site.tail = entry
	}
	site.head = entry
}

func (runtime *imageCacheRuntime) remove(entry *imageCacheEntry) {
	if entry == nil || entry.owner == nil || entry.owner.entries[entry.key] != entry {
		return
	}
	site := entry.owner
	delete(site.entries, entry.key)
	runtime.unlinkGlobal(entry)
	site.unlink(entry)
	runtime.bytes -= entry.cost
	site.bytes -= entry.cost
	if runtime.bytes < 0 {
		runtime.bytes = 0
	}
	if site.bytes < 0 {
		site.bytes = 0
	}
}

func (site *imageCacheSite) getLocked(key imageCacheKey, now time.Time) *imageCacheEntry {
	entry := site.entries[key]
	if entry == nil {
		return nil
	}
	if !now.Before(entry.expiresAt) {
		site.runtime.remove(entry)
		return nil
	}
	site.runtime.unlinkGlobal(entry)
	site.runtime.linkGlobalFront(entry)
	site.unlink(entry)
	site.linkFront(entry)
	return entry
}

func (site *imageCacheSite) storeLocked(key imageCacheKey, entry *imageCacheEntry, now time.Time) bool {
	runtime := site.runtime
	if site.closed || entry == nil || !now.Before(entry.expiresAt) || runtime.maxProcessBytes <= 0 || runtime.maxSiteBytes <= 0 {
		return false
	}
	entry.key, entry.owner = key, site
	entry.cost += imageCacheKeyBytes(key)
	if entry.cost > runtime.maxSiteBytes || entry.cost > runtime.maxProcessBytes {
		return false
	}
	if old := site.entries[key]; old != nil {
		runtime.remove(old)
	}
	site.entries[key] = entry
	site.linkFront(entry)
	runtime.linkGlobalFront(entry)
	site.bytes += entry.cost
	runtime.bytes += entry.cost
	for site.bytes > runtime.maxSiteBytes && site.tail != nil {
		runtime.remove(site.tail)
	}
	for runtime.bytes > runtime.maxProcessBytes && runtime.globalTail != nil {
		runtime.remove(runtime.globalTail)
	}
	return site.entries[key] == entry
}

func (site *imageCacheSite) reserveFlightLocked(key imageCacheKey) int64 {
	runtime := site.runtime
	if runtime.maxProcessBytes <= 0 || runtime.maxSiteBytes <= 0 {
		return 0
	}
	keyBytes := imageCacheKeyBytes(key)
	minimum := imageCacheEntryOverhead + keyBytes + imageCacheContentLengthReservationBytes
	target := imageCacheMaximumFlightReservation(key)
	if target > runtime.maxSiteBytes {
		target = runtime.maxSiteBytes
	}
	if target > runtime.maxProcessBytes {
		target = runtime.maxProcessBytes
	}
	if target <= minimum {
		return 0
	}
	for {
		siteAvailable := runtime.maxSiteBytes - site.bytes
		processAvailable := runtime.maxProcessBytes - runtime.bytes
		available := siteAvailable
		if processAvailable < available {
			available = processAvailable
		}
		if available > minimum {
			reservation := target
			if reservation > available {
				reservation = available
			}
			site.bytes += reservation
			runtime.bytes += reservation
			return reservation
		}
		if siteAvailable <= minimum {
			if site.tail == nil {
				return 0
			}
			runtime.remove(site.tail)
			continue
		}
		if processAvailable <= minimum {
			if runtime.globalTail == nil {
				return 0
			}
			runtime.remove(runtime.globalTail)
			continue
		}
		return 0
	}
}

func (site *imageCacheSite) releaseFlightReservationLocked(flight *imageCacheFlight) {
	if flight == nil || flight.reservedBytes <= 0 {
		return
	}
	reservation := flight.reservedBytes
	flight.reservedBytes = 0
	site.bytes -= reservation
	site.runtime.bytes -= reservation
	if site.bytes < 0 {
		site.bytes = 0
	}
	if site.runtime.bytes < 0 {
		site.runtime.bytes = 0
	}
}

func (site *imageCacheSite) lookup(key imageCacheKey, now time.Time) (*imageCacheEntry, *imageCacheFlight, bool) {
	if site == nil || site.runtime == nil {
		return nil, nil, false
	}
	site.runtime.mu.Lock()
	defer site.runtime.mu.Unlock()
	if site.closed {
		return nil, nil, false
	}
	return site.getLocked(key, now), site.flights[key], true
}

func (site *imageCacheSite) lookupOrBegin(key imageCacheKey, now time.Time) (*imageCacheEntry, *imageCacheFlight, bool, bool) {
	if site == nil || site.runtime == nil {
		return nil, nil, false, false
	}
	site.runtime.mu.Lock()
	defer site.runtime.mu.Unlock()
	if site.closed {
		return nil, nil, false, false
	}
	if entry := site.getLocked(key, now); entry != nil {
		return entry, nil, false, true
	}
	if flight := site.flights[key]; flight != nil {
		return nil, flight, false, true
	}
	reservation := site.reserveFlightLocked(key)
	if reservation <= 0 {
		return nil, nil, false, false
	}
	flight := &imageCacheFlight{done: make(chan struct{}), reservedBytes: reservation}
	site.flights[key] = flight
	return nil, flight, true, true
}

func (site *imageCacheSite) beginFlightCapture(key imageCacheKey, flight *imageCacheFlight) (int64, bool) {
	if site == nil || site.runtime == nil || flight == nil {
		return 0, false
	}
	site.runtime.mu.Lock()
	defer site.runtime.mu.Unlock()
	if site.closed || site.flights[key] != flight || flight.reservedBytes <= 0 {
		return 0, false
	}
	flight.captureStarted = true
	return flight.reservedBytes, true
}

func (site *imageCacheSite) finishFlight(key imageCacheKey, flight *imageCacheFlight, entry *imageCacheEntry, now time.Time) {
	if site == nil || site.runtime == nil || flight == nil {
		return
	}
	site.runtime.mu.Lock()
	defer site.runtime.mu.Unlock()
	if site.flights[key] != flight {
		site.releaseFlightReservationLocked(flight)
		return
	}
	keyBytes := imageCacheKeyBytes(key)
	entryFits := entry != nil && entry.cost <= flight.reservedBytes && keyBytes <= flight.reservedBytes-entry.cost
	site.releaseFlightReservationLocked(flight)
	if entryFits {
		flight.stored = site.storeLocked(key, entry, now)
	}
	delete(site.flights, key)
	close(flight.done)
}

func (site *imageCacheSite) close() {
	if site == nil || site.runtime == nil {
		return
	}
	site.runtime.mu.Lock()
	defer site.runtime.mu.Unlock()
	if site.closed {
		return
	}
	site.closed = true
	for site.tail != nil {
		site.runtime.remove(site.tail)
	}
	for key, flight := range site.flights {
		if !flight.captureStarted {
			site.releaseFlightReservationLocked(flight)
		}
		delete(site.flights, key)
		close(flight.done)
	}
}

func normalizeEmbyImageCachePath(requestURL *url.URL) (string, bool) {
	if requestURL == nil || requestURL.Opaque != "" || requestURL.Fragment != "" || requestURL.RawFragment != "" {
		return "", false
	}
	if requestURL.RawPath != "" {
		decoded, err := url.PathUnescape(requestURL.RawPath)
		if err != nil || decoded != requestURL.Path {
			return "", false
		}
	}
	escaped := requestURL.EscapedPath()
	if !strings.HasPrefix(escaped, "/") {
		return "", false
	}
	rawSegments := strings.Split(strings.TrimPrefix(escaped, "/"), "/")
	if len(rawSegments) < 4 {
		return "", false
	}
	segments := make([]string, len(rawSegments))
	for i, raw := range rawSegments {
		decoded, err := url.PathUnescape(raw)
		if err != nil || decoded == "" || decoded == "." || decoded == ".." || !utf8.ValidString(decoded) || strings.ContainsAny(decoded, "/\\") || strings.IndexFunc(decoded, unicode.IsControl) >= 0 {
			return "", false
		}
		segments[i] = decoded
	}
	base := 0
	if strings.EqualFold(segments[0], "emby") {
		if len(segments) < 5 {
			return "", false
		}
		segments[0] = "emby"
		base = 1
	}
	if !strings.EqualFold(segments[base], "Items") || !strings.EqualFold(segments[base+2], "Images") || len(segments) <= base+3 {
		return "", false
	}
	segments[base] = "Items"
	segments[base+2] = "Images"
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return "/" + strings.Join(segments, "/"), true
}

func imageCacheRequestKeyFor(site *imageCacheSite, primary *url.URL, r *http.Request) (imageCacheKey, bool) {
	if site == nil || site.runtime == nil || primary == nil || r == nil || r.URL == nil || r.Method != http.MethodGet && r.Method != http.MethodHead {
		return imageCacheKey{}, false
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 || hasUpgradeIntent(r) || isReservedDynamicRoute(r.URL.Path) || cacheRequestForcesRevalidation(r) {
		return imageCacheKey{}, false
	}
	if cacheHeaderPresent(r.Header, "Range") || cacheHeaderPresent(r.Header, "If-Range") {
		return imageCacheKey{}, false
	}
	canonicalRoute, ok := normalizeEmbyImageCachePath(r.URL)
	if !ok {
		return imageCacheKey{}, false
	}
	decodedRoute, err := url.PathUnescape(canonicalRoute)
	if err != nil {
		return imageCacheKey{}, false
	}
	upstreamURL := &url.URL{Path: decodedRoute, RawPath: canonicalRoute, RawQuery: r.URL.RawQuery, ForceQuery: r.URL.ForceQuery}
	applyUpstreamURL(upstreamURL, primary)
	representationQuery, credentialQuery, ok := splitCanonicalCacheQuery(upstreamURL.RawQuery)
	if !ok {
		return imageCacheKey{}, false
	}
	credentialIdentity, ok := cacheCredentialDigest(site.runtime.credentialKey, credentialQuery, r.Header)
	if !ok {
		return imageCacheKey{}, false
	}
	representation, ok := cacheHeaderDigest(r.Header, "Accept", "Accept-Encoding")
	if !ok {
		return imageCacheKey{}, false
	}
	authority := redirectHostKey(primary)
	if authority == "" {
		return imageCacheKey{}, false
	}
	return imageCacheKey{
		siteID: site.siteID, primaryAuthority: authority, canonicalPath: upstreamURL.EscapedPath(),
		canonicalQuery: representationQuery, forceQuery: upstreamURL.ForceQuery,
		credentialIdentity: credentialIdentity, representation: representation,
	}, true
}

var imageCacheReplayHeaderNames = []string{
	"Accept-Ranges", "Access-Control-Allow-Credentials", "Access-Control-Allow-Headers",
	"Access-Control-Allow-Methods", "Access-Control-Allow-Origin", "Access-Control-Expose-Headers",
	"Cache-Control", "Content-Disposition", "Content-Encoding", "Content-Language", "Content-Type", "Date",
	"Cross-Origin-Resource-Policy", "ETag", "Expires", "Last-Modified", "Timing-Allow-Origin", "Vary",
	"X-Content-Type-Options",
}

func imageCacheSafeVary(header http.Header) bool {
	values, ok := cacheHeaderValues(header, "Vary")
	if !ok {
		return false
	}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			name := strings.TrimSpace(part)
			if name == "" {
				return false
			}
			for i := 0; i < len(name); i++ {
				if !isHTTPTokenByte(name[i]) {
					return false
				}
			}
			if !strings.EqualFold(name, "Accept") && !strings.EqualFold(name, "Accept-Encoding") {
				return false
			}
		}
	}
	return true
}

func parseCacheDeltaSeconds(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	const maxSeconds = uint64((1<<63 - 1) / int64(time.Second))
	var seconds uint64
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
		digit := uint64(value[i] - '0')
		if seconds > (maxSeconds-digit)/10 {
			return 0, false
		}
		seconds = seconds*10 + digit
	}
	return time.Duration(seconds * uint64(time.Second)), true
}

func cacheResponseFreshness(header http.Header, now time.Time, ttl time.Duration) (time.Time, time.Duration, bool) {
	if ttl <= 0 {
		return time.Time{}, 0, false
	}
	directives, ok := parseCacheControlDirectives(header, "Cache-Control")
	if !ok {
		return time.Time{}, 0, false
	}
	for _, name := range []string{"private", "no-store", "no-cache"} {
		if cacheDirectivePresent(directives, name) {
			return time.Time{}, 0, false
		}
	}

	initialAge := time.Duration(0)
	ageValues, ok := cacheHeaderValues(header, "Age")
	if !ok || len(ageValues) > 1 {
		return time.Time{}, 0, false
	}
	if len(ageValues) == 1 {
		initialAge, ok = parseCacheDeltaSeconds(ageValues[0])
		if !ok {
			return time.Time{}, 0, false
		}
	}

	var dateValue time.Time
	hasDate := false
	dateValues, ok := cacheHeaderValues(header, "Date")
	if !ok || len(dateValues) > 1 {
		return time.Time{}, 0, false
	}
	if len(dateValues) == 1 {
		dateValue, _ = http.ParseTime(strings.TrimSpace(dateValues[0]))
		if dateValue.IsZero() {
			return time.Time{}, 0, false
		}
		hasDate = true
		if apparentAge := now.Sub(dateValue); apparentAge > initialAge {
			initialAge = apparentAge
		}
	}
	const maxAgeDuration = time.Duration(1<<63 - 1)
	if initialAge < 0 {
		initialAge = 0
	} else if initialAge == maxAgeDuration {
		return time.Time{}, 0, false
	}

	remaining := ttl
	maxAge, exists, valid := cacheDirectiveValue(directives, "s-maxage")
	if !exists {
		maxAge, exists, valid = cacheDirectiveValue(directives, "max-age")
	}
	if !valid {
		return time.Time{}, 0, false
	}
	if exists {
		freshnessLifetime, valid := parseCacheDeltaSeconds(maxAge)
		if !valid || freshnessLifetime <= initialAge {
			return time.Time{}, 0, false
		}
		if originRemaining := freshnessLifetime - initialAge; originRemaining < remaining {
			remaining = originRemaining
		}
	} else {
		expiresValues, valid := cacheHeaderValues(header, "Expires")
		if !valid || len(expiresValues) > 1 {
			return time.Time{}, 0, false
		}
		if len(expiresValues) == 1 {
			expiresValue, err := http.ParseTime(strings.TrimSpace(expiresValues[0]))
			if err != nil {
				return time.Time{}, 0, false
			}
			freshnessLifetime := expiresValue.Sub(now)
			if hasDate {
				freshnessLifetime = expiresValue.Sub(dateValue)
			}
			if freshnessLifetime <= initialAge {
				return time.Time{}, 0, false
			}
			if originRemaining := freshnessLifetime - initialAge; originRemaining < remaining {
				remaining = originRemaining
			}
		}
	}
	if remaining <= 0 {
		return time.Time{}, 0, false
	}
	return now.Add(remaining), initialAge, true
}

func cacheResponseAgeValue(initialAge time.Duration, responseAt, now time.Time) string {
	if initialAge < 0 {
		initialAge = 0
	}
	resident := now.Sub(responseAt)
	if resident < 0 {
		resident = 0
	}
	const maxAgeDuration = time.Duration(1<<63 - 1)
	if initialAge > maxAgeDuration-resident {
		initialAge = maxAgeDuration
	} else {
		initialAge += resident
	}
	seconds := int64(initialAge / time.Second)
	if initialAge%time.Second != 0 {
		seconds++
	}
	return strconv.FormatInt(seconds, 10)
}

type imageCacheMetadata struct {
	header            http.Header
	declaredLength    int64
	hasDeclaredLength bool
	expiresAt         time.Time
	initialAge        time.Duration
	replayHeaderBytes int64
}

func imageCacheResponseMetadata(header http.Header, status int, now time.Time, ttl time.Duration, maxHeaderBytes int64) (imageCacheMetadata, bool) {
	if status != http.StatusOK || cacheHeaderPresent(header, "Set-Cookie") || cacheHeaderPresent(header, "Content-Range") || cacheHeaderPresent(header, "Trailer") || cacheHeaderPresent(header, "Warning") || cachePragmaNoCache(header) || !imageCacheSafeVary(header) {
		return imageCacheMetadata{}, false
	}
	contentTypes, ok := cacheHeaderValues(header, "Content-Type")
	if !ok || len(contentTypes) != 1 {
		return imageCacheMetadata{}, false
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	mediaType = strings.ToLower(mediaType)
	if err != nil || !strings.HasPrefix(mediaType, "image/") || len(mediaType) <= len("image/") || strings.TrimPrefix(mediaType, "image/") == "*" {
		return imageCacheMetadata{}, false
	}
	for _, name := range []string{"Surrogate-Control", "CDN-Cache-Control"} {
		directives, valid := parseCacheControlDirectives(header, name)
		if !valid {
			return imageCacheMetadata{}, false
		}
		for _, forbidden := range []string{"private", "no-store", "no-cache"} {
			if cacheDirectivePresent(directives, forbidden) {
				return imageCacheMetadata{}, false
			}
		}
	}
	declaredLength := int64(0)
	hasDeclaredLength := false
	lengths, ok := cacheHeaderValues(header, "Content-Length")
	if !ok || len(lengths) > 1 {
		return imageCacheMetadata{}, false
	}
	if len(lengths) == 1 {
		declaredLength, err = strconv.ParseInt(strings.TrimSpace(lengths[0]), 10, 64)
		if err != nil || declaredLength < 0 || declaredLength > imageCacheMaxBodyBytes {
			return imageCacheMetadata{}, false
		}
		hasDeclaredLength = true
	}
	expiresAt, initialAge, fresh := cacheResponseFreshness(header, now, ttl)
	if !fresh {
		return imageCacheMetadata{}, false
	}
	replay, headerBytes, safe := safeCachedResponseHeadersWithin(header, imageCacheReplayHeaderNames, maxHeaderBytes)
	if !safe {
		return imageCacheMetadata{}, false
	}
	return imageCacheMetadata{
		header: replay, declaredLength: declaredLength, hasDeclaredLength: hasDeclaredLength,
		expiresAt: expiresAt, initialAge: initialAge, replayHeaderBytes: headerBytes,
	}, true
}

type imageCacheCaptureWriter struct {
	http.ResponseWriter
	runtime           *imageCacheRuntime
	reservedBytes     int64
	keyBytes          int64
	captureLimit      int64
	wroteFinal        bool
	sawInformational  bool
	cacheable         bool
	complete          bool
	declaredLength    int64
	hasDeclaredLength bool
	responseAt        time.Time
	initialAge        time.Duration
	expiresAt         time.Time
	replayHeader      http.Header
	replayHeaderBytes int64
	body              []byte
}

func newImageCacheCaptureWriter(w http.ResponseWriter, runtime *imageCacheRuntime, reservedBytes, keyBytes int64) *imageCacheCaptureWriter {
	return &imageCacheCaptureWriter{
		ResponseWriter: w, runtime: runtime, reservedBytes: reservedBytes, keyBytes: keyBytes, complete: true,
	}
}

func (w *imageCacheCaptureWriter) discard() {
	w.cacheable = false
	w.complete = false
	w.captureLimit = 0
	w.body = nil
	w.replayHeader = nil
}

func (w *imageCacheCaptureWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		w.sawInformational = true
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.wroteFinal {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.wroteFinal = true
	if w.runtime != nil {
		w.responseAt = w.runtime.currentTime()
		maxHeaderBytes := w.reservedBytes - w.keyBytes - imageCacheEntryOverhead - imageCacheContentLengthReservationBytes
		if maxHeaderBytes > maxCacheReplayHeaderBytes {
			maxHeaderBytes = maxCacheReplayHeaderBytes
		}
		metadata, cacheable := imageCacheResponseMetadata(w.Header(), status, w.responseAt, w.runtime.ttl, maxHeaderBytes)
		w.cacheable = cacheable && !w.sawInformational
		if w.cacheable {
			w.declaredLength = metadata.declaredLength
			w.hasDeclaredLength = metadata.hasDeclaredLength
			w.expiresAt = metadata.expiresAt
			w.initialAge = metadata.initialAge
			w.replayHeader = metadata.header
			w.replayHeaderBytes = metadata.replayHeaderBytes
			w.captureLimit = w.reservedBytes - w.keyBytes - imageCacheEntryOverhead - w.replayHeaderBytes - imageCacheContentLengthReservationBytes
			if w.captureLimit > imageCacheMaxBodyBytes {
				w.captureLimit = imageCacheMaxBodyBytes
			}
			if w.captureLimit < 0 || w.hasDeclaredLength && w.declaredLength > w.captureLimit {
				w.discard()
			} else {
				capacity := w.captureLimit
				if w.hasDeclaredLength {
					capacity = w.declaredLength
				}
				if capacity < 0 || capacity > imageCacheMaxBodyBytes {
					w.discard()
				} else if capacity > 0 {
					w.body = make([]byte, 0, int(capacity))
				}
			}
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *imageCacheCaptureWriter) Write(payload []byte) (int, error) {
	if !w.wroteFinal {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(payload)
	if w.cacheable {
		captured := int64(len(w.body)) + int64(n)
		if err != nil || n != len(payload) || captured > w.captureLimit || w.hasDeclaredLength && captured > w.declaredLength {
			w.discard()
		} else if n > 0 {
			w.body = append(w.body, payload[:n]...)
		}
	}
	return n, err
}

func (w *imageCacheCaptureWriter) Flush() {
	if !w.wroteFinal {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *imageCacheCaptureWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *imageCacheCaptureWriter) entry() *imageCacheEntry {
	if !w.wroteFinal || !w.cacheable || !w.complete || int64(len(w.body)) > w.captureLimit || w.hasDeclaredLength && int64(len(w.body)) != w.declaredLength || w.replayHeader == nil {
		return nil
	}
	w.replayHeader.Set("Content-Length", strconv.Itoa(len(w.body)))
	headerBytes := w.replayHeaderBytes + int64(len("Content-Length")+len(w.replayHeader.Get("Content-Length"))+16)
	if headerBytes > maxCacheReplayHeaderBytes {
		return nil
	}
	cost := int64(cap(w.body)) + headerBytes + imageCacheEntryOverhead
	if cost > w.reservedBytes || w.keyBytes > w.reservedBytes-cost {
		return nil
	}
	body := w.body
	w.body = nil
	header := w.replayHeader
	w.replayHeader = nil
	return &imageCacheEntry{
		header: header, body: body, responseAt: w.responseAt, initialAge: w.initialAge, expiresAt: w.expiresAt,
		cost: cost,
	}
}

func serveImageCacheEntry(w http.ResponseWriter, r *http.Request, entry *imageCacheEntry, now time.Time) {
	header := w.Header()
	for name := range header {
		delete(header, name)
	}
	for name, values := range entry.header {
		for _, value := range values {
			header.Add(name, value)
		}
	}
	header.Set("Age", cacheResponseAgeValue(entry.initialAge, entry.responseAt, now))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(entry.body)
	}
}

func (site *imageCacheSite) serve(w http.ResponseWriter, r *http.Request, primary *url.URL, next http.Handler) {
	key, eligible := imageCacheRequestKeyFor(site, primary, r)
	if !eligible {
		next.ServeHTTP(w, r)
		return
	}
	now := site.runtime.currentTime()
	if r.Method == http.MethodHead {
		entry, flight, available := site.lookup(key, now)
		if !available {
			next.ServeHTTP(w, r)
			return
		}
		if entry != nil {
			serveImageCacheEntry(w, r, entry, now)
			return
		}
		if flight != nil {
			select {
			case <-flight.done:
				hitNow := site.runtime.currentTime()
				if entry, _, available := site.lookup(key, hitNow); available && entry != nil {
					serveImageCacheEntry(w, r, entry, hitNow)
					return
				}
			case <-r.Context().Done():
			}
		}
		next.ServeHTTP(w, r)
		return
	}

	entry, flight, leader, available := site.lookupOrBegin(key, now)
	if !available {
		next.ServeHTTP(w, r)
		return
	}
	if entry != nil {
		serveImageCacheEntry(w, r, entry, now)
		return
	}
	if !leader {
		select {
		case <-flight.done:
			hitNow := site.runtime.currentTime()
			if entry, _, available := site.lookup(key, hitNow); available && entry != nil {
				serveImageCacheEntry(w, r, entry, hitNow)
				return
			}
		case <-r.Context().Done():
		}
		next.ServeHTTP(w, r)
		return
	}

	var candidate *imageCacheEntry
	defer func() {
		site.finishFlight(key, flight, candidate, site.runtime.currentTime())
	}()
	reservedBytes, captureAllowed := site.beginFlightCapture(key, flight)
	if !captureAllowed {
		next.ServeHTTP(w, r)
		return
	}
	capture := newImageCacheCaptureWriter(w, site.runtime, reservedBytes, imageCacheKeyBytes(key))
	next.ServeHTTP(capture, r)
	// Publication happens only after ReverseProxy returns from a complete body
	// copy. Panics, short writes, client disconnects and length mismatches leave
	// candidate nil and merely wake identical waiters.
	candidate = capture.entry()
}
