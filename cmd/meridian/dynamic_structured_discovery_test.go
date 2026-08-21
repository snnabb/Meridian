package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newStructuredDiscoveryTestIssuer(t *testing.T) *dynamicCapabilityIssuer {
	return newStructuredDiscoveryTestIssuerForProfile(t, dynamicProfileCompatible)
}

func newStructuredDiscoveryTestIssuerForProfile(t *testing.T, profile string) *dynamicCapabilityIssuer {
	t.Helper()
	limits, ok := dynamicLimitsForProfile(profile)
	if !ok {
		t.Fatalf("dynamic profile %q is unavailable", profile)
	}
	resolver := dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	})
	_, state := redirectRuntimeState(t, limits, resolver)
	t.Cleanup(state.close)
	return &dynamicCapabilityIssuer{
		key:            bytes.Repeat([]byte{0x42}, 32),
		siteID:         41,
		policyRevision: 7,
		policy: dynamicRedirectPolicy{
			configured: true,
			available:  true,
			profile:    profile,
			limits:     limits,
			sources:    allDynamicDiscoverySources(),
		},
		state: state,
	}
}

func mustStructuredURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := normalizeDynamicURL(raw)
	if err != nil {
		t.Fatalf("normalize %q: %v", raw, err)
	}
	return parsed
}

func capabilityTokenFromRoute(t *testing.T, route string) string {
	t.Helper()
	if !strings.HasPrefix(route, dynamicRoutePrefix) {
		t.Fatalf("route %q lacks dynamic prefix", route)
	}
	remainder := strings.TrimPrefix(route, dynamicRoutePrefix)
	token, _, _ := strings.Cut(remainder, "/")
	if token == "" {
		t.Fatalf("route %q has no token", route)
	}
	return token
}

func structuredCapabilityRoutes(value string) []string {
	routes := make([]string, 0)
	for offset := 0; offset < len(value); {
		relative := strings.Index(value[offset:], dynamicRoutePrefix)
		if relative < 0 {
			break
		}
		start := offset + relative
		end := start
		for end < len(value) && !strings.ContainsRune("\"' <>&\t\r\n", rune(value[end])) {
			end++
		}
		routes = append(routes, value[start:end])
		offset = end
	}
	return routes
}

func TestStructuredCapabilityIsEncryptedAuthenticatedAndStable(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	target := mustStructuredURL(t, "https://cdn.example.com/video/master.m3u8?ApiKey=origin-secret")
	previous := mustStructuredURL(t, "https://api.example.com/Items/1/PlaybackInfo")

	first, discoveryErr := issuer.mint(context.Background(), previous, target, dynamicDiscoverySourcePlaybackInfo)
	if discoveryErr != nil {
		t.Fatalf("mint first capability: %v", discoveryErr)
	}
	second, discoveryErr := issuer.mint(context.Background(), previous, target, dynamicDiscoverySourcePlaybackInfo)
	if discoveryErr != nil {
		t.Fatalf("mint repeated capability: %v", discoveryErr)
	}
	if first != second {
		t.Fatalf("live-safe capability was not stable:\nfirst  %s\nsecond %s", first, second)
	}
	if strings.Contains(first, "cdn.example.com") || strings.Contains(first, "origin-secret") {
		t.Fatalf("capability route disclosed target material: %s", first)
	}

	token := capabilityTokenFromRoute(t, first)
	claims, err := openDynamicCapability(issuer.key, token)
	if err != nil {
		t.Fatalf("open capability: %v", err)
	}
	if claims.Target != target.String() || claims.SiteID != issuer.siteID || claims.PolicyRevision != issuer.policyRevision || claims.Source != dynamicDiscoverySourcePlaybackInfo {
		t.Fatalf("claims = %#v", claims)
	}
	tampered := token[:len(token)-1] + "A"
	if tampered == token {
		tampered = token[:len(token)-1] + "B"
	}
	if _, err := openDynamicCapability(issuer.key, tampered); err == nil {
		t.Fatal("tampered capability was accepted")
	}
}

func TestPlaybackInfoRewriterUsesOnlySchemaURLFields(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://api.example.com/Items/abc/PlaybackInfo")
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
	payload := []byte(`{
		"mediaSources": [
			{
				"protocol": "File",
				"path": "/srv/private/movie.mkv",
				"transcodingUrl": "/Videos/abc/master.m3u8?ApiKey=local-token",
				"directStreamUrl": "https://cdn.example.com/movie.mkv?sig=direct-secret",
				"mediaStreams": [
					{"deliveryUrl":"https://sub.example.com/sub.vtt?sig=subtitle-secret","isExternalUrl":true}
				],
				"vendor": {"url":"https://ignored.example.com/arbitrary"}
			},
			{
				"Protocol": "Http",
				"Path": "https://video.example.com/live.ts?token=path-secret",
				"RequiredHttpHeaders": {}
			}
		]
	}`)
	rewritten, err := rewritePlaybackInfoResponse(payload, session)
	if err != nil {
		t.Fatalf("rewrite PlaybackInfo: %v", err)
	}
	text := string(rewritten)
	for _, secret := range []string{"direct-secret", "subtitle-secret", "path-secret", "cdn.example.com", "sub.example.com", "video.example.com"} {
		if strings.Contains(text, secret) {
			t.Fatalf("rewritten PlaybackInfo leaked %q: %s", secret, text)
		}
	}
	if !strings.Contains(text, `"transcodingUrl":"/Videos/abc/master.m3u8?ApiKey=local-token"`) {
		t.Fatalf("same-origin relative TranscodingUrl changed: %s", text)
	}
	if !strings.Contains(text, `"path":"/srv/private/movie.mkv"`) {
		t.Fatalf("File protocol path changed: %s", text)
	}
	if !strings.Contains(text, "https://ignored.example.com/arbitrary") {
		t.Fatalf("schema-unknown URL was scanned or removed: %s", text)
	}
	if strings.Count(text, dynamicRoutePrefix) != 3 {
		t.Fatalf("dynamic route count = %d, want 3: %s", strings.Count(text, dynamicRoutePrefix), text)
	}
}

func TestPlaybackInfoRemotePathWithRequiredHeadersFailsClosed(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://api.example.com/Items/abc/PlaybackInfo")
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
	payload := []byte(`{"MediaSources":[{"Protocol":"Http","Path":"https://video.example.com/live.ts","RequiredHttpHeaders":{"Authorization":"secret"}}]}`)
	if _, err := rewritePlaybackInfoResponse(payload, session); err == nil {
		t.Fatal("credential-bearing remote Path was accepted")
	}
}

func TestPlaybackInfoRewriteDiagnosticCodeIsStableAndSecretFree(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", want: "none"},
		{name: "invalid json", err: errors.New("invalid PlaybackInfo JSON"), want: "invalid_json"},
		{name: "media sources", err: errors.New("PlaybackInfo MediaSources has an invalid type"), want: "media_sources_invalid"},
		{name: "required headers", err: errors.New("PlaybackInfo RequiredHttpHeaders has an invalid value"), want: "required_headers_invalid"},
		{name: "origin headers", err: errors.New("external subtitle URL requires unsupported origin headers"), want: "origin_headers_unsupported"},
		{name: "invalid discovered URL", err: errors.New("invalid discovered URL"), want: "url_invalid"},
		{name: "discovered URL whitespace", err: errors.New("invalid discovered URL: surrounding whitespace"), want: "url_surrounding_whitespace"},
		{name: "discovered URL fragment", err: errors.New("invalid discovered URL: fragment"), want: "url_fragment"},
		{name: "protocol type", err: errors.New("PlaybackInfo field Protocol has an invalid type"), want: "protocol_invalid"},
		{name: "capability", err: newDynamicProxyError(dynamicObservationReasonDomainDenied), want: "capability_domain_denied"},
		{name: "unknown does not echo secret", err: errors.New("unexpected upstream value bearer-secret"), want: "unclassified"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := playbackInfoRewriteDiagnosticCode(test.err); got != test.want {
				t.Fatalf("diagnostic code = %q, want %q", got, test.want)
			}
			if strings.Contains(playbackInfoRewriteDiagnosticCode(test.err), "secret") {
				t.Fatal("diagnostic code exposed error content")
			}
		})
	}
	if got := playbackInfoRewriteDiagnosticFingerprint(errors.New("unexpected upstream value bearer-secret")); len(got) != 8 || strings.Contains(got, "secret") {
		t.Fatalf("diagnostic fingerprint is unsafe: %q", got)
	}
	if !playbackInfoAutomaticFallbackAllowed(errors.New("invalid discovered URL: target normalization host")) {
		t.Fatal("URL normalization failure must allow automatic proxy fallback")
	}
	for _, err := range []error{
		errors.New("external subtitle URL requires unsupported origin headers"),
		errors.New("PlaybackInfo RequiredHttpHeaders has an invalid value"),
		errors.New("invalid PlaybackInfo JSON"),
	} {
		if playbackInfoAutomaticFallbackAllowed(err) {
			t.Fatalf("security or structure error unexpectedly allowed fallback: %v", err)
		}
	}
}

func TestPlaybackInfoRelativeExternalDeliveryURLWithRequiredHeadersFailsClosed(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://api.example.com/Items/abc/PlaybackInfo")
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
	payload := []byte(`{"MediaSources":[{"RequiredHttpHeaders":{"Authorization":"secret"},"MediaStreams":[{"DeliveryUrl":"/Videos/abc/Subtitles/1/Stream.ass","IsExternalUrl":true}]}]}`)
	if _, err := rewritePlaybackInfoResponse(payload, session); err == nil {
		t.Fatal("credential-bearing relative subtitle was accepted")
	}
}

func TestCompatibleAndExtremePlaybackInfoAcceptSchemelessHostPortURLs(t *testing.T) {
	for _, test := range []struct {
		name   string
		input  string
		target string
	}{
		{name: "bare authority", input: "cflocal.xxlb.net:80/Videos/1/stream.mp4?token=origin-secret", target: "http://cflocal.xxlb.net:80/Videos/1/stream.mp4?token=origin-secret"},
		{name: "http missing slashes", input: "http:gfplay.xxlb.net:80/Videos/1/stream.mp4?token=origin-secret", target: "http://gfplay.xxlb.net:80/Videos/1/stream.mp4?token=origin-secret"},
		{name: "http single slash", input: "http:/gfplay.xxlb.net:80/Videos/1/stream.mp4?token=origin-secret", target: "http://gfplay.xxlb.net:80/Videos/1/stream.mp4?token=origin-secret"},
	} {
		for _, profile := range []string{dynamicProfileCompatible, dynamicProfileExtreme} {
			t.Run(test.name+"/"+profile, func(t *testing.T) {
				issuer := newStructuredDiscoveryTestIssuerForProfile(t, profile)
				base := mustStructuredURL(t, "http://line.example.com/Items/1/PlaybackInfo")
				session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
				payload, err := json.Marshal(map[string]any{"MediaSources": []any{map[string]any{"DirectStreamUrl": test.input}}})
				if err != nil {
					t.Fatalf("marshal PlaybackInfo: %v", err)
				}
				rewritten, err := rewritePlaybackInfoResponse(payload, session)
				if err != nil {
					t.Fatalf("rewrite %s PlaybackInfo URL: %v", profile, err)
				}
				routes := structuredCapabilityRoutes(string(rewritten))
				if len(routes) != 1 || strings.Contains(string(rewritten), "xxlb.net") || strings.Contains(string(rewritten), "origin-secret") {
					t.Fatalf("URL was not protected by one capability route: %s", rewritten)
				}
				claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, routes[0]))
				if err != nil {
					t.Fatalf("open URL capability: %v", err)
				}
				if claims.Target != test.target {
					t.Fatalf("capability target = %q, want %q", claims.Target, test.target)
				}
			})
		}

		t.Run(test.name+"/safe", func(t *testing.T) {
			issuer := newStructuredDiscoveryTestIssuerForProfile(t, dynamicProfileSafe)
			base := mustStructuredURL(t, "http://line.example.com/Items/1/PlaybackInfo")
			session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
			payload, err := json.Marshal(map[string]any{"MediaSources": []any{map[string]any{"DirectStreamUrl": test.input}}})
			if err != nil {
				t.Fatalf("marshal PlaybackInfo: %v", err)
			}
			if _, err := rewritePlaybackInfoResponse(payload, session); err == nil {
				t.Fatal("Safe unexpectedly accepted a malformed host:port URL")
			}
		})
	}
}

func TestAutomaticPlaybackInfoFallbackRewritesValidURLsAndPreservesInvalidOnes(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "http://line.example.com/Items/1/PlaybackInfo")
	payload := []byte(`{"MediaSources":[{"DirectStreamUrl":"http://line.example.com/Videos/1/original.mkv?token=origin-secret","MediaStreams":[{"DeliveryUrl":"http://backend.invalidtld/subtitle.vtt","IsExternalUrl":true}]}]}`)

	strictSession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
	if _, err := rewritePlaybackInfoResponse(payload, strictSession); err == nil {
		t.Fatal("strict PlaybackInfo rewrite unexpectedly accepted the invalid optional URL")
	}
	strictSession.rollback()

	fallbackSession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
	rewritten, err := rewriteAutomaticPlaybackInfoResponse(payload, fallbackSession)
	if err != nil {
		t.Fatalf("automatic PlaybackInfo fallback: %v", err)
	}
	text := string(rewritten)
	if !strings.Contains(text, `"DirectStreamUrl":"/Videos/1/original.mkv?token=origin-secret"`) {
		t.Fatalf("same-authority playback URL was not kept on the proxy: %s", text)
	}
	if !strings.Contains(text, `"DeliveryUrl":"http://backend.invalidtld/subtitle.vtt"`) {
		t.Fatalf("invalid optional URL was not preserved: %s", text)
	}
}

func TestAutomaticPlaybackInfoFallbackPreservesAndLearnsRelativeStreamURL(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://origin.example.com/Items/1/PlaybackInfo")
	clientBase := mustStructuredURL(t, "https://public.example.com/Items/1/PlaybackInfo")
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, learningBase: clientBase, source: dynamicDiscoverySourcePlaybackInfo}
	payload := []byte(`{"MediaSources":[{"DirectStreamUrl":"/vendor/playback-entry?media_id=panel-secret","TranscodingUrl":"video.m3u8?token=manifest-secret"}]}`)
	rewritten, err := rewriteAutomaticPlaybackInfoResponse(payload, session)
	if err != nil {
		t.Fatalf("automatic relative PlaybackInfo fallback: %v", err)
	}
	if !strings.Contains(string(rewritten), "/vendor/playback-entry?media_id=panel-secret") || !strings.Contains(string(rewritten), "video.m3u8?token=manifest-secret") || strings.Contains(string(rewritten), dynamicRoutePrefix) {
		t.Fatalf("automatic relative stream changed: %s", rewritten)
	}
	if !session.commit() {
		t.Fatal("commit relative PlaybackInfo rewrite")
	}
	session.publishLearnedPlaybackPaths()
	now := time.Now()
	for _, pathValue := range []string{"/vendor/playback-entry", "/Items/1/video.m3u8"} {
		if !issuer.state.hasLearnedPlaybackPath(pathValue, now) {
			t.Fatalf("relative PlaybackInfo path %q was not learned", pathValue)
		}
	}
}

func TestPlaybackInfoRelativeManifestDoesNotRequireAdvancedSource(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	issuer.policy.sources = []string{dynamicDiscoverySourceRedirect, dynamicDiscoverySourcePlaybackInfo}
	base := mustStructuredURL(t, "https://origin.example.com/Items/1/PlaybackInfo")
	clientBase := mustStructuredURL(t, "https://public.example.com/Items/1/PlaybackInfo")
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, learningBase: clientBase, source: dynamicDiscoverySourcePlaybackInfo}
	payload := []byte(`{"MediaSources":[{"TranscodingUrl":"/Videos/1/master.m3u8?api_key=relative-client","TranscodingSubProtocol":"hls"}]}`)
	rewritten, err := rewritePlaybackInfoResponse(payload, session)
	if err != nil {
		t.Fatalf("rewrite relative manifest with advanced source disabled: %v", err)
	}
	if !strings.Contains(string(rewritten), "/Videos/1/master.m3u8?api_key=relative-client") || strings.Contains(string(rewritten), dynamicRoutePrefix) {
		t.Fatalf("relative manifest changed with advanced source disabled: %s", rewritten)
	}
	if !session.commit() {
		t.Fatal("commit relative manifest PlaybackInfo rewrite")
	}
	session.publishLearnedPlaybackPaths()
	if !issuer.state.hasLearnedPlaybackPath("/Videos/1/master.m3u8", time.Now()) {
		t.Fatal("relative manifest path was not learned")
	}
}

func TestAutomaticProxyPolicyIgnoresLegacyPerSiteDiscoverySettings(t *testing.T) {
	policy, err := newDynamicRedirectPolicy(Site{
		DynamicDiscoveryEnabled:    false,
		DynamicProfile:             dynamicProfileSafe,
		DynamicDiscoverySources:    []string{},
		DynamicDomainRules:         []DynamicDomainRule{},
		DynamicAllowHTTPSDowngrade: false,
	}, true)
	if err != nil {
		t.Fatalf("automatic proxy policy: %v", err)
	}
	if !policy.configured || !policy.available || policy.profile != dynamicProfileCompatible || !policy.allowHTTPSDowngrade {
		t.Fatalf("automatic proxy policy = %#v", policy)
	}
	for _, source := range allDynamicDiscoverySources() {
		if !policy.sourceEnabled(source) {
			t.Fatalf("automatic proxy source %q is disabled", source)
		}
	}
}

func TestPlaybackInfoPathProtocolAndURLFormsFailClosed(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://api.example.com/Items/abc/PlaybackInfo")

	fileSession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
	filePayload := []byte(`{"MediaSources":[{"Protocol":"File","Path":"C:\\Media\\movie.mkv"}]}`)
	fileOutput, err := rewritePlaybackInfoResponse(filePayload, fileSession)
	if err != nil || !strings.Contains(string(fileOutput), `C:\\Media\\movie.mkv`) {
		t.Fatalf("Windows File path was not preserved: output=%s err=%v", fileOutput, err)
	}

	for name, payload := range map[string]string{
		"unsupported remote protocol":         `{"MediaSources":[{"Protocol":"Rtsp","Path":"rtsp://camera.example.com/live"}]}`,
		"backslash direct stream":             `{"MediaSources":[{"DirectStreamUrl":"\\\\evil.example.com\\video.mp4"}]}`,
		"relative direct stream dot path":     `{"MediaSources":[{"DirectStreamUrl":"../video.mkv"}]}`,
		"relative direct stream fragment":     `{"MediaSources":[{"DirectStreamUrl":"video.mkv#part"}]}`,
		"relative direct stream query only":   `{"MediaSources":[{"DirectStreamUrl":"?media_id=1"}]}`,
		"relative direct ambiguous slashes":   `{"MediaSources":[{"DirectStreamUrl":"///evil.example/video.mkv"}]}`,
		"relative subtitle dot path":          `{"MediaSources":[{"MediaStreams":[{"DeliveryUrl":"../subtitle.vtt","IsExternalUrl":true}]}]}`,
		"relative subtitle encoded dot path":  `{"MediaSources":[{"MediaStreams":[{"DeliveryUrl":"%2e%2e/subtitle.vtt","IsExternalUrl":true}]}]}`,
		"relative subtitle fragment":          `{"MediaSources":[{"MediaStreams":[{"DeliveryUrl":"subtitle.vtt#part","IsExternalUrl":true}]}]}`,
		"relative subtitle backslash":         `{"MediaSources":[{"MediaStreams":[{"DeliveryUrl":"Subtitles\\subtitle.vtt","IsExternalUrl":true}]}]}`,
		"relative subtitle ambiguous slashes": `{"MediaSources":[{"MediaStreams":[{"DeliveryUrl":"///evil.example/subtitle.vtt","IsExternalUrl":true}]}]}`,
	} {
		for _, rewriteRelative := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/rewrite-relative-%t", name, rewriteRelative), func(t *testing.T) {
				session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo, rewriteRelative: rewriteRelative}
				defer session.rollback()
				if _, err := rewritePlaybackInfoResponse([]byte(payload), session); err == nil {
					t.Fatal("ambiguous or unsupported PlaybackInfo URL was accepted")
				}
			})
		}
	}
}

func TestPlaybackInfoRelativeExternalDeliveryURLStaysOnProxy(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://video.emos.best/emby/Items/ve-173940/PlaybackInfo")
	for _, test := range []struct {
		name     string
		delivery string
		want     string
	}{
		{name: "root relative", delivery: "/emby/Videos/ve-173940/34o70dwlzpq7_null/Subtitles/8298/Stream.ass", want: "/emby/Videos/ve-173940/34o70dwlzpq7_null/Subtitles/8298/Stream.ass"},
		{name: "path relative", delivery: "Subtitles/8298/Stream.vtt", want: "/emby/Items/ve-173940/Subtitles/8298/Stream.vtt"},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
			defer session.rollback()
			payload := structuredTestJSON(t, map[string]any{"MediaSources": []any{map[string]any{
				"DirectStreamUrl": "https://video.emos.best/emby/emya/video?server=emos&media_id=34o70dwlzpq7",
				"MediaStreams":    []any{map[string]any{"DeliveryUrl": test.delivery, "IsExternalUrl": true}},
			}}})
			rewritten, err := rewritePlaybackInfoResponse(payload, session)
			if err != nil {
				t.Fatalf("rewrite PlaybackInfo with relative external subtitle: %v", err)
			}

			var result struct {
				MediaSources []struct {
					DirectStreamURL string `json:"DirectStreamUrl"`
					MediaStreams    []struct {
						DeliveryURL string `json:"DeliveryUrl"`
					} `json:"MediaStreams"`
				} `json:"MediaSources"`
			}
			if err := json.Unmarshal(rewritten, &result); err != nil || len(result.MediaSources) != 1 || len(result.MediaSources[0].MediaStreams) != 1 {
				t.Fatalf("decode rewritten PlaybackInfo: result=%#v err=%v", result, err)
			}
			if got := result.MediaSources[0].DirectStreamURL; got != "/emby/emya/video?server=emos&media_id=34o70dwlzpq7" {
				t.Fatalf("DirectStreamUrl = %q", got)
			}
			if got := result.MediaSources[0].MediaStreams[0].DeliveryURL; got != test.want {
				t.Fatalf("relative DeliveryUrl = %q, want %q", got, test.want)
			}
			if len(issuer.state.capabilities) != 0 || issuer.state.capabilityMemory != 0 {
				t.Fatalf("relative subtitle minted a capability: entries=%d bytes=%d", len(issuer.state.capabilities), issuer.state.capabilityMemory)
			}
		})
	}
}

func TestHLSRewriterEncryptsExternalAndNestedURLsDeterministically(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://api.example.com/Videos/abc/master.m3u8")
	manifest := []byte("#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"a\",URI=\"https://cdn.example.com/audio.m3u8?sig=audio-secret\"\n#EXT-X-STREAM-INF:BANDWIDTH=1000,AUDIO=\"a\"\nmain.m3u8?ApiKey=local-token\n")

	rewrite := func(relative bool) string {
		session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceHLS, rewriteRelative: relative}
		payload, err := rewriteHLSResponse(manifest, session)
		if err != nil {
			t.Fatalf("rewrite HLS: %v", err)
		}
		return string(payload)
	}
	first := rewrite(false)
	second := rewrite(false)
	if first != second {
		t.Fatalf("HLS rewrite was not deterministic:\n%s\n%s", first, second)
	}
	if strings.Contains(first, "cdn.example.com") || strings.Contains(first, "audio-secret") {
		t.Fatalf("HLS rewrite leaked external target: %s", first)
	}
	if !strings.Contains(first, "main.m3u8?ApiKey=local-token") {
		t.Fatalf("same-origin relative variant changed: %s", first)
	}
	if strings.Count(first, dynamicRoutePrefix) != 1 {
		t.Fatalf("external HLS route count = %d, want 1", strings.Count(first, dynamicRoutePrefix))
	}

	nestedSession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: mustStructuredURL(t, "https://cdn.example.com/audio.m3u8?sig=audio-secret"), source: dynamicDiscoverySourceHLS, rewriteRelative: true}
	nested, err := rewriteHLSResponse([]byte("#EXTM3U\n#EXT-X-TARGETDURATION:4\n#EXTINF:4,\nsegment.ts?sig=segment-secret\n#EXT-X-ENDLIST\n"), nestedSession)
	if err != nil {
		t.Fatalf("rewrite nested HLS: %v", err)
	}
	if !strings.Contains(string(nested), dynamicRoutePrefix) || strings.Contains(string(nested), "segment-secret") {
		t.Fatalf("nested HLS URI was not encrypted: %s", nested)
	}
	if _, err := rewriteHLSResponse([]byte("#EXTM3U\n#EXT-X-DEFINE:NAME=\"x\",VALUE=\"segment\"\n{$x}.ts\n"), nestedSession); err == nil {
		t.Fatal("unsupported HLS variable substitution did not fail closed")
	}
	if _, err := rewriteHLSResponse([]byte("#EXTM3U\n\\\\evil.example.com\\segment.ts\n"), nestedSession); err == nil {
		t.Fatal("backslash HLS URI did not fail closed")
	}
}

func TestHLSRenditionReportCyclesReusePublishedShallowCapabilities(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	masterBase := mustStructuredURL(t, "https://api.example.com/live/master.m3u8")
	masterSession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: masterBase, source: dynamicDiscoverySourceHLS}
	master := []byte("#EXTM3U\n#EXT-X-VERSION:9\n#EXT-X-STREAM-INF:BANDWIDTH=1000\nhttps://cdn.example.com/a.m3u8\n#EXT-X-STREAM-INF:BANDWIDTH=2000\nhttps://cdn.example.com/b.m3u8\n")
	rewrittenMaster, err := rewriteHLSResponse(master, masterSession)
	if err != nil || !masterSession.commit() {
		t.Fatalf("rewrite and commit HLS rendition master: %v", err)
	}
	routesByTarget := make(map[string]string)
	for _, route := range structuredCapabilityRoutes(string(rewrittenMaster)) {
		claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, route))
		if err != nil {
			t.Fatalf("open rendition capability: %v", err)
		}
		routesByTarget[claims.Target] = route
	}
	aRoute := routesByTarget["https://cdn.example.com/a.m3u8"]
	bRoute := routesByTarget["https://cdn.example.com/b.m3u8"]
	if aRoute == "" || bRoute == "" {
		t.Fatalf("master rendition routes = %#v\n%s", routesByTarget, rewrittenMaster)
	}

	rewriteReport := func(baseURL, reportURI, wantRoute string) {
		t.Helper()
		session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: mustStructuredURL(t, baseURL), source: dynamicDiscoverySourceHLS, depth: maxDynamicManifestDepth, rewriteRelative: true}
		playlist := []byte("#EXTM3U\n#EXT-X-VERSION:9\n#EXT-X-TARGETDURATION:4\n#EXT-X-MEDIA-SEQUENCE:1\n#EXT-X-RENDITION-REPORT:URI=\"" + reportURI + "\",LAST-MSN=1\n#EXTINF:4,\nsegment.m4s\n")
		rewritten, err := rewriteHLSResponse(playlist, session)
		if err != nil {
			session.rollback()
			t.Fatalf("rewrite over-depth rendition report: %v", err)
		}
		if !strings.Contains(string(rewritten), `URI="`+wantRoute+`"`) {
			session.rollback()
			t.Fatalf("rendition report did not reuse shallow route %q: %s", wantRoute, rewritten)
		}
		if !session.commit() {
			t.Fatal("commit rendition report rewrite")
		}
	}
	rewriteReport("https://cdn.example.com/a.m3u8", "b.m3u8", bRoute)
	rewriteReport("https://cdn.example.com/b.m3u8", "a.m3u8", aRoute)
}

func TestHLSInterstitialAssetURLsFailWithoutAbsolutePublicCapabilityBase(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://cdn.example.com/live.m3u8")
	for _, attribute := range []string{`X-ASSET-URI="https://ads.example.com/asset.m3u8"`, `X-ASSET-LIST="https://ads.example.com/assets.json"`} {
		session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceHLS, rewriteRelative: true}
		playlist := []byte("#EXTM3U\n#EXT-X-VERSION:9\n#EXT-X-TARGETDURATION:4\n#EXT-X-MEDIA-SEQUENCE:1\n#EXT-X-DATERANGE:ID=\"ad\",CLASS=\"com.apple.hls.interstitial\"," + attribute + "\n#EXTINF:4,\nsegment.m4s\n")
		if _, err := rewriteHLSResponse(playlist, session); err == nil {
			session.rollback()
			t.Fatalf("HLS interstitial attribute was accepted without a public capability base: %s", attribute)
		}
		session.rollback()
	}
}

func TestDASHRewriterClonesInheritedTemplateAndExpandsSignedValues(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://api.example.com/media/manifest.mpd")
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceDASH}
	manifest := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static">
  <Period><AdaptationSet mimeType="video/mp4">
    <SegmentTemplate initialization="https://cdn.example.com/init-$RepresentationID$.mp4?sig=init-secret" media="https://cdn.example.com/chunk-$Number%05d$.m4s?sig=media-secret" startNumber="1"/>
    <Representation id="video-main" bandwidth="1000"/>
  </AdaptationSet></Period>
</MPD>`)
	rewritten, err := rewriteDASHResponse(manifest, session)
	if err != nil {
		t.Fatalf("rewrite DASH: %v", err)
	}
	text := string(rewritten)
	if strings.Contains(text, "cdn.example.com") || strings.Contains(text, "init-secret") || strings.Contains(text, "media-secret") {
		t.Fatalf("DASH rewrite leaked target material: %s", text)
	}
	if strings.Count(text, dynamicRoutePrefix) != 2 || strings.Contains(text, "$RepresentationID$") || !strings.Contains(text, "$Number%05d$") {
		t.Fatalf("DASH template routes are incomplete or retain fixed identifiers: %s", text)
	}
	var parsed struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(rewritten, &parsed); err != nil || parsed.XMLName.Local != "MPD" {
		t.Fatalf("rewritten DASH is not XML MPD: name=%v err=%v\n%s", parsed.XMLName, err, text)
	}

	marker := dynamicRoutePrefix
	firstStart := strings.Index(text, marker)
	if firstStart < 0 {
		t.Fatal("DASH output has no capability route")
	}
	firstEnd := firstStart
	for firstEnd < len(text) && text[firstEnd] != '"' && text[firstEnd] != '&' {
		firstEnd++
	}
	firstRoute := text[firstStart:firstEnd]
	firstClaims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, firstRoute))
	if err != nil {
		t.Fatalf("open fixed DASH capability: %v", err)
	}
	if len(firstClaims.Template) != 0 || len(firstClaims.TemplateFixed) != 1 || firstClaims.TemplateFixed[0] != "video-main" || strings.Contains(firstClaims.Target, "video-main") {
		t.Fatalf("fixed DASH claims = %#v", firstClaims)
	}
	fixedTarget, err := resolveDASHCapabilityTarget(firstClaims, "")
	if err != nil || !strings.Contains(fixedTarget.String(), "init-video-main.mp4") {
		t.Fatalf("fixed DASH target = %v err=%v", fixedTarget, err)
	}
	secondRelative := strings.Index(text[firstEnd:], marker)
	if secondRelative < 0 {
		t.Fatal("DASH output has no dynamic template capability")
	}
	secondStart := firstEnd + secondRelative
	secondEnd := secondStart
	for secondEnd < len(text) && text[secondEnd] != '"' && text[secondEnd] != '&' {
		secondEnd++
	}
	secondRoute := text[secondStart:secondEnd]
	claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, secondRoute))
	if err != nil {
		t.Fatalf("open dynamic DASH capability: %v", err)
	}
	if len(claims.Template) != 1 || dashTemplateIdentifier(claims.Template[0]) != "Number" {
		t.Fatalf("dynamic DASH template claims = %#v", claims.Template)
	}
	if _, err := resolveDASHCapabilityTarget(claims, "v0-1"); err == nil {
		t.Fatal("DASH template accepted a value shorter than the authored width")
	}
	target, err := resolveDASHCapabilityTarget(claims, "v0-00042")
	if err != nil {
		t.Fatalf("expand DASH capability: %v", err)
	}
	if !strings.Contains(target.String(), "chunk-00042.m4s") || !strings.Contains(target.String(), "sig=") {
		t.Fatalf("expanded DASH target = %s", target)
	}
}

func TestStructuredResponsePipelineBoundsGzipAndInvalidatesValidators(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	body := []byte(`{"MediaSources":[{"DirectStreamUrl":"https://cdn.example.com/video.mp4?sig=secret"}]}`)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/Items/1/PlaybackInfo", nil)
	response := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}, "ETag": {`"stale"`}},
		Body:          io.NopCloser(bytes.NewReader(compressed.Bytes())),
		ContentLength: int64(compressed.Len()),
		Request:       request,
	}
	if err := rewriteDynamicStructuredResponse(response, issuer, false); err != nil {
		t.Fatalf("rewrite compressed response: %v", err)
	}
	rewritten, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Content-Encoding") != "" || response.Header.Get("ETag") != "" || response.Header.Get("Cache-Control") != "private, no-store" {
		t.Fatalf("rewritten headers = %#v", response.Header)
	}
	if !strings.Contains(string(rewritten), dynamicRoutePrefix) || strings.Contains(string(rewritten), "secret") {
		t.Fatalf("rewritten compressed body = %s", rewritten)
	}

	bombBody := append([]byte(`{"MediaSources":[],"padding":"`), bytes.Repeat([]byte("A"), minDynamicCompressionRatioBytes+1)...)
	bombBody = append(bombBody, []byte(`"}`)...)
	var bombCompressed bytes.Buffer
	bombWriter := gzip.NewWriter(&bombCompressed)
	if _, err := bombWriter.Write(bombBody); err != nil {
		t.Fatal(err)
	}
	if err := bombWriter.Close(); err != nil {
		t.Fatal(err)
	}
	bombResponse := &http.Response{
		Header:        http.Header{"Content-Encoding": {"gzip"}},
		Body:          io.NopCloser(bytes.NewReader(bombCompressed.Bytes())),
		ContentLength: int64(bombCompressed.Len()),
	}
	if _, err := readDynamicStructuredBody(bombResponse, 4<<20); err == nil || !strings.Contains(err.Error(), "compression ratio") {
		t.Fatalf("gzip expansion error=%v, want compression-ratio rejection", err)
	}

	oversizedCompressed := &http.Response{
		Header:        http.Header{"Content-Encoding": {"gzip"}},
		Body:          io.NopCloser(bytes.NewReader(compressed.Bytes())),
		ContentLength: (4 << 20) + 1,
	}
	if _, err := readDynamicStructuredBody(oversizedCompressed, 4<<20); err == nil || !strings.Contains(err.Error(), "compressed structured response body") {
		t.Fatalf("compressed input error=%v, want input-limit rejection", err)
	}
}

func TestPlaybackInfoDisabledPassesThroughWhileRedirectDiscoveryRemainsEnabled(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	issuer.policy.sources = []string{dynamicDiscoverySourceRedirect}
	if !issuer.policy.sourceEnabled(dynamicDiscoverySourceRedirect) || issuer.policy.sourceEnabled(dynamicDiscoverySourcePlaybackInfo) {
		t.Fatalf("PlaybackInfo-off policy sources = %#v", issuer.policy.sources)
	}

	payload := `{"MediaSources":[{"DirectStreamUrl":"https://cdn.example.com/video.mp4?token=upstream-secret"}]}`
	request := httptest.NewRequest(http.MethodPost, "https://api.example.com/Items/1/PlaybackInfo", nil)
	body := &redirectRuntimeCloseSpy{Reader: strings.NewReader(payload)}
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("ETag", `"upstream-validator"`)
	response := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        header,
		Body:          body,
		ContentLength: int64(len(payload)),
		Request:       request,
	}
	if err := rewriteDynamicStructuredResponse(response, issuer, false); err != nil {
		t.Fatalf("PlaybackInfo-off pass-through: %v", err)
	}
	if body.closed.Load() || response.Body != body || response.ContentLength != int64(len(payload)) || response.Header.Get("ETag") != `"upstream-validator"` || response.Header.Get("Cache-Control") != "" {
		t.Fatalf("PlaybackInfo-off response was modified: closed=%t length=%d headers=%#v", body.closed.Load(), response.ContentLength, response.Header)
	}
	passedThrough, err := io.ReadAll(response.Body)
	if err != nil || string(passedThrough) != payload {
		t.Fatalf("PlaybackInfo-off body=%q err=%v, want unchanged", passedThrough, err)
	}
	if len(issuer.state.capabilities) != 0 {
		t.Fatalf("PlaybackInfo-off minted %d capabilities", len(issuer.state.capabilities))
	}
	_ = response.Body.Close()
}
func TestDynamicParseBudgetEnforcesPerSiteConcurrency(t *testing.T) {
	runtime := newDynamicRuntime()
	limits, ok := dynamicLimitsForProfile(dynamicProfileCompatible)
	if !ok {
		t.Fatal("compatible profile is unavailable")
	}
	state := newDynamicSiteState(runtime, limits)
	releaseFirst, ok := state.acquireParse(1)
	if !ok {
		t.Fatal("first parse reservation failed")
	}
	releaseSecond, ok := state.acquireParse(1)
	if !ok {
		releaseFirst()
		t.Fatal("second parse reservation failed")
	}
	if release, acquired := state.acquireParse(1); acquired {
		release()
		releaseFirst()
		releaseSecond()
		t.Fatal("third concurrent parse reservation was accepted")
	}
	releaseFirst()
	releaseThird, ok := state.acquireParse(1)
	if !ok {
		releaseSecond()
		t.Fatal("parse capacity was not restored after release")
	}
	releaseSecond()
	releaseThird()
}

func TestCapabilityRoutePinsDialAndStripsCrossOriginSecrets(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	target := mustStructuredURL(t, "https://cdn.example.com/video.mp4?sig=origin-secret")
	route, discoveryErr := issuer.mint(context.Background(), mustStructuredURL(t, "https://api.example.com/Items/1/PlaybackInfo"), target, dynamicDiscoverySourcePlaybackInfo)
	if discoveryErr != nil {
		t.Fatalf("mint capability: %v", discoveryErr)
	}
	captures := make(chan redirectRuntimeDialCapture, 1)
	issuer.transportFactory = redirectRuntimeFactory(captures, func(*http.Request) string {
		return "HTTP/1.1 206 Partial Content\r\nContent-Type: video/mp4\r\nContent-Length: 4\r\nContent-Range: bytes 0-3/10\r\nSet-Cookie: upstream=secret\r\n\r\ndata"
	})

	request := httptest.NewRequest(http.MethodGet, "https://site.example.com"+route, nil)
	request.Header.Set("Range", "bytes=0-3")
	request.Header.Set("Authorization", "Bearer client-secret")
	request.Header.Set("Cookie", "session=client-secret")
	recorder := httptest.NewRecorder()
	issuer.serve(recorder, request)
	if recorder.Code != http.StatusPartialContent || recorder.Body.String() != "data" {
		t.Fatalf("capability response = %d %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Set-Cookie") != "" || recorder.Header().Get("Cache-Control") != "private, no-store" || recorder.Header().Get("Content-Range") != "bytes 0-3/10" {
		t.Fatalf("capability response headers = %#v", recorder.Header())
	}
	select {
	case capture := <-captures:
		if capture.err != nil || capture.address != "1.1.1.1:443" || capture.request.URL.RequestURI() != "/video.mp4?sig=origin-secret" {
			t.Fatalf("pinned capture = %#v", capture)
		}
		if capture.request.Header.Get("Authorization") != "" || capture.request.Header.Get("Cookie") != "" || capture.request.Header.Get("Range") != "bytes=0-3" {
			t.Fatalf("cross-origin request headers = %#v", capture.request.Header)
		}
	case <-time.After(time.Second):
		t.Fatal("capability route did not dial the pinned transport")
	}

	invalid := httptest.NewRecorder()
	issuer.serve(invalid, httptest.NewRequest(http.MethodGet, "https://site.example.com"+dynamicRoutePrefix+"tampered", nil))
	if invalid.Code != http.StatusNotFound || invalid.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("invalid capability response = %d %#v", invalid.Code, invalid.Header())
	}
}

func TestCapabilityRouteDirectModeRedirectsPlaybackInfoMainVideo(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	issuer.site.MainVideoStreamMode = mainVideoStreamModeDirect
	target := mustStructuredURL(t, "https://cdn.example.com/video.mp4?sig=client-target")
	route, discoveryErr := issuer.mint(context.Background(), mustStructuredURL(t, "https://api.example.com/Items/1/PlaybackInfo"), target, dynamicDiscoverySourcePlaybackInfo)
	if discoveryErr != nil {
		t.Fatalf("mint direct capability: %v", discoveryErr)
	}

	for _, path := range []string{route, "/emby" + route + "?X-Emby-Token=client-query"} {
		recorder := httptest.NewRecorder()
		issuer.serve(recorder, httptest.NewRequest(http.MethodGet, "https://site.example.com"+path, nil))
		if recorder.Code != http.StatusTemporaryRedirect || recorder.Header().Get("Location") != target.String() || recorder.Header().Get("Content-Length") != "0" {
			t.Fatalf("direct capability response for %q = %d %#v", path, recorder.Code, recorder.Header())
		}
	}
}

func TestHLSCapabilityDeliveryDirectivesAreConstrained(t *testing.T) {
	target := mustStructuredURL(t, "https://cdn.example.com/live.m3u8?a=one&sig=signed&z=last")
	claims := dynamicCapabilityClaims{Source: dynamicDiscoverySourceHLS, Kind: dynamicCapabilityKindManifest, Depth: 1}
	updated, err := applyHLSCapabilityDirectives(target, claims, "_HLS_msn=12&_HLS_part=3&_HLS_skip=YES")
	if err != nil {
		t.Fatalf("apply HLS delivery directives: %v", err)
	}
	if updated.RawQuery != "_HLS_msn=12&_HLS_part=3&_HLS_skip=YES&a=one&sig=signed&z=last" {
		t.Fatalf("updated HLS query = %q", updated.RawQuery)
	}
	rawSigned := mustStructuredURL(t, "https://cdn.example.com/live.m3u8?sig=a%2fb%2B&a=one%7Etwo")
	if _, err := applyHLSCapabilityDirectives(rawSigned, claims, "_HLS_msn=12"); err == nil {
		t.Fatal("LL-HLS directives accepted a non-canonical raw signed query")
	}
	for _, raw := range []string{"token=attacker", "_HLS_msn=abc", "_HLS_msn=1&_HLS_msn=2"} {
		if _, err := applyHLSCapabilityDirectives(target, claims, raw); err == nil {
			t.Fatalf("unsafe delivery directives %q were accepted", raw)
		}
	}
}

func TestStructuredDiscoveryProxyLifecycleEndToEnd(t *testing.T) {
	app := newTestApp(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Items/1/PlaybackInfo" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"MediaSources":[{"DirectStreamUrl":"https://cdn.example.com/movie.mp4?sig=e2e-secret","MediaStreams":[{"DeliveryUrl":"/Videos/1/Subtitles/2/Stream.ass","IsExternalUrl":true}]}]}`)
	}))
	defer upstream.Close()

	port := freePort(t)
	site, err := app.db.CreateSiteRecord(Site{
		Name:                    "structured-e2e",
		ListenPort:              port,
		IngressMode:             ingressModePort,
		TargetURL:               upstream.URL,
		PlaybackMode:            "direct",
		StreamHosts:             "[]",
		UAMode:                  "infuse",
		DynamicDiscoveryEnabled: true,
		DynamicProfile:          dynamicProfileCompatible,
		DynamicDiscoverySources: allDynamicDiscoverySources(),
	})
	if err != nil {
		t.Fatalf("create e2e site: %v", err)
	}
	key := bytes.Repeat([]byte{0x55}, 32)
	if err := app.pm.ConfigureDynamicDiscovery(key, "panel.example.com", 9090, func() ([]net.Addr, error) { return nil, nil }); err != nil {
		t.Fatalf("configure dynamic discovery: %v", err)
	}
	app.dynamicRouteKey = append([]byte(nil), key...)
	app.pm.dynamicRuntime.resolver = dynamicIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	})
	captures := make(chan redirectRuntimeDialCapture, 1)
	app.pm.dynamicTransportFactory = redirectRuntimeFactory(captures, func(*http.Request) string {
		return "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nContent-Length: 8\r\nSet-Cookie: origin=secret\r\n\r\nmovie-ok"
	})
	releasePort(port)
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("start e2e site: %v", err)
	}
	t.Cleanup(func() { _ = app.pm.StopSite(site.ID) })

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	response, err := http.Get(baseURL + "/Items/1/PlaybackInfo")
	if err != nil {
		t.Fatalf("fetch rewritten PlaybackInfo: %v", err)
	}
	payload, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("PlaybackInfo response status=%d read=%v body=%s", response.StatusCode, readErr, payload)
	}
	text := string(payload)
	if strings.Contains(text, "cdn.example.com") || strings.Contains(text, "e2e-secret") {
		t.Fatalf("e2e PlaybackInfo leaked target: %s", text)
	}
	if !strings.Contains(text, `"DeliveryUrl":"/Videos/1/Subtitles/2/Stream.ass"`) {
		t.Fatalf("e2e PlaybackInfo lost relative external subtitle: %s", text)
	}
	start := strings.Index(text, dynamicRoutePrefix)
	if start < 0 {
		t.Fatalf("e2e PlaybackInfo has no capability: %s", text)
	}
	end := strings.IndexByte(text[start:], '"')
	if end < 0 {
		t.Fatalf("e2e capability is not JSON-delimited: %s", text)
	}
	route := text[start : start+end]

	request, err := http.NewRequest(http.MethodGet, baseURL+route, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Cookie", "meridian_session=must-not-cross")
	mediaResponse, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("consume e2e capability: %v", err)
	}
	mediaBody, readErr := io.ReadAll(mediaResponse.Body)
	_ = mediaResponse.Body.Close()
	if readErr != nil || mediaResponse.StatusCode != http.StatusOK || string(mediaBody) != "movie-ok" {
		t.Fatalf("media response status=%d read=%v body=%q", mediaResponse.StatusCode, readErr, mediaBody)
	}
	if mediaResponse.Header.Get("Set-Cookie") != "" || mediaResponse.Header.Get("Cache-Control") != "private, no-store" {
		t.Fatalf("media response headers = %#v", mediaResponse.Header)
	}
	select {
	case capture := <-captures:
		if capture.err != nil || capture.address != "1.1.1.1:443" || capture.request.Header.Get("Cookie") != "" || capture.request.URL.RequestURI() != "/movie.mp4?sig=e2e-secret" {
			t.Fatalf("e2e pinned request = %#v", capture)
		}
	case <-time.After(time.Second):
		t.Fatal("e2e capability did not reach pinned transport")
	}
}

func TestRelativePlaybackInfoVendorRedirectStaysOnProxyEndToEnd(t *testing.T) {
	app := newTestApp(t)
	apiRouteHits := make(chan struct{}, 1)
	apiUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Items/ve-173940/PlaybackInfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"MediaSources":[{"DirectStreamUrl":"/vendor/playback-entry?server=emos&media_id=panel-secret"}]}`)
		case "/vendor/playback-entry":
			if r.URL.Query().Get("server") != "emos" || r.URL.Query().Get("media_id") != "panel-secret" {
				http.Error(w, "unexpected vendor query", http.StatusBadRequest)
				return
			}
			select {
			case apiRouteHits <- struct{}{}:
			default:
			}
			w.Header().Set("Location", "https://media.vendor.com/movie.mkv?sig=backend-secret")
			w.WriteHeader(http.StatusPermanentRedirect)
		default:
			http.NotFound(w, r)
		}
	}))
	defer apiUpstream.Close()
	playbackRouteHits := make(chan struct{}, 1)
	playbackUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case playbackRouteHits <- struct{}{}:
		default:
		}
		http.Error(w, "control endpoint reached playback target", http.StatusBadGateway)
	}))
	defer playbackUpstream.Close()

	port := freePort(t)
	site, err := app.db.CreateSiteRecord(Site{
		Name:                    "relative-vendor-redirect-e2e",
		ListenPort:              port,
		IngressMode:             ingressModePort,
		TargetURL:               apiUpstream.URL,
		PlaybackTargetURL:       playbackUpstream.URL,
		PlaybackMode:            "direct",
		StreamHosts:             "[]",
		UAMode:                  "infuse",
		DynamicDiscoveryEnabled: true,
		DynamicProfile:          dynamicProfileCompatible,
		DynamicDiscoverySources: allDynamicDiscoverySources(),
	})
	if err != nil {
		t.Fatalf("create relative vendor redirect site: %v", err)
	}
	key := bytes.Repeat([]byte{0x5a}, 32)
	if err := app.pm.ConfigureDynamicDiscovery(key, "panel.example.com", 9090, func() ([]net.Addr, error) { return nil, nil }); err != nil {
		t.Fatalf("configure relative vendor discovery: %v", err)
	}
	app.dynamicRouteKey = append([]byte(nil), key...)
	app.pm.dynamicRuntime.resolver = dynamicIPResolverFunc(func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "media.vendor.com" {
			return nil, fmt.Errorf("unexpected DNS host %q", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	})
	captures := make(chan redirectRuntimeDialCapture, 1)
	app.pm.dynamicTransportFactory = redirectRuntimeFactory(captures, func(*http.Request) string {
		return "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nContent-Length: 8\r\n\r\nmovie-ok"
	})
	releasePort(port)
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("start relative vendor redirect site: %v", err)
	}
	t.Cleanup(func() { _ = app.pm.StopSite(site.ID) })

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	response, err := client.Get(baseURL + "/Items/ve-173940/PlaybackInfo")
	if err != nil {
		t.Fatalf("fetch relative vendor PlaybackInfo: %v", err)
	}
	payload, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("relative vendor PlaybackInfo status=%d read=%v body=%s", response.StatusCode, readErr, payload)
	}
	var playbackInfo struct {
		MediaSources []struct {
			DirectStreamURL string `json:"DirectStreamUrl"`
		} `json:"MediaSources"`
	}
	if err := json.Unmarshal(payload, &playbackInfo); err != nil || len(playbackInfo.MediaSources) != 1 {
		t.Fatalf("decode relative vendor PlaybackInfo: payload=%s err=%v", payload, err)
	}
	panelRoute := playbackInfo.MediaSources[0].DirectStreamURL
	if panelRoute != "/vendor/playback-entry?server=emos&media_id=panel-secret" {
		t.Fatalf("relative vendor URL changed: %s", payload)
	}

	panelResponse, err := client.Get(baseURL + panelRoute)
	if err != nil {
		t.Fatalf("request learned vendor endpoint: %v", err)
	}
	panelBody, panelReadErr := io.ReadAll(panelResponse.Body)
	_ = panelResponse.Body.Close()
	backendRoute := panelResponse.Header.Get("Location")
	if panelReadErr != nil || panelResponse.StatusCode != http.StatusPermanentRedirect || !strings.HasPrefix(backendRoute, dynamicRoutePrefix) || strings.Contains(backendRoute, "vendor.com") || strings.Contains(backendRoute, "backend-secret") {
		t.Fatalf("vendor redirect status=%d read=%v Location=%q body=%s", panelResponse.StatusCode, panelReadErr, backendRoute, panelBody)
	}
	select {
	case <-apiRouteHits:
	default:
		t.Fatal("learned playback control endpoint did not reach the API target")
	}
	select {
	case <-playbackRouteHits:
		t.Fatal("learned playback control endpoint was sent to playback_target_url")
	default:
	}

	mediaRequest, err := http.NewRequest(http.MethodGet, baseURL+backendRoute, nil)
	if err != nil {
		t.Fatal(err)
	}
	mediaRequest.Header.Set("Cookie", "meridian_session=must-not-cross; application=must-not-cross")
	mediaRequest.Header.Set("Authorization", "Bearer must-not-cross")
	mediaResponse, err := client.Do(mediaRequest)
	if err != nil {
		t.Fatalf("consume discovered backend capability: %v", err)
	}
	mediaBody, readErr := io.ReadAll(mediaResponse.Body)
	_ = mediaResponse.Body.Close()
	if readErr != nil || mediaResponse.StatusCode != http.StatusOK || string(mediaBody) != "movie-ok" {
		t.Fatalf("discovered backend status=%d read=%v body=%q", mediaResponse.StatusCode, readErr, mediaBody)
	}
	select {
	case capture := <-captures:
		if capture.err != nil || capture.address != "1.1.1.1:443" || capture.request.URL.RequestURI() != "/movie.mkv?sig=backend-secret" || capture.request.Header.Get("Cookie") != "" || capture.request.Header.Get("Authorization") != "" {
			t.Fatalf("discovered backend request = %#v", capture)
		}
	case <-time.After(time.Second):
		t.Fatal("discovered backend capability did not reach the pinned transport")
	}
}

func TestFailedDynamicSiteStartClosesRuntimeState(t *testing.T) {
	app := newTestApp(t)
	// Match StartSite's wildcard listener exactly. On Windows, occupying only
	// 127.0.0.1 can still allow a separate ":port" listener to bind.
	occupied, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("occupy listener: %v", err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port
	site, err := app.db.CreateSiteRecord(Site{
		Name:                    "failed-dynamic-start",
		ListenPort:              port,
		IngressMode:             ingressModePort,
		TargetURL:               "http://127.0.0.1:8096",
		PlaybackMode:            "direct",
		StreamHosts:             "[]",
		UAMode:                  "infuse",
		DynamicDiscoveryEnabled: true,
		DynamicProfile:          dynamicProfileCompatible,
		DynamicDiscoverySources: allDynamicDiscoverySources(),
	})
	if err != nil {
		t.Fatalf("create failed-start site: %v", err)
	}
	key := bytes.Repeat([]byte{0x66}, 32)
	if err := app.pm.ConfigureDynamicDiscovery(key, "panel.example.com", 9090, func() ([]net.Addr, error) { return nil, nil }); err != nil {
		t.Fatalf("configure dynamic discovery: %v", err)
	}
	app.pm.dynamicRuntime.mu.Lock()
	before := len(app.pm.dynamicRuntime.states)
	app.pm.dynamicRuntime.mu.Unlock()
	if err := app.pm.StartSite(*site); err == nil {
		_ = app.pm.StopSite(site.ID)
		t.Fatal("StartSite unexpectedly bound an occupied port")
	}
	app.pm.dynamicRuntime.mu.Lock()
	after := len(app.pm.dynamicRuntime.states)
	app.pm.dynamicRuntime.mu.Unlock()
	if after != before {
		t.Fatalf("failed StartSite leaked runtime states: before=%d after=%d", before, after)
	}
}

type structuredRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f structuredRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestConfiguredInternalHostnameUsesTrustedCapability(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base, err := normalizeTargetURL("http://emby:8096/master.m3u8")
	if err != nil {
		t.Fatalf("normalize configured internal origin: %v", err)
	}
	authority := redirectHostKey(base)
	issuer.configuredAuthorities = map[string]bool{authority: true}
	issuer.primaryAuthority = authority
	issuer.configuredTransport = structuredRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("transport should not be used while rewriting")
	})
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceHLS}
	route, err := session.rewriteManifest("child.m3u8")
	if err != nil {
		t.Fatalf("rewrite configured internal manifest: %v", err)
	}
	claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, route))
	if err != nil {
		t.Fatalf("open configured internal capability: %v", err)
	}
	if !claims.Trusted || claims.Target != "http://emby:8096/child.m3u8" {
		t.Fatalf("configured internal claims = %#v", claims)
	}
}

func TestConfiguredOriginHLSUsesTypedRecursiveCapabilities(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://origin.example.com/master.m3u8")
	authority := redirectHostKey(base)
	issuer.configuredAuthorities = map[string]bool{authority: true}
	issuer.primaryAuthority = authority
	issuer.site = Site{IngressMode: ingressModePort}
	var captured *http.Request
	issuer.configuredTransport = structuredRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		captured = request.Clone(request.Context())
		captured.Header = request.Header.Clone()
		header := make(http.Header)
		header.Set("Content-Type", "application/vnd.apple.mpegurl")
		body := "#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6,\nsegment.ts\n#EXT-X-ENDLIST\n"
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request}, nil
	})

	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceHLS}
	rewritten, err := rewriteHLSResponse([]byte("#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1000\nchild.m3u8\n"), session)
	if err != nil {
		t.Fatalf("rewrite configured master: %v", err)
	}
	if !session.commit() {
		t.Fatal("commit configured master capabilities")
	}
	masterText := string(rewritten)
	start := strings.Index(masterText, dynamicRoutePrefix)
	if start < 0 {
		t.Fatalf("configured child playlist was not capability-routed: %s", masterText)
	}
	route := strings.TrimSpace(masterText[start:])
	claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, route))
	if err != nil {
		t.Fatalf("open configured manifest capability: %v", err)
	}
	if !claims.Trusted || claims.Kind != dynamicCapabilityKindManifest || claims.Depth != 1 || claims.Source != dynamicDiscoverySourceHLS || claims.Target != "https://origin.example.com/child.m3u8" {
		t.Fatalf("configured manifest claims = %#v", claims)
	}

	request := httptest.NewRequest(http.MethodGet, "https://site.example"+route, nil)
	request.Header.Set("Authorization", "Bearer primary-origin")
	request.Header.Set("Cookie", sessionCookieName+"=admin; emby=allowed")
	recorder := httptest.NewRecorder()
	issuer.serve(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("configured manifest response = %d %s", recorder.Code, recorder.Body.String())
	}
	childText := recorder.Body.String()
	childStart := strings.Index(childText, dynamicRoutePrefix)
	if childStart < 0 {
		t.Fatalf("configured segment was not capability-routed: %s", childText)
	}
	childRoute := strings.TrimSpace(strings.SplitN(childText[childStart:], "\n", 2)[0])
	childClaims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, childRoute))
	if err != nil {
		t.Fatalf("open configured resource capability: %v", err)
	}
	if !childClaims.Trusted || childClaims.Kind != dynamicCapabilityKindResource || childClaims.Depth != 0 || childClaims.Target != "https://origin.example.com/segment.ts" {
		t.Fatalf("configured resource claims = %#v", childClaims)
	}
	if captured == nil || captured.URL.String() != "https://origin.example.com/child.m3u8" || captured.Header.Get("Authorization") != "Bearer primary-origin" || strings.Contains(captured.Header.Get("Cookie"), sessionCookieName+"=") || !strings.Contains(captured.Header.Get("Cookie"), "emby=allowed") {
		t.Fatalf("configured transport request = %#v", captured)
	}
	if recorder.Header().Get("Content-Security-Policy") == "" || recorder.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("configured manifest security headers = %#v", recorder.Header())
	}
}

func TestCapabilityResourceRejectsStructuredAndActiveContent(t *testing.T) {
	for _, test := range []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "manifest", contentType: "application/vnd.apple.mpegurl", body: "#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6,\nhttps://leak.example/segment.ts\n"},
		{name: "active-html", contentType: "text/html", body: `<script>location='https://leak.example/'</script>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			issuer := newStructuredDiscoveryTestIssuer(t)
			base := mustStructuredURL(t, "https://origin.example.com/master.m3u8")
			authority := redirectHostKey(base)
			issuer.configuredAuthorities = map[string]bool{authority: true}
			issuer.primaryAuthority = authority
			issuer.configuredTransport = structuredRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
				header := make(http.Header)
				header.Set("Content-Type", test.contentType)
				return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(test.body)), ContentLength: int64(len(test.body)), Request: request}, nil
			})
			session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceHLS}
			route, err := session.rewrite("resource.bin")
			if err != nil {
				t.Fatalf("mint configured resource: %v", err)
			}
			if !session.commit() {
				t.Fatal("commit configured resource capability")
			}
			recorder := httptest.NewRecorder()
			issuer.serve(recorder, httptest.NewRequest(http.MethodGet, "https://site.example"+route, nil))
			if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), "leak.example") {
				t.Fatalf("resource confusion response = %d %q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestCapabilityResourceTrustsTypedMediaDespiteManifestSuffix(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://origin.example.com/master.m3u8")
	authority := redirectHostKey(base)
	issuer.configuredAuthorities = map[string]bool{authority: true}
	issuer.primaryAuthority = authority
	issuer.configuredTransport = structuredRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("Content-Type", "application/octet-stream")
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader("key")), ContentLength: 3, Request: request}, nil
	})
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceHLS}
	route, err := session.rewrite("key.m3u8")
	if err != nil || !session.commit() {
		t.Fatalf("mint typed resource capability: route=%q err=%v", route, err)
	}
	recorder := httptest.NewRecorder()
	issuer.serve(recorder, httptest.NewRequest(http.MethodGet, "https://site.example"+route, nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "key" {
		t.Fatalf("typed resource response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestCapabilityResourceSanitizesUpstreamErrorBody(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://origin.example.com/master.m3u8")
	authority := redirectHostKey(base)
	issuer.configuredAuthorities = map[string]bool{authority: true}
	issuer.primaryAuthority = authority
	issuer.configuredTransport = structuredRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("Content-Type", "text/plain")
		header.Set("Retry-After", "3")
		body := "failed target https://origin.example.com/private?token=secret"
		return &http.Response{StatusCode: http.StatusBadGateway, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request}, nil
	})
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceHLS}
	route, err := session.rewrite("segment.ts")
	if err != nil || !session.commit() {
		t.Fatalf("mint failed-resource capability: route=%q err=%v", route, err)
	}
	recorder := httptest.NewRecorder()
	issuer.serve(recorder, httptest.NewRequest(http.MethodGet, "https://site.example"+route, nil))
	if recorder.Code != http.StatusBadGateway || recorder.Header().Get("Retry-After") != "3" || recorder.Body.String() != `{"error":"upstream dynamic request failed"}` || strings.Contains(recorder.Body.String(), "token=secret") {
		t.Fatalf("sanitized resource error = %d headers=%#v body=%q", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

func TestPlaybackInfoExternalManifestClaimsParserAndDepth(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://api.example.com/Items/1/PlaybackInfo")
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
	rewritten, err := rewritePlaybackInfoResponse([]byte(`{"MediaSources":[{"TranscodingUrl":"https://cdn.example.com/live/master.m3u8","TranscodingSubProtocol":"hls"}]}`), session)
	if err != nil {
		t.Fatalf("rewrite external PlaybackInfo manifest: %v", err)
	}
	text := string(rewritten)
	start := strings.Index(text, dynamicRoutePrefix)
	if start < 0 {
		t.Fatalf("external PlaybackInfo manifest has no capability: %s", text)
	}
	end := strings.IndexByte(text[start:], '"')
	if end < 0 {
		t.Fatalf("external PlaybackInfo capability is not JSON-delimited: %s", text)
	}
	route := text[start : start+end]
	claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, route))
	if err != nil {
		t.Fatalf("open PlaybackInfo manifest capability: %v", err)
	}
	if claims.Source != dynamicDiscoverySourceHLS || claims.Kind != dynamicCapabilityKindManifest || claims.Depth != 1 {
		t.Fatalf("PlaybackInfo manifest claims = %#v", claims)
	}

	deep := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: mustStructuredURL(t, claims.Target), source: dynamicDiscoverySourceHLS, depth: maxDynamicManifestDepth}
	if _, err := deep.rewriteManifest("deeper.m3u8"); err == nil {
		t.Fatal("manifest recursion beyond the signed depth limit was accepted")
	}
}

func TestPlaybackInfoPathAndDeliveryURLCarryManifestClaims(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://api.example.com/Items/1/PlaybackInfo")
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
	defer session.rollback()
	payload := []byte(`{"MediaSources":[{"Protocol":"Http","Path":"https://cdn.example.com/live/path.mpd","MediaStreams":[{"IsExternalUrl":true,"DeliveryUrl":"https://captions.example.com/live/subtitle","DeliveryMethod":"Hls"}]}]}`)
	rewritten, err := rewritePlaybackInfoResponse(payload, session)
	if err != nil {
		t.Fatalf("rewrite classified PlaybackInfo fields: %v", err)
	}
	var result struct {
		MediaSources []struct {
			Path         string `json:"Path"`
			MediaStreams []struct {
				DeliveryURL string `json:"DeliveryUrl"`
			} `json:"MediaStreams"`
		} `json:"MediaSources"`
	}
	if err := json.Unmarshal(rewritten, &result); err != nil || len(result.MediaSources) != 1 || len(result.MediaSources[0].MediaStreams) != 1 {
		t.Fatalf("decode rewritten PlaybackInfo: result=%#v err=%v", result, err)
	}
	for name, route := range map[string]string{"Path": result.MediaSources[0].Path, "DeliveryUrl": result.MediaSources[0].MediaStreams[0].DeliveryURL} {
		claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, route))
		if err != nil {
			t.Fatalf("open %s capability: %v", name, err)
		}
		wantSource := dynamicDiscoverySourceDASH
		if name == "DeliveryUrl" {
			wantSource = dynamicDiscoverySourceHLS
		}
		if claims.Source != wantSource || claims.Kind != dynamicCapabilityKindManifest || claims.Depth != 1 {
			t.Fatalf("%s claims = %#v", name, claims)
		}
	}
}

func TestConfiguredPrefixPlaybackInfoUsesExpectedSourceAndTrustedAbsoluteCapability(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	upstreamBase := mustStructuredURL(t, "https://origin.example.com/jellyfin/Items/1/PlaybackInfo")
	authority := redirectHostKey(upstreamBase)
	issuer.configuredAuthorities = map[string]bool{authority: true}
	issuer.primaryAuthority = authority
	issuer.configuredTransport = structuredRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected configured transport call")
	})
	request := httptest.NewRequest(http.MethodGet, upstreamBase.String(), nil)
	request = request.WithContext(context.WithValue(request.Context(), dynamicExpectedStructuredSourceContextKey{}, dynamicDiscoverySourcePlaybackInfo))
	clientBase := mustStructuredURL(t, "https://public.example.com/Items/1/PlaybackInfo")
	request = request.WithContext(context.WithValue(request.Context(), dynamicPlaybackInfoBaseContextKey{}, clientBase))
	body := `{"MediaSources":[{"DirectStreamUrl":"https://origin.example.com/jellyfin/Videos/1/stream.mp4?api_key=absolute-secret","TranscodingUrl":"/Videos/1/master.m3u8?api_key=relative-client"}]}`
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	response := &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request}
	expectedSource := dynamicResponseExpectedStructuredSource(response)
	if expectedSource != dynamicDiscoverySourcePlaybackInfo {
		t.Fatalf("configured prefix expected source = %q", expectedSource)
	}
	if err := rewriteDynamicStructuredResponseExpected(response, issuer, false, expectedSource, 0, false); err != nil {
		t.Fatalf("rewrite configured prefix PlaybackInfo: %v", err)
	}
	rewritten, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read configured prefix PlaybackInfo: %v", err)
	}
	var payload struct {
		MediaSources []struct {
			DirectStreamURL string `json:"DirectStreamUrl"`
			TranscodingURL  string `json:"TranscodingUrl"`
		} `json:"MediaSources"`
	}
	if err := json.Unmarshal(rewritten, &payload); err != nil || len(payload.MediaSources) != 1 {
		t.Fatalf("decode configured prefix PlaybackInfo: payload=%#v err=%v", payload, err)
	}
	media := payload.MediaSources[0]
	if media.TranscodingURL != "/Videos/1/master.m3u8?api_key=relative-client" {
		t.Fatalf("configured relative URL changed to %q", media.TranscodingURL)
	}
	claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, media.DirectStreamURL))
	if err != nil {
		t.Fatalf("open configured absolute PlaybackInfo capability: %v", err)
	}
	if !claims.Trusted || claims.Source != dynamicDiscoverySourcePlaybackInfo || claims.Target != "https://origin.example.com/jellyfin/Videos/1/stream.mp4?api_key=absolute-secret" || strings.Count(claims.Target, "/jellyfin/") != 1 {
		t.Fatalf("configured absolute PlaybackInfo claims = %#v", claims)
	}
	if !issuer.state.hasLearnedPlaybackPath("/Videos/1/master.m3u8", time.Now()) {
		t.Fatal("relative PlaybackInfo URL was not learned through the client-facing path")
	}
	if strings.Contains(string(rewritten), "absolute-secret") || strings.Contains(string(rewritten), "origin.example.com") {
		t.Fatalf("configured PlaybackInfo target leaked in response: %s", rewritten)
	}

	requiredBody := `{"MediaSources":[{"DirectStreamUrl":"https://origin.example.com/jellyfin/Videos/1/stream.mp4","RequiredHttpHeaders":{"X-Required":"secret"}}]}`
	requiredHeader := make(http.Header)
	requiredHeader.Set("Content-Type", "application/json")
	requiredResponse := &http.Response{StatusCode: http.StatusOK, Header: requiredHeader, Body: io.NopCloser(strings.NewReader(requiredBody)), ContentLength: int64(len(requiredBody)), Request: request}
	if err := rewriteDynamicStructuredResponseExpected(requiredResponse, issuer, false, expectedSource, 0, false); err == nil {
		t.Fatal("configured absolute PlaybackInfo URL with required headers was accepted")
	}
}

func TestPathIngressPlaybackInfoPrefixesRelativeAndDynamicRoutes(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	issuer.pathPrefix = "/emby"
	upstreamBase := mustStructuredURL(t, "https://origin.example.com/Items/1/PlaybackInfo")
	authority := redirectHostKey(upstreamBase)
	issuer.configuredAuthorities = map[string]bool{authority: true}
	issuer.primaryAuthority = authority
	issuer.configuredTransport = structuredRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected configured transport call")
	})
	request := httptest.NewRequest(http.MethodGet, upstreamBase.String(), nil)
	request = request.WithContext(context.WithValue(request.Context(), dynamicExpectedStructuredSourceContextKey{}, dynamicDiscoverySourcePlaybackInfo))
	body := `{"MediaSources":[{"DirectStreamUrl":"https://origin.example.com/Videos/1/stream.mp4?api_key=absolute-secret","TranscodingUrl":"/Videos/1/master.m3u8?api_key=relative-client"}]}`
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	response := &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request}
	if err := rewriteDynamicStructuredResponseExpected(response, issuer, true, dynamicDiscoverySourcePlaybackInfo, 0, false); err != nil {
		t.Fatalf("rewrite path PlaybackInfo: %v", err)
	}
	rewritten, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		MediaSources []struct {
			DirectStreamURL string `json:"DirectStreamUrl"`
			TranscodingURL  string `json:"TranscodingUrl"`
		} `json:"MediaSources"`
	}
	if err := json.Unmarshal(rewritten, &payload); err != nil || len(payload.MediaSources) != 1 {
		t.Fatalf("decode path PlaybackInfo: payload=%#v err=%v", payload, err)
	}
	media := payload.MediaSources[0]
	if media.TranscodingURL != "/emby/Videos/1/master.m3u8?api_key=relative-client" {
		t.Fatalf("path relative URL=%q", media.TranscodingURL)
	}
	if !strings.HasPrefix(media.DirectStreamURL, "/emby"+dynamicRoutePrefix) {
		t.Fatalf("path dynamic URL=%q", media.DirectStreamURL)
	}
	claims, err := openDynamicCapability(issuer.key, issuer.capabilityToken(media.DirectStreamURL))
	if err != nil || claims.Target != "https://origin.example.com/Videos/1/stream.mp4?api_key=absolute-secret" {
		t.Fatalf("path capability claims=%#v err=%v", claims, err)
	}
}

func TestPathIngressPlaybackInfoMovesEmbeddedPrefixOutsideEmbyBase(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	issuer.pathPrefix = "/sntp"
	base := mustStructuredURL(t, "https://origin.example.com/emby/Items/1/PlaybackInfo")
	request := httptest.NewRequest(http.MethodGet, base.String(), nil)
	request = request.WithContext(context.WithValue(request.Context(), dynamicExpectedStructuredSourceContextKey{}, dynamicDiscoverySourcePlaybackInfo))
	body := `{"MediaSources":[{"DirectStreamUrl":"/emby/sntp/videos/1975846/original.mkv","TranscodingUrl":"/jellyfin/sntp/Videos/1975846/master.m3u8"}]}`
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	response := &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request}
	if err := rewriteDynamicStructuredResponseExpected(response, issuer, true, dynamicDiscoverySourcePlaybackInfo, 0, false); err != nil {
		t.Fatalf("rewrite embedded path PlaybackInfo: %v", err)
	}
	rewritten, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(rewritten)
	for _, want := range []string{
		`"DirectStreamUrl":"/sntp/emby/videos/1975846/original.mkv"`,
		`"TranscodingUrl":"/sntp/jellyfin/Videos/1975846/master.m3u8"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rewritten PlaybackInfo lacks %s: %s", want, text)
		}
	}
	if strings.Contains(text, "/emby/sntp/") || strings.Contains(text, "/jellyfin/sntp/") {
		t.Fatalf("embedded ingress prefix survived: %s", text)
	}
}

func TestConfiguredOriginDASHTemplateUsesTrustedTransport(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://origin.example.com/manifest.mpd")
	authority := redirectHostKey(base)
	issuer.configuredAuthorities = map[string]bool{authority: true}
	issuer.primaryAuthority = authority
	var fetched string
	issuer.configuredTransport = structuredRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		fetched = request.URL.String()
		header := make(http.Header)
		header.Set("Content-Type", "video/mp4")
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader("chunk")), ContentLength: 5, Request: request}, nil
	})
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceDASH}
	payload := []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><AdaptationSet><SegmentTemplate media="chunk-$Number%05d$.m4s" initialization="init.mp4"/><Representation id="v"/></AdaptationSet></Period></MPD>`)
	rewritten, err := rewriteDASHResponse(payload, session)
	if err != nil {
		t.Fatalf("rewrite configured DASH template: %v", err)
	}
	if !session.commit() {
		t.Fatal("commit configured DASH capability")
	}
	text := string(rewritten)
	start := strings.Index(text, dynamicRoutePrefix)
	if start < 0 {
		t.Fatalf("configured DASH template has no capability: %s", text)
	}
	end := strings.IndexByte(text[start:], '"')
	if end < 0 {
		t.Fatalf("configured DASH capability is not attribute-delimited: %s", text)
	}
	templateRoute := text[start : start+end]
	token := capabilityTokenFromRoute(t, templateRoute)
	claims, err := openDynamicCapability(issuer.key, token)
	if err != nil {
		t.Fatalf("open configured DASH template capability: %v", err)
	}
	if !claims.Trusted || claims.Kind != dynamicCapabilityKindResource || claims.Source != dynamicDiscoverySourceDASH || len(claims.Template) != 1 {
		t.Fatalf("configured DASH template claims = %#v", claims)
	}
	baseRoute := dynamicRoutePrefix + token
	recorder := httptest.NewRecorder()
	issuer.serve(recorder, httptest.NewRequest(http.MethodGet, "https://site.example"+baseRoute+"/v0-00001", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "chunk" {
		t.Fatalf("configured DASH template response = %d %q", recorder.Code, recorder.Body.String())
	}
	if fetched != "https://origin.example.com/chunk-00001.m4s" {
		t.Fatalf("configured DASH template fetched %q", fetched)
	}
}

func TestStructuredManifestDRMExtensionsFailClosed(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	hlsBase := mustStructuredURL(t, "https://api.example.com/live/master.m3u8")
	hlsSession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: hlsBase, source: dynamicDiscoverySourceHLS}
	for _, manifest := range []string{
		"#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"https://keys.example.com/key\"\n#EXTINF:6,\nsegment.ts\n",
		"#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXT-X-KEY:METHOD=AES-128,KEYFORMAT=\"com.apple.streamingkeydelivery\",URI=\"https://keys.example.com/key\"\n#EXTINF:6,\nsegment.ts\n",
	} {
		if _, err := rewriteHLSResponse([]byte(manifest), hlsSession); err == nil {
			t.Fatalf("HLS DRM manifest was accepted: %s", manifest)
		}
	}

	dashBase := mustStructuredURL(t, "https://api.example.com/live/manifest.mpd")
	dashSession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: dashBase, source: dynamicDiscoverySourceDASH}
	drmMPD := []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><AdaptationSet><ContentProtection schemeIdUri="urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"/><Representation><BaseURL>video.mp4</BaseURL></Representation></AdaptationSet></Period></MPD>`)
	if _, err := rewriteDASHResponse(drmMPD, dashSession); err == nil {
		t.Fatal("DASH ContentProtection was accepted")
	}
	for name, manifest := range map[string]string{
		"foreign BaseURL":         `<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" xmlns:x="urn:attacker"><Period><AdaptationSet><Representation><x:BaseURL>https://other.example.com/</x:BaseURL><SegmentList><SegmentURL media="segment.m4s"/></SegmentList></Representation></AdaptationSet></Period></MPD>`,
		"foreign SegmentTemplate": `<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" xmlns:x="urn:attacker"><Period><AdaptationSet><x:SegmentTemplate media="https://other.example.com/chunk-$Number$.m4s"/><Representation id="v" bandwidth="1000"/></AdaptationSet></Period></MPD>`,
		"metrics reporting":       `<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><AdaptationSet><Representation><BaseURL>video.mp4</BaseURL></Representation></AdaptationSet></Period><Metrics metrics="buffer"><Reporting schemeIdUri="urn:dvb:dash:reporting:2014" value="https://report.example.com/metrics"/></Metrics></MPD>`,
	} {
		t.Run(name, func(t *testing.T) {
			session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: dashBase, source: dynamicDiscoverySourceDASH}
			if _, err := rewriteDASHResponse([]byte(manifest), session); err == nil {
				t.Fatalf("unsupported DASH construct was accepted: %s", manifest)
			}
		})
	}
}

func TestDASHTemplatePreservesLiteralDollarAsAuthenticatedData(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	if !validDASHRepresentationID(strings.Repeat("a", 256) + ":main") {
		t.Fatal("valid long DASH RepresentationID was rejected")
	}
	base := mustStructuredURL(t, "https://api.example.com/live/manifest.mpd")
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceDASH}
	defer session.rollback()
	manifest := []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><AdaptationSet><SegmentTemplate media="https://cdn.example.com/$RepresentationID$-chunk-$$-$Number$.m4s"/><Representation id="video:main" bandwidth="1000"/></AdaptationSet></Period></MPD>`)
	rewritten, err := rewriteDASHResponse(manifest, session)
	if err != nil {
		t.Fatalf("rewrite literal-dollar DASH template: %v", err)
	}
	text := string(rewritten)
	start := strings.Index(text, dynamicRoutePrefix)
	if start < 0 {
		t.Fatalf("literal-dollar template has no capability: %s", text)
	}
	end := strings.IndexByte(text[start:], '"')
	if end < 0 {
		t.Fatalf("literal-dollar capability is not delimited: %s", text)
	}
	claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, text[start:start+end]))
	if err != nil {
		t.Fatalf("open literal-dollar capability: %v", err)
	}
	if len(claims.Template) != 1 || claims.Template[0] != "Number" || len(claims.TemplateFixed) != 1 || claims.TemplateFixed[0] != "video:main" || strings.Contains(claims.Target, "video:main") || !strings.Contains(claims.Target, dashFixedTemplateClaimMarker(0)+"-chunk-"+dashLiteralDollarClaimMarker+"-$Number$.m4s") {
		t.Fatalf("literal-dollar claims = %#v", claims)
	}
	target, err := resolveDASHCapabilityTarget(claims, "v0-7")
	if err != nil || !strings.Contains(target.String(), "video:main-chunk-$-7.m4s") {
		t.Fatalf("literal-dollar target = %v err=%v", target, err)
	}
}

func TestDASHTemplateFixedClaimsPreserveURLStructureAndNumericIdentity(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://api.example.com/live/manifest.mpd")
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceDASH}
	defer session.rollback()
	manifest := []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><AdaptationSet><SegmentTemplate media="https://cdn-$RepresentationID$.example.com/chunk-$Number$.m4s?id=$RepresentationID$"/><Representation id="1080p" bandwidth="1000"/></AdaptationSet></Period></MPD>`)
	rewritten, err := rewriteDASHResponse(manifest, session)
	if err != nil {
		t.Fatalf("rewrite fixed-authority DASH template: %v", err)
	}
	routes := structuredCapabilityRoutes(string(rewritten))
	if len(routes) != 1 {
		t.Fatalf("fixed-authority DASH routes = %v\n%s", routes, rewritten)
	}
	claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, routes[0]))
	if err != nil {
		t.Fatalf("open fixed-authority claims: %v", err)
	}
	if len(claims.TemplateFixed) != 2 || claims.TemplateFixed[0] != "1080p" || claims.TemplateFixed[1] != "1080p" || strings.Contains(claims.Target, "1080p") || !strings.Contains(claims.Target, dashFixedTemplateClaimMarker(0)) {
		t.Fatalf("fixed-authority claims = %#v", claims)
	}
	target, err := resolveDASHCapabilityTarget(claims, "v0-7")
	if err != nil || target.String() != "https://cdn-1080p.example.com/chunk-7.m4s?id=1080p" {
		t.Fatalf("fixed-authority target = %v err=%v", target, err)
	}

	variableAuthority := []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><AdaptationSet><SegmentTemplate media="https://cdn-$Number$.example.com/chunk.m4s"/><Representation id="v" bandwidth="1000"/></AdaptationSet></Period></MPD>`)
	if _, err := rewriteDASHResponse(variableAuthority, &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceDASH}); err == nil {
		t.Fatal("client-bound DASH authority template was accepted")
	}
	colonFirstSegment := []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><AdaptationSet><SegmentTemplate media="$RepresentationID$/chunk-$Number$.m4s"/><Representation id="video:main" bandwidth="1000"/></AdaptationSet></Period></MPD>`)
	if _, err := rewriteDASHResponse(colonFirstSegment, &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceDASH}); err == nil {
		t.Fatal("relative DASH template with a colon in its substituted first segment was accepted")
	}
	if !validDASHRepresentationID("video%3Amain$alt") || validDASHRepresentationID("video%2Fmain") {
		t.Fatal("DASH RepresentationID pct-encoded pchar validation is incorrect")
	}
	encodedSession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceDASH}
	defer encodedSession.rollback()
	encodedManifest := []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><AdaptationSet><SegmentTemplate media="https://cdn.example.com/video/$RepresentationID$/chunk-$Number$.m4s"/><Representation id="video%3Amain$alt" bandwidth="1000"/></AdaptationSet></Period></MPD>`)
	encodedRewritten, err := rewriteDASHResponse(encodedManifest, encodedSession)
	if err != nil {
		t.Fatalf("rewrite pct-encoded RepresentationID: %v", err)
	}
	encodedRoutes := structuredCapabilityRoutes(string(encodedRewritten))
	if len(encodedRoutes) != 1 {
		t.Fatalf("pct-encoded RepresentationID routes = %v", encodedRoutes)
	}
	encodedClaims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, encodedRoutes[0]))
	if err != nil {
		t.Fatalf("open pct-encoded RepresentationID claims: %v", err)
	}
	encodedTarget, err := resolveDASHCapabilityTarget(encodedClaims, "v0-2")
	if err != nil || encodedTarget.String() != "https://cdn.example.com/video/video%3Amain$alt/chunk-2.m4s" {
		t.Fatalf("pct-encoded RepresentationID target = %v err=%v", encodedTarget, err)
	}
	querySession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceDASH}
	defer querySession.rollback()
	queryManifest := []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><AdaptationSet><SegmentTemplate media="https://cdn.example.com/chunk-$Number$.m4s?id=$RepresentationID$"/><Representation id="a&amp;b" bandwidth="1000"/></AdaptationSet></Period></MPD>`)
	queryRewritten, err := rewriteDASHResponse(queryManifest, querySession)
	if err != nil {
		t.Fatalf("rewrite query RepresentationID: %v", err)
	}
	queryRoutes := structuredCapabilityRoutes(string(queryRewritten))
	if len(queryRoutes) != 1 {
		t.Fatalf("query RepresentationID routes = %v", queryRoutes)
	}
	queryClaims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, queryRoutes[0]))
	if err != nil {
		t.Fatalf("open query RepresentationID claims: %v", err)
	}
	queryTarget, err := resolveDASHCapabilityTarget(queryClaims, "v0-3")
	if err != nil || queryTarget.RawQuery != "id=a&b" {
		t.Fatalf("raw query RepresentationID target = %v err=%v", queryTarget, err)
	}

	numericClaims := dynamicCapabilityClaims{Source: dynamicDiscoverySourceDASH, Target: "https://cdn.example.com:443/$Number$/chunk-$Number%05d$.m4s", Template: []string{"Number", "Number%05d"}}
	if _, err := resolveDASHCapabilityTarget(numericClaims, "v0-1/v1-99999"); err == nil {
		t.Fatal("mixed-format DASH suffix accepted inconsistent Number values")
	}
	numericTarget, err := resolveDASHCapabilityTarget(numericClaims, "v0-1/v1-00001")
	if err != nil || numericTarget.String() != "https://cdn.example.com:443/1/chunk-00001.m4s" {
		t.Fatalf("mixed-format consistent target = %v err=%v", numericTarget, err)
	}
}

func TestDASHInheritedSegmentAddressingUsesEachRepresentationBase(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://api.example.com/live/manifest.mpd")
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceDASH}
	defer session.rollback()
	manifest := []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period>
<AdaptationSet><SegmentTemplate media="https://template.example.com/chunk-$Number$.m4s"><Initialization sourceURL="https://template.example.com/init.mp4?sig=init"/><RepresentationIndex sourceURL="https://template.example.com/index.sidx?sig=index"/><BitstreamSwitching sourceURL="https://template.example.com/switch.m4s?sig=switch"/></SegmentTemplate><Representation id="templated" bandwidth="1000"/></AdaptationSet>
<AdaptationSet><SegmentList><Initialization sourceURL="init.mp4"/><SegmentURL media="segment.m4s"/></SegmentList><Representation id="a"><BaseURL>https://a.example.com/video/</BaseURL></Representation><Representation id="b"><BaseURL>https://b.example.com/video/</BaseURL></Representation></AdaptationSet>
<AdaptationSet><SegmentBase><Initialization sourceURL="init.mp4"/><RepresentationIndex sourceURL="index.sidx"/></SegmentBase><Representation id="c"><BaseURL>https://c.example.com/video/</BaseURL></Representation><Representation id="d"><BaseURL>https://d.example.com/video/</BaseURL></Representation></AdaptationSet>
</Period></MPD>`)
	rewritten, err := rewriteDASHResponse(manifest, session)
	if err != nil {
		t.Fatalf("rewrite inherited DASH addressing: %v", err)
	}
	text := string(rewritten)
	for _, secret := range []string{"template.example.com", "a.example.com", "b.example.com", "c.example.com", "d.example.com", "sig=init", "sig=index", "sig=switch"} {
		if strings.Contains(text, secret) {
			t.Fatalf("inherited DASH output leaked %q: %s", secret, text)
		}
	}
	if strings.Count(text, "<SegmentTemplate") != 1 || strings.Count(text, "<SegmentList") != 2 || strings.Count(text, "<SegmentBase") != 2 {
		t.Fatalf("effective DASH addressing clones are incomplete: %s", text)
	}
	targets := make([]string, 0)
	seenTokens := make(map[string]bool)
	for _, route := range structuredCapabilityRoutes(text) {
		token := capabilityTokenFromRoute(t, route)
		if seenTokens[token] {
			continue
		}
		seenTokens[token] = true
		claims, err := openDynamicCapability(issuer.key, token)
		if err != nil {
			t.Fatalf("open inherited DASH capability: %v", err)
		}
		targets = append(targets, claims.Target)
	}
	for _, want := range []string{
		"https://template.example.com/init.mp4?sig=init",
		"https://template.example.com/index.sidx?sig=index",
		"https://template.example.com/switch.m4s?sig=switch",
		"https://a.example.com/video/init.mp4", "https://a.example.com/video/segment.m4s",
		"https://b.example.com/video/init.mp4", "https://b.example.com/video/segment.m4s",
		"https://c.example.com/video/init.mp4", "https://c.example.com/video/index.sidx",
		"https://d.example.com/video/init.mp4", "https://d.example.com/video/index.sidx",
	} {
		found := false
		for _, target := range targets {
			if target == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("inherited DASH target %q missing from %v", want, targets)
		}
	}
}

func TestDASHInheritedAddressingPreservesXSDChildOrder(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://api.example.com/live/manifest.mpd")
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceDASH}
	defer session.rollback()
	manifest := []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><AdaptationSet><SegmentList><SegmentURL media="segment.m4s"/></SegmentList><Representation id="v"><SegmentList><Initialization sourceURL="init.mp4"/></SegmentList></Representation></AdaptationSet></Period></MPD>`)
	rewritten, err := rewriteDASHResponse(manifest, session)
	if err != nil {
		t.Fatalf("rewrite ordered inherited SegmentList: %v", err)
	}
	text := string(rewritten)
	initialization := strings.Index(text, "<Initialization")
	segment := strings.Index(text, "<SegmentURL")
	if initialization < 0 || segment < 0 || initialization > segment {
		t.Fatalf("effective SegmentList violates XSD child order: %s", text)
	}
}

func TestDASHEventUTCTimingAndLocationBoundaries(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://api.example.com/live/manifest.mpd")
	allowedSession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceDASH}
	defer allowedSession.rollback()
	allowed := []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><UTCTiming schemeIdUri="urn:mpeg:dash:utc:direct:2014" value="2026-08-04T12:00:00Z"/><UTCTiming schemeIdUri="urn:mpeg:dash:utc:http-head:2014" value="https://clock.example.com/time"/><Period><EventStream schemeIdUri="urn:mpeg:dash:event:callback:2015"><Event messageData="https://callback.example.com/event?id=secret"/></EventStream><EventStream schemeIdUri="urn:mpeg:dash:event:2012" value="1"/></Period></MPD>`)
	rewritten, err := rewriteDASHResponse(allowed, allowedSession)
	if err != nil {
		t.Fatalf("rewrite allowed DASH timing/events: %v", err)
	}
	if strings.Contains(string(rewritten), "clock.example.com") || strings.Contains(string(rewritten), "callback.example.com") || strings.Count(string(rewritten), dynamicRoutePrefix) != 2 {
		t.Fatalf("allowed DASH timing/events were not capability-bound: %s", rewritten)
	}

	for name, manifest := range map[string]string{
		"in-band callback":        `<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><AdaptationSet><InbandEventStream schemeIdUri="urn:mpeg:dash:event:callback:2015"/></AdaptationSet></Period></MPD>`,
		"MPD patch event":         `<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><EventStream schemeIdUri="urn:mpeg:dash:event:2012" value="2"/></Period></MPD>`,
		"MPD replacement event":   `<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><AdaptationSet><InbandEventStream schemeIdUri="urn:mpeg:dash:event:2012" value="3"/></AdaptationSet></Period></MPD>`,
		"callback nested payload": `<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><EventStream schemeIdUri="urn:mpeg:dash:event:callback:2015"><Event messageData="https://callback.example.com/event"><Payload>https://bypass.example.com/</Payload></Event></EventStream></Period></MPD>`,
		"NTP timing":              `<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><UTCTiming schemeIdUri="urn:mpeg:dash:utc:ntp:2014" value="ntp.example.com"/></MPD>`,
		"unknown timing":          `<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><UTCTiming schemeIdUri="urn:vendor:clock" value="https://clock.example.com/time"/></MPD>`,
	} {
		t.Run(name, func(t *testing.T) {
			session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceDASH}
			defer session.rollback()
			if _, err := rewriteDASHResponse([]byte(manifest), session); err == nil {
				t.Fatalf("unsupported DASH fetch behavior was accepted: %s", manifest)
			}
		})
	}

	reloadBase := mustStructuredURL(t, "https://reload.example.com/live/current.mpd")
	reloadSession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: reloadBase, source: dynamicDiscoverySourceDASH, depth: maxDynamicManifestDepth, rewriteRelative: true}
	defer reloadSession.rollback()
	reloadManifest := []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Location>https://reload.example.com/live/current.mpd</Location></MPD>`)
	reloaded, err := rewriteDASHResponse(reloadManifest, reloadSession)
	if err != nil {
		t.Fatalf("rewrite same-depth DASH Location: %v", err)
	}
	routes := structuredCapabilityRoutes(string(reloaded))
	if len(routes) != 1 {
		t.Fatalf("DASH Location routes = %v\n%s", routes, reloaded)
	}
	claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, routes[0]))
	if err != nil || claims.Kind != dynamicCapabilityKindManifest || claims.Source != dynamicDiscoverySourceDASH || claims.Depth != maxDynamicManifestDepth {
		t.Fatalf("same-depth DASH Location claims = %#v err=%v", claims, err)
	}
}

func TestStructuredManifestParsingHonorsCancellation(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		name    string
		source  string
		path    string
		payload []byte
	}{
		{name: "hls", source: dynamicDiscoverySourceHLS, path: "https://api.example.com/live.m3u8", payload: []byte("#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6,\nsegment.ts\n")},
		{name: "dash", source: dynamicDiscoverySourceDASH, path: "https://api.example.com/live.mpd", payload: []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period/></MPD>`)},
		{name: "playback-info", source: dynamicDiscoverySourcePlaybackInfo, path: "https://api.example.com/Items/1/PlaybackInfo", payload: []byte(`{"MediaSources":[]}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := &dynamicRewriteSession{ctx: ctx, issuer: issuer, base: mustStructuredURL(t, test.path), source: test.source}
			var err error
			switch test.source {
			case dynamicDiscoverySourceHLS:
				_, err = rewriteHLSResponse(test.payload, session)
			case dynamicDiscoverySourceDASH:
				_, err = rewriteDASHResponse(test.payload, session)
			case dynamicDiscoverySourcePlaybackInfo:
				_, err = rewritePlaybackInfoResponse(test.payload, session)
			}
			if err == nil {
				t.Fatal("canceled structured parse was accepted")
			}
		})
	}
}

func TestCapabilityRegistryGloballyPrunesAndAccountsMemory(t *testing.T) {
	limits, ok := dynamicLimitsForProfile(dynamicProfileCompatible)
	if !ok {
		t.Fatal("compatible profile is unavailable")
	}
	runtime := newDynamicRuntime()
	stale := newDynamicSiteState(runtime, limits)
	active := newDynamicSiteState(runtime, limits)
	t.Cleanup(stale.close)
	t.Cleanup(active.close)
	now := time.Unix(1_700_000_000, 0)
	if _, ok := stale.registerCapability("stale-token", "stale-target", now.Add(time.Second), now, nil); !ok {
		t.Fatal("register stale capability")
	}
	if _, ok := active.registerCapability("active-token", "active-target", now.Add(time.Hour), now, nil); !ok {
		t.Fatal("register active capability")
	}
	if !stale.settleCapabilities([]string{"stale-token"}, true, now) || !active.settleCapabilities([]string{"active-token"}, true, now) {
		t.Fatal("publish registry test capabilities")
	}
	wantActiveMemory := dynamicCapabilityEntryMemory("active-token", "active-target")
	if runtime.activeCapabilities != 2 || runtime.capabilityMemory <= wantActiveMemory {
		t.Fatalf("initial registry accounting count=%d bytes=%d", runtime.activeCapabilities, runtime.capabilityMemory)
	}
	if !active.useCapability("active-token", now.Add(dynamicCapabilityPruneInterval+time.Second)) {
		t.Fatal("active capability disappeared during global prune")
	}
	if len(stale.capabilities) != 0 || stale.capabilityMemory != 0 || runtime.activeCapabilities != 1 || runtime.capabilityMemory != wantActiveMemory {
		t.Fatalf("global prune accounting stale=%d staleBytes=%d count=%d bytes=%d wantBytes=%d", len(stale.capabilities), stale.capabilityMemory, runtime.activeCapabilities, runtime.capabilityMemory, wantActiveMemory)
	}
	active.removeCapability("active-token")
	if runtime.activeCapabilities != 0 || runtime.capabilityMemory != 0 {
		t.Fatalf("registry removal accounting count=%d bytes=%d", runtime.activeCapabilities, runtime.capabilityMemory)
	}
}

func TestRejectedCapabilityRequestDoesNotRefreshIdleExpiry(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://origin.example.com/master.m3u8")
	authority := redirectHostKey(base)
	issuer.configuredAuthorities = map[string]bool{authority: true}
	issuer.primaryAuthority = authority
	issuer.configuredTransport = structuredRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid capability query reached the configured transport")
		return nil, nil
	})
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceHLS}
	route, err := session.rewriteManifest("child.m3u8")
	if err != nil {
		t.Fatalf("mint manifest capability: %v", err)
	}
	if !session.commit() {
		t.Fatal("commit manifest capability")
	}
	token := capabilityTokenFromRoute(t, route)
	key := sha256.Sum256([]byte(token))
	before := issuer.state.capabilities[key].lastUsed
	recorder := httptest.NewRecorder()
	issuer.serve(recorder, httptest.NewRequest(http.MethodGet, "https://site.example"+route+"?attacker=value", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("invalid capability query response = %d", recorder.Code)
	}
	after := issuer.state.capabilities[key].lastUsed
	if !after.Equal(before) {
		t.Fatalf("invalid request refreshed idle expiry: before=%v after=%v", before, after)
	}
}

func TestExpiredManifestCapabilityRollsBackMintedChildren(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	request := httptest.NewRequest(http.MethodGet, "https://cdn.example.com/master.m3u8", nil)
	body := "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1000\nhttps://child.example.com/nested.m3u8\n"
	header := make(http.Header)
	header.Set("Content-Type", "application/vnd.apple.mpegurl")
	response := &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request}
	err := rewriteDynamicStructuredResponseAccepted(response, issuer, true, dynamicDiscoverySourceHLS, 1, true, nil, func() bool { return false })
	if !errors.Is(err, errDynamicCapabilityExpiredDuringUse) {
		t.Fatalf("expired parent result = %v", err)
	}
	if len(issuer.state.capabilities) != 0 || issuer.state.capabilityMemory != 0 || len(issuer.state.authorities) != 0 || len(issuer.state.runtime.authorities) != 0 {
		t.Fatalf("expired parent retained children count=%d bytes=%d siteAuthorities=%d globalAuthorities=%d", len(issuer.state.capabilities), issuer.state.capabilityMemory, len(issuer.state.authorities), len(issuer.state.runtime.authorities))
	}
}

func TestStructuredWorkingSetAccountsForRetainedAllocations(t *testing.T) {
	tooLarge := &http.Response{ContentLength: globalDynamicMaxStructuredInputBytes + 1, Header: make(http.Header)}
	if _, _, _, err := dynamicStructuredWorkingSet(tooLarge, 64<<20); err == nil {

		t.Fatal("oversized structured input received a working-set reservation")
	}
	unknownCompressed := &http.Response{ContentLength: 128, Header: http.Header{"Content-Encoding": []string{"gzip"}}}
	memory, input, output, err := dynamicStructuredWorkingSet(unknownCompressed, 64<<20)
	if err != nil || memory != globalDynamicMaxSiteParseMemoryBytes || input != globalDynamicMaxStructuredInputBytes || output != globalDynamicMaxStructuredOutputBytes {
		t.Fatalf("compressed working set = memory=%d input=%d output=%d err=%v", memory, input, output, err)
	}
	known := &http.Response{ContentLength: 1 << 20, Header: make(http.Header)}
	memory, input, output, err = dynamicStructuredWorkingSet(known, 64<<20)
	if err != nil || memory != 12<<20 || input != globalDynamicMaxStructuredInputBytes || output != 3<<20 {
		t.Fatalf("known working set = memory=%d input=%d output=%d err=%v", memory, input, output, err)
	}
}

func TestExtremePlaybackInfoUnknownLengthSharesReplayParseBudget(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuerForProfile(t, dynamicProfileExtreme)
	const replayBytes = int64(1668)
	releaseReplay, acquired := issuer.state.acquireParse(replayBytes)
	if !acquired {
		t.Fatal("reserve replay body memory")
	}
	defer releaseReplay()

	payload := `{"MediaSources":[]}`
	request := httptest.NewRequest(http.MethodPost, "https://api.example.com/Items/1/PlaybackInfo", nil)
	response := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(strings.NewReader(payload)),
		ContentLength: -1,
		Request:       request,
	}
	if err := rewriteDynamicStructuredResponse(response, issuer, false); err != nil {
		t.Fatalf("rewrite response while replay memory is retained: %v", err)
	}
	if issuer.state.parseMemory != replayBytes || issuer.state.runtime.parseMemory != replayBytes {
		t.Fatalf("parse memory after response rewrite site/global=%d/%d, want retained replay %d", issuer.state.parseMemory, issuer.state.runtime.parseMemory, replayBytes)
	}
	rewritten, err := io.ReadAll(response.Body)
	if err != nil || string(rewritten) != payload {
		t.Fatalf("rewritten PlaybackInfo=%q err=%v", rewritten, err)
	}
}

func TestDynamicRedirectFailsClosedForDisabledStructuredSource(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	issuer.policy.sources = []string{dynamicDiscoverySourceRedirect}
	request := httptest.NewRequest(http.MethodGet, "https://cdn.example.com/master.m3u8", nil)
	body := &redirectRuntimeCloseSpy{Reader: strings.NewReader("#EXTM3U\n#EXT-X-ENDLIST\n")}
	header := make(http.Header)
	header.Set("Content-Type", "application/vnd.apple.mpegurl")
	response := &http.Response{StatusCode: http.StatusOK, Header: header, Body: body, ContentLength: 25, Request: request}
	var denied *dynamicProxyError
	if err := rewriteDynamicStructuredResponse(response, issuer, true); !errors.As(err, &denied) || denied.reasonCode != dynamicObservationReasonRequestUnclassified || !body.closed.Load() {
		t.Fatalf("disabled HLS response err=%v bodyClosed=%t", err, body.closed.Load())
	}

	mediaBody := &redirectRuntimeCloseSpy{Reader: strings.NewReader("media")}
	mediaHeader := make(http.Header)
	mediaHeader.Set("Content-Type", "video/mp4")
	media := &http.Response{StatusCode: http.StatusOK, Header: mediaHeader, Body: mediaBody, ContentLength: 5, Request: request}
	if err := rewriteDynamicStructuredResponse(media, issuer, true); err != nil || mediaBody.closed.Load() {
		t.Fatalf("typed media response err=%v bodyClosed=%t", err, mediaBody.closed.Load())
	}
	_ = mediaBody.Close()
}

func TestTrustedCapabilityDoesNotGainManualRedirectSemantics(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuerForProfile(t, dynamicProfileSafe)
	origin := mustStructuredURL(t, "https://origin.example.com/master.m3u8")
	privateTarget, parseErr := url.Parse("http://127.0.0.1:18080/private.m3u8")
	if parseErr != nil {
		t.Fatalf("parse private manual target: %v", parseErr)
	}
	originAuthority := redirectHostKey(origin)
	privateAuthority := redirectHostKey(privateTarget)
	issuer.primaryAuthority = originAuthority
	issuer.configuredAuthorities = map[string]bool{originAuthority: true, privateAuthority: true}
	calls := 0
	issuer.configuredTransport = structuredRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if redirectHostKey(request.URL) == originAuthority {
			return &http.Response{
				StatusCode: http.StatusSeeOther,
				Header:     http.Header{"Location": []string{privateTarget.String()}},
				Body:       io.NopCloser(strings.NewReader("redirect")),
				Request:    request,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/vnd.apple.mpegurl"}},
			Body:       io.NopCloser(strings.NewReader("#EXTM3U\n#EXT-X-ENDLIST\n")),
			Request:    request,
		}, nil
	})
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: origin, source: dynamicDiscoverySourceHLS}
	route, rewriteErr := session.rewriteManifest("child.m3u8")
	if rewriteErr != nil || !session.commit() {
		t.Fatalf("mint trusted capability route=%q err=%v", route, rewriteErr)
	}
	recorder := httptest.NewRecorder()
	issuer.serve(recorder, httptest.NewRequest(http.MethodGet, "https://site.example"+route, nil))
	if recorder.Code != http.StatusBadGateway || calls != 1 || strings.Contains(recorder.Body.String(), privateTarget.String()) {
		t.Fatalf("trusted capability redirect status=%d calls=%d body=%q, want sanitized 502/1", recorder.Code, calls, recorder.Body.String())
	}
}

func TestManifestCapabilityPreservesSanitizedUpstreamError(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://origin.example.com/master.m3u8")
	authority := redirectHostKey(base)
	issuer.configuredAuthorities = map[string]bool{authority: true}
	issuer.primaryAuthority = authority
	issuer.configuredTransport = structuredRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("Content-Type", "text/html")
		header.Set("Location", "https://leak.example/private?token=secret")
		header.Set("Retry-After", "7")
		header.Set("Set-Cookie", "secret=yes")
		body := "upstream leaked https://leak.example/private?token=secret"
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request}, nil
	})
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourceHLS}
	route, err := session.rewriteManifest("child.m3u8")
	if err != nil || !session.commit() {
		t.Fatalf("mint error manifest capability: route=%q err=%v", route, err)
	}
	token := capabilityTokenFromRoute(t, route)
	key := sha256.Sum256([]byte(token))
	before := issuer.state.capabilities[key].lastUsed
	recorder := httptest.NewRecorder()
	issuer.serve(recorder, httptest.NewRequest(http.MethodGet, "https://site.example"+route, nil))
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") != "7" || recorder.Header().Get("Set-Cookie") != "" {
		t.Fatalf("sanitized manifest error = %d headers=%#v", recorder.Code, recorder.Header())
	}
	if strings.Contains(recorder.Body.String(), "leak.example") || recorder.Body.String() != `{"error":"upstream manifest request failed"}` {
		t.Fatalf("sanitized manifest error body = %q", recorder.Body.String())
	}
	if after := issuer.state.capabilities[key].lastUsed; !after.Equal(before) {
		t.Fatalf("failed manifest refreshed capability: before=%v after=%v", before, after)
	}
	if got := validDynamicRetryAfter([]string{"999999"}, time.Now()); got != "" {
		t.Fatalf("unbounded Retry-After accepted: %q", got)
	}
}

func TestConcurrentRewriteSessionsReferenceCountProvisionalCapability(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuer(t)
	base := mustStructuredURL(t, "https://api.example.com/Items/1/PlaybackInfo")
	first := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
	second := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
	firstRoute, firstErr := first.rewrite("https://child.example.com/media.ts")
	secondRoute, secondErr := second.rewrite("https://child.example.com/media.ts")
	if firstErr != nil || secondErr != nil || firstRoute != secondRoute {
		t.Fatalf("shared provisional capability routes=%q/%q errors=%v/%v", firstRoute, secondRoute, firstErr, secondErr)
	}
	token := capabilityTokenFromRoute(t, firstRoute)
	key := sha256.Sum256([]byte(token))
	entry := issuer.state.capabilities[key]
	if entry.pendingUses != 2 || entry.published || issuer.state.hasCapability(token, time.Now()) {
		t.Fatalf("initial provisional entry = %#v", entry)
	}
	first.rollback()
	entry = issuer.state.capabilities[key]
	if entry.pendingUses != 1 || entry.published {
		t.Fatalf("entry after first rollback = %#v", entry)
	}
	if !second.commit() || !issuer.state.hasCapability(token, time.Now()) {
		t.Fatal("surviving rewrite could not publish shared capability")
	}
	entry = issuer.state.capabilities[key]
	if entry.pendingUses != 0 || !entry.published {
		t.Fatalf("published shared entry = %#v", entry)
	}
}

func TestCapabilityLookupsEnforceExactAbsoluteAndIdleExpiry(t *testing.T) {
	limits, ok := dynamicLimitsForProfile(dynamicProfileCompatible)
	if !ok {
		t.Fatal("compatible profile is unavailable")
	}
	now := time.Unix(1_700_000_000, 0)
	for _, test := range []struct {
		name      string
		token     string
		expiresAt time.Time
		lookupAt  time.Time
		use       bool
	}{
		{name: "absolute has", token: "absolute-has", expiresAt: now.Add(time.Second), lookupAt: now.Add(2 * time.Second)},
		{name: "absolute use", token: "absolute-use", expiresAt: now.Add(time.Second), lookupAt: now.Add(2 * time.Second), use: true},
		{name: "idle has", token: "idle-has", expiresAt: now.Add(24 * time.Hour), lookupAt: now.Add(time.Duration(limits.IdleExpirySeconds+1) * time.Second)},
		{name: "idle use", token: "idle-use", expiresAt: now.Add(24 * time.Hour), lookupAt: now.Add(time.Duration(limits.IdleExpirySeconds+1) * time.Second), use: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := newDynamicRuntime()
			state := newDynamicSiteState(runtime, limits)
			t.Cleanup(state.close)
			if _, registered := state.registerCapability(test.token, test.name, test.expiresAt, now, nil); !registered || !state.settleCapabilities([]string{test.token}, true, now) {
				t.Fatal("register expiry test capability")
			}
			runtime.lastCapabilityPrune = test.lookupAt
			valid := state.hasCapability(test.token, test.lookupAt)
			if test.use {
				valid = state.useCapability(test.token, test.lookupAt)
			}
			if valid || len(state.capabilities) != 0 {
				t.Fatalf("expired capability valid=%t entries=%d", valid, len(state.capabilities))
			}
		})
	}
}

func structuredTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal structured test JSON: %v", err)
	}
	return payload
}

func structuredTestStringifiedJSON(t *testing.T, value any) string {
	t.Helper()
	return string(structuredTestJSON(t, value))
}

func assertStructuredRewriteFailsAtomically(t *testing.T, profile, source, requestURL, contentType string, payload []byte) {
	t.Helper()
	issuer := newStructuredDiscoveryTestIssuerForProfile(t, profile)
	request := httptest.NewRequest(http.MethodGet, requestURL, nil)
	header := make(http.Header)
	header.Set("Content-Type", contentType)
	response := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(payload)),
		ContentLength: int64(len(payload)),
		Request:       request,
	}
	if err := rewriteDynamicStructuredResponseExpected(response, issuer, false, source, 0, false); err == nil {
		t.Fatal("unsafe structured response was accepted")
	}
	if len(issuer.state.capabilities) != 0 || issuer.state.capabilityMemory != 0 ||
		len(issuer.state.authorities) != 0 || len(issuer.state.runtime.authorities) != 0 ||
		issuer.state.runtime.activeCapabilities != 0 || issuer.state.runtime.capabilityMemory != 0 {
		t.Fatalf("failed rewrite retained state: capabilities=%d capabilityBytes=%d siteAuthorities=%d globalAuthorities=%d globalCapabilities=%d globalBytes=%d",
			len(issuer.state.capabilities), issuer.state.capabilityMemory, len(issuer.state.authorities),
			len(issuer.state.runtime.authorities), issuer.state.runtime.activeCapabilities, issuer.state.runtime.capabilityMemory)
	}
}

func TestExtremePlaybackInfoAcceptsStringifiedCollectionsAndWholeStringURLs(t *testing.T) {
	for _, shape := range []string{"object", "array"} {
		t.Run(shape, func(t *testing.T) {
			issuer := newStructuredDiscoveryTestIssuerForProfile(t, dynamicProfileExtreme)
			stream := map[string]any{
				"IsExternalUrl": true,
				"DeliveryUrl":   "https://captions.example.com/subtitle.vtt?token=caption-secret",
			}
			attachment := map[string]any{
				"AttachmentUrl": "https://attachments.example.com/font.bin?token=attachment-secret",
			}
			source := map[string]any{
				"DirectStreamUrl": "https://media.example.com/video.mp4?token=direct-secret",
				"Nested": map[string]any{
					"Artwork": "https://art.example.com/poster.jpg?token=art-secret",
				},
				"Description": "watch https://prose.example.com/help without treating prose as a URL",
				"RequiredHttpHeaders": map[string]any{
					"Origin": "https://headers.example.com",
				},
			}
			if shape == "object" {
				source["MediaStreams"] = structuredTestStringifiedJSON(t, stream)
				source["MediaAttachments"] = structuredTestStringifiedJSON(t, attachment)
			} else {
				source["MediaStreams"] = structuredTestStringifiedJSON(t, []any{stream})
				source["MediaAttachments"] = structuredTestStringifiedJSON(t, []any{attachment})
			}
			var mediaSources any = []any{source}
			if shape == "object" {
				mediaSources = source
			}
			payload := structuredTestJSON(t, map[string]any{
				"MediaSources": structuredTestStringifiedJSON(t, mediaSources),
				"RootAsset":    "https://root-assets.example.com/catalog.json?token=root-secret",
				"Summary":      "root prose includes https://root-prose.example.com/help and stays literal",
				"RequiredHttpHeaders": map[string]any{
					"Referer": "https://root-header.example.com/context",
				},
			})
			session := &dynamicRewriteSession{
				ctx:    context.Background(),
				issuer: issuer,
				base:   mustStructuredURL(t, "https://api.example.com/Items/1/PlaybackInfo"),
				source: dynamicDiscoverySourcePlaybackInfo,
			}
			rewritten, err := rewritePlaybackInfoResponse(payload, session)
			if err != nil {
				session.rollback()
				t.Fatalf("rewrite Extreme stringified PlaybackInfo: %v", err)
			}
			defer session.rollback()

			var decoded map[string]any
			if err := json.Unmarshal(rewritten, &decoded); err != nil {
				t.Fatalf("decode Extreme PlaybackInfo: %v\n%s", err, rewritten)
			}
			media, ok := decoded["MediaSources"].([]any)
			if !ok || len(media) != 1 {
				t.Fatalf("normalized MediaSources = %#v", decoded["MediaSources"])
			}
			mediaSource, ok := media[0].(map[string]any)
			if !ok {
				t.Fatalf("normalized MediaSource = %#v", media[0])
			}
			if streams, ok := mediaSource["MediaStreams"].([]any); !ok || len(streams) != 1 {
				t.Fatalf("normalized MediaStreams = %#v", mediaSource["MediaStreams"])
			}
			if attachments, ok := mediaSource["MediaAttachments"].([]any); !ok || len(attachments) != 1 {
				t.Fatalf("normalized MediaAttachments = %#v", mediaSource["MediaAttachments"])
			}
			if mediaSource["Description"] != "watch https://prose.example.com/help without treating prose as a URL" ||
				decoded["Summary"] != "root prose includes https://root-prose.example.com/help and stays literal" {
				t.Fatalf("prose strings were rewritten: %#v", decoded)
			}
			sourceHeaders, ok := mediaSource["RequiredHttpHeaders"].(map[string]any)
			if !ok || sourceHeaders["Origin"] != "https://headers.example.com" {
				t.Fatalf("MediaSource RequiredHttpHeaders were scanned: %#v", mediaSource["RequiredHttpHeaders"])
			}
			rootHeaders, ok := decoded["RequiredHttpHeaders"].(map[string]any)
			if !ok || rootHeaders["Referer"] != "https://root-header.example.com/context" {
				t.Fatalf("root RequiredHttpHeaders were scanned: %#v", decoded["RequiredHttpHeaders"])
			}

			expectedTargets := map[string]bool{
				"https://media.example.com/video.mp4?token=direct-secret":          true,
				"https://captions.example.com/subtitle.vtt?token=caption-secret":   true,
				"https://attachments.example.com/font.bin?token=attachment-secret": true,
				"https://art.example.com/poster.jpg?token=art-secret":              true,
				"https://root-assets.example.com/catalog.json?token=root-secret":   false,
			}
			routes := structuredCapabilityRoutes(string(rewritten))
			if len(routes) != len(expectedTargets) {
				t.Fatalf("Extreme PlaybackInfo routes = %v\n%s", routes, rewritten)
			}
			seen := make(map[string]bool, len(routes))
			for _, route := range routes {
				claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, route))
				if err != nil {
					t.Fatalf("open Extreme PlaybackInfo capability: %v", err)
				}
				wantHeaders, exists := expectedTargets[claims.Target]
				if !exists {
					t.Fatalf("unexpected Extreme PlaybackInfo claims = %#v", claims)
				}
				seen[claims.Target] = true
				if wantHeaders {
					if len(claims.RequiredHeaders) != 1 || claims.RequiredHeaders[0] != (dynamicCapabilityHeaderClaim{Name: "Origin", Value: "https://headers.example.com"}) {
						t.Fatalf("subtree capability headers = %#v", claims)
					}
				} else if len(claims.RequiredHeaders) != 0 {
					t.Fatalf("root capability inherited MediaSource headers = %#v", claims)
				}
			}
			if len(seen) != len(expectedTargets) {
				t.Fatalf("Extreme PlaybackInfo targets = %v", seen)
			}
			text := string(rewritten)
			for _, leaked := range []string{
				"media.example.com", "captions.example.com", "attachments.example.com", "art.example.com", "root-assets.example.com",
				"direct-secret", "caption-secret", "attachment-secret", "art-secret", "root-secret",
			} {
				if strings.Contains(text, leaked) {
					t.Fatalf("Extreme PlaybackInfo leaked %q: %s", leaked, text)
				}
			}
		})
	}
}

func TestExtremePlaybackInfoAbsoluteHTTPPathOverridesProtocol(t *testing.T) {
	cases := []struct {
		name     string
		protocol any
	}{
		{name: "file", protocol: "File"},
		{name: "conflicting remote protocol", protocol: "Rtsp"},
		{name: "conflicting type", protocol: map[string]any{"name": "File"}},
	}
	for _, test := range cases {
		t.Run("extreme/"+test.name, func(t *testing.T) {
			issuer := newStructuredDiscoveryTestIssuerForProfile(t, dynamicProfileExtreme)
			payload := structuredTestJSON(t, map[string]any{
				"MediaSources": []any{map[string]any{
					"Protocol": test.protocol,
					"Path":     "https://path.example.com/live/manifest.mpd?token=path-secret",
				}},
			})
			session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: mustStructuredURL(t, "https://api.example.com/Items/1/PlaybackInfo"), source: dynamicDiscoverySourcePlaybackInfo}
			rewritten, err := rewritePlaybackInfoResponse(payload, session)
			if err != nil {
				session.rollback()
				t.Fatalf("rewrite absolute Extreme Path: %v", err)
			}
			defer session.rollback()
			routes := structuredCapabilityRoutes(string(rewritten))
			if len(routes) != 1 || strings.Contains(string(rewritten), "path.example.com") || strings.Contains(string(rewritten), "path-secret") {
				t.Fatalf("absolute Extreme Path was not capability-bound: %s", rewritten)
			}
			claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, routes[0]))
			if err != nil || claims.Target != "https://path.example.com/live/manifest.mpd?token=path-secret" || claims.Source != dynamicDiscoverySourceDASH || claims.Kind != dynamicCapabilityKindManifest {
				t.Fatalf("absolute Extreme Path claims = %#v err=%v", claims, err)
			}
		})
	}

	for _, profile := range []string{dynamicProfileSafe, dynamicProfileCompatible} {
		for _, test := range cases {
			t.Run(profile+"/"+test.name, func(t *testing.T) {
				issuer := newStructuredDiscoveryTestIssuerForProfile(t, profile)
				payload := structuredTestJSON(t, map[string]any{
					"MediaSources": []any{map[string]any{
						"Protocol": test.protocol,
						"Path":     "https://path.example.com/live/manifest.mpd?token=path-secret",
					}},
				})
				session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: mustStructuredURL(t, "https://api.example.com/Items/1/PlaybackInfo"), source: dynamicDiscoverySourcePlaybackInfo}
				rewritten, err := rewritePlaybackInfoResponse(payload, session)
				defer session.rollback()
				if test.name == "file" {
					if err != nil || !strings.Contains(string(rewritten), "https://path.example.com/live/manifest.mpd?token=path-secret") || strings.Contains(string(rewritten), dynamicRoutePrefix) {
						t.Fatalf("%s File Path strict behavior output=%s err=%v", profile, rewritten, err)
					}
				} else if err == nil {
					t.Fatalf("%s accepted conflicting Protocol %#v", profile, test.protocol)
				}
			})
		}
	}
}

func TestSafeAndCompatiblePlaybackInfoKeepStrictCollectionAndSchemaBehavior(t *testing.T) {
	for _, profile := range []string{dynamicProfileSafe, dynamicProfileCompatible} {
		t.Run(profile, func(t *testing.T) {
			issuer := newStructuredDiscoveryTestIssuerForProfile(t, profile)
			base := mustStructuredURL(t, "https://api.example.com/Items/1/PlaybackInfo")
			stringified := structuredTestJSON(t, map[string]any{
				"MediaSources": structuredTestStringifiedJSON(t, map[string]any{"Protocol": "File", "Path": "/srv/movie.mkv"}),
			})
			stringifiedSession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
			if _, err := rewritePlaybackInfoResponse(stringified, stringifiedSession); err == nil {
				stringifiedSession.rollback()
				t.Fatal("stringified MediaSources was accepted outside Extreme")
			}
			stringifiedSession.rollback()

			strict := structuredTestJSON(t, map[string]any{
				"MediaSources": []any{map[string]any{
					"Protocol": "File",
					"Path":     "/srv/movie.mkv",
					"Vendor": map[string]any{
						"Artwork": "https://vendor-assets.example.com/poster.jpg?token=vendor-secret",
					},
				}},
				"RootAsset": "https://root-assets.example.com/catalog.json?token=root-secret",
			})
			strictSession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
			rewritten, err := rewritePlaybackInfoResponse(strict, strictSession)
			defer strictSession.rollback()
			if err != nil || !strings.Contains(string(rewritten), "vendor-assets.example.com") || !strings.Contains(string(rewritten), "root-assets.example.com") || strings.Contains(string(rewritten), dynamicRoutePrefix) {
				t.Fatalf("%s schema-only behavior output=%s err=%v", profile, rewritten, err)
			}
		})
	}
}

func TestExtremeRequiredHeadersAreAEADBoundExactAndNotPropagatedAcrossRedirect(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuerForProfile(t, dynamicProfileExtreme)
	target := mustStructuredURL(t, "https://origin.example.com/initial.m3u8?sig=parent-secret")
	authority := redirectHostKey(target)
	issuer.configuredAuthorities = map[string]bool{authority: true}
	issuer.primaryAuthority = authority
	var captures []*http.Request
	issuer.configuredTransport = structuredRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		captured := request.Clone(request.Context())
		captured.Header = request.Header.Clone()
		captures = append(captures, captured)
		if len(captures) == 1 {
			header := make(http.Header)
			header.Set("Location", "/final.m3u8")
			return &http.Response{StatusCode: http.StatusFound, Header: header, Body: http.NoBody, ContentLength: 0, Request: request}, nil
		}
		if len(captures) == 2 {
			body := "#EXTM3U\n#EXT-X-TARGETDURATION:4\n#EXTINF:4,\nchild.ts?sig=child-secret\n#EXT-X-ENDLIST\n"
			header := make(http.Header)
			header.Set("Content-Type", "application/vnd.apple.mpegurl")
			return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request}, nil
		}
		return nil, fmt.Errorf("unexpected configured transport request %d", len(captures))
	})

	requiredInput := map[string]any{
		"accept":          " application/vnd.apple.mpegurl ",
		"ACCEPT-language": " en-US ",
		"origin":          " https://player.example.com ",
		"referer":         " https://player.example.com/watch ",
		"user-agent":      " Extreme Player/1.0 ",
	}
	payload := structuredTestJSON(t, map[string]any{
		"MediaSources": []any{map[string]any{
			"TranscodingUrl":      target.String(),
			"RequiredHttpHeaders": requiredInput,
		}},
	})
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: mustStructuredURL(t, "https://api.example.com/Items/1/PlaybackInfo"), source: dynamicDiscoverySourcePlaybackInfo}
	rewritten, err := rewritePlaybackInfoResponse(payload, session)
	if err != nil || !session.commit() {
		session.rollback()
		t.Fatalf("mint RequiredHeaders manifest capability: output=%s err=%v", rewritten, err)
	}
	routes := structuredCapabilityRoutes(string(rewritten))
	if len(routes) != 1 || strings.Contains(string(rewritten), "origin.example.com") || strings.Contains(string(rewritten), "parent-secret") {
		t.Fatalf("RequiredHeaders target was not hidden: %s", rewritten)
	}
	parentRoute := routes[0]
	parentToken := capabilityTokenFromRoute(t, parentRoute)
	claims, err := openDynamicCapability(issuer.key, parentToken)
	if err != nil {
		t.Fatalf("open RequiredHeaders capability: %v", err)
	}
	expectedHeaders := map[string]string{
		"Accept":          "application/vnd.apple.mpegurl",
		"Accept-Language": "en-US",
		"Origin":          "https://player.example.com",
		"Referer":         "https://player.example.com/watch",
		"User-Agent":      "Extreme Player/1.0",
	}
	if !claims.Trusted || claims.Target != "https://origin.example.com/initial.m3u8?sig=parent-secret" || claims.Source != dynamicDiscoverySourceHLS || claims.Kind != dynamicCapabilityKindManifest || claims.Depth != 1 || len(claims.RequiredHeaders) != len(expectedHeaders) {
		t.Fatalf("RequiredHeaders parent claims = %#v", claims)
	}
	for _, header := range claims.RequiredHeaders {
		if expectedHeaders[header.Name] != header.Value {
			t.Fatalf("RequiredHeaders claim = %#v, want %v", claims.RequiredHeaders, expectedHeaders)
		}
	}

	tamperedIndex := len(parentToken) / 2
	tamperedByte := byte('A')
	if parentToken[tamperedIndex] == tamperedByte {
		tamperedByte = 'B'
	}
	tampered := parentToken[:tamperedIndex] + string(tamperedByte) + parentToken[tamperedIndex+1:]
	if _, err := openDynamicCapability(issuer.key, tampered); err == nil {
		t.Fatal("tampered RequiredHeaders AEAD capability was accepted")
	}
	templated := claims
	templated.Template = []string{"Number"}
	if _, err := sealDynamicCapability(issuer.key, templated); err == nil {
		t.Fatal("RequiredHeaders were accepted on a suffix/template capability")
	}

	for _, suffix := range []string{"/v0-1", "?_HLS_msn=1"} {
		recorder := httptest.NewRecorder()
		issuer.serve(recorder, httptest.NewRequest(http.MethodGet, "https://site.example"+parentRoute+suffix, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("inexact RequiredHeaders capability %q returned %d", suffix, recorder.Code)
		}
	}
	if len(captures) != 0 {
		t.Fatalf("inexact RequiredHeaders requests reached upstream: %d", len(captures))
	}

	request := httptest.NewRequest(http.MethodGet, "https://site.example"+parentRoute, nil)
	for name := range expectedHeaders {
		request.Header.Set(name, "client-value")
	}
	recorder := httptest.NewRecorder()
	issuer.serve(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("redirected RequiredHeaders manifest response = %d %q", recorder.Code, recorder.Body.String())
	}
	if len(captures) != 2 || captures[0].URL.String() != "https://origin.example.com/initial.m3u8?sig=parent-secret" || captures[1].URL.String() != "https://origin.example.com/final.m3u8" {
		t.Fatalf("RequiredHeaders redirect captures = %#v", captures)
	}
	for name, value := range expectedHeaders {
		if got := captures[0].Header.Get(name); got != value {
			t.Fatalf("initial capability header %s = %q, want %q", name, got, value)
		}
		if got := captures[1].Header.Get(name); got == value {
			t.Fatalf("RequiredHeaders propagated across redirect: %s=%q", name, got)
		}
	}
	childRoutes := structuredCapabilityRoutes(recorder.Body.String())
	if len(childRoutes) != 1 || strings.Contains(recorder.Body.String(), "child-secret") {
		t.Fatalf("redirected manifest child was not capability-bound: %s", recorder.Body.String())
	}
	childClaims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, childRoutes[0]))
	if err != nil || childClaims.Target != "https://origin.example.com/child.ts?sig=child-secret" || len(childClaims.RequiredHeaders) != 0 {
		t.Fatalf("redirected parser inherited RequiredHeaders: claims=%#v err=%v", childClaims, err)
	}
}

func TestExtremeRequiredHeadersInheritOnlyToSameAuthorityHLSChildren(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuerForProfile(t, dynamicProfileExtreme)
	target := mustStructuredURL(t, "https://cdn.example.com/live/master.m3u8?sig=parent-secret")
	authority := redirectHostKey(target)
	issuer.configuredAuthorities = map[string]bool{authority: true}
	issuer.primaryAuthority = authority
	var captured *http.Request
	issuer.configuredTransport = structuredRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		captured = request.Clone(request.Context())
		captured.Header = request.Header.Clone()
		body := "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-STREAM-INF:BANDWIDTH=1000\nchild.m3u8?sig=same-secret\n#EXT-X-STREAM-INF:BANDWIDTH=2000\nhttps://other.example.com/other.m3u8?sig=cross-secret\n"
		header := make(http.Header)
		header.Set("Content-Type", "application/vnd.apple.mpegurl")
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request}, nil
	})
	payload := structuredTestJSON(t, map[string]any{
		"MediaSources": []any{map[string]any{
			"TranscodingUrl": target.String(),
			"RequiredHttpHeaders": map[string]any{
				"Accept-Language": "fr-CA",
				"Referer":         "https://player.example.com/watch",
			},
		}},
	})
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: mustStructuredURL(t, "https://api.example.com/Items/1/PlaybackInfo"), source: dynamicDiscoverySourcePlaybackInfo}
	rewritten, err := rewritePlaybackInfoResponse(payload, session)
	if err != nil || !session.commit() {
		session.rollback()
		t.Fatalf("mint inheritable RequiredHeaders capability: output=%s err=%v", rewritten, err)
	}
	parentRoutes := structuredCapabilityRoutes(string(rewritten))
	if len(parentRoutes) != 1 {
		t.Fatalf("parent RequiredHeaders routes = %v", parentRoutes)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://site.example"+parentRoutes[0], nil)
	request.Header.Set("Referer", "https://attacker.example.com/")
	issuer.serve(recorder, request)
	if recorder.Code != http.StatusOK || captured == nil || captured.Header.Get("Accept-Language") != "fr-CA" || captured.Header.Get("Referer") != "https://player.example.com/watch" {
		t.Fatalf("parent RequiredHeaders request status=%d captured=%#v body=%s", recorder.Code, captured, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "other.example.com") || strings.Contains(recorder.Body.String(), "same-secret") || strings.Contains(recorder.Body.String(), "cross-secret") {
		t.Fatalf("child manifest leaked targets: %s", recorder.Body.String())
	}
	childRoutes := structuredCapabilityRoutes(recorder.Body.String())
	if len(childRoutes) != 2 {
		t.Fatalf("child RequiredHeaders routes = %v\n%s", childRoutes, recorder.Body.String())
	}
	seenSame := false
	seenCross := false
	for _, route := range childRoutes {
		claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, route))
		if err != nil {
			t.Fatalf("open child RequiredHeaders capability: %v", err)
		}
		switch claims.Target {
		case "https://cdn.example.com/live/child.m3u8?sig=same-secret":
			seenSame = true
			if len(claims.RequiredHeaders) != 2 || claims.RequiredHeaders[0] != (dynamicCapabilityHeaderClaim{Name: "Accept-Language", Value: "fr-CA"}) || claims.RequiredHeaders[1] != (dynamicCapabilityHeaderClaim{Name: "Referer", Value: "https://player.example.com/watch"}) {
				t.Fatalf("same-authority child headers = %#v", claims)
			}
		case "https://other.example.com/other.m3u8?sig=cross-secret":
			seenCross = true
			if len(claims.RequiredHeaders) != 0 {
				t.Fatalf("cross-authority child inherited headers = %#v", claims)
			}
		default:
			t.Fatalf("unexpected child RequiredHeaders claims = %#v", claims)
		}
	}
	if !seenSame || !seenCross {
		t.Fatalf("child capability coverage same=%t cross=%t", seenSame, seenCross)
	}
}

func TestExtremeRequiredHeadersRejectUnsafeAndOversizedClaimsAtomically(t *testing.T) {
	payloadWithHeaders := func(headers map[string]any) []byte {
		return structuredTestJSON(t, map[string]any{
			"MediaSources": []any{
				map[string]any{"DirectStreamUrl": "https://rollback.example.com/first.mp4?sig=rollback-secret"},
				map[string]any{
					"DirectStreamUrl":     "https://headers-target.example.com/second.mp4?sig=target-secret",
					"RequiredHttpHeaders": headers,
				},
			},
		})
	}
	for _, name := range []string{"Authorization", "Cookie", "X-Emby-Token", "X-Forwarded-For", "Connection", "Proxy-Authorization", "Range"} {
		t.Run("forbidden/"+name, func(t *testing.T) {
			assertStructuredRewriteFailsAtomically(t, dynamicProfileExtreme, dynamicDiscoverySourcePlaybackInfo,
				"https://api.example.com/Items/1/PlaybackInfo", "application/json", payloadWithHeaders(map[string]any{name: "secret"}))
		})
	}

	tooMany := make(map[string]any)
	for index := range maxExtremeRequiredHeaderClaims + 1 {
		tooMany[fmt.Sprintf("X-Header-%d", index)] = "value"
	}
	invalid := map[string]map[string]any{
		"entry limit":      tooMany,
		"byte limit":       {"Referer": strings.Repeat("a", maxExtremeRequiredHeaderClaimBytes)},
		"duplicate casing": {"Accept": "video/mp4", "accept": "application/octet-stream"},
		"empty value":      {"Origin": "  "},
		"control value":    {"Referer": "https://player.example.com/\nsecret"},
		"non-string value": {"User-Agent": 7},
	}
	for name, headers := range invalid {
		t.Run(name, func(t *testing.T) {
			assertStructuredRewriteFailsAtomically(t, dynamicProfileExtreme, dynamicDiscoverySourcePlaybackInfo,
				"https://api.example.com/Items/1/PlaybackInfo", "application/json", payloadWithHeaders(headers))
		})
	}

	legacyPayload := structuredTestJSON(t, map[string]any{
		"MediaSources": []any{map[string]any{
			"DirectStreamUrl": "https://headers-target.example.com/video.mp4",
			"RequiredHttpHeaders": map[string]any{
				"Accept": "video/mp4",
			},
		}},
	})
	for _, profile := range []string{dynamicProfileSafe, dynamicProfileCompatible} {
		t.Run(profile+" strict gate", func(t *testing.T) {
			assertStructuredRewriteFailsAtomically(t, profile, dynamicDiscoverySourcePlaybackInfo,
				"https://api.example.com/Items/1/PlaybackInfo", "application/json", legacyPayload)
		})
	}
}

func TestExtremeHLSDefinesLocalVariablesAndRewritesSafeExtensionURIs(t *testing.T) {
	manifest := []byte("#EXTM3U\n" +
		"#EXT-X-VERSION:9\n" +
		"#EXT-X-DEFINE:NAME=\"cdn\",VALUE=\"https://cdn.example.com\"\n" +
		"#EXT-X-DEFINE:NAME=\"path\",VALUE=\"video\"\n" +
		"#EXT-X-VENDOR-METADATA:URI=\"{$cdn}/{$path}/metadata.json?sig=unknown-secret\",ALT-URI=\"https://alt.example.com/metadata.bin?sig=alternate-secret\",ID=\"offline\"\n" +
		"#EXT-X-START:TIME-OFFSET=0,VENDOR-URI=\"https://start.example.com/start.bin?sig=start-secret\"\n" +
		"#EXT-X-STREAM-INF:BANDWIDTH=1000\n" +
		"{$cdn}/{$path}/child.m3u8?sig=variant-secret\n")
	issuer := newStructuredDiscoveryTestIssuerForProfile(t, dynamicProfileExtreme)
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: mustStructuredURL(t, "https://api.example.com/live/master.m3u8"), source: dynamicDiscoverySourceHLS}
	rewritten, err := rewriteHLSResponse(manifest, session)
	if err != nil {
		session.rollback()
		t.Fatalf("rewrite Extreme HLS extensions: %v", err)
	}
	defer session.rollback()
	text := string(rewritten)
	if strings.Contains(text, "#EXT-X-DEFINE") || strings.Contains(text, "{$") {
		t.Fatalf("Extreme HLS retained variable machinery: %s", text)
	}
	for _, leaked := range []string{"cdn.example.com", "alt.example.com", "start.example.com", "unknown-secret", "alternate-secret", "start-secret", "variant-secret"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("Extreme HLS leaked %q: %s", leaked, text)
		}
	}
	expected := map[string]string{
		"https://cdn.example.com/video/metadata.json?sig=unknown-secret": dynamicCapabilityKindResource,
		"https://alt.example.com/metadata.bin?sig=alternate-secret":      dynamicCapabilityKindResource,
		"https://start.example.com/start.bin?sig=start-secret":           dynamicCapabilityKindResource,
		"https://cdn.example.com/video/child.m3u8?sig=variant-secret":    dynamicCapabilityKindManifest,
	}
	routes := structuredCapabilityRoutes(text)
	if len(routes) != len(expected) {
		t.Fatalf("Extreme HLS extension routes = %v\n%s", routes, text)
	}
	seen := make(map[string]bool, len(routes))
	for _, route := range routes {
		claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, route))
		if err != nil {
			t.Fatalf("open Extreme HLS extension capability: %v", err)
		}
		kind, exists := expected[claims.Target]
		if !exists || claims.Source != dynamicDiscoverySourceHLS || claims.Kind != kind {
			t.Fatalf("Extreme HLS extension claims = %#v", claims)
		}
		seen[claims.Target] = true
	}
	if len(seen) != len(expected) {
		t.Fatalf("Extreme HLS extension targets = %v", seen)
	}

	for _, profile := range []string{dynamicProfileSafe, dynamicProfileCompatible} {
		t.Run(profile+" strict gate", func(t *testing.T) {
			legacyIssuer := newStructuredDiscoveryTestIssuerForProfile(t, profile)
			legacySession := &dynamicRewriteSession{ctx: context.Background(), issuer: legacyIssuer, base: mustStructuredURL(t, "https://api.example.com/live/master.m3u8"), source: dynamicDiscoverySourceHLS}
			if _, err := rewriteHLSResponse(manifest, legacySession); err == nil {
				legacySession.rollback()
				t.Fatal("Extreme HLS extensions were accepted outside Extreme")
			}
			legacySession.rollback()
			if len(legacyIssuer.state.capabilities) != 0 || len(legacyIssuer.state.authorities) != 0 {
				t.Fatal("rejected legacy HLS extension retained provisional state")
			}
		})
	}
}

func TestExtremeHLSRejectsUnresolvedSensitiveAndActiveExtensionsAtomically(t *testing.T) {
	baseManifest := func(extension string) []byte {
		return []byte("#EXTM3U\n" +
			"#EXT-X-TARGETDURATION:4\n" +
			"#EXTINF:4,\n" +
			"https://rollback-hls.example.com/segment.ts?sig=rollback-secret\n" +
			extension + "\n" +
			"#EXT-X-ENDLIST\n")
	}
	cases := map[string]string{
		"undefined variable": "#EXT-X-VENDOR-METADATA:URI=\"{$missing}/metadata.json\"",
		"non-local import":   "#EXT-X-DEFINE:IMPORT=\"cdn\"",
		"sensitive DRM URI":  "#EXT-X-VENDOR-DRM:LICENSE-URI=\"https://license.example.com/key\"",
		"content steering":   "#EXT-X-CONTENT-STEERING:SERVER-URI=\"https://steering.example.com/config\"",
	}
	for name, extension := range cases {
		t.Run(name, func(t *testing.T) {
			assertStructuredRewriteFailsAtomically(t, dynamicProfileExtreme, dynamicDiscoverySourceHLS,
				"https://api.example.com/live/master.m3u8", "application/vnd.apple.mpegurl", baseManifest(extension))
		})
	}
}

func TestExtremeDASHPreservesSafeDRMAndForeignWrappersWhileRewritingStandardURLs(t *testing.T) {
	manifest := []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" xmlns:cenc="urn:mpeg:cenc:2013" xmlns:v="urn:vendor:passive-metadata">
  <Period>
    <v:Wrapper v:mode="passive">
      <v:Label>offline metadata</v:Label>
      <AdaptationSet>
        <ContentProtection schemeIdUri="urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed">
          <cenc:pssh>c2FmZS1kcm0tbWV0YWRhdGE=</cenc:pssh>
          <v:Marker v:kind="offline">opaque metadata</v:Marker>
        </ContentProtection>
        <v:Envelope v:state="idle">
          <Representation id="video-main"><BaseURL>https://cdn.example.com/video/main.mp4?sig=dash-secret</BaseURL></Representation>
        </v:Envelope>
      </AdaptationSet>
    </v:Wrapper>
  </Period>
</MPD>`)
	issuer := newStructuredDiscoveryTestIssuerForProfile(t, dynamicProfileExtreme)
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: mustStructuredURL(t, "https://api.example.com/live/manifest.mpd"), source: dynamicDiscoverySourceDASH}
	rewritten, err := rewriteDASHResponse(manifest, session)
	if err != nil {
		session.rollback()
		t.Fatalf("rewrite Extreme DASH compatibility metadata: %v", err)
	}
	defer session.rollback()
	text := string(rewritten)
	for _, preserved := range []string{"ContentProtection", "pssh", "c2FmZS1kcm0tbWV0YWRhdGE=", "Wrapper", "Envelope", "offline metadata", "opaque metadata", "urn:vendor:passive-metadata"} {
		if !strings.Contains(text, preserved) {
			t.Fatalf("Extreme DASH dropped %q: %s", preserved, text)
		}
	}
	if strings.Contains(text, "cdn.example.com") || strings.Contains(text, "dash-secret") {
		t.Fatalf("Extreme DASH leaked raw BaseURL: %s", text)
	}
	routes := structuredCapabilityRoutes(text)
	if len(routes) != 1 {
		t.Fatalf("Extreme DASH safe-wrapper routes = %v\n%s", routes, text)
	}
	claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, routes[0]))
	if err != nil || claims.Target != "https://cdn.example.com/video/main.mp4?sig=dash-secret" || claims.Source != dynamicDiscoverySourceDASH || claims.Kind != dynamicCapabilityKindResource {
		t.Fatalf("Extreme DASH safe-wrapper claims = %#v err=%v", claims, err)
	}
	var root struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(rewritten, &root); err != nil || root.XMLName != (xml.Name{Space: "urn:mpeg:dash:schema:mpd:2011", Local: "MPD"}) {
		t.Fatalf("rewritten Extreme DASH XML root=%v err=%v\n%s", root.XMLName, err, text)
	}
}

func TestSafeAndCompatibleDASHRejectExtremeDRMAndForeignWrappers(t *testing.T) {
	features := map[string][]byte{
		"ContentProtection": []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"><Period><AdaptationSet><ContentProtection schemeIdUri="urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"/><Representation id="v"><BaseURL>video.mp4</BaseURL></Representation></AdaptationSet></Period></MPD>`),
		"foreign wrapper":   []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" xmlns:v="urn:vendor:passive"><Period><v:Wrapper><Representation id="v"><BaseURL>video.mp4</BaseURL></Representation></v:Wrapper></Period></MPD>`),
	}
	for _, profile := range []string{dynamicProfileSafe, dynamicProfileCompatible} {
		for feature, manifest := range features {
			t.Run(profile+"/"+feature, func(t *testing.T) {
				issuer := newStructuredDiscoveryTestIssuerForProfile(t, profile)
				session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: mustStructuredURL(t, "https://api.example.com/live/manifest.mpd"), source: dynamicDiscoverySourceDASH}
				if _, err := rewriteDASHResponse(manifest, session); err == nil {
					session.rollback()
					t.Fatalf("%s accepted Extreme DASH %s", profile, feature)
				}
				session.rollback()
				if len(issuer.state.capabilities) != 0 || len(issuer.state.authorities) != 0 {
					t.Fatal("rejected legacy DASH feature retained provisional state")
				}
			})
		}
	}
}

func TestExtremeDASHRejectsForeignFetchesAndActiveStructuresAtomically(t *testing.T) {
	manifestWith := func(extension string) []byte {
		return []byte(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" xmlns:v="urn:vendor:passive" xmlns:xlink="http://www.w3.org/1999/xlink">
  <Period><AdaptationSet>
    <Representation id="safe"><BaseURL>https://rollback-dash.example.com/video.mp4?sig=rollback-secret</BaseURL></Representation>` +
			extension +
			`</AdaptationSet></Period>
</MPD>`)
	}
	cases := map[string]string{
		"foreign URL attribute":  `<v:Metadata v:url="https://foreign.example.com/metadata"/>`,
		"xlink fetch":            `<SupplementalProperty schemeIdUri="urn:vendor:test" xlink:href="https://xlink.example.com/document"/>`,
		"xml base":               `<SupplementalProperty schemeIdUri="urn:vendor:test" xml:base="https://xml-base.example.com/"/>`,
		"license URL":            `<ContentProtection schemeIdUri="urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"><v:LicenseUrl>https://license.example.com/key</v:LicenseUrl></ContentProtection>`,
		"encoded license URL":    `<ContentProtection schemeIdUri="urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"><v:pssh>aHR0cHM6Ly9saWNlbnNlLmV4YW1wbGUuY29t</v:pssh></ContentProtection>`,
		"content steering":       `<ContentSteering defaultServiceLocation="primary"/>`,
		"foreign active element": `<v:SegmentTemplate media="https://segments.example.com/chunk-$Number$.m4s"/>`,
	}
	for name, extension := range cases {
		t.Run(name, func(t *testing.T) {
			assertStructuredRewriteFailsAtomically(t, dynamicProfileExtreme, dynamicDiscoverySourceDASH,
				"https://api.example.com/live/manifest.mpd", "application/dash+xml", manifestWith(extension))
		})
	}
}

func TestSafeAndCompatiblePlaybackInfoKeepLegacyNestedCollectionHandling(t *testing.T) {
	streamText := structuredTestStringifiedJSON(t, map[string]any{
		"IsExternalUrl": true,
		"DeliveryUrl":   "https://captions.example.com/subtitle.vtt?sig=legacy-secret",
	})
	attachmentText := structuredTestStringifiedJSON(t, []any{map[string]any{
		"AttachmentUrl": "https://attachments.example.com/font.bin?sig=legacy-secret",
	}})
	for _, profile := range []string{dynamicProfileSafe, dynamicProfileCompatible} {
		t.Run(profile, func(t *testing.T) {
			issuer := newStructuredDiscoveryTestIssuerForProfile(t, profile)
			base := mustStructuredURL(t, "https://api.example.com/Items/1/PlaybackInfo")
			streamPayload := structuredTestJSON(t, map[string]any{
				"MediaSources": []any{map[string]any{"MediaStreams": streamText}},
			})
			streamSession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
			if _, err := rewritePlaybackInfoResponse(streamPayload, streamSession); err == nil {
				streamSession.rollback()
				t.Fatal("legacy profile accepted stringified MediaStreams")
			}
			streamSession.rollback()

			attachmentPayload := structuredTestJSON(t, map[string]any{
				"MediaSources": []any{map[string]any{"MediaAttachments": attachmentText}},
			})
			attachmentSession := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: base, source: dynamicDiscoverySourcePlaybackInfo}
			rewritten, err := rewritePlaybackInfoResponse(attachmentPayload, attachmentSession)
			defer attachmentSession.rollback()
			if err != nil || !strings.Contains(string(rewritten), "attachments.example.com") || strings.Contains(string(rewritten), dynamicRoutePrefix) {
				t.Fatalf("legacy MediaAttachments handling output=%s err=%v", rewritten, err)
			}
		})
	}
}

func TestSafeAndCompatibleHLSRejectExtremeFeaturesIndependently(t *testing.T) {
	features := map[string][]byte{
		"DEFINE":                []byte("#EXTM3U\n#EXT-X-DEFINE:NAME=\"segment\",VALUE=\"video\"\n#EXT-X-TARGETDURATION:4\n#EXTINF:4,\n{$segment}.ts\n#EXT-X-ENDLIST\n"),
		"unknown URI attribute": []byte("#EXTM3U\n#EXT-X-VENDOR-METADATA:URI=\"https://metadata.example.com/value.json\"\n#EXT-X-STREAM-INF:BANDWIDTH=1000\nchild.m3u8\n"),
	}
	for _, profile := range []string{dynamicProfileSafe, dynamicProfileCompatible} {
		for feature, manifest := range features {
			t.Run(profile+"/"+feature, func(t *testing.T) {
				issuer := newStructuredDiscoveryTestIssuerForProfile(t, profile)
				session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: mustStructuredURL(t, "https://api.example.com/live/master.m3u8"), source: dynamicDiscoverySourceHLS}
				if _, err := rewriteHLSResponse(manifest, session); err == nil {
					session.rollback()
					t.Fatalf("%s accepted Extreme HLS feature %s", profile, feature)
				}
				session.rollback()
				if len(issuer.state.capabilities) != 0 || len(issuer.state.authorities) != 0 {
					t.Fatal("rejected legacy HLS feature retained provisional state")
				}
			})
		}
	}
}

func TestExtremePlaybackInfoAbsoluteHTTPPathOverridesFileProtocol(t *testing.T) {
	issuer := newStructuredDiscoveryTestIssuerForProfile(t, dynamicProfileExtreme)
	payload := []byte(`{"MediaSources":[{"Protocol":"File","Path":"http://path-http.example.com:8080/live/video.mp4?token=http-secret"}]}`)
	session := &dynamicRewriteSession{ctx: context.Background(), issuer: issuer, base: mustStructuredURL(t, "http://api.example.com:8096/Items/1/PlaybackInfo"), source: dynamicDiscoverySourcePlaybackInfo}
	rewritten, err := rewritePlaybackInfoResponse(payload, session)
	if err != nil {
		session.rollback()
		t.Fatalf("rewrite absolute HTTP PlaybackInfo Path: %v", err)
	}
	defer session.rollback()
	routes := structuredCapabilityRoutes(string(rewritten))
	if len(routes) != 1 || strings.Contains(string(rewritten), "path-http.example.com") || strings.Contains(string(rewritten), "http-secret") {
		t.Fatalf("absolute HTTP PlaybackInfo Path was not hidden: %s", rewritten)
	}
	claims, err := openDynamicCapability(issuer.key, capabilityTokenFromRoute(t, routes[0]))
	if err != nil || claims.Target != "http://path-http.example.com:8080/live/video.mp4?token=http-secret" || claims.Source != dynamicDiscoverySourcePlaybackInfo || claims.Kind != dynamicCapabilityKindResource {
		t.Fatalf("absolute HTTP PlaybackInfo Path claims = %#v err=%v", claims, err)
	}
}
