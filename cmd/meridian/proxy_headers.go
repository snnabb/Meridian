package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	clientIPModeBoth   = "both"
	clientIPModeRealIP = "real_ip"
	clientIPModeNone   = "none"
)

func normalizeClientIPMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", clientIPModeBoth:
		return clientIPModeBoth, nil
	case clientIPModeRealIP:
		return clientIPModeRealIP, nil
	case clientIPModeNone:
		return clientIPModeNone, nil
	default:
		return "", fmt.Errorf("invalid client_ip_mode")
	}
}

func applyClientIPMode(header http.Header, mode string) {
	switch mode {
	case clientIPModeRealIP:
		header.Del("X-Forwarded-For")
	case clientIPModeNone:
		header.Del("X-Real-IP")
		header.Del("X-Forwarded-For")
	}
}

func applyUAProfileHeaders(header http.Header, profile UAProfile) {
	header.Set("User-Agent", profile.UserAgent)
	rewriteEmbyAuthorizationHeaders(header, "X-Emby-Authorization", profile)
	rewriteEmbyAuthorizationHeaders(header, "Authorization", profile)
}

// applyUAHeaderPolicy applies a resolved UAHeaderPolicy to outbound headers.
// Rewrite mode sets the configured User-Agent and rewrites Emby Client/Version
// identity; passthrough leaves every inbound identity header untouched.
func applyUAHeaderPolicy(header http.Header, policy UAHeaderPolicy) {
	if !policy.Rewrite {
		return
	}
	applyUAProfileHeaders(header, policy.Profile)
}

type publicHostIngressContextKey struct{}
type pathIngressContextKey struct{}

func applySiteForwardedHost(header http.Header, inbound *http.Request, site Site) {
	header.Del("X-Forwarded-Host")
	header.Del("X-Forwarded-Prefix")
	if inbound == nil {
		return
	}
	if ingressUsesPath(site.IngressMode) {
		if prefix, _ := inbound.Context().Value(pathIngressContextKey{}).(string); prefix == site.PathPrefix {
			header.Set("X-Forwarded-Host", inbound.Host)
			header.Set("X-Forwarded-Prefix", prefix)
		}
		return
	}
	if !ingressUsesHost(site.IngressMode) {
		return
	}
	sharedIngress, _ := inbound.Context().Value(publicHostIngressContextKey{}).(bool)
	if sharedIngress && requestPublicHost(inbound.Host) == site.PublicHost {
		header.Set("X-Forwarded-Host", site.PublicHost)
	}
}

// stripCookieByName removes Meridian's management session before any site
// request leaves the process. Browser cookies are scoped by host, not port, so
// a panel session could otherwise ride along to a site listener on the same
// host. Malformed Cookie input is dropped in full rather than risk retaining a
// disguised management credential.
func stripCookieByName(header http.Header, name string) {
	var rawValues []string
	for key, values := range header {
		if strings.EqualFold(key, "Cookie") {
			rawValues = append(rawValues, values...)
			delete(header, key)
		}
	}
	if len(rawValues) == 0 {
		return
	}

	kept := make([]string, 0)
	for _, raw := range rawValues {
		cookies, err := http.ParseCookie(raw)
		if err != nil {
			return
		}
		for _, cookie := range cookies {
			if cookie.Name != name {
				kept = append(kept, cookie.String())
			}
		}
	}
	if len(kept) > 0 {
		header.Set("Cookie", strings.Join(kept, "; "))
	}
}

func prepareUpstreamHeaders(header http.Header, inbound *http.Request, policy UAHeaderPolicy, trustedProxies ...[]*net.IPNet) {
	prepareUpstreamHeadersWithClientIPMode(header, inbound, policy, clientIPModeBoth, trustedProxies...)
}

func prepareUpstreamHeadersWithClientIPMode(header http.Header, inbound *http.Request, policy UAHeaderPolicy, clientIPMode string, trustedProxies ...[]*net.IPNet) {
	stripCookieByName(header, sessionCookieName)
	setTrustedForwardingHeaders(header, inbound, trustedProxies...)
	applyClientIPMode(header, clientIPMode)
	applyUAHeaderPolicy(header, policy)
}

func prepareWebSocketUpstreamHeaders(inbound *http.Request, target *url.URL, policy UAHeaderPolicy, upstreamPolicies ...upstreamHeaderPolicy) http.Header {
	return prepareWebSocketUpstreamHeadersWithTrustedProxies(inbound, target, policy, nil, upstreamPolicies...)
}

func prepareWebSocketUpstreamHeadersWithTrustedProxies(inbound *http.Request, target *url.URL, policy UAHeaderPolicy, trustedProxies []*net.IPNet, upstreamPolicies ...upstreamHeaderPolicy) http.Header {
	return prepareWebSocketUpstreamHeadersWithClientIPMode(inbound, target, policy, trustedProxies, clientIPModeBoth, upstreamPolicies...)
}

func prepareWebSocketUpstreamHeadersWithClientIPMode(inbound *http.Request, target *url.URL, policy UAHeaderPolicy, trustedProxies []*net.IPNet, clientIPMode string, upstreamPolicies ...upstreamHeaderPolicy) http.Header {
	header := inbound.Header.Clone()
	// RFC 9110 hop-by-hop: every header named by the inbound Connection header
	// is consumed by the first recipient and must not be forwarded. Delete them
	// all before rebuilding the upgrade headers below.
	for _, value := range inbound.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if token = strings.TrimSpace(token); token != "" {
				header.Del(token)
			}
		}
	}
	for _, name := range []string{
		// Content-Length must go with the other hop-by-hop headers: the upgrade
		// path never reads r.Body, so letting a length through would tell the
		// upstream to frame bytes as a body that this side never sends.
		"Content-Length",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
	header.Set("Connection", "Upgrade")
	header.Set("Upgrade", "websocket")
	header.Set("Host", target.Host)
	prepareUpstreamHeadersWithClientIPMode(header, inbound, policy, clientIPMode, trustedProxies)
	if len(upstreamPolicies) > 0 {
		upstreamPolicies[0].apply(header, target)
	}
	return header
}

// stripPanelSessionSetCookies prevents an upstream site from overwriting the
// management session on a sibling port/route. Preserve valid application
// cookies verbatim; malformed individual values fail closed because browser
// parsers may otherwise interpret them more permissively than net/http.
func stripPanelSessionSetCookies(header http.Header) {
	values := header.Values("Set-Cookie")
	header.Del("Set-Cookie")
	for _, value := range values {
		cookie, err := http.ParseSetCookie(value)
		if err != nil || cookie.Name == sessionCookieName {
			continue
		}
		header.Add("Set-Cookie", value)
	}
}
