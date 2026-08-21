package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

func parseTrustedProxyCIDRs(value string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid TRUSTED_PROXY_CIDRS entry %q: %w", raw, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func remoteAddressIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(remoteAddr)
}

func isTrustedProxy(ip net.IP, networks []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func requestClientKey(r *http.Request, trustedProxies []*net.IPNet) string {
	peerIP := remoteAddressIP(r.RemoteAddr)
	if isTrustedProxy(peerIP, trustedProxies) {
		// The trusted edge must normalize the client address into a single
		// X-Real-IP value. Never select from X-Forwarded-For: common
		// $proxy_add_x_forwarded_for configurations retain attacker-supplied
		// left-most values and would let clients rotate the login limiter key.
		if value, ok := singleForwardedHeaderValue(r.Header, "X-Real-IP"); ok {
			if forwarded := net.ParseIP(value); forwarded != nil {
				return forwarded.String()
			}
		}
	}
	if peerIP != nil {
		return peerIP.String()
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

func isManagedForwardingHeaderName(name string) bool {
	lowerName := strings.ToLower(name)
	if lowerName == "forwarded" || lowerName == "x-real-ip" || strings.HasPrefix(lowerName, "x-forwarded-") {
		return true
	}
	switch lowerName {
	case "cf-connecting-ip", "cf-connecting-ipv6", "fastly-client-ip", "fly-client-ip",
		"true-client-ip", "x-appengine-user-ip", "x-azure-clientip", "x-client-ip",
		"x-cluster-client-ip", "x-envoy-external-address", "x-original-forwarded-for":
		return true
	default:
		return false
	}
}

func removeClientForwardingHeaders(header http.Header) {
	for name := range header {
		if isManagedForwardingHeaderName(name) {
			delete(header, name)
		}
	}
}

func singleForwardedHeaderValue(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	value := strings.TrimSpace(values[0])
	if value == "" || strings.Contains(value, ",") {
		return "", false
	}
	return value, true
}

func setTrustedForwardingHeaders(header http.Header, inbound *http.Request, trustedProxies ...[]*net.IPNet) {
	removeClientForwardingHeaders(header)
	if inbound == nil {
		return
	}
	var configured []*net.IPNet
	if len(trustedProxies) > 0 {
		configured = trustedProxies[0]
	}
	peerIP := remoteAddressIP(inbound.RemoteAddr)
	clientIP := peerIP
	forwardedProto := "http"
	if inbound.TLS != nil {
		forwardedProto = "https"
	}
	if isTrustedProxy(peerIP, configured) {
		// Trust only the single value a configured edge proxy normalized. Never
		// relay an arbitrary inbound X-Forwarded-For chain to the upstream.
		if value, ok := singleForwardedHeaderValue(inbound.Header, "X-Real-IP"); ok {
			if forwardedIP := net.ParseIP(value); forwardedIP != nil {
				clientIP = forwardedIP
			}
		}
		if candidateProto, ok := singleForwardedHeaderValue(inbound.Header, "X-Forwarded-Proto"); ok {
			if strings.EqualFold(candidateProto, "http") || strings.EqualFold(candidateProto, "https") {
				forwardedProto = strings.ToLower(candidateProto)
			}
		}
	}
	if clientIP != nil {
		header.Set("X-Forwarded-For", clientIP.String())
		header.Set("X-Real-IP", clientIP.String())
	}
	header.Set("X-Forwarded-Proto", forwardedProto)
}

func requestIsHTTPS(r *http.Request, trustedProxies []*net.IPNet) bool {
	if r.TLS != nil {
		return true
	}
	if !isTrustedProxy(remoteAddressIP(r.RemoteAddr), trustedProxies) {
		return false
	}
	forwardedProto, ok := singleForwardedHeaderValue(r.Header, "X-Forwarded-Proto")
	return ok && strings.EqualFold(forwardedProto, "https")
}
