package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var dynamicForbiddenPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func containsDynamicUnsafeRune(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) >= 0
}

// normalizeDynamicHost applies the IDNA Lookup profile used by DNS resolvers.
// The returned host is lower-case ASCII without a trailing dot; IP literals
// are returned in netip canonical form and reported through isIP.
func normalizeDynamicHostSyntax(value string) (host string, isIP bool, err error) {
	value = strings.TrimSpace(value)
	if value == "" || containsDynamicUnsafeRune(value) {
		return "", false, fmt.Errorf("host is empty or contains whitespace/control characters")
	}
	if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
		if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
			return "", false, fmt.Errorf("host contains mismatched brackets")
		}
		value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
		if net.ParseIP(value) == nil || !strings.Contains(value, ":") {
			return "", false, fmt.Errorf("only IPv6 literals may use brackets")
		}
	}
	if strings.ContainsAny(value, "/\\@?#") || strings.Contains(value, "%") {
		return "", false, fmt.Errorf("host contains URL syntax or an IPv6 zone")
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return "", false, fmt.Errorf("host is empty")
	}
	if parsedIP := net.ParseIP(value); parsedIP != nil {
		addr, ok := netip.AddrFromSlice(parsedIP)
		if !ok {
			return "", false, fmt.Errorf("host contains an invalid IP address")
		}
		return addr.Unmap().String(), true, nil
	}

	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", false, fmt.Errorf("host is not valid IDNA: %w", err)
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if ascii == "" || len(ascii) > 253 {
		return "", false, fmt.Errorf("host must be 1-253 ASCII bytes")
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false, fmt.Errorf("host contains an invalid DNS label")
		}
		for i := range len(label) {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false, fmt.Errorf("host contains an invalid DNS label")
			}
		}
	}
	return ascii, false, nil
}

func normalizeDynamicHost(value string) (host string, isIP bool, err error) {
	host, isIP, err = normalizeDynamicHostSyntax(value)
	if err != nil || isIP {
		return host, isIP, err
	}
	publicSuffix, icann := publicsuffix.PublicSuffix(host)
	if publicSuffix == "" || (!icann && !strings.Contains(publicSuffix, ".")) {
		return "", false, fmt.Errorf("host must use a recognized public suffix")
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(host); err != nil {
		return "", false, fmt.Errorf("host must be below a public suffix")
	}
	return host, false, nil
}

func dynamicURLDecodedComponentIsSafe(value string, query bool) bool {
	if value == "" {
		return true
	}
	var decoded string
	var err error
	if query {
		decoded, err = url.QueryUnescape(value)
	} else {
		decoded, err = url.PathUnescape(value)
	}
	if err != nil {
		return false
	}
	// Raw whitespace is rejected before parsing. Percent-encoded spaces and
	// query '+' remain escaped on the wire and are valid URL data; decoded
	// controls and backslashes remain forbidden to prevent request ambiguity.
	return strings.IndexFunc(decoded, unicode.IsControl) < 0 && !strings.Contains(decoded, `\`)
}
func dynamicURLPathHasDotSegments(value string) bool {
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return true
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func dynamicEffectivePort(target *url.URL) (string, bool) {
	if target == nil {
		return "", false
	}
	port := target.Port()
	if port == "" {
		switch strings.ToLower(target.Scheme) {
		case "http":
			return "80", true
		case "https":
			return "443", true
		default:
			return "", false
		}
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return "", false
	}
	return strconv.Itoa(parsedPort), true
}

func dynamicURLHost(host, port string, explicitPort bool) string {
	if explicitPort {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// normalizeDynamicURL is deliberately separate from normalizeTargetURL: the
// latter preserves v1.7's manual-site conveniences, while future discovered
// targets use this strict security boundary. Default-port presentation stays
// intact because signed media URLs can bind the exact HTTP Host authority.
func normalizeDynamicURL(value string) (*url.URL, error) {
	if value == "" {
		return nil, fmt.Errorf("dynamic URL is required")
	}
	if len(value) > maxDynamicTargetURLBytes {
		return nil, fmt.Errorf("dynamic URL must not exceed %d bytes", maxDynamicTargetURLBytes)
	}
	if value != strings.TrimSpace(value) || containsDynamicUnsafeRune(value) {
		return nil, fmt.Errorf("dynamic URL contains whitespace or control characters")
	}
	if strings.Contains(value, `\`) {
		return nil, fmt.Errorf("dynamic URL must not contain backslashes")
	}
	if strings.Contains(value, "#") {
		return nil, fmt.Errorf("dynamic URL must not contain a fragment")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse dynamic URL: %w", err)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("dynamic URL scheme must be http or https")
	}
	if parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("dynamic URL must be an absolute hierarchical URL")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("dynamic URL must not contain userinfo")
	}
	if parsed.Fragment != "" || parsed.RawFragment != "" {
		return nil, fmt.Errorf("dynamic URL must not contain a fragment")
	}
	if strings.Contains(parsed.Host, "%") {
		return nil, fmt.Errorf("dynamic URL must not contain an IPv6 zone or escaped host")
	}
	if strings.HasPrefix(parsed.Host, "[") {
		if ip := net.ParseIP(parsed.Hostname()); ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("dynamic URL brackets require an IPv6 literal")
		}
	}
	if !dynamicURLDecodedComponentIsSafe(parsed.EscapedPath(), false) || !dynamicURLDecodedComponentIsSafe(parsed.RawQuery, true) {
		return nil, fmt.Errorf("dynamic URL contains an escaped whitespace or control character")
	}
	if dynamicURLPathHasDotSegments(parsed.EscapedPath()) {
		return nil, fmt.Errorf("dynamic URL must not contain dot path segments")
	}

	host, isIP, err := normalizeDynamicHost(parsed.Hostname())
	if err != nil {
		return nil, fmt.Errorf("invalid dynamic URL host: %w", err)
	}
	if isIP {
		if _, err := validateDynamicResolvedIPs([]net.IP{net.ParseIP(host)}); err != nil {
			return nil, fmt.Errorf("invalid dynamic URL host: %w", err)
		}
	}
	explicitPort := parsed.Port() != ""
	if !explicitPort && strings.HasSuffix(parsed.Host, ":") {
		return nil, fmt.Errorf("dynamic URL contains an invalid port")
	}
	port, ok := dynamicEffectivePort(parsed)
	if !ok {
		return nil, fmt.Errorf("dynamic URL contains an invalid port")
	}
	parsed.Host = dynamicURLHost(host, port, explicitPort)
	return parsed, nil
}

func dynamicIPIsPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, prefix := range dynamicForbiddenPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// validateDynamicResolvedIPs rejects an entire DNS result if any answer is
// non-public. That all-or-nothing rule prevents mixed-answer rebinding from
// succeeding merely because one public address was returned first.
func validateDynamicResolvedIPs(ips []net.IP) ([]net.IP, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("dynamic target resolved to no IP addresses")
	}
	validated := make([]net.IP, 0, len(ips))
	seen := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, fmt.Errorf("dynamic target returned an invalid IP address")
		}
		addr = addr.Unmap()
		if !dynamicIPIsPublic(addr) {
			return nil, fmt.Errorf("dynamic target returned a non-public or special IP address")
		}
		if seen[addr] {
			continue
		}
		seen[addr] = true
		validated = append(validated, net.IP(addr.AsSlice()))
	}
	return validated, nil
}

var errDynamicSelfTarget = errors.New("dynamic target refers to Meridian or a local interface")

type dynamicInterfaceAddrsFunc func() ([]net.Addr, error)

// dynamicSelfTargetPolicy keeps immutable configured-host and baseline-interface
// snapshots, plus a live interface enumerator used again at resolution,
// transport construction, and immediately before each pinned dial.
type dynamicSelfTargetPolicy struct {
	deniedHosts    map[string]struct{}
	localIPs       map[netip.Addr]struct{}
	interfaceAddrs dynamicInterfaceAddrsFunc
}

func dynamicInterfaceAddrIP(value net.Addr) (netip.Addr, error) {
	if value == nil {
		return netip.Addr{}, fmt.Errorf("local interface returned a nil address")
	}
	var ip net.IP
	switch typed := value.(type) {
	case *net.IPNet:
		ip = typed.IP
	case *net.IPAddr:
		ip = typed.IP
	default:
		raw := value.String()
		if parsed, _, err := net.ParseCIDR(raw); err == nil {
			ip = parsed
		} else {
			if zone := strings.LastIndex(raw, "%"); zone >= 0 {
				raw = raw[:zone]
			}
			ip = net.ParseIP(raw)
		}
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("local interface returned an invalid IP address %q", value.String())
	}
	return addr.Unmap(), nil
}

func snapshotDynamicInterfaceIPs(interfaceAddrs dynamicInterfaceAddrsFunc) (map[netip.Addr]struct{}, error) {
	if interfaceAddrs == nil {
		interfaceAddrs = net.InterfaceAddrs
	}
	addresses, err := interfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("snapshot local interface addresses: %w", err)
	}
	localIPs := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		ip, err := dynamicInterfaceAddrIP(address)
		if err != nil {
			return nil, fmt.Errorf("snapshot local interface addresses: %w", err)
		}
		localIPs[ip] = struct{}{}
	}
	return localIPs, nil
}

func newDynamicSelfTargetPolicy(panelHost string, panelPort int, sites []Site, interfaceAddrs dynamicInterfaceAddrsFunc) (*dynamicSelfTargetPolicy, error) {
	if panelPort < 1 || panelPort > 65535 {
		return nil, fmt.Errorf("panel listener port must be between 1 and 65535")
	}
	panelHost, err := normalizePublicHost(panelHost)
	if err != nil {
		return nil, fmt.Errorf("invalid panel authority for dynamic self-target policy: %w", err)
	}
	if interfaceAddrs == nil {
		interfaceAddrs = net.InterfaceAddrs
	}
	localIPs, err := snapshotDynamicInterfaceIPs(interfaceAddrs)
	if err != nil {
		return nil, err
	}
	policy := &dynamicSelfTargetPolicy{
		deniedHosts:    make(map[string]struct{}, len(sites)+1),
		localIPs:       localIPs,
		interfaceAddrs: interfaceAddrs,
	}
	if panelHost != "" {
		policy.deniedHosts[panelHost] = struct{}{}
	}
	for _, site := range sites {
		publicHost, err := normalizePublicHost(site.PublicHost)
		if err != nil {
			return nil, fmt.Errorf("site %d has an invalid dynamic self-target authority: %w", site.ID, err)
		}
		mode, err := normalizeIngressMode(site.IngressMode, publicHost)
		if err != nil {
			return nil, fmt.Errorf("site %d has invalid ingress for dynamic self-target policy: %w", site.ID, err)
		}
		if publicHost != "" {
			policy.deniedHosts[publicHost] = struct{}{}
		}
		if ingressUsesPort(mode) && (site.ListenPort < 1 || site.ListenPort > 65535) {
			return nil, fmt.Errorf("site %d has an invalid listener port", site.ID)
		}
	}
	return policy, nil
}

func (p *dynamicSelfTargetPolicy) validateNormalizedTarget(target *url.URL) error {
	if p == nil {
		return fmt.Errorf("dynamic self-target policy snapshot is required")
	}
	if target == nil {
		return fmt.Errorf("dynamic target is required")
	}
	host, isIP, err := normalizeDynamicHost(target.Hostname())
	if err != nil {
		return fmt.Errorf("validate dynamic self-target authority: %w", err)
	}
	if _, denied := p.deniedHosts[host]; denied {
		return fmt.Errorf("%w: authority host %s is served by Meridian", errDynamicSelfTarget, host)
	}
	if _, ok := dynamicEffectivePort(target); !ok {
		return fmt.Errorf("validate dynamic self-target authority: target has no effective port")
	}
	if isIP {
		if err := p.validateIP(net.ParseIP(host)); err != nil {
			return fmt.Errorf("validate dynamic self-target literal: %w", err)
		}
	}
	return nil
}

func (p *dynamicSelfTargetPolicy) validateIPAgainst(ip net.IP, currentLocalIPs map[netip.Addr]struct{}) error {
	if p == nil {
		return fmt.Errorf("dynamic self-target policy snapshot is required")
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("dynamic target returned an invalid IP address")
	}
	addr = addr.Unmap()
	if _, denied := p.localIPs[addr]; denied {
		return fmt.Errorf("%w: resolved IP is assigned to a local interface", errDynamicSelfTarget)
	}
	if _, denied := currentLocalIPs[addr]; denied {
		return fmt.Errorf("%w: resolved IP is currently assigned to a local interface", errDynamicSelfTarget)
	}
	return nil
}

func (p *dynamicSelfTargetPolicy) validateIP(ip net.IP) error {
	if p == nil {
		return fmt.Errorf("dynamic self-target policy snapshot is required")
	}
	currentLocalIPs, err := snapshotDynamicInterfaceIPs(p.interfaceAddrs)
	if err != nil {
		return err
	}
	return p.validateIPAgainst(ip, currentLocalIPs)
}

func validateDynamicResolvedIPsWithPolicy(ips []net.IP, policy *dynamicSelfTargetPolicy) ([]net.IP, error) {
	if policy == nil {
		return nil, fmt.Errorf("dynamic self-target policy snapshot is required")
	}
	validated, err := validateDynamicResolvedIPs(ips)
	if err != nil {
		return nil, err
	}
	currentLocalIPs, err := snapshotDynamicInterfaceIPs(policy.interfaceAddrs)
	if err != nil {
		return nil, err
	}
	for _, ip := range validated {
		if err := policy.validateIPAgainst(ip, currentLocalIPs); err != nil {
			return nil, err
		}
	}
	return validated, nil
}

type dynamicIPResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

func resolveDynamicURLIPs(ctx context.Context, resolver dynamicIPResolver, target *url.URL, maxIPs int, policy *dynamicSelfTargetPolicy) ([]net.IP, error) {
	if policy == nil {
		return nil, fmt.Errorf("dynamic self-target policy snapshot is required")
	}
	if maxIPs < 1 || maxIPs > maxDynamicResolvedIPCount {
		return nil, fmt.Errorf("dynamic IP limit must be between 1 and %d", maxDynamicResolvedIPCount)
	}
	if target == nil {
		return nil, fmt.Errorf("dynamic target is required")
	}
	normalized, err := normalizeDynamicURL(target.String())
	if err != nil {
		return nil, err
	}
	if err := policy.validateNormalizedTarget(normalized); err != nil {
		return nil, err
	}
	if ip := net.ParseIP(normalized.Hostname()); ip != nil {
		return validateDynamicResolvedIPsWithPolicy([]net.IP{ip}, policy)
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	answers, err := resolver.LookupIPAddr(ctx, normalized.Hostname())
	if err != nil {
		return nil, fmt.Errorf("resolve dynamic target: %w", err)
	}
	if len(answers) > maxIPs {
		return nil, fmt.Errorf("dynamic target returned %d IP addresses, limit is %d", len(answers), maxIPs)
	}
	ips := make([]net.IP, 0, len(answers))
	for _, answer := range answers {
		if answer.Zone != "" {
			return nil, fmt.Errorf("dynamic target returned an IPv6 zone")
		}
		ips = append(ips, answer.IP)
	}
	return validateDynamicResolvedIPsWithPolicy(ips, policy)
}

type dynamicDialContextFunc func(context.Context, string, string) (net.Conn, error)

func newDynamicTransport(target *url.URL, pinnedIPs []net.IP, policy *dynamicSelfTargetPolicy) (*http.Transport, error) {
	if policy == nil {
		return nil, fmt.Errorf("dynamic self-target policy snapshot is required")
	}
	if len(pinnedIPs) < 1 || len(pinnedIPs) > maxDynamicResolvedIPCount {
		return nil, fmt.Errorf("dynamic transport requires between 1 and %d pinned IP addresses", maxDynamicResolvedIPCount)
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: -1}
	return newDynamicTransportWithDialer(target, pinnedIPs, dialer.DialContext, policy)
}

func newDynamicTransportWithDialer(target *url.URL, pinnedIPs []net.IP, dial dynamicDialContextFunc, policy *dynamicSelfTargetPolicy) (*http.Transport, error) {
	return newDynamicTransportWithDialerTimeout(target, pinnedIPs, dial, policy, dynamicPinnedDialTimeout)
}

func newDynamicTransportWithDialerTimeout(target *url.URL, pinnedIPs []net.IP, dial dynamicDialContextFunc, policy *dynamicSelfTargetPolicy, totalDialTimeout time.Duration) (*http.Transport, error) {
	if policy == nil {
		return nil, fmt.Errorf("dynamic self-target policy snapshot is required")
	}
	if len(pinnedIPs) < 1 || len(pinnedIPs) > maxDynamicResolvedIPCount {
		return nil, fmt.Errorf("dynamic transport requires between 1 and %d pinned IP addresses", maxDynamicResolvedIPCount)
	}
	if target == nil || dial == nil {
		return nil, fmt.Errorf("dynamic transport requires a target and dialer")
	}
	if totalDialTimeout <= 0 {
		return nil, fmt.Errorf("dynamic transport requires a positive total dial timeout")
	}
	normalized, err := normalizeDynamicURL(target.String())
	if err != nil {
		return nil, err
	}
	if err := policy.validateNormalizedTarget(normalized); err != nil {
		return nil, err
	}
	validated, err := validateDynamicResolvedIPsWithPolicy(pinnedIPs, policy)
	if err != nil {
		return nil, err
	}
	expectedHost := normalized.Hostname()
	expectedPort, ok := dynamicEffectivePort(normalized)
	if !ok {
		return nil, fmt.Errorf("dynamic transport target has no effective port")
	}
	if directIP := net.ParseIP(expectedHost); directIP != nil {
		for _, pinnedIP := range validated {
			if !pinnedIP.Equal(directIP) {
				return nil, fmt.Errorf("dynamic transport pins do not match the literal target IP")
			}
		}
	}
	pins := validated

	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		TLSClientConfig:       secureTLSConfig(expectedHost),
		DialContext:           nil,
		MaxIdleConns:          -1,
		MaxIdleConnsPerHost:   -1,
		MaxConnsPerHost:       1,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("dynamic transport received an invalid dial authority: %w", err)
		}
		host, _, err = normalizeDynamicHost(host)
		if err != nil || host != expectedHost || port != expectedPort {
			return nil, fmt.Errorf("dynamic transport refused unpinned authority")
		}
		if err := policy.validateNormalizedTarget(normalized); err != nil {
			return nil, err
		}
		dialCtx, cancel := context.WithTimeout(ctx, totalDialTimeout)
		defer cancel()
		var lastErr error
		for _, ip := range pins {
			if err := dialCtx.Err(); err != nil {
				lastErr = err
				break
			}
			if (network == "tcp4" && ip.To4() == nil) || (network == "tcp6" && ip.To4() != nil) {
				continue
			}
			if err := policy.validateIP(ip); err != nil {
				return nil, err
			}
			conn, dialErr := dial(dialCtx, network, net.JoinHostPort(ip.String(), expectedPort))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no pinned IP address supports network %s", network)
		}
		return nil, fmt.Errorf("dial dynamic target using pinned IPs: %w", lastErr)
	}
	return transport, nil
}
