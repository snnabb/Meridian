package main

import (
	"net/http"
	"strings"
)

type embyAuthAttribute struct {
	name       string
	attrStart  int
	attrEnd    int
	valueStart int
	valueEnd   int
}

func isEmbyAuthWhitespace(value byte) bool {
	return value == ' ' || value == '\t'
}

func isEmbyAuthToken(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '-' || value == '_'
}

func parseEmbyAuthorizationAttributes(value string, offset int) ([]embyAuthAttribute, bool) {
	attributes := make([]embyAuthAttribute, 0, 4)
	for {
		for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
			offset++
		}
		nameStart := offset
		for offset < len(value) && isEmbyAuthToken(value[offset]) {
			offset++
		}
		if nameStart == offset {
			return nil, false
		}
		name := value[nameStart:offset]
		for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
			offset++
		}
		if offset >= len(value) || value[offset] != '=' {
			return nil, false
		}
		offset++
		for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
			offset++
		}
		if offset >= len(value) || value[offset] != '"' {
			return nil, false
		}
		offset++
		valueStart := offset
		for offset < len(value) && value[offset] != '"' {
			if value[offset] == '\\' || value[offset] < 0x20 || value[offset] == 0x7f {
				return nil, false
			}
			offset++
		}
		if offset >= len(value) {
			return nil, false
		}
		attributes = append(attributes, embyAuthAttribute{
			name:       name,
			attrStart:  nameStart,
			attrEnd:    offset + 1,
			valueStart: valueStart,
			valueEnd:   offset,
		})
		offset++
		for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
			offset++
		}
		if offset == len(value) {
			return attributes, true
		}
		if value[offset] != ',' {
			return nil, false
		}
		offset++
		if offset == len(value) {
			return nil, false
		}
	}
}

func rewriteEmbyAuthorizationValue(value string, profile UAProfile) string {
	offset := 0
	for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
		offset++
	}
	schemeStart := offset
	for offset < len(value) && isEmbyAuthToken(value[offset]) {
		offset++
	}
	if schemeStart == offset {
		return value
	}
	scheme := value[schemeStart:offset]
	if !strings.EqualFold(scheme, "MediaBrowser") && !strings.EqualFold(scheme, "Emby") {
		return value
	}
	if offset < len(value) && !isEmbyAuthWhitespace(value[offset]) {
		return value
	}
	for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
		offset++
	}
	if offset == len(value) {
		prefix := value
		if len(value) == schemeStart+len(scheme) {
			prefix += " "
		}
		return prefix + "Client=\"" + profile.Client + "\", Version=\"" + profile.Version + "\""
	}

	attributes, ok := parseEmbyAuthorizationAttributes(value, offset)
	if !ok {
		return value
	}
	clientIndex, versionIndex := -1, -1
	for index, attribute := range attributes {
		switch {
		case strings.EqualFold(attribute.name, "Client"):
			if clientIndex >= 0 {
				return value
			}
			clientIndex = index
		case strings.EqualFold(attribute.name, "Version"):
			if versionIndex >= 0 {
				return value
			}
			versionIndex = index
		}
	}

	type replacement struct {
		start int
		end   int
		value string
	}
	replacements := make([]replacement, 0, 2)
	if clientIndex >= 0 {
		attribute := attributes[clientIndex]
		replacements = append(replacements, replacement{attribute.valueStart, attribute.valueEnd, profile.Client})
	}
	if versionIndex >= 0 {
		attribute := attributes[versionIndex]
		replacements = append(replacements, replacement{attribute.valueStart, attribute.valueEnd, profile.Version})
	}

	if len(replacements) == 2 && replacements[0].start < replacements[1].start {
		replacements[0], replacements[1] = replacements[1], replacements[0]
	}
	rewritten := value
	for _, replacement := range replacements {
		rewritten = rewritten[:replacement.start] + replacement.value + rewritten[replacement.end:]
	}
	if clientIndex < 0 {
		rewritten += ", Client=\"" + profile.Client + "\""
	}
	if versionIndex < 0 {
		rewritten += ", Version=\"" + profile.Version + "\""
	}
	return rewritten
}

func rewriteEmbyAuthorizationHeaders(header http.Header, headerName string, profile UAProfile) {
	for name, values := range header {
		if !strings.EqualFold(name, headerName) {
			continue
		}
		for index, value := range values {
			values[index] = rewriteEmbyAuthorizationValue(value, profile)
		}
	}
}

// stripEmbyAuthorizationToken removes the Token attribute from an Emby
// authorization value, leaving every other attribute byte-identical. The
// boolean result reports whether the value is safe to forward: false means the
// value carries (or may carry) an access token that could not be stripped, and
// the caller must drop the entire header instead of forwarding it. Values
// without any recognizable Token attribute are returned unchanged with true.
// A value whose only attribute is the token is reduced to its bare scheme.
func stripEmbyAuthorizationToken(value string) (string, bool) {
	offset := 0
	for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
		offset++
	}
	schemeStart := offset
	for offset < len(value) && isEmbyAuthToken(value[offset]) {
		offset++
	}
	if schemeStart == offset {
		// Empty or whitespace-only value: nothing to strip.
		return value, true
	}
	scheme := value[schemeStart:offset]
	if !strings.EqualFold(scheme, "MediaBrowser") && !strings.EqualFold(scheme, "Emby") {
		// Unknown scheme: it cannot be proven token-free, so fail closed.
		return value, false
	}
	schemeEnd := offset
	if offset < len(value) && !isEmbyAuthWhitespace(value[offset]) {
		return value, false
	}
	for offset < len(value) && isEmbyAuthWhitespace(value[offset]) {
		offset++
	}
	if offset == len(value) {
		// A bare scheme carries no attributes and therefore no token.
		return value, true
	}
	attributes, ok := parseEmbyAuthorizationAttributes(value, offset)
	if !ok {
		return value, false
	}
	tokenIndex := -1
	for index, attribute := range attributes {
		if strings.EqualFold(attribute.name, "Token") {
			if tokenIndex >= 0 {
				// Duplicate Token attributes cannot be stripped without
				// guessing which one the server honors: fail closed.
				return value, false
			}
			tokenIndex = index
		}
	}
	if tokenIndex < 0 {
		return value, true
	}
	attribute := attributes[tokenIndex]
	switch {
	case tokenIndex == 0 && len(attributes) == 1:
		// The only attribute is the token: leave the bare scheme.
		return value[:schemeEnd] + value[attribute.attrEnd:], true
	case tokenIndex == 0:
		// The token is the first attribute: drop it together with the
		// delimiter that followed it.
		return value[:attribute.attrStart] + value[attributes[1].attrStart:], true
	default:
		// The token sits after other attributes: drop the delimiter before
		// it together with the attribute itself.
		return value[:attributes[tokenIndex-1].attrEnd] + value[attribute.attrEnd:], true
	}
}

// stripSensitiveRedirectHeaders removes browser credentials and access tokens
// before a playback redirect crosses to a different authority. Only the Emby
// identity fields (Client/Version/Device/DeviceId) survive, and the UA profile
// is reapplied by the caller afterwards. Cross-authority protection is
// fail-closed: an X-Emby-Authorization value that may still carry a token is
// dropped together with the whole header rather than forwarded.
func stripSensitiveRedirectHeaders(header http.Header) {
	header.Del("Cookie")
	header.Del("Authorization")
	header.Del("Proxy-Authorization")
	// Dedicated token headers must not follow the hop either.
	header.Del("X-Emby-Token")
	header.Del("X-MediaBrowser-Token")
	for name, values := range header {
		if !strings.EqualFold(name, "X-Emby-Authorization") {
			continue
		}
		for index, value := range values {
			stripped, safe := stripEmbyAuthorizationToken(value)
			if !safe {
				header.Del(name)
				break
			}
			values[index] = stripped
		}
	}
}
