package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// UpstreamHeaderView is the write-only representation returned by the API.
// Header values are never serialized back to a browser.
type UpstreamHeaderView struct {
	Name       string `json:"name"`
	Configured bool   `json:"configured"`
}

// UpstreamHeaderInput is a full-snapshot API input. On update, an omitted or
// empty value preserves the existing encrypted value for the same header name.
// Omitting the header row from the snapshot removes it.
type UpstreamHeaderInput struct {
	Name  string  `json:"name"`
	Value *string `json:"value,omitempty"`
}

type storedUpstreamHeader struct {
	Name       string `json:"name"`
	Ciphertext string `json:"ciphertext"`
}

type upstreamHeaderPolicy struct {
	authority string
	values    http.Header
}

func isHTTPTokenByte(value byte) bool {
	if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", rune(value))
}

func normalizeUpstreamHeaderName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxUpstreamHeaderName {
		return "", fmt.Errorf("upstream header name must be 1-%d bytes", maxUpstreamHeaderName)
	}
	for i := 0; i < len(value); i++ {
		if !isHTTPTokenByte(value[i]) {
			return "", fmt.Errorf("upstream header name contains invalid characters")
		}
	}
	name := http.CanonicalHeaderKey(value)
	lower := strings.ToLower(name)
	if isManagedForwardingHeaderName(lower) {
		return "", fmt.Errorf("upstream header %s is managed by Meridian and cannot be overridden", name)
	}
	switch lower {
	case "authorization", "connection", "content-length", "cookie", "host",
		"keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
		"te", "trailer", "transfer-encoding", "upgrade", "user-agent",
		"x-emby-authorization", "x-emby-token", "x-mediabrowser-token":
		return "", fmt.Errorf("upstream header %s is managed by Meridian and cannot be overridden", name)
	}
	if strings.HasPrefix(lower, "sec-websocket-") {
		return "", fmt.Errorf("upstream header %s is managed by Meridian and cannot be overridden", name)
	}
	return name, nil
}

func normalizeUpstreamHeaderValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxUpstreamHeaderValue {
		return "", fmt.Errorf("upstream header value must be 1-%d bytes", maxUpstreamHeaderValue)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return "", fmt.Errorf("upstream header value must contain printable ASCII characters only")
		}
	}
	return value, nil
}

func resolveUpstreamHeaderKey(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	if strings.ContainsAny(value, " \t\r\n\v\f") {
		return nil, fmt.Errorf("UPSTREAM_HEADER_KEY must not contain whitespace")
	}
	if len(value) < 32 {
		return nil, fmt.Errorf("UPSTREAM_HEADER_KEY must be at least 32 bytes")
	}
	sum := sha256.Sum256([]byte(value))
	key := make([]byte, len(sum))
	copy(key, sum[:])
	return key, nil
}

func encryptUpstreamHeaderValue(name, value, authority string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("UPSTREAM_HEADER_KEY is required to configure upstream headers")
	}
	if authority == "" {
		return "", fmt.Errorf("a valid target authority is required to configure upstream headers")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate upstream header nonce: %w", err)
	}
	aad := []byte("meridian-upstream-header:v2:" + strings.ToLower(name) + "\x00" + authority)
	sealed := gcm.Seal(nil, nonce, []byte(value), aad)
	payload := append(append([]byte{}, nonce...), sealed...)
	return "v2:" + base64.RawURLEncoding.EncodeToString(payload), nil
}

func decryptUpstreamHeaderValue(name, ciphertext, authority string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("UPSTREAM_HEADER_KEY is required for configured upstream headers")
	}
	if !strings.HasPrefix(ciphertext, "v2:") {
		return "", fmt.Errorf("unsupported upstream header ciphertext version")
	}
	if authority == "" {
		return "", fmt.Errorf("a valid target authority is required for configured upstream headers")
	}
	aad := []byte("meridian-upstream-header:v2:" + strings.ToLower(name) + "\x00" + authority)
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(ciphertext, "v2:"))
	if err != nil {
		return "", fmt.Errorf("decode upstream header ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(payload) < gcm.NonceSize()+gcm.Overhead() {
		return "", fmt.Errorf("upstream header ciphertext is truncated")
	}
	nonce, sealed := payload[:gcm.NonceSize()], payload[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return "", fmt.Errorf("decrypt upstream header value: %w", err)
	}
	return string(plain), nil
}

func parseStoredUpstreamHeaders(raw string) ([]storedUpstreamHeader, error) {
	if strings.TrimSpace(raw) == "" {
		return []storedUpstreamHeader{}, nil
	}
	var headers []storedUpstreamHeader
	if err := json.Unmarshal([]byte(raw), &headers); err != nil {
		return nil, fmt.Errorf("invalid stored upstream_headers: %w", err)
	}
	if len(headers) > maxUpstreamHeaders {
		return nil, fmt.Errorf("stored upstream_headers exceeds %d entries", maxUpstreamHeaders)
	}
	seen := make(map[string]bool, len(headers))
	for i := range headers {
		name, err := normalizeUpstreamHeaderName(headers[i].Name)
		if err != nil {
			return nil, fmt.Errorf("invalid stored upstream header: %w", err)
		}
		key := strings.ToLower(name)
		if seen[key] {
			return nil, fmt.Errorf("duplicate stored upstream header %s", name)
		}
		seen[key] = true
		headers[i].Name = name
		if !strings.HasPrefix(headers[i].Ciphertext, "v2:") {
			return nil, fmt.Errorf("invalid stored ciphertext for upstream header %s", name)
		}
	}
	if headers == nil {
		headers = []storedUpstreamHeader{}
	}
	return headers, nil
}

func upstreamHeaderViews(raw string) ([]UpstreamHeaderView, error) {
	stored, err := parseStoredUpstreamHeaders(raw)
	if err != nil {
		return nil, err
	}
	views := make([]UpstreamHeaderView, len(stored))
	for i, header := range stored {
		views[i] = UpstreamHeaderView{Name: header.Name, Configured: true}
	}
	return views, nil
}

func mergeUpstreamHeaders(existingRaw string, requested []UpstreamHeaderInput, key []byte, targetURL string) (string, error) {
	if len(requested) > maxUpstreamHeaders {
		return "", fmt.Errorf("upstream_headers must contain at most %d entries", maxUpstreamHeaders)
	}
	existing, err := parseStoredUpstreamHeaders(existingRaw)
	if err != nil {
		return "", err
	}
	existingByName := make(map[string]storedUpstreamHeader, len(existing))
	for _, header := range existing {
		existingByName[strings.ToLower(header.Name)] = header
	}
	target, err := normalizeTargetURL(targetURL)
	if err != nil {
		return "", fmt.Errorf("invalid target_url: %w", err)
	}
	authority := redirectHostKey(target)

	merged := make([]storedUpstreamHeader, 0, len(requested))
	seen := make(map[string]bool, len(requested))
	for _, input := range requested {
		name, err := normalizeUpstreamHeaderName(input.Name)
		if err != nil {
			return "", err
		}
		nameKey := strings.ToLower(name)
		if seen[nameKey] {
			return "", fmt.Errorf("duplicate upstream header %s", name)
		}
		seen[nameKey] = true

		value := ""
		if input.Value != nil {
			value = strings.TrimSpace(*input.Value)
		}
		if value == "" {
			old, ok := existingByName[nameKey]
			if !ok {
				return "", fmt.Errorf("a value is required for new upstream header %s", name)
			}
			merged = append(merged, storedUpstreamHeader{Name: name, Ciphertext: old.Ciphertext})
			continue
		}
		value, err = normalizeUpstreamHeaderValue(value)
		if err != nil {
			return "", fmt.Errorf("invalid value for upstream header %s: %w", name, err)
		}
		ciphertext, err := encryptUpstreamHeaderValue(name, value, authority, key)
		if err != nil {
			return "", err
		}
		merged = append(merged, storedUpstreamHeader{Name: name, Ciphertext: ciphertext})
	}
	raw, err := json.Marshal(merged)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func resolveUpstreamHeaderPolicy(raw string, key []byte, target *url.URL) (upstreamHeaderPolicy, error) {
	stored, err := parseStoredUpstreamHeaders(raw)
	if err != nil {
		return upstreamHeaderPolicy{}, err
	}
	policy := upstreamHeaderPolicy{authority: redirectHostKey(target), values: make(http.Header, len(stored))}
	for _, header := range stored {
		value, err := decryptUpstreamHeaderValue(header.Name, header.Ciphertext, policy.authority, key)
		if err != nil {
			return upstreamHeaderPolicy{}, fmt.Errorf("resolve upstream header %s: %w", header.Name, err)
		}
		value, err = normalizeUpstreamHeaderValue(value)
		if err != nil {
			return upstreamHeaderPolicy{}, fmt.Errorf("resolve upstream header %s: %w", header.Name, err)
		}
		policy.values.Set(header.Name, value)
	}
	return policy, nil
}

func (p upstreamHeaderPolicy) apply(header http.Header, target *url.URL) {
	for name := range p.values {
		header.Del(name)
	}
	if target == nil || redirectHostKey(target) != p.authority {
		return
	}
	for name, values := range p.values {
		header[name] = append([]string(nil), values...)
	}
}
