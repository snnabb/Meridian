package main

import (
	"bytes"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

type hlsAttributeSpan struct {
	name       string
	valueStart int
	valueEnd   int
	quoted     bool
}

func isHLSAttributeNameByte(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '-'
}

func parseHLSAttributeList(value string) ([]hlsAttributeSpan, error) {
	spans := make([]hlsAttributeSpan, 0, 8)
	seen := make(map[string]bool)
	for offset := 0; offset < len(value); {
		nameStart := offset
		for offset < len(value) && isHLSAttributeNameByte(value[offset]) {
			offset++
		}
		if nameStart == offset || offset >= len(value) || value[offset] != '=' {
			return nil, fmt.Errorf("invalid HLS attribute list")
		}
		name := value[nameStart:offset]
		if seen[name] {
			return nil, fmt.Errorf("duplicate HLS attribute")
		}
		seen[name] = true
		offset++
		span := hlsAttributeSpan{name: name}
		if offset < len(value) && value[offset] == '"' {
			span.quoted = true
			offset++
			span.valueStart = offset
			for offset < len(value) && value[offset] != '"' {
				if value[offset] < 0x20 || value[offset] == 0x7f {
					return nil, fmt.Errorf("invalid HLS quoted string")
				}
				offset++
			}
			if offset >= len(value) {
				return nil, fmt.Errorf("unterminated HLS quoted string")
			}
			span.valueEnd = offset
			offset++
		} else {
			span.valueStart = offset
			for offset < len(value) && value[offset] != ',' {
				if value[offset] <= 0x20 || value[offset] == 0x7f {
					return nil, fmt.Errorf("invalid HLS attribute value")
				}
				offset++
			}
			span.valueEnd = offset
			if span.valueStart == span.valueEnd {
				return nil, fmt.Errorf("empty HLS attribute value")
			}
		}
		if len(spans) >= globalDynamicMaxHLSAttributesPerTag {
			return nil, fmt.Errorf("HLS attribute count exceeds its limit")
		}
		spans = append(spans, span)
		if offset == len(value) {
			break
		}
		if value[offset] != ',' || offset+1 == len(value) {
			return nil, fmt.Errorf("invalid HLS attribute delimiter")
		}
		offset++
	}
	if len(spans) == 0 {
		return nil, fmt.Errorf("empty HLS attribute list")
	}
	return spans, nil
}
func hlsAttributeValue(value string, attributes []hlsAttributeSpan, name string) (string, bool) {
	for _, attribute := range attributes {
		if attribute.name == name {
			return value[attribute.valueStart:attribute.valueEnd], true
		}
	}
	return "", false
}

func validateHLSURIAttributes(tag, value string, attributes []hlsAttributeSpan) error {
	uri, hasURI := hlsAttributeValue(value, attributes, "URI")
	requireURI := func() error {
		if !hasURI || uri == "" {
			return fmt.Errorf("HLS tag requires a URI attribute")
		}
		return nil
	}
	requireIdentityAES128 := func(method string) error {
		keyFormat, hasKeyFormat := hlsAttributeValue(value, attributes, "KEYFORMAT")
		if !strings.EqualFold(method, "AES-128") || hasKeyFormat && keyFormat != "identity" {
			return fmt.Errorf("HLS DRM key formats are unsupported")
		}
		return nil
	}
	switch tag {
	case "#EXT-X-KEY":
		method, hasMethod := hlsAttributeValue(value, attributes, "METHOD")
		if !hasMethod {
			return fmt.Errorf("HLS key tag requires METHOD")
		}
		if strings.EqualFold(method, "NONE") {
			if hasURI {
				return fmt.Errorf("HLS METHOD=NONE must not include URI")
			}
			return nil
		}
		if err := requireIdentityAES128(method); err != nil {
			return err
		}
		return requireURI()
	case "#EXT-X-SESSION-KEY":
		method, hasMethod := hlsAttributeValue(value, attributes, "METHOD")
		if !hasMethod || strings.EqualFold(method, "NONE") {
			return fmt.Errorf("HLS session key requires an encryption METHOD")
		}
		if err := requireIdentityAES128(method); err != nil {
			return err
		}
		return requireURI()
	case "#EXT-X-MEDIA":
		mediaType, hasType := hlsAttributeValue(value, attributes, "TYPE")
		if !hasType {
			return fmt.Errorf("HLS media tag requires TYPE")
		}
		switch strings.ToUpper(mediaType) {
		case "SUBTITLES":
			return requireURI()
		case "CLOSED-CAPTIONS":
			if hasURI {
				return fmt.Errorf("HLS closed captions must not include URI")
			}
		}
		return nil
	case "#EXT-X-SESSION-DATA":
		_, hasDataID := hlsAttributeValue(value, attributes, "DATA-ID")
		_, hasValue := hlsAttributeValue(value, attributes, "VALUE")
		if !hasDataID || hasURI == hasValue {
			return fmt.Errorf("HLS session data requires DATA-ID and exactly one of URI or VALUE")
		}
		return nil
	case "#EXT-X-PRELOAD-HINT":
		hintType, hasType := hlsAttributeValue(value, attributes, "TYPE")
		if !hasType || strings.ToUpper(hintType) != "PART" && strings.ToUpper(hintType) != "MAP" {
			return fmt.Errorf("unsupported HLS preload hint type")
		}
		return requireURI()
	case "#EXT-X-RENDITION-REPORT":
		if err := requireURI(); err != nil {
			return err
		}
		reference, err := url.Parse(uri)
		if err != nil || reference.IsAbs() || reference.Host != "" {
			return fmt.Errorf("HLS rendition report URI must be relative")
		}
		return nil
	case "#EXT-X-DATERANGE":
		return nil
	default:
		return requireURI()
	}
}

func rewriteHLSURI(value string, session *dynamicRewriteSession) (string, error) {
	return rewriteHLSURIKind(value, session, dynamicCapabilityKindResource)
}

func rewriteHLSURIKind(value string, session *dynamicRewriteSession, kind string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || containsDynamicUnsafeRune(value) || strings.Contains(value, `\`) {
		return "", fmt.Errorf("invalid HLS URI")
	}
	if strings.Contains(value, "{$") {
		return "", fmt.Errorf("HLS variable substitution is unsupported")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Fragment != "" || parsed.RawFragment != "" {
		return "", fmt.Errorf("invalid HLS URI")
	}
	if parsed.Scheme != "" && !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return "", fmt.Errorf("unsupported HLS URI scheme")
	}
	return session.rewriteAgainstKind(value, session.base, kind)
}

func hlsAttributeResourceKind(tag, name string) string {
	switch tag {
	case "#EXT-X-MEDIA", "#EXT-X-I-FRAME-STREAM-INF", "#EXT-X-IMAGE-STREAM-INF", "#EXT-X-RENDITION-REPORT":
		return dynamicCapabilityKindManifest
	case "#EXT-X-DATERANGE":
		if name == "X-ASSET-URI" {
			return dynamicCapabilityKindManifest
		}
	}
	return dynamicCapabilityKindResource
}

func rewriteHLSAttributeLine(line string, names map[string]bool, session *dynamicRewriteSession) (string, error) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 || colon+1 >= len(line) {
		return "", fmt.Errorf("invalid HLS tag attribute list")
	}
	attributes, err := parseHLSAttributeList(line[colon+1:])
	if err != nil {
		return "", err
	}
	if err := validateHLSURIAttributes(line[:colon], line[colon+1:], attributes); err != nil {
		return "", err
	}
	type replacement struct {
		start int
		end   int
		value string
	}
	replacements := make([]replacement, 0, 2)
	for _, attribute := range attributes {
		if !names[attribute.name] {
			continue
		}
		if !attribute.quoted {
			return "", fmt.Errorf("HLS URI attribute must be quoted")
		}
		start := colon + 1 + attribute.valueStart
		end := colon + 1 + attribute.valueEnd
		rewritten, err := rewriteHLSURIKind(line[start:end], session, hlsAttributeResourceKind(line[:colon], attribute.name))
		if err != nil {
			return "", err
		}
		if rewritten != line[start:end] {
			replacements = append(replacements, replacement{start: start, end: end, value: rewritten})
		}
	}
	for index := len(replacements) - 1; index >= 0; index-- {
		replacement := replacements[index]
		line = line[:replacement.start] + replacement.value + line[replacement.end:]
	}
	return line, nil
}

const (
	maxExtremeHLSVariableCount      = globalDynamicMaxHLSAttributesPerTag
	maxExtremeHLSVariableNameBytes  = 128
	maxExtremeHLSVariableValueBytes = maxDynamicTargetURLBytes
	maxExtremeHLSVariableTableBytes = globalDynamicMaxStringBytes
)

type extremeHLSVariableTable struct {
	values     map[string]string
	bytesUsed  int
	countLimit int
	byteLimit  int
}

func newExtremeHLSVariableTable(session *dynamicRewriteSession) *extremeHLSVariableTable {
	countLimit := maxExtremeHLSVariableCount
	if session != nil && session.issuer != nil && session.issuer.policy.limits.MaxURLsPerResponse < countLimit {
		countLimit = session.issuer.policy.limits.MaxURLsPerResponse
	}
	byteLimit := maxExtremeHLSVariableTableBytes
	if session != nil {
		if outputLimit := session.structuredOutputLimit(); outputLimit > 0 && outputLimit < int64(byteLimit) {
			byteLimit = int(outputLimit)
		}
	}
	return &extremeHLSVariableTable{
		values:     make(map[string]string),
		countLimit: countLimit,
		byteLimit:  byteLimit,
	}
}

func isExtremeHLSVariableName(value string) bool {
	if value == "" || len(value) > maxExtremeHLSVariableNameBytes {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func (table *extremeHLSVariableTable) defineFromExtremeHLSLine(line string) error {
	if table == nil {
		return fmt.Errorf("HLS variable table is unavailable")
	}
	colon := strings.IndexByte(line, ':')
	if colon < 0 || colon+1 >= len(line) {
		return fmt.Errorf("invalid HLS variable definition")
	}
	attributes, err := parseHLSAttributeList(line[colon+1:])
	if err != nil {
		return err
	}
	var name, value, imported string
	var hasName, hasValue, hasImport bool
	var nameQuoted, valueQuoted, importQuoted bool
	for _, attribute := range attributes {
		attributeValue := line[colon+1+attribute.valueStart : colon+1+attribute.valueEnd]
		switch attribute.name {
		case "NAME":
			name, hasName, nameQuoted = attributeValue, true, attribute.quoted
		case "VALUE":
			value, hasValue, valueQuoted = attributeValue, true, attribute.quoted
		case "IMPORT":
			imported, hasImport, importQuoted = attributeValue, true, attribute.quoted
		default:
			return fmt.Errorf("unsupported HLS variable definition attribute")
		}
	}
	if hasImport {
		if hasName || hasValue || len(attributes) != 1 || !importQuoted || !isExtremeHLSVariableName(imported) {
			return fmt.Errorf("invalid HLS variable import")
		}
		if _, exists := table.values[imported]; !exists {
			return fmt.Errorf("HLS variable import is not locally defined")
		}
		return nil
	}
	if !hasName || !hasValue || len(attributes) != 2 || !nameQuoted || !valueQuoted || !isExtremeHLSVariableName(name) {
		return fmt.Errorf("invalid HLS variable definition")
	}
	if len(value) > maxExtremeHLSVariableValueBytes || strings.Contains(value, "{$") || value != "" && (containsDynamicUnsafeRune(value) || strings.Contains(value, `\`)) {
		return fmt.Errorf("invalid HLS variable value")
	}
	if _, exists := table.values[name]; exists {
		return fmt.Errorf("duplicate HLS variable definition")
	}
	if len(table.values) >= table.countLimit {
		return fmt.Errorf("HLS variable count exceeds its limit")
	}
	entryBytes := len(name) + len(value)
	if entryBytes > table.byteLimit-table.bytesUsed {
		return fmt.Errorf("HLS variable table exceeds its budget")
	}
	table.values[name] = value
	table.bytesUsed += entryBytes
	return nil
}

func (table *extremeHLSVariableTable) substituteExtremeHLSURI(value string) (string, error) {
	if !strings.Contains(value, "{$") {
		return value, nil
	}
	if table == nil {
		return "", fmt.Errorf("HLS variable substitution is unavailable")
	}
	var output strings.Builder
	output.Grow(min(len(value), maxExtremeHLSVariableValueBytes))
	for cursor := 0; ; {
		markerOffset := strings.Index(value[cursor:], "{$")
		if markerOffset < 0 {
			if len(value)-cursor > maxDynamicTargetURLBytes-output.Len() {
				return "", fmt.Errorf("HLS substituted URI exceeds its limit")
			}
			output.WriteString(value[cursor:])
			break
		}
		markerStart := cursor + markerOffset
		markerEndOffset := strings.IndexByte(value[markerStart+2:], '}')
		if markerEndOffset < 0 {
			return "", fmt.Errorf("invalid HLS variable reference")
		}
		markerEnd := markerStart + 2 + markerEndOffset
		name := value[markerStart+2 : markerEnd]
		if !isExtremeHLSVariableName(name) {
			return "", fmt.Errorf("invalid HLS variable reference")
		}
		replacement, exists := table.values[name]
		if !exists {
			return "", fmt.Errorf("unresolved HLS variable")
		}
		literalBytes := markerStart - cursor
		if literalBytes > maxDynamicTargetURLBytes-output.Len() || len(replacement) > maxDynamicTargetURLBytes-output.Len()-literalBytes {
			return "", fmt.Errorf("HLS substituted URI exceeds its limit")
		}
		output.WriteString(value[cursor:markerStart])
		output.WriteString(replacement)
		cursor = markerEnd + 1
	}
	resolved := output.String()
	if resolved == "" || len(resolved) > maxDynamicTargetURLBytes || strings.Contains(resolved, "{$") {
		return "", fmt.Errorf("invalid substituted HLS URI")
	}
	return resolved, nil
}

type extremeHLSReplacement struct {
	start int
	end   int
	value string
}

func applyExtremeHLSReplacements(line string, replacements []extremeHLSReplacement) string {
	for index := len(replacements) - 1; index >= 0; index-- {
		replacement := replacements[index]
		line = line[:replacement.start] + replacement.value + line[replacement.end:]
	}
	return line
}

func isExtremeHLSURIAttributeName(name string) bool {
	return name == "URI" || strings.HasSuffix(name, "-URI")
}

func isExtremeHLSPotentialURLAttributeName(name string) bool {
	return name == "URL" || strings.HasSuffix(name, "-URL")
}

func isExtremeHLSSensitiveURIReference(tag, name string) bool {
	for _, marker := range []string{"KEY", "DRM", "LICENSE", "WIDEVINE", "PLAYREADY", "FAIRPLAY", "CENC", "SKD", "CKC"} {
		if strings.Contains(tag, marker) || strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func isExtremeHLSUnknownTagName(tag string) bool {
	const prefix = "#EXT-X-"
	if !strings.HasPrefix(tag, prefix) || len(tag) == len(prefix) || tag[len(tag)-1] == '-' {
		return false
	}
	for index := len(prefix); index < len(tag); index++ {
		if !isHLSAttributeNameByte(tag[index]) {
			return false
		}
	}
	return true
}

func extremeHLSValueMayExposeURI(value string) bool {
	candidate := strings.Trim(value, `"`)
	if candidate == "" {
		return false
	}
	if strings.Contains(candidate, `\`) || strings.HasPrefix(candidate, "//") || strings.Contains(candidate, "://") {
		return true
	}
	reference, err := url.Parse(candidate)
	return err == nil && (reference.IsAbs() || reference.Host != "")
}

func validateExtremeHLSOpaqueTagValue(value string) error {
	if strings.Contains(value, "{$") {
		return fmt.Errorf("unresolved HLS variable outside a URI")
	}
	upperValue := strings.ToUpper(value)
	if strings.Contains(value, "=") && (strings.Contains(upperValue, "URI") || strings.Contains(upperValue, "URL")) || extremeHLSValueMayExposeURI(value) {
		return fmt.Errorf("unsupported URI-bearing HLS extension tag")
	}
	return nil
}

func rewriteExtremeHLSParsedAttributeLine(line string, attributes []hlsAttributeSpan, baseNames map[string]bool, validateKnown, rejectPotentialURI bool, variables *extremeHLSVariableTable, session *dynamicRewriteSession) (string, error) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 || colon+1 >= len(line) {
		return "", fmt.Errorf("invalid HLS tag attribute list")
	}
	tag := line[:colon]
	names := make(map[string]bool, len(baseNames)+2)
	for name := range baseNames {
		names[name] = true
	}
	expansions := make([]extremeHLSReplacement, 0, 2)
	for _, attribute := range attributes {
		knownURIName := baseNames[attribute.name]
		if !knownURIName && !isExtremeHLSURIAttributeName(attribute.name) {
			attributeValue := line[colon+1+attribute.valueStart : colon+1+attribute.valueEnd]
			if strings.Contains(attributeValue, "{$") {
				return "", fmt.Errorf("unresolved HLS variable outside a URI")
			}
			if isExtremeHLSPotentialURLAttributeName(attribute.name) || rejectPotentialURI && extremeHLSValueMayExposeURI(attributeValue) {
				return "", fmt.Errorf("unsupported URI-bearing HLS extension attribute")
			}
			continue
		}
		if !knownURIName && isExtremeHLSSensitiveURIReference(tag, attribute.name) {
			return "", fmt.Errorf("unsupported HLS DRM or key URI extension")
		}
		if !attribute.quoted {
			return "", fmt.Errorf("HLS URI attribute must be quoted")
		}
		start := colon + 1 + attribute.valueStart
		end := colon + 1 + attribute.valueEnd
		expanded, err := variables.substituteExtremeHLSURI(line[start:end])
		if err != nil {
			return "", err
		}
		if expanded != line[start:end] {
			expansions = append(expansions, extremeHLSReplacement{start: start, end: end, value: expanded})
		}
		names[attribute.name] = true
	}
	if len(names) == 0 {
		return line, nil
	}
	expandedLine := applyExtremeHLSReplacements(line, expansions)
	expandedAttributes, err := parseHLSAttributeList(expandedLine[colon+1:])
	if err != nil {
		return "", err
	}
	if validateKnown {
		if err := validateHLSURIAttributes(tag, expandedLine[colon+1:], expandedAttributes); err != nil {
			return "", err
		}
	}
	rewrites := make([]extremeHLSReplacement, 0, len(names))
	for _, attribute := range expandedAttributes {
		if !names[attribute.name] {
			continue
		}
		if !attribute.quoted {
			return "", fmt.Errorf("HLS URI attribute must be quoted")
		}
		start := colon + 1 + attribute.valueStart
		end := colon + 1 + attribute.valueEnd
		rewritten, err := rewriteHLSURIKind(expandedLine[start:end], session, hlsAttributeResourceKind(tag, attribute.name))
		if err != nil {
			return "", err
		}
		if rewritten != expandedLine[start:end] {
			rewrites = append(rewrites, extremeHLSReplacement{start: start, end: end, value: rewritten})
		}
	}
	rewrittenLine := applyExtremeHLSReplacements(expandedLine, rewrites)
	if int64(len(rewrittenLine)) > globalDynamicMaxStringBytes {
		return "", fmt.Errorf("HLS rewritten line exceeds its limit")
	}
	return rewrittenLine, nil
}

func rewriteExtremeHLSKnownAttributeLine(line string, names map[string]bool, variables *extremeHLSVariableTable, session *dynamicRewriteSession) (string, error) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 || colon+1 >= len(line) {
		return "", fmt.Errorf("invalid HLS tag attribute list")
	}
	attributes, err := parseHLSAttributeList(line[colon+1:])
	if err != nil {
		return "", err
	}
	return rewriteExtremeHLSParsedAttributeLine(line, attributes, names, true, false, variables, session)
}

func rewriteExtremeHLSAdditionalAttributeLine(line string, variables *extremeHLSVariableTable, session *dynamicRewriteSession) (string, error) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return line, nil
	}
	if colon+1 >= len(line) {
		return line, validateExtremeHLSOpaqueTagValue("")
	}
	attributes, err := parseHLSAttributeList(line[colon+1:])
	if err != nil {
		if opaqueErr := validateExtremeHLSOpaqueTagValue(line[colon+1:]); opaqueErr != nil {
			return "", opaqueErr
		}
		return line, nil
	}
	return rewriteExtremeHLSParsedAttributeLine(line, attributes, nil, false, false, variables, session)
}

func rewriteExtremeHLSUnknownTagLine(line string, variables *extremeHLSVariableTable, session *dynamicRewriteSession) (string, error) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return line, nil
	}
	if colon+1 >= len(line) {
		return "", fmt.Errorf("invalid HLS extension tag value")
	}
	attributes, err := parseHLSAttributeList(line[colon+1:])
	if err != nil {
		if opaqueErr := validateExtremeHLSOpaqueTagValue(line[colon+1:]); opaqueErr != nil {
			return "", opaqueErr
		}
		return line, nil
	}
	return rewriteExtremeHLSParsedAttributeLine(line, attributes, nil, false, true, variables, session)
}

func knownHLSManifestTag(tag string) bool {
	switch tag {
	case "#EXTINF",
		"#EXT-X-VERSION", "#EXT-X-DEFINE", "#EXT-X-START", "#EXT-X-INDEPENDENT-SEGMENTS",
		"#EXT-X-KEY", "#EXT-X-BYTERANGE", "#EXT-X-DISCONTINUITY", "#EXT-X-MAP",
		"#EXT-X-PROGRAM-DATE-TIME", "#EXT-X-GAP", "#EXT-X-BITRATE", "#EXT-X-DATERANGE",
		"#EXT-X-TARGETDURATION", "#EXT-X-MEDIA-SEQUENCE", "#EXT-X-DISCONTINUITY-SEQUENCE",
		"#EXT-X-ENDLIST", "#EXT-X-PLAYLIST-TYPE", "#EXT-X-I-FRAMES-ONLY", "#EXT-X-ALLOW-CACHE",
		"#EXT-X-PART", "#EXT-X-SERVER-CONTROL", "#EXT-X-PART-INF", "#EXT-X-PRELOAD-HINT",
		"#EXT-X-RENDITION-REPORT", "#EXT-X-SKIP", "#EXT-X-MEDIA", "#EXT-X-STREAM-INF",
		"#EXT-X-I-FRAME-STREAM-INF", "#EXT-X-SESSION-DATA", "#EXT-X-SESSION-KEY",
		"#EXT-X-CONTENT-STEERING", "#EXT-X-IMAGE-STREAM-INF":
		return true
	default:
		return false
	}
}

func rewriteHLSResponse(payload []byte, session *dynamicRewriteSession) ([]byte, error) {
	if session == nil || session.issuer == nil || !utf8.Valid(payload) || len(payload) == 0 {
		return nil, fmt.Errorf("invalid HLS manifest")
	}
	sawCRLF := false
	sawLF := false
	for index, value := range payload {
		if (value < 0x20 && value != '\t' && value != '\r' && value != '\n') || value == 0x7f {
			return nil, fmt.Errorf("HLS manifest contains a control character")
		}
		if value == '\r' && (index+1 >= len(payload) || payload[index+1] != '\n') {
			return nil, fmt.Errorf("HLS manifest contains a bare carriage return")
		}
		if value == '\r' {
			sawCRLF = true
		}
		if value == '\n' && (index == 0 || payload[index-1] != '\r') {
			sawLF = true
		}
	}
	if sawCRLF && sawLF {
		return nil, fmt.Errorf("HLS manifest mixes newline styles")
	}
	maxLines := session.issuer.policy.limits.MaxURLsPerResponse*8 + 1024
	if bytes.Count(payload, []byte{'\n'})+1 > maxLines {
		return nil, fmt.Errorf("HLS manifest contains too many lines")
	}
	text := string(payload)
	separator := "\n"
	if sawCRLF {
		separator = "\r\n"
	}
	lines := strings.Split(text, separator)
	if len(lines) == 0 || lines[0] != "#EXTM3U" {
		return nil, fmt.Errorf("HLS manifest is missing EXTM3U")
	}
	extremeCompatibility := session.issuer.policy.profile == dynamicProfileExtreme
	var extremeVariables *extremeHLSVariableTable
	if extremeCompatibility {
		extremeVariables = newExtremeHLSVariableTable(session)
	}
	uriTags := map[string]map[string]bool{
		"#EXT-X-KEY":                {"URI": true},
		"#EXT-X-MAP":                {"URI": true},
		"#EXT-X-MEDIA":              {"URI": true},
		"#EXT-X-I-FRAME-STREAM-INF": {"URI": true},
		"#EXT-X-SESSION-KEY":        {"URI": true},
		"#EXT-X-SESSION-DATA":       {"URI": true},
		"#EXT-X-IMAGE-STREAM-INF":   {"URI": true},
		"#EXT-X-RENDITION-REPORT":   {"URI": true},
		"#EXT-X-PRELOAD-HINT":       {"URI": true},
		"#EXT-X-PART":               {"URI": true},
		"#EXT-X-DATERANGE":          {"X-ASSET-URI": true, "X-URI": true},
	}
	singletons := make(map[string]bool)
	multivariant := false
	media := false
	expectVariantURI := false
	sawUnscopedURI := false
	for index, line := range lines {
		if index&255 == 0 {
			if err := session.ctx.Err(); err != nil {
				return nil, fmt.Errorf("HLS parsing deadline exceeded")
			}
		}
		if int64(len(line)) > globalDynamicMaxStringBytes {
			return nil, fmt.Errorf("HLS line exceeds its limit")
		}
		if index == 0 {
			continue
		}
		if line == "" {
			if expectVariantURI {
				return nil, fmt.Errorf("HLS variant tag is not followed by a URI")
			}
			continue
		}
		if !strings.HasPrefix(line, "#") {
			if multivariant && !expectVariantURI {
				return nil, fmt.Errorf("HLS multivariant URI is missing STREAM-INF")
			}
			kind := dynamicCapabilityKindResource
			if expectVariantURI {
				kind = dynamicCapabilityKindManifest
				expectVariantURI = false
			} else {
				sawUnscopedURI = true
			}
			if strings.ContainsAny(line, " \t") {
				return nil, fmt.Errorf("HLS URI line contains whitespace")
			}
			if line != strings.TrimSpace(line) {
				return nil, fmt.Errorf("HLS URI line contains surrounding whitespace")
			}
			uriValue := line
			if extremeCompatibility {
				resolved, err := extremeVariables.substituteExtremeHLSURI(uriValue)
				if err != nil {
					return nil, err
				}
				uriValue = resolved
			}
			rewritten, err := rewriteHLSURIKind(uriValue, session, kind)
			if err != nil {
				return nil, err
			}
			lines[index] = rewritten
			continue
		}
		if expectVariantURI {
			return nil, fmt.Errorf("HLS variant tag is not followed by a URI")
		}
		tag := line
		if colon := strings.IndexByte(line, ':'); colon >= 0 {
			tag = line[:colon]
		}
		if strings.HasPrefix(tag, "#EXT") && !knownHLSManifestTag(tag) {
			if !extremeCompatibility || !isExtremeHLSUnknownTagName(tag) {
				return nil, fmt.Errorf("unsupported HLS tag")
			}
			rewritten, err := rewriteExtremeHLSUnknownTagLine(line, extremeVariables, session)
			if err != nil {
				return nil, err
			}
			lines[index] = rewritten
			continue
		}
		switch tag {
		case "#EXT-X-DEFINE":
			if !extremeCompatibility {
				return nil, fmt.Errorf("HLS variable substitution is unsupported")
			}
			if err := extremeVariables.defineFromExtremeHLSLine(line); err != nil {
				return nil, err
			}
			lines[index] = ""
			continue
		case "#EXT-X-CONTENT-STEERING":
			return nil, fmt.Errorf("HLS content steering is unsupported")
		case "#EXT-X-VERSION", "#EXT-X-START", "#EXT-X-INDEPENDENT-SEGMENTS", "#EXT-X-SKIP":
			if singletons[tag] {
				return nil, fmt.Errorf("duplicate singleton HLS tag")
			}
			singletons[tag] = true
		}
		if tag == "#EXT-X-VERSION" {
			versionText := strings.TrimPrefix(line, "#EXT-X-VERSION:")
			version, err := strconv.Atoi(versionText)
			if err != nil || version < 1 || version > 13 {
				return nil, fmt.Errorf("unsupported HLS protocol version")
			}
		}
		if tag == "#EXT-X-STREAM-INF" {
			expectVariantURI = true
		}
		switch tag {
		case "#EXT-X-MEDIA", "#EXT-X-STREAM-INF", "#EXT-X-I-FRAME-STREAM-INF", "#EXT-X-IMAGE-STREAM-INF", "#EXT-X-SESSION-DATA", "#EXT-X-SESSION-KEY":
			multivariant = true
			if sawUnscopedURI {
				return nil, fmt.Errorf("HLS multivariant URI is missing STREAM-INF")
			}
		case "#EXT-X-TARGETDURATION", "#EXT-X-MEDIA-SEQUENCE", "#EXT-X-DISCONTINUITY-SEQUENCE", "#EXT-X-ENDLIST", "#EXT-X-PLAYLIST-TYPE", "#EXT-X-I-FRAMES-ONLY", "#EXT-X-PART-INF", "#EXT-X-SERVER-CONTROL", "#EXT-X-PRELOAD-HINT", "#EXT-X-RENDITION-REPORT", "#EXT-X-SKIP", "#EXTINF", "#EXT-X-BYTERANGE", "#EXT-X-DISCONTINUITY", "#EXT-X-KEY", "#EXT-X-MAP", "#EXT-X-PROGRAM-DATE-TIME", "#EXT-X-DATERANGE", "#EXT-X-GAP", "#EXT-X-BITRATE", "#EXT-X-PART":
			media = true
		}
		if multivariant && media {
			return nil, fmt.Errorf("HLS manifest mixes multivariant and media tags")
		}
		if tag == "#EXT-X-DATERANGE" {
			colon := strings.IndexByte(line, ':')
			attributes, err := parseHLSAttributeList(line[colon+1:])
			if err != nil {
				return nil, err
			}
			for _, attribute := range attributes {
				if attribute.name == "X-ASSET-LIST" || attribute.name == "X-ASSET-URI" {
					return nil, fmt.Errorf("HLS interstitial asset URLs require an unavailable absolute public capability base")
				}
			}
		}
		if names := uriTags[tag]; names != nil {
			var rewritten string
			var err error
			if extremeCompatibility {
				rewritten, err = rewriteExtremeHLSKnownAttributeLine(line, names, extremeVariables, session)
			} else {
				rewritten, err = rewriteHLSAttributeLine(line, names, session)
			}
			if err != nil {
				return nil, err
			}
			lines[index] = rewritten
		} else if extremeCompatibility {
			rewritten, err := rewriteExtremeHLSAdditionalAttributeLine(line, extremeVariables, session)
			if err != nil {
				return nil, err
			}
			lines[index] = rewritten
		}
	}
	if !multivariant && !media {
		return nil, fmt.Errorf("HLS manifest type is not recognized")
	}
	if expectVariantURI {
		return nil, fmt.Errorf("HLS variant tag is not followed by a URI")
	}
	if extremeCompatibility {
		for _, line := range lines {
			if strings.Contains(line, "{$") {
				return nil, fmt.Errorf("unresolved HLS variable")
			}
			if int64(len(line)) > globalDynamicMaxStringBytes {
				return nil, fmt.Errorf("HLS rewritten line exceeds its limit")
			}
		}
	}
	outputLimit := session.structuredOutputLimit()
	outputSize := int64(len(separator) * (len(lines) - 1))
	for _, line := range lines {
		if int64(len(line)) > outputLimit-outputSize {
			return nil, fmt.Errorf("HLS rewritten manifest exceeds its body budget")
		}
		outputSize += int64(len(line))
	}
	output := dynamicBoundedBuffer{limit: outputLimit}
	for index, line := range lines {
		if index > 0 {
			if _, err := output.WriteString(separator); err != nil {
				return nil, err
			}
		}
		if _, err := output.WriteString(line); err != nil {
			return nil, err
		}
	}
	return output.Bytes(), nil
}
