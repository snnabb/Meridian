package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

type dashSegmentAddressing struct {
	kind string
	node *dashXMLNode
}

func isDASHSegmentAddressing(name string) bool {
	return name == "SegmentTemplate" || name == "SegmentList" || name == "SegmentBase"
}

func dashSegmentAddressingChildRank(content dashXMLContent) int {
	if content.node == nil {
		return -1
	}
	if content.node.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
		return 5
	}
	switch content.node.start.Name.Local {
	case "Initialization":
		return 0
	case "RepresentationIndex":
		return 1
	case "SegmentTimeline":
		return 2
	case "BitstreamSwitching":
		return 3
	case "SegmentURL":
		return 4
	default:
		return 5
	}
}

func mergeDASHSegmentAddressing(inherited, local *dashSegmentAddressing) *dashSegmentAddressing {
	if local == nil {
		if inherited == nil {
			return nil
		}
		return &dashSegmentAddressing{kind: inherited.kind, node: cloneDASHXMLNode(inherited.node)}
	}
	if inherited == nil || inherited.kind != local.kind {
		return &dashSegmentAddressing{kind: local.kind, node: cloneDASHXMLNode(local.node)}
	}
	merged := cloneDASHXMLNode(inherited.node)
	for _, attribute := range local.node.start.Attr {
		replaced := false
		for index := range merged.start.Attr {
			if merged.start.Attr[index].Name == attribute.Name {
				merged.start.Attr[index] = attribute
				replaced = true
				break
			}
		}
		if !replaced {
			merged.start.Attr = append(merged.start.Attr, attribute)
		}
	}
	localElementNames := make(map[xml.Name]bool)
	for _, child := range local.node.content {
		if child.node != nil {
			localElementNames[child.node.start.Name] = true
		}
	}
	if len(localElementNames) != 0 {
		filtered := merged.content[:0]
		for _, child := range merged.content {
			if child.node != nil && localElementNames[child.node.start.Name] {
				continue
			}
			filtered = append(filtered, child)
		}
		merged.content = filtered
		for _, child := range local.node.content {
			if child.node != nil {
				merged.content = append(merged.content, dashXMLContent{node: cloneDASHXMLNode(child.node)})
			}
		}
	}
	sort.SliceStable(merged.content, func(left, right int) bool {
		return dashSegmentAddressingChildRank(merged.content[left]) < dashSegmentAddressingChildRank(merged.content[right])
	})
	return &dashSegmentAddressing{kind: local.kind, node: merged}
}

func rewriteDASHURLAttribute(node *dashXMLNode, name string, base *url.URL, template bool, session *dynamicRewriteSession, bindings *dashTemplateBindings) error {
	index, err := dashAttributeIndex(node, name, dashExtremeCompatibilityEnabled(session))
	if err != nil || index < 0 {
		return err
	}
	value := node.start.Attr[index].Value
	if template {
		if bindings == nil {
			return fmt.Errorf("DASH template bindings are unavailable")
		}
		rewritten, err := rewriteDASHTemplate(value, base, session, *bindings)
		if err != nil {
			return err
		}
		node.start.Attr[index].Value = rewritten
		return nil
	}
	rewritten, _, err := rewriteDASHReference(value, base, session, dynamicCapabilityKindResource)
	if err != nil {
		return err
	}
	node.start.Attr[index].Value = rewritten
	return nil
}

func validateDASHLeafElement(node *dashXMLNode, ctx context.Context, extremeCompatibility bool) error {
	if err := validateDASHNodeNamespace(node, extremeCompatibility); err != nil {
		return err
	}
	for _, child := range node.content {
		if child.node != nil {
			if !extremeCompatibility || child.node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011" {
				return fmt.Errorf("DASH segment addressing element has unsupported content")
			}
			if err := validateDASHExtremeCompatibilityInertSubtree(ctx, child.node); err != nil {
				return err
			}
			continue
		}
		if strings.TrimSpace(string(child.text)) != "" {
			return fmt.Errorf("DASH segment addressing element has unsupported content")
		}
	}
	return nil
}

func validateDASHSegmentTimeline(node *dashXMLNode, ctx context.Context, extremeCompatibility bool) error {
	if err := validateDASHNodeNamespace(node, extremeCompatibility); err != nil {
		return err
	}
	for _, child := range node.content {
		if child.node == nil {
			if strings.TrimSpace(string(child.text)) != "" {
				return fmt.Errorf("DASH SegmentTimeline has unsupported text")
			}
			continue
		}
		if child.node.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
			if !extremeCompatibility {
				return fmt.Errorf("DASH SegmentTimeline has an unsupported child")
			}
			if err := validateDASHExtremeCompatibilityInertSubtree(ctx, child.node); err != nil {
				return err
			}
			continue
		}
		if child.node.start.Name.Local != "S" {
			return fmt.Errorf("DASH SegmentTimeline has an unsupported child")
		}
		if err := validateDASHLeafElement(child.node, ctx, extremeCompatibility); err != nil {
			return err
		}
	}
	return nil
}

func rewriteDASHSegmentAddressing(addressing *dashSegmentAddressing, base *url.URL, session *dynamicRewriteSession, bindings dashTemplateBindings) error {
	if addressing == nil || addressing.node == nil || !isDASHSegmentAddressing(addressing.kind) || addressing.node.start.Name.Local != addressing.kind {
		return fmt.Errorf("DASH segment addressing is unavailable")
	}
	extremeCompatibility := dashExtremeCompatibilityEnabled(session)
	if err := validateDASHNodeNamespace(addressing.node, extremeCompatibility); err != nil {
		return err
	}
	if addressing.kind == "SegmentTemplate" {
		for _, attribute := range []string{"media", "initialization", "index", "bitstreamSwitching"} {
			if err := rewriteDASHURLAttribute(addressing.node, attribute, base, true, session, &bindings); err != nil {
				return err
			}
		}
	}
	for _, content := range addressing.node.content {
		if content.node == nil {
			if strings.TrimSpace(string(content.text)) != "" {
				return fmt.Errorf("DASH segment addressing has unsupported text")
			}
			continue
		}
		child := content.node
		if err := validateDASHNodeNamespace(child, extremeCompatibility); err != nil {
			return err
		}
		if child.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
			if err := validateDASHExtremeCompatibilityInertSubtree(session.ctx, child); err != nil {
				return err
			}
			continue
		}
		switch child.start.Name.Local {
		case "SegmentURL":
			if addressing.kind != "SegmentList" {
				return fmt.Errorf("DASH SegmentURL is outside SegmentList")
			}
			for _, attribute := range []string{"media", "index"} {
				if err := rewriteDASHURLAttribute(child, attribute, base, false, session, nil); err != nil {
					return err
				}
			}
			if err := validateDASHLeafElement(child, session.ctx, extremeCompatibility); err != nil {
				return err
			}
		case "Initialization", "RepresentationIndex", "BitstreamSwitching":
			if addressing.kind == "SegmentBase" && child.start.Name.Local == "BitstreamSwitching" {
				return fmt.Errorf("DASH SegmentBase has an unsupported child")
			}
			if err := rewriteDASHURLAttribute(child, "sourceURL", base, false, session, nil); err != nil {
				return err
			}
			if err := validateDASHLeafElement(child, session.ctx, extremeCompatibility); err != nil {
				return err
			}
		case "SegmentTimeline":
			if addressing.kind == "SegmentBase" {
				return fmt.Errorf("DASH SegmentBase has an unsupported timeline")
			}
			if err := validateDASHSegmentTimeline(child, session.ctx, extremeCompatibility); err != nil {
				return err
			}
		default:
			return fmt.Errorf("DASH segment addressing has an unsupported child")
		}
	}
	return nil
}

func validateDASHNodeNamespace(node *dashXMLNode, extremeCompatibility bool) error {
	if !extremeCompatibility {
		if node == nil || node.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
			return fmt.Errorf("DASH foreign-namespace elements are unsupported")
		}
		for _, attribute := range node.start.Attr {
			if attribute.Name.Space == "http://www.w3.org/1999/xlink" && attribute.Name.Local == "href" {
				return fmt.Errorf("DASH xlink fetches are unsupported")
			}
			if attribute.Name.Space != "" && !(attribute.Name.Space == "http://www.w3.org/XML/1998/namespace" && attribute.Name.Local == "lang") {
				return fmt.Errorf("DASH foreign-namespace attributes are unsupported")
			}
		}
		return nil
	}
	if node == nil {
		return fmt.Errorf("DASH foreign-namespace elements are unsupported")
	}
	if node.start.Name.Space == "http://www.w3.org/1999/xlink" {
		return fmt.Errorf("DASH xlink fetches are unsupported")
	}
	for _, attribute := range node.start.Attr {
		if err := validateDASHExtremeCompatibilityAttribute(node.start.Name.Space, attribute); err != nil {
			return err
		}
	}
	if node.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
		if dashExtremeCompatibilityActiveNamespace(node.start.Name.Space) || dashExtremeCompatibilityNetworkName(node.start.Name.Local) {
			return fmt.Errorf("DASH foreign extension has active network semantics")
		}
		for _, content := range node.content {
			if content.node == nil && dashExtremeCompatibilityNetworkReference(string(content.text)) {
				return fmt.Errorf("DASH foreign extension contains an external reference")
			}
		}
	}
	return nil
}

func dashExtremeCompatibilityNamespaceDeclaration(attribute xml.Attr) bool {
	return attribute.Name.Space == "xmlns" || attribute.Name.Space == "" && attribute.Name.Local == "xmlns"
}

func dashExtremeCompatibilityNormalizedName(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			return unicode.ToLower(character)
		}
		return -1
	}, value)
}

func dashExtremeCompatibilityNetworkName(value string) bool {
	switch dashExtremeCompatibilityNormalizedName(value) {
	case "baseurl", "segmentbase", "segmentlist", "segmenturl", "segmenttemplate",
		"initialization", "representationindex", "bitstreamswitching", "location", "utctiming",
		"patchlocation", "contentsteering", "importedmpd", "metrics", "reporting",
		"href", "src", "url", "uri", "sourceurl", "sourceuri", "serverurl", "serveruri",
		"licenseurl", "licenseuri", "laurl", "certurl", "certificateurl", "callbackurl", "reloaduri",
		"targeturl", "asseturl", "asseturi", "manifesturl", "manifesturi", "resourceurl", "resourceuri",
		"fonturl", "fonturi", "endpoint", "redirect", "querytemplate", "includeinrequests",
		"urlqueryinfo", "exturlqueryinfo", "exthttpheaderinfo", "fontdownload":
		return true
	default:
		return false
	}
}

func dashExtremeCompatibilityActiveNamespace(namespace string) bool {
	switch namespace {
	case "urn:dvb:dash:fontdownload:2014",
		"urn:mpeg:dash:schema:urlparam:2014", "urn:mpeg:dash:schema:urlparam:2016",
		"urn:mpeg:dash:urlparam:2014", "urn:mpeg:dash:urlparam:2016":
		return true
	default:
		return false
	}
}

func dashExtremeCompatibilityNetworkReference(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	for _, marker := range []string{"http://", "https://", "ws://", "wss://", "ftp://", "ftps://", "file://", "smb://", "rtsp://"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.HasPrefix(lower, "/") || strings.HasPrefix(lower, "./") || strings.HasPrefix(lower, "../") || strings.HasPrefix(lower, "?")
}

func validateDASHExtremeCompatibilityAttribute(ownerNamespace string, attribute xml.Attr) error {
	if dashExtremeCompatibilityNamespaceDeclaration(attribute) {
		return nil
	}
	if attribute.Name.Space == "http://www.w3.org/1999/xlink" {
		return fmt.Errorf("DASH xlink fetches are unsupported")
	}
	if attribute.Name.Space == "http://www.w3.org/XML/1998/namespace" && attribute.Name.Local == "base" {
		return fmt.Errorf("DASH xml:base references are unsupported")
	}
	if ownerNamespace == "urn:mpeg:dash:schema:mpd:2011" && attribute.Name.Space == "" {
		return nil
	}
	name := dashExtremeCompatibilityNormalizedName(attribute.Name.Local)
	if dashExtremeCompatibilityActiveNamespace(attribute.Name.Space) || dashExtremeCompatibilityNetworkName(name) || name != "schemeiduri" && dashExtremeCompatibilityNetworkReference(attribute.Value) {
		return fmt.Errorf("DASH foreign attribute has active network semantics")
	}
	return nil
}

func validateDASHExtremeCompatibilityEncodedDRMMetadata(value string) error {
	compact := strings.Map(func(character rune) rune {
		if unicode.IsSpace(character) {
			return -1
		}
		return character
	}, value)
	if compact == "" {
		return fmt.Errorf("DASH DRM metadata is empty")
	}
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(compact)
	}
	if err != nil || len(decoded) == 0 {
		return fmt.Errorf("DASH DRM metadata is malformed")
	}
	normalized := make([]byte, 0, len(decoded))
	for _, value := range decoded {
		if value == 0 {
			continue
		}
		if value >= 'A' && value <= 'Z' {
			value += 'a' - 'A'
		}
		normalized = append(normalized, value)
	}
	markers := [...][]byte{
		[]byte("http://"), []byte("https://"), []byte("la_url"), []byte("lui_url"),
		[]byte("laurl"), []byte("certurl"), []byte("licenseurl"), []byte("license_url"),
		[]byte("serverurl"), []byte("server_url"),
	}
	for _, marker := range markers {
		if bytes.Contains(normalized, marker) {
			return fmt.Errorf("DASH DRM metadata contains an external license or certificate reference")
		}
	}
	return nil
}

func validateDASHExtremeCompatibilityDRMNode(ctx context.Context, node *dashXMLNode) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("DASH parsing deadline exceeded")
	}
	if err := validateDASHNodeNamespace(node, true); err != nil {
		return err
	}
	if dashExtremeCompatibilityNetworkName(node.start.Name.Local) {
		return fmt.Errorf("DASH DRM metadata contains active network semantics")
	}
	for _, attribute := range node.start.Attr {
		if dashExtremeCompatibilityNamespaceDeclaration(attribute) {
			continue
		}
		name := dashExtremeCompatibilityNormalizedName(attribute.Name.Local)
		if dashExtremeCompatibilityNetworkName(name) || name != "schemeiduri" && dashExtremeCompatibilityNetworkReference(attribute.Value) {
			return fmt.Errorf("DASH DRM metadata contains an external license or certificate reference")
		}
	}
	name := dashExtremeCompatibilityNormalizedName(node.start.Name.Local)
	if name == "pssh" || name == "pro" || name == "protectionheader" {
		value, err := dashNodeText(node)
		if err != nil {
			return fmt.Errorf("DASH DRM metadata is malformed")
		}
		return validateDASHExtremeCompatibilityEncodedDRMMetadata(value)
	}
	for _, content := range node.content {
		if content.node != nil {
			if err := validateDASHExtremeCompatibilityDRMNode(ctx, content.node); err != nil {
				return err
			}
			continue
		}
		if dashExtremeCompatibilityNetworkReference(string(content.text)) {
			return fmt.Errorf("DASH DRM metadata contains an external license or certificate reference")
		}
	}
	return nil
}

func validateDASHExtremeCompatibilityContentProtection(ctx context.Context, node *dashXMLNode) error {
	if node == nil || node.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" || node.start.Name.Local != "ContentProtection" {
		return fmt.Errorf("DASH ContentProtection metadata is unavailable")
	}
	return validateDASHExtremeCompatibilityDRMNode(ctx, node)
}

func validateDASHExtremeCompatibilityInertSubtree(ctx context.Context, node *dashXMLNode) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("DASH parsing deadline exceeded")
	}
	if err := validateDASHNodeNamespace(node, true); err != nil {
		return err
	}
	if node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011" && node.start.Name.Local == "ContentProtection" {
		return validateDASHExtremeCompatibilityContentProtection(ctx, node)
	}
	if node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011" && dashExtremeCompatibilityNetworkName(node.start.Name.Local) {
		return fmt.Errorf("DASH inert extension contains a fetch-capable element")
	}
	for _, attribute := range node.start.Attr {
		if dashExtremeCompatibilityNamespaceDeclaration(attribute) {
			continue
		}
		name := dashExtremeCompatibilityNormalizedName(attribute.Name.Local)
		if dashExtremeCompatibilityNetworkName(name) || name != "schemeiduri" && dashExtremeCompatibilityNetworkReference(attribute.Value) {
			return fmt.Errorf("DASH inert extension contains an external reference")
		}
	}
	for _, content := range node.content {
		if content.node != nil {
			if err := validateDASHExtremeCompatibilityInertSubtree(ctx, content.node); err != nil {
				return err
			}
			continue
		}
		if dashExtremeCompatibilityNetworkReference(string(content.text)) {
			return fmt.Errorf("DASH inert extension contains an external reference")
		}
	}
	return nil
}

func dashRepresentationBindings(node *dashXMLNode, extremeCompatibility bool) (dashTemplateBindings, error) {
	var bindings dashTemplateBindings
	idIndex, err := dashAttributeIndex(node, "id", extremeCompatibility)
	if err != nil {
		return bindings, err
	}
	if idIndex >= 0 {
		bindings.representationID = node.start.Attr[idIndex].Value
	}
	bandwidthIndex, err := dashAttributeIndex(node, "bandwidth", extremeCompatibility)
	if err != nil {
		return bindings, err
	}
	if bandwidthIndex >= 0 {
		bindings.bandwidth = node.start.Attr[bandwidthIndex].Value
	}
	return bindings, nil
}
