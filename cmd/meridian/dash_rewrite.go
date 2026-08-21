package main

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	dashTemplateMarkerPrefix           = "__MERIDIAN_DASH_TEMPLATE_"
	dashLiteralDollarClaimMarker       = dashTemplateMarkerPrefix + "LITERAL_DOLLAR__"
	dashFixedTemplateClaimMarkerPrefix = "meridian-dash-fixed-"
)

type dashTemplateMarker struct {
	sentinel   string
	expression string
	literal    bool
	fixed      bool
	fixedIndex int
}

type dashTemplateBindings struct {
	representationID string
	bandwidth        string
}

func dashFixedTemplateClaimMarker(index int) string {
	return dashFixedTemplateClaimMarkerPrefix + strconv.Itoa(index) + "-x"
}

func sanitizeDASHTemplate(value string) (string, []dashTemplateMarker, error) {
	const markerPrefix = dashTemplateMarkerPrefix
	if value == "" || len(value) > maxDynamicTargetURLBytes || strings.Contains(value, markerPrefix) || strings.Contains(strings.ToLower(value), dashFixedTemplateClaimMarkerPrefix) || containsDynamicUnsafeRune(value) {
		return "", nil, fmt.Errorf("invalid DASH URL template")
	}
	markers := make([]dashTemplateMarker, 0, 4)
	var output strings.Builder
	output.Grow(len(value))
	for offset := 0; offset < len(value); {
		if value[offset] != '$' {
			output.WriteByte(value[offset])
			offset++
			continue
		}
		if offset+1 < len(value) && value[offset+1] == '$' {
			sentinel := markerPrefix + strconv.Itoa(len(markers)) + "__"
			markers = append(markers, dashTemplateMarker{sentinel: sentinel, literal: true})
			output.WriteString(sentinel)
			offset += 2
			continue
		}
		end := strings.IndexByte(value[offset+1:], '$')
		if end < 0 {
			return "", nil, fmt.Errorf("unterminated DASH URL template expression")
		}
		end += offset + 1
		expression := value[offset+1 : end]
		if dashTemplateIdentifier(expression) == "" {
			return "", nil, fmt.Errorf("unsupported DASH URL template expression")
		}
		sentinel := markerPrefix + strconv.Itoa(len(markers)) + "__"
		markers = append(markers, dashTemplateMarker{sentinel: sentinel, expression: expression})
		output.WriteString(sentinel)
		offset = end + 1
	}
	return output.String(), markers, nil
}

func formatDASHFixedTemplateValue(expression string, bindings dashTemplateBindings) (string, bool, error) {
	match := dashTemplateExpressionPattern.FindStringSubmatch(expression)
	if match == nil {
		return "", false, fmt.Errorf("invalid DASH template expression")
	}
	switch match[1] {
	case "RepresentationID":
		if !validDASHRepresentationID(bindings.representationID) {
			return "", true, fmt.Errorf("invalid DASH RepresentationID")
		}
		return bindings.representationID, true, nil
	case "Bandwidth":
		bandwidth, err := strconv.ParseUint(bindings.bandwidth, 10, 64)
		if err != nil {
			return "", true, fmt.Errorf("invalid DASH Bandwidth")
		}
		base := 10
		switch match[3] {
		case "o":
			base = 8
		case "x", "X":
			base = 16
		}
		formatted := strconv.FormatUint(bandwidth, base)
		if match[3] == "X" {
			formatted = strings.ToUpper(formatted)
		}
		if match[2] != "" {
			width, _ := strconv.Atoi(match[2])
			if len(formatted) < width {
				formatted = strings.Repeat("0", width-len(formatted)) + formatted
			}
		}
		return formatted, true, nil
	default:
		return "", false, nil
	}
}

func prepareDASHTemplateReferences(sanitized string, markers []dashTemplateMarker, bindings dashTemplateBindings) (string, string, []string, error) {
	reference, err := url.Parse(sanitized)
	if err != nil || reference.User != nil || reference.Fragment != "" || reference.RawFragment != "" || reference.Opaque != "" {
		return "", "", nil, fmt.Errorf("invalid DASH URL template")
	}
	validationText := sanitized
	claimText := sanitized
	fixedValues := make([]string, 0, len(markers))
	for index := range markers {
		marker := &markers[index]
		inHost := strings.Count(reference.Host, marker.sentinel)
		inPath := strings.Count(reference.EscapedPath(), marker.sentinel)
		inQuery := strings.Count(reference.RawQuery, marker.sentinel)
		if inHost+inPath+inQuery != 1 {
			return "", "", nil, fmt.Errorf("DASH template expression crosses or modifies a URL structural boundary")
		}
		if marker.literal {
			if inHost != 0 {
				return "", "", nil, fmt.Errorf("DASH literal dollar cannot modify an authority")
			}
			validationText = strings.Replace(validationText, marker.sentinel, "$", 1)
			continue
		}
		fixedValue, fixed, err := formatDASHFixedTemplateValue(marker.expression, bindings)
		if err != nil {
			return "", "", nil, err
		}
		if !fixed {
			if inHost != 0 {
				return "", "", nil, fmt.Errorf("client-bound DASH template expression cannot modify an authority")
			}
			continue
		}
		marker.fixed = true
		marker.fixedIndex = len(fixedValues)
		fixedValues = append(fixedValues, fixedValue)
		validationText = strings.Replace(validationText, marker.sentinel, fixedValue, 1)
		claimText = strings.Replace(claimText, marker.sentinel, dashFixedTemplateClaimMarker(marker.fixedIndex), 1)
	}
	return validationText, claimText, fixedValues, nil
}

func restoreDASHTemplateClaimMarkers(value string, markers []dashTemplateMarker) (string, []string, error) {
	expressions := make([]string, 0, len(markers))
	for _, marker := range markers {
		if marker.fixed {
			if strings.Count(value, dashFixedTemplateClaimMarker(marker.fixedIndex)) != 1 {
				return "", nil, fmt.Errorf("fixed DASH template marker was lost or duplicated")
			}
			continue
		}
		if strings.Count(value, marker.sentinel) != 1 {
			return "", nil, fmt.Errorf("DASH URL template marker was lost or duplicated")
		}
		replacement := dashLiteralDollarClaimMarker
		if !marker.literal {
			replacement = "$" + marker.expression + "$"
			expressions = append(expressions, marker.expression)
		}
		value = strings.Replace(value, marker.sentinel, replacement, 1)
	}
	return value, expressions, nil
}

func restoreDASHLocalTemplateMarkers(value string, markers []dashTemplateMarker) (string, error) {
	for _, marker := range markers {
		if marker.literal || marker.fixed {
			continue
		}
		if strings.Count(value, marker.sentinel) != 1 {
			return "", fmt.Errorf("DASH URL template marker was lost or duplicated")
		}
		value = strings.Replace(value, marker.sentinel, "$"+marker.expression+"$", 1)
	}
	return value, nil
}

func dashTemplatePublicSuffix(expressions []string) string {
	var output strings.Builder
	for index, expression := range expressions {
		output.WriteString("/v")
		output.WriteString(strconv.Itoa(index))
		output.WriteString("-$")
		output.WriteString(expression)
		output.WriteByte('$')
	}
	return output.String()
}

func rewriteDASHTemplate(value string, base *url.URL, session *dynamicRewriteSession, bindings dashTemplateBindings) (string, error) {
	if session == nil || session.issuer == nil || session.base == nil || base == nil {
		return "", fmt.Errorf("DASH rewrite session is unavailable")
	}
	if err := session.ctx.Err(); err != nil {
		return "", fmt.Errorf("DASH parsing deadline exceeded")
	}
	sanitized, markers, err := sanitizeDASHTemplate(value)
	if err != nil {
		return "", err
	}
	validationText, claimText, fixedValues, err := prepareDASHTemplateReferences(sanitized, markers, bindings)
	if err != nil {
		return "", err
	}
	validationReference, validationErr := url.Parse(validationText)
	claimReference, claimErr := url.Parse(claimText)
	if validationErr != nil || claimErr != nil || validationReference.User != nil || claimReference.User != nil || validationReference.Fragment != "" || claimReference.Fragment != "" || validationReference.RawFragment != "" || claimReference.RawFragment != "" || validationReference.Opaque != "" || claimReference.Opaque != "" {
		return "", fmt.Errorf("invalid DASH URL template")
	}
	resolvedValidation := base.ResolveReference(validationReference)
	resolvedClaim := base.ResolveReference(claimReference)
	configured := session.source == dynamicDiscoverySourceDASH && session.issuer.configuredAuthorities[redirectHostKey(resolvedValidation)]
	var validationTarget *url.URL
	var claimURL *url.URL
	if configured {
		validationTarget, validationErr = normalizeTrustedCapabilityURL(resolvedValidation.String())
		claimURL, claimErr = normalizeTrustedCapabilityURL(resolvedClaim.String())
	} else {
		validationTarget, validationErr = normalizeDynamicURL(resolvedValidation.String())
		claimURL, claimErr = normalizeDynamicURL(resolvedClaim.String())
	}
	if validationErr != nil || claimErr != nil {
		return "", fmt.Errorf("invalid DASH URL template")
	}
	claimTarget, expressions, err := restoreDASHTemplateClaimMarkers(claimURL.String(), markers)
	if err != nil {
		return "", err
	}
	if !configured && !session.rewriteRelative && sameRedirectAuthority(session.base, validationTarget) {
		localTemplate, err := restoreDASHLocalTemplateMarkers(validationTarget.RequestURI(), markers)
		return localTemplate, err
	}
	session.urlCount++
	if session.urlCount > session.issuer.policy.limits.MaxURLsPerResponse {
		return "", fmt.Errorf("discovered URL count exceeds its limit")
	}
	seenKey := "dash-template\x00" + strconv.FormatBool(configured) + "\x00" + claimTarget + "\x00" + strings.Join(expressions, "\x1f") + "\x00" + strings.Join(fixedValues, "\x1f")
	if route, exists := session.seen[seenKey]; exists {
		return route, nil
	}
	var route string
	var acquired bool
	var discoveryErr *dynamicProxyError
	if configured {
		route, acquired, discoveryErr = session.issuer.mintTrustedValidatedTracked(validationTarget, claimTarget, expressions, fixedValues, session.source, dynamicCapabilityKindResource, 0)
	} else {
		route, acquired, discoveryErr = session.issuer.mintValidatedDASHTemplateTracked(session.ctx, base, validationTarget, session.source, claimTarget, expressions, fixedValues)
	}
	if discoveryErr != nil {
		return "", discoveryErr
	}
	baseRoute := route
	route += dashTemplatePublicSuffix(expressions)
	if session.seen == nil {
		session.seen = make(map[string]string)
	}
	session.seen[seenKey] = route
	if acquired {
		token := session.issuer.capabilityToken(baseRoute)
		session.minted = append(session.minted, token)
	}
	return route, nil
}
func rewriteDASHUTCTiming(node *dashXMLNode, base *url.URL, session *dynamicRewriteSession) error {
	schemeIndex, err := dashAttributeIndex(node, "schemeIdUri", dashExtremeCompatibilityEnabled(session))
	if err != nil || schemeIndex < 0 {
		return fmt.Errorf("DASH UTCTiming requires one supported scheme")
	}
	valueIndex, err := dashAttributeIndex(node, "value", dashExtremeCompatibilityEnabled(session))
	if err != nil || valueIndex < 0 {
		return fmt.Errorf("DASH UTCTiming requires a value")
	}
	scheme := node.start.Attr[schemeIndex].Value
	switch scheme {
	case "urn:mpeg:dash:utc:direct:2012", "urn:mpeg:dash:utc:direct:2014":
		if _, err := time.Parse(time.RFC3339, node.start.Attr[valueIndex].Value); err != nil {
			return fmt.Errorf("invalid DASH direct UTC value")
		}
		return nil
	case "urn:mpeg:dash:utc:http-head:2012", "urn:mpeg:dash:utc:http-head:2014",
		"urn:mpeg:dash:utc:http-xsdate:2012", "urn:mpeg:dash:utc:http-xsdate:2014",
		"urn:mpeg:dash:utc:http-iso:2012", "urn:mpeg:dash:utc:http-iso:2014",
		"urn:mpeg:dash:utc:http-ntp:2014":
		return rewriteDASHURLAttribute(node, "value", base, false, session, nil)
	default:
		return fmt.Errorf("unsupported DASH UTCTiming scheme")
	}
}

func rewriteDASHEventDescriptor(node *dashXMLNode, base *url.URL, session *dynamicRewriteSession) error {
	extremeCompatibility := dashExtremeCompatibilityEnabled(session)
	schemeIndex, err := dashAttributeIndex(node, "schemeIdUri", extremeCompatibility)
	if err != nil || schemeIndex < 0 {
		return err
	}
	scheme := node.start.Attr[schemeIndex].Value
	valueIndex, err := dashAttributeIndex(node, "value", extremeCompatibility)
	if err != nil {
		return err
	}
	if scheme == "urn:mpeg:dash:event:2012" {
		if valueIndex < 0 || node.start.Attr[valueIndex].Value != "1" {
			return fmt.Errorf("DASH MPD patch or replacement events are unsupported")
		}
		return nil
	}
	if scheme != "urn:mpeg:dash:event:callback:2015" {
		return nil
	}
	if node.start.Name.Local == "InbandEventStream" {
		return fmt.Errorf("DASH in-band callback events are unsupported")
	}
	for _, content := range node.content {
		if content.node == nil {
			if strings.TrimSpace(string(content.text)) != "" {
				return fmt.Errorf("DASH callback EventStream has unsupported payload")
			}
			continue
		}
		event := content.node
		if event.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
			if !extremeCompatibility {
				return fmt.Errorf("DASH callback EventStream has an unsupported child")
			}
			if err := validateDASHExtremeCompatibilityInertSubtree(session.ctx, event); err != nil {
				return err
			}
			continue
		}
		if event.start.Name.Local != "Event" {
			return fmt.Errorf("DASH callback EventStream has an unsupported child")
		}
		if err := validateDASHLeafElement(event, session.ctx, extremeCompatibility); err != nil {
			return err
		}
		messageIndex, err := dashAttributeIndex(event, "messageData", extremeCompatibility)
		if err != nil || messageIndex < 0 {
			return fmt.Errorf("DASH callback Event requires messageData")
		}
		if err := rewriteDASHURLAttribute(event, "messageData", base, false, session, nil); err != nil {
			return err
		}
	}
	return nil
}

func rewriteDASHNode(node *dashXMLNode, inheritedBase *url.URL, inheritedAddressing *dashSegmentAddressing, session *dynamicRewriteSession) (int, error) {
	if node == nil || inheritedBase == nil || session == nil {
		return 0, fmt.Errorf("DASH traversal state is unavailable")
	}
	if err := session.ctx.Err(); err != nil {
		return 0, fmt.Errorf("DASH parsing deadline exceeded")
	}
	extremeCompatibility := dashExtremeCompatibilityEnabled(session)
	if err := validateDASHNodeNamespace(node, extremeCompatibility); err != nil {
		return 0, err
	}
	standardNode := node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011"
	if !standardNode && node.start.Name.Local == "ContentProtection" {
		return 0, fmt.Errorf("DASH foreign ContentProtection elements are unsupported")
	}
	if standardNode {
		switch node.start.Name.Local {
		case "PatchLocation", "ContentSteering", "ImportedMPD", "Metrics", "Reporting":
			return 0, fmt.Errorf("unsupported DASH external document or reporting")
		case "ContentProtection":
			if !extremeCompatibility {
				return 0, fmt.Errorf("DASH DRM is unsupported")
			}
			if err := validateDASHExtremeCompatibilityContentProtection(session.ctx, node); err != nil {
				return 0, err
			}
			return 0, nil
		}
	}
	currentBase := inheritedBase
	baseIndexes := make([]int, 0, 1)
	addressingIndex := -1
	var localAddressing *dashSegmentAddressing
	for index, child := range node.content {
		if child.node == nil || child.node.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
			continue
		}
		switch child.node.start.Name.Local {
		case "BaseURL":
			if err := validateDASHNodeNamespace(child.node, extremeCompatibility); err != nil {
				return 0, err
			}
			baseIndexes = append(baseIndexes, index)
		case "SegmentTemplate", "SegmentList", "SegmentBase":
			if err := validateDASHNodeNamespace(child.node, extremeCompatibility); err != nil {
				return 0, err
			}
			if localAddressing != nil {
				return 0, fmt.Errorf("multiple DASH segment addressing elements at one level")
			}
			localAddressing = &dashSegmentAddressing{kind: child.node.start.Name.Local, node: child.node}
			addressingIndex = index
		}
	}
	if len(baseIndexes) > 1 {
		return 0, fmt.Errorf("multiple DASH BaseURL alternatives are unsupported")
	}
	if len(baseIndexes) == 1 {
		baseNode := node.content[baseIndexes[0]].node
		value, err := dashNodeText(baseNode)
		if err != nil {
			return 0, err
		}
		rewritten, resolved, err := rewriteDASHReference(value, inheritedBase, session, dynamicCapabilityKindResource)
		if err != nil {
			return 0, err
		}
		setDASHNodeText(baseNode, rewritten)
		currentBase = resolved
	}
	effectiveAddressing := mergeDASHSegmentAddressing(inheritedAddressing, localAddressing)
	if standardNode && node.start.Name.Local == "Representation" && effectiveAddressing != nil {
		bindings, err := dashRepresentationBindings(node, extremeCompatibility)
		if err != nil {
			return 0, err
		}
		if err := rewriteDASHSegmentAddressing(effectiveAddressing, currentBase, session, bindings); err != nil {
			return 0, err
		}
		if addressingIndex >= 0 {
			node.content[addressingIndex].node = effectiveAddressing.node
		} else {
			node.content = append(node.content, dashXMLContent{node: effectiveAddressing.node})
			addressingIndex = len(node.content) - 1
		}
	}
	if standardNode {
		switch node.start.Name.Local {
		case "UTCTiming":
			if err := rewriteDASHUTCTiming(node, currentBase, session); err != nil {
				return 0, err
			}
		case "EventStream", "InbandEventStream":
			if err := rewriteDASHEventDescriptor(node, currentBase, session); err != nil {
				return 0, err
			}
		case "Location":
			value, err := dashNodeText(node)
			if err != nil {
				return 0, err
			}
			reloadDepth := max(1, session.depth)
			rewritten, err := session.rewriteAgainstSourceKindDepth(value, session.base, dynamicDiscoverySourceDASH, dynamicCapabilityKindManifest, reloadDepth)
			if err != nil {
				return 0, err
			}
			setDASHNodeText(node, rewritten)
		}
	}
	representations := 0
	if standardNode && node.start.Name.Local == "Representation" {
		representations = 1
	}
	for _, child := range node.content {
		if child.node == nil || child.node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011" && (child.node.start.Name.Local == "BaseURL" || isDASHSegmentAddressing(child.node.start.Name.Local)) {
			continue
		}
		count, err := rewriteDASHNode(child.node, currentBase, effectiveAddressing, session)
		if err != nil {
			return 0, err
		}
		representations += count
	}
	if !(standardNode && node.start.Name.Local == "Representation") && localAddressing != nil {
		if representations == 0 {
			return 0, fmt.Errorf("DASH segment addressing has no Representation scope")
		}
		node.content = append(node.content[:addressingIndex], node.content[addressingIndex+1:]...)
	}
	return representations, nil
}

func dashXMLShape(node *dashXMLNode) (int64, int64) {
	if node == nil {
		return 0, 0
	}
	nodes := int64(1)
	bytesUsed := int64(32 + len(node.start.Name.Space) + len(node.start.Name.Local))
	for _, attribute := range node.start.Attr {
		bytesUsed += int64(24 + len(attribute.Name.Space) + len(attribute.Name.Local) + len(attribute.Value))
	}
	for _, child := range node.content {
		if child.node != nil {
			childNodes, childBytes := dashXMLShape(child.node)
			nodes += childNodes
			bytesUsed += childBytes
		} else {
			bytesUsed += int64(len(child.text))
		}
	}
	return nodes, bytesUsed
}

func estimateDASHCloneExpansion(node *dashXMLNode, inheritedNodes, inheritedBytes int64, cloneNodes, cloneBytes *int64, maxCloneBytes int64) error {
	if node == nil {
		return nil
	}
	effectiveNodes := inheritedNodes
	effectiveBytes := inheritedBytes
	for _, child := range node.content {
		if child.node != nil && child.node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011" && isDASHSegmentAddressing(child.node.start.Name.Local) {
			localNodes, localBytes := dashXMLShape(child.node)
			effectiveNodes += localNodes
			effectiveBytes += localBytes
		}
	}
	if node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011" && node.start.Name.Local == "Representation" && effectiveNodes > 0 {
		if effectiveNodes > globalDynamicMaxXMLNodes-*cloneNodes || effectiveBytes > maxCloneBytes-*cloneBytes {
			return fmt.Errorf("DASH inherited template expansion exceeds its budget")
		}
		*cloneNodes += effectiveNodes
		*cloneBytes += effectiveBytes
	}
	for _, child := range node.content {
		if child.node == nil || child.node.start.Name.Space == "urn:mpeg:dash:schema:mpd:2011" && isDASHSegmentAddressing(child.node.start.Name.Local) {
			continue
		}
		if err := estimateDASHCloneExpansion(child.node, effectiveNodes, effectiveBytes, cloneNodes, cloneBytes, maxCloneBytes); err != nil {
			return err
		}
	}
	return nil
}

func rewriteDASHResponse(payload []byte, session *dynamicRewriteSession) ([]byte, error) {
	if session == nil || session.issuer == nil || session.ctx == nil {
		return nil, fmt.Errorf("DASH rewrite session is unavailable")
	}
	root, err := parseDASHXML(session.ctx, payload)
	if err != nil {
		return nil, err
	}
	maxCloneBytes := session.structuredOutputLimit() - int64(len(payload))
	if maxCloneBytes < 0 {
		return nil, fmt.Errorf("DASH response exceeds its body budget")
	}
	var cloneNodes, cloneBytes int64
	if err := estimateDASHCloneExpansion(root, 0, 0, &cloneNodes, &cloneBytes, maxCloneBytes); err != nil {
		return nil, err
	}
	if _, err := rewriteDASHNode(root, session.base, nil, session); err != nil {
		return nil, err
	}
	output := dynamicBoundedBuffer{limit: session.structuredOutputLimit()}
	if _, err := output.Write([]byte(xml.Header)); err != nil {
		return nil, err
	}
	encoder := xml.NewEncoder(&output)
	if err := encodeDASHXMLNode(session.ctx, encoder, root, dashExtremeCompatibilityEnabled(session)); err != nil {
		return nil, err
	}
	if err := encoder.Flush(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
