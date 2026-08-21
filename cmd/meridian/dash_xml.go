package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"
)

type dashXMLContent struct {
	node *dashXMLNode
	text []byte
}

type dashXMLNode struct {
	start   xml.StartElement
	content []dashXMLContent
}

func parseDASHXML(ctx context.Context, payload []byte) (*dashXMLNode, error) {
	if !utf8.Valid(payload) || len(payload) == 0 {
		return nil, fmt.Errorf("invalid DASH XML encoding")
	}
	decoder := xml.NewDecoder(bytes.NewReader(payload))
	decoder.Strict = true
	if ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("DASH parsing deadline exceeded")
	}
	stack := make([]*dashXMLNode, 0, 16)
	var root *dashXMLNode
	nodeCount := 0
	tokenCount := 0
	attributeCount := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid DASH XML")
		}
		tokenCount++
		if tokenCount > globalDynamicMaxXMLTokens {
			return nil, fmt.Errorf("DASH XML token count exceeds its limit")
		}
		switch value := token.(type) {
		case xml.StartElement:
			nodeCount++
			if nodeCount&255 == 0 {
				if err := ctx.Err(); err != nil {
					return nil, fmt.Errorf("DASH parsing deadline exceeded")
				}
			}
			if nodeCount > globalDynamicMaxXMLNodes || len(stack)+1 > globalDynamicMaxParseDepth || int64(len(value.Name.Local)) > globalDynamicMaxStringBytes {
				return nil, fmt.Errorf("DASH XML exceeds its structural limits")
			}
			attributeCount += len(value.Attr)
			if len(value.Attr) > globalDynamicMaxXMLAttributesPerElement || attributeCount > globalDynamicMaxXMLAttributes {
				return nil, fmt.Errorf("DASH XML attribute count exceeds its limit")
			}
			for _, attribute := range value.Attr {
				if int64(len(attribute.Name.Space)) > globalDynamicMaxStringBytes || int64(len(attribute.Name.Local)) > globalDynamicMaxStringBytes || int64(len(attribute.Value)) > globalDynamicMaxStringBytes {
					return nil, fmt.Errorf("DASH XML attribute exceeds its limit")
				}
			}
			node := &dashXMLNode{start: value.Copy()}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("DASH XML has multiple roots")
				}
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.content = append(parent.content, dashXMLContent{node: node})
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("invalid DASH XML nesting")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			copyText := append([]byte(nil), value...)
			if int64(len(copyText)) > globalDynamicMaxStringBytes {
				return nil, fmt.Errorf("DASH XML text exceeds its limit")
			}
			if len(stack) == 0 {
				if len(bytes.TrimSpace(copyText)) != 0 {
					return nil, fmt.Errorf("DASH XML contains text outside its root")
				}
			} else {
				node := stack[len(stack)-1]
				node.content = append(node.content, dashXMLContent{text: copyText})
			}
		case xml.Comment:
			// Comments are not semantically relevant to URL resolution.
		case xml.ProcInst:
			if len(stack) != 0 || !strings.EqualFold(value.Target, "xml") {
				return nil, fmt.Errorf("unsupported DASH processing instruction")
			}
		case xml.Directive:
			return nil, fmt.Errorf("DASH XML directives are not supported")
		}
	}
	if root == nil || len(stack) != 0 || root.start.Name.Local != "MPD" || root.start.Name.Space != "urn:mpeg:dash:schema:mpd:2011" {
		return nil, fmt.Errorf("DASH XML root or namespace is invalid")
	}
	return root, nil
}

func encodeDASHXMLNode(ctx context.Context, encoder *xml.Encoder, node *dashXMLNode, extremeCompatibility bool) error {
	if node == nil {
		return fmt.Errorf("DASH XML node is unavailable")
	}
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("DASH encoding deadline exceeded")
	}
	if extremeCompatibility {
		attributes := node.start.Attr[:0]
		for _, attribute := range node.start.Attr {
			if !dashExtremeCompatibilityNamespaceDeclaration(attribute) || attribute.Name.Space == "" && attribute.Name.Local == "xmlns" && attribute.Value == "" {
				attributes = append(attributes, attribute)
			}
		}
		node.start.Attr = attributes
	}
	if err := encoder.EncodeToken(node.start); err != nil {
		return err
	}
	for _, child := range node.content {
		if child.node != nil {
			if err := encodeDASHXMLNode(ctx, encoder, child.node, extremeCompatibility); err != nil {
				return err
			}
		} else if len(child.text) > 0 {
			if err := encoder.EncodeToken(xml.CharData(child.text)); err != nil {
				return err
			}
		}
	}
	return encoder.EncodeToken(node.start.End())
}

func cloneDASHXMLNode(node *dashXMLNode) *dashXMLNode {
	if node == nil {
		return nil
	}
	clone := &dashXMLNode{start: node.start.Copy(), content: make([]dashXMLContent, len(node.content))}
	for index, child := range node.content {
		if child.node != nil {
			clone.content[index].node = cloneDASHXMLNode(child.node)
		} else {
			clone.content[index].text = append([]byte(nil), child.text...)
		}
	}
	return clone
}

func dashNodeText(node *dashXMLNode) (string, error) {
	if node == nil {
		return "", fmt.Errorf("DASH text node is unavailable")
	}
	var output strings.Builder
	for _, child := range node.content {
		if child.node != nil {
			return "", fmt.Errorf("DASH URL element contains nested XML")
		}
		output.Write(child.text)
	}
	value := strings.TrimSpace(output.String())
	if value == "" || int64(len(value)) > globalDynamicMaxStringBytes {
		return "", fmt.Errorf("DASH URL element is empty or too large")
	}
	return value, nil
}

func setDASHNodeText(node *dashXMLNode, value string) {
	node.content = []dashXMLContent{{text: []byte(value)}}
}

func dashExtremeCompatibilityEnabled(session *dynamicRewriteSession) bool {
	return session != nil && session.issuer != nil && session.issuer.policy.profile == dynamicProfileExtreme
}

func dashAttributeIndex(node *dashXMLNode, local string, extremeCompatibility bool) (int, error) {
	index := -1
	for candidate := range node.start.Attr {
		if node.start.Attr[candidate].Name.Local != local {
			continue
		}
		if node.start.Attr[candidate].Name.Space != "" {
			if extremeCompatibility {
				continue
			}
			return -1, fmt.Errorf("DASH standard attribute uses a foreign namespace")
		}
		if index >= 0 {
			return -1, fmt.Errorf("duplicate DASH attribute")
		}
		index = candidate
	}
	return index, nil
}

func resolveDASHReference(base *url.URL, value string) (*url.URL, error) {
	if base == nil || value == "" || value != strings.TrimSpace(value) || containsDynamicUnsafeRune(value) || strings.Contains(value, `\`) {
		return nil, fmt.Errorf("invalid DASH URL")
	}
	reference, err := url.Parse(value)
	if err != nil || reference.User != nil || reference.Fragment != "" || reference.RawFragment != "" {
		return nil, fmt.Errorf("invalid DASH URL")
	}
	resolved := base.ResolveReference(reference)
	resolved.Scheme = strings.ToLower(resolved.Scheme)
	if resolved.Scheme != "http" && resolved.Scheme != "https" || resolved.Host == "" || resolved.User != nil {
		return nil, fmt.Errorf("unsupported DASH URL")
	}
	return resolved, nil
}

func rewriteDASHReference(value string, base *url.URL, session *dynamicRewriteSession, kind string) (string, *url.URL, error) {
	resolved, err := resolveDASHReference(base, value)
	if err != nil {
		return "", nil, err
	}
	rewritten, err := session.rewriteAgainstKind(value, base, kind)
	return rewritten, resolved, err
}
