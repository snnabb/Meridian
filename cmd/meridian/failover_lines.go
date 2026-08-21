package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// FailoverLine stores presentation metadata separately from the legacy list of
// enabled failover targets. Keeping both representations preserves old backups
// and API clients while allowing disabled lines to remain editable.
type FailoverLine struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

func normalizePrimaryLineName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "主线路"
	}
	if len([]rune(name)) > 100 {
		return "", errors.New("primary line name is too long")
	}
	return name, nil
}

func normalizeFailoverLines(primary string, lines []FailoverLine, legacy []string) ([]FailoverLine, []string, error) {
	if len(lines) == 0 && len(legacy) > 0 {
		lines = make([]FailoverLine, 0, len(legacy))
		for i, target := range legacy {
			lines = append(lines, FailoverLine{Name: fmt.Sprintf("线路%d", i+2), URL: target, Enabled: true})
		}
	}
	if len(lines) > maxFailoverTargets-1 {
		return nil, nil, errors.New("failover_lines must contain at most 7 backup lines")
	}

	normalized := make([]FailoverLine, 0, len(lines))
	enabledTargets := make([]string, 0, len(lines))
	for i, line := range lines {
		line.Name = strings.TrimSpace(line.Name)
		line.URL = strings.TrimSpace(line.URL)
		if line.Name == "" {
			line.Name = fmt.Sprintf("线路%d", i+2)
		}
		if len([]rune(line.Name)) > 100 {
			return nil, nil, errors.New("failover line name is too long")
		}
		if line.URL == "" {
			return nil, nil, errors.New("failover line URL is required")
		}
		if _, err := normalizeTargetURL(line.URL); err != nil {
			return nil, nil, fmt.Errorf("invalid failover line %q: %w", line.Name, err)
		}
		normalized = append(normalized, line)
		if line.Enabled {
			enabledTargets = append(enabledTargets, line.URL)
		}
	}
	if _, err := parseFailoverTargets(primary, enabledTargets); err != nil {
		return nil, nil, err
	}
	return normalized, enabledTargets, nil
}

func decodeStoredFailoverLines(raw string, primary string, legacy []string) ([]FailoverLine, []string, error) {
	var lines []FailoverLine
	trimmed := strings.TrimSpace(raw)
	if trimmed != "" && trimmed != "[]" {
		if err := json.Unmarshal([]byte(trimmed), &lines); err != nil {
			return nil, nil, fmt.Errorf("invalid stored failover_lines: %w", err)
		}
	}
	return normalizeFailoverLines(primary, lines, legacy)
}
