package main

import "strings"

type systemUpdateRequest struct {
	Version string `json:"version"`
	// Accept the former stable selector for older clients, but never beta.
	Channel string `json:"channel,omitempty"`
	Action  string `json:"action,omitempty"`
}

func (r *systemUpdateRequest) normalize() bool {
	if r.Channel != "" && r.Channel != "stable" {
		return false
	}
	if r.Action == "" {
		r.Action = "update"
	}
	if r.Action == "rollback" {
		return r.Version == ""
	}
	return r.Action == "update" && strings.HasPrefix(r.Version, "v") && stableVersionPattern.MatchString(r.Version)
}
