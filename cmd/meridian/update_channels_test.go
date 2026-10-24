package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChannelReleaseOrderingAndFiltering(t *testing.T) {
	for _, row := range []struct {
		a, b string
		want bool
	}{
		{"v1.15.0-beta.2", "v1.15.0-beta.1", true}, {"v1.15.0-beta.10", "v1.15.0-beta.2", true},
		{"v1.15.0", "v1.15.0-beta.10", true}, {"v1.15.0-beta.1", "v1.15.0", false},
		{"v1.14.9", "v1.15.0-beta.1", false}, {"v1.15.0-beta.1;id", "v1.14.2", false},
	} {
		if got := channelVersionNewer(row.a, row.b); got != row.want {
			t.Errorf("%s > %s = %v", row.a, row.b, got)
		}
	}
	assets := []map[string]string{{"name": "SHA256SUMS"}, {"name": "SHA256SUMS.bundle"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"tag_name": "v99.0.0-beta.1", "prerelease": true, "draft": true, "assets": assets},
			{"tag_name": "v98.0.0-beta.1", "prerelease": true},
			{"tag_name": "v1.15.0-beta.2", "prerelease": true, "assets": assets},
			{"tag_name": "v1.15.0-beta.10", "prerelease": true, "assets": assets},
			{"tag_name": "v1.14.2", "assets": assets},
		})
	}))
	defer server.Close()
	got, err := fetchChannelRelease(context.Background(), server.Client(), server.URL, "v1.14.2", "beta")
	if err != nil || got.Latest != "v1.15.0-beta.10" || !got.Available {
		t.Fatalf("%+v %v", got, err)
	}
}
func TestUpdateRequestChannelBoundaries(t *testing.T) {
	for _, row := range []struct {
		request systemUpdateRequest
		valid   bool
	}{
		{systemUpdateRequest{Version: "v1.15.0-beta.1"}, false},
		{systemUpdateRequest{Version: "v1.15.0-beta.1", Channel: "beta"}, true},
		{systemUpdateRequest{Version: "v1.15.0", Channel: "unknown"}, false},
		{systemUpdateRequest{Action: "rollback"}, true},
		{systemUpdateRequest{Action: "rollback", Version: "v1.14.2"}, false},
		{systemUpdateRequest{Version: "../../bad", Channel: "beta"}, false},
	} {
		if got := row.request.normalize(); got != row.valid {
			t.Errorf("%+v: %v", row.request, got)
		}
	}
}
