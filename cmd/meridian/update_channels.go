package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var channelVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-beta\.([1-9][0-9]*))?$`)

func validUpdateChannel(channel string) bool { return channel == "stable" || channel == "beta" }
func versionForChannel(version, channel string) bool {
	return validUpdateChannel(channel) && channelVersionPattern.MatchString(version) && (channel == "beta" || !strings.Contains(version, "-"))
}
func channelVersionNewer(candidate, current string) bool {
	a, b := channelVersionPattern.FindStringSubmatch(candidate), channelVersionPattern.FindStringSubmatch(current)
	if a == nil {
		return false
	}
	if b == nil {
		return versionNewer(strings.Split(candidate, "-")[0], current)
	}
	for i := 1; i <= 3; i++ {
		av, ae := strconv.ParseUint(a[i], 10, 64)
		bv, be := strconv.ParseUint(b[i], 10, 64)
		if ae != nil || be != nil {
			return false
		}
		if av != bv {
			return av > bv
		}
	}
	if a[4] == "" {
		return b[4] != ""
	}
	if b[4] == "" {
		return false
	}
	av, ae := strconv.ParseUint(a[4], 10, 64)
	bv, be := strconv.ParseUint(b[4], 10, 64)
	return ae == nil && be == nil && av > bv
}
func fetchChannelRelease(ctx context.Context, client *http.Client, endpoint, current, channel string) (updateRelease, error) {
	if !validUpdateChannel(channel) {
		return updateRelease{}, errors.New("无效更新通道")
	}
	if channel == "stable" {
		release, err := fetchUpdateRelease(ctx, client, endpoint, current)
		release.Channel = channel
		release.Available = channelVersionNewer(release.Latest, current)
		return release, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return updateRelease{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Meridian/"+appVersion)
	resp, err := client.Do(req)
	if err != nil {
		return updateRelease{}, errors.New("无法连接 GitHub")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return updateRelease{}, fmt.Errorf("GitHub 版本检查返回 HTTP %d", resp.StatusCode)
	}
	var releases []struct {
		Tag        string `json:"tag_name"`
		Body       string `json:"body"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil || len(data) > 4<<20 || json.Unmarshal(data, &releases) != nil {
		return updateRelease{}, errors.New("版本信息无效")
	}
	result := updateRelease{Current: current, Channel: channel}
	for _, release := range releases {
		if release.Draft || !versionForChannel(release.Tag, channel) || release.Prerelease != strings.Contains(release.Tag, "-beta.") {
			continue
		}
		assets := map[string]bool{}
		for _, asset := range release.Assets {
			assets[asset.Name] = true
		}
		if !assets["SHA256SUMS"] || !assets["SHA256SUMS.bundle"] {
			continue
		}
		if result.Latest != "" && !channelVersionNewer(release.Tag, result.Latest) {
			continue
		}
		result.Latest = release.Tag
		result.Notes = release.Body
	}
	if result.Latest == "" {
		return result, errors.New("测试通道暂无已打包并签名的版本")
	}
	result.URL = "https://github.com/snnabb/Meridian/releases/tag/" + result.Latest
	result.Available = channelVersionNewer(result.Latest, current)
	return result, nil
}

type systemUpdateRequest struct {
	Version string `json:"version"`
	Channel string `json:"channel,omitempty"`
	Action  string `json:"action,omitempty"`
}

func (r *systemUpdateRequest) normalize() bool {
	if r.Channel == "" {
		r.Channel = "stable"
	}
	if r.Action == "" {
		r.Action = "update"
	}
	if r.Action == "rollback" {
		return r.Version == "" && validUpdateChannel(r.Channel)
	}
	return r.Action == "update" && versionForChannel(r.Version, r.Channel)
}
