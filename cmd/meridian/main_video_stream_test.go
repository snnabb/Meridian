package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMainVideoStreamRequestClassification(t *testing.T) {
	tests := []struct {
		name   string
		method string
		target string
		want   bool
	}{
		{"mp4", http.MethodGet, "/media/movie.mp4", true},
		{"mixed-case mkv", http.MethodHead, "/media/Movie.MKV", true},
		{"video stream", http.MethodGet, "/Videos/1/stream", true},
		{"video stream opaque extension", http.MethodGet, "/Videos/1/stream.bin", true},
		{"emby original", http.MethodGet, "/emby/Videos/1/original", true},
		{"video download", http.MethodGet, "/Videos/1/download", true},
		{"item download", http.MethodGet, "/Items/1/download", true},
		{"static query", http.MethodGet, "/Videos/1?Static=true", true},
		{"hls manifest", http.MethodGet, "/Videos/1/stream.m3u8", false},
		{"dash manifest", http.MethodGet, "/Videos/1/manifest.mpd", false},
		{"hls segment", http.MethodGet, "/media/segment.ts", false},
		{"subtitle", http.MethodGet, "/Videos/1/Subtitles/2/Stream.ass", false},
		{"image", http.MethodGet, "/Items/1/Images/Primary.jpg", false},
		{"static asset", http.MethodGet, "/web/app.js", false},
		{"playback info", http.MethodGet, "/Items/1/PlaybackInfo", false},
		{"ordinary api", http.MethodGet, "/System/Info/Public", false},
		{"post video", http.MethodPost, "/Videos/1/stream", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(test.method, "http://meridian.example"+test.target, nil)
			if got := isMainVideoStreamRequest(r); got != test.want {
				t.Fatalf("isMainVideoStreamRequest(%s %s) = %v, want %v", test.method, test.target, got, test.want)
			}
		})
	}
}

func TestMainVideoDirectModeRedirectsOnlyMainVideo(t *testing.T) {
	app := newTestApp(t)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		if r.URL.Path == "/base/Videos/1/stream.mkv" {
			if r.Header.Get("Range") != "bytes=0-1" || r.Header.Get("X-Emby-Token") != "client-token" {
				t.Errorf("direct probe headers = %#v", r.Header)
			}
			w.Header().Set("Content-Range", "bytes 0-1/10")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = io.WriteString(w, "video-body-must-not-cross")
			return
		}
		_, _ = io.WriteString(w, "proxied:"+r.URL.Path)
	}))
	defer upstream.Close()

	port := freePort(t)
	site, err := app.db.CreateSiteRecord(Site{
		Name:                "main-video-direct",
		ListenPort:          port,
		IngressMode:         ingressModePort,
		TargetURL:           upstream.URL + "/base?origin_secret=must-not-leak",
		PlaybackMode:        "direct",
		MainVideoStreamMode: mainVideoStreamModeDirect,
		StreamHosts:         "[]",
		UAMode:              passthroughUAMode,
	})
	if err != nil {
		t.Fatalf("create direct site: %v", err)
	}
	releasePort(port)
	if err := app.pm.StartSite(*site); err != nil {
		t.Fatalf("start direct site: %v", err)
	}
	t.Cleanup(func() { _ = app.pm.StopSite(site.ID) })

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	req, err := http.NewRequest(http.MethodGet, baseURL+"/Videos/1/stream.mkv?api_key=client-visible", nil)
	if err != nil {
		t.Fatalf("build direct main video request: %v", err)
	}
	req.Header.Set("Range", "bytes=0-1")
	req.Header.Set("X-Emby-Token", "client-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request direct main video: %v", err)
	}
	_ = resp.Body.Close()
	location := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusTemporaryRedirect || !strings.HasSuffix(location, "/base/Videos/1/stream.mkv?api_key=client-visible") || strings.Contains(location, "origin_secret") {
		t.Fatalf("direct response status=%d Location=%q", resp.StatusCode, location)
	}
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("direct main video probe reached upstream %d times, want 1", got)
	}

	for _, path := range []string{"/media/segment.ts", "/Videos/1/Subtitles/2/Stream.ass", "/System/Info/Public"} {
		resp, err = client.Get(baseURL + path)
		if err != nil {
			t.Fatalf("request proxied path %s: %v", path, err)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "proxied:") {
			t.Fatalf("proxied path %s status=%d read=%v body=%q", path, resp.StatusCode, readErr, body)
		}
	}
	if got := upstreamHits.Load(); got != 4 {
		t.Fatalf("total upstream hits = %d, want 4", got)
	}
}

func TestMainVideoDirectTransportFallsBackWithoutProxyingOriginBody(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusPartialContent, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			body := &redirectRuntimeCloseSpy{Reader: strings.NewReader("origin-video-body")}
			fallback, err := url.Parse("https://origin.example.net/Videos/42/stream.mkv?api_key=client-visible")
			if err != nil {
				t.Fatalf("parse fallback: %v", err)
			}
			transport := &redirectFollowTransport{
				base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: make(http.Header), Body: body, Request: req}, nil
				}),
				mainVideoDirect: true,
				dynamicPolicy:   redirectRuntimePolicy(dynamicProfileCompatible, true),
			}
			req := httptest.NewRequest(http.MethodGet, "https://origin.example.net/Videos/42/stream.mkv", nil)
			req = req.WithContext(context.WithValue(req.Context(), mainVideoDirectFallbackContextKey{}, fallback))
			resp, roundTripErr := transport.RoundTrip(req)
			if roundTripErr != nil {
				t.Fatalf("direct fallback round trip: %v", roundTripErr)
			}
			if resp.StatusCode != http.StatusTemporaryRedirect || resp.Header.Get("Location") != fallback.String() || !body.closed.Load() {
				t.Fatalf("fallback response status/location/bodyClosed=%d/%q/%t", resp.StatusCode, resp.Header.Get("Location"), body.closed.Load())
			}
		})
	}
}

func TestMainVideoDirectTransportFallsBackWhenOriginProbeFails(t *testing.T) {
	fallback, err := url.Parse("https://origin.example.net/Videos/42/stream.mkv")
	if err != nil {
		t.Fatalf("parse fallback: %v", err)
	}
	transport := &redirectFollowTransport{
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("origin unavailable")
		}),
		mainVideoDirect: true,
	}
	req := httptest.NewRequest(http.MethodGet, fallback.String(), nil)
	req = req.WithContext(context.WithValue(req.Context(), mainVideoDirectFallbackContextKey{}, fallback))
	resp, roundTripErr := transport.RoundTrip(req)
	if roundTripErr != nil || resp == nil || resp.StatusCode != http.StatusTemporaryRedirect || resp.Header.Get("Location") != fallback.String() {
		t.Fatalf("probe failure fallback response/error = %#v/%v", resp, roundTripErr)
	}
}

func TestMainVideoStreamModeDefaultsToProxyAndRejectsUnknownValues(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSiteRecord(Site{
		Name:         "main-video-default",
		ListenPort:   freePort(t),
		IngressMode:  ingressModePort,
		TargetURL:    "http://127.0.0.1:8096",
		PlaybackMode: "direct",
		StreamHosts:  "[]",
		UAMode:       passthroughUAMode,
	})
	if err != nil {
		t.Fatalf("create default site: %v", err)
	}
	if site.MainVideoStreamMode != mainVideoStreamModeProxy {
		t.Fatalf("default main_video_stream_mode = %q, want proxy", site.MainVideoStreamMode)
	}

	invalid := *site
	invalid.MainVideoStreamMode = "automatic"
	if err := app.db.UpdateSiteRecord(invalid); err == nil || !strings.Contains(err.Error(), "main_video_stream_mode") {
		t.Fatalf("unknown mode error = %v", err)
	}
}
