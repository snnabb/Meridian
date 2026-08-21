package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type shortReadCloser struct {
	data []byte
}

func (r *shortReadCloser) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := 1
	if n > len(p) {
		n = len(p)
	}
	copy(p[:n], r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func (r *shortReadCloser) Close() error { return nil }

type shortResponseWriter struct {
	header http.Header
	buf    bytes.Buffer
}

type shortErrorResponseWriter struct {
	header http.Header
}

func (writer *shortErrorResponseWriter) Header() http.Header { return writer.header }
func (writer *shortErrorResponseWriter) WriteHeader(int)     {}
func (writer *shortErrorResponseWriter) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	return 1, io.ErrUnexpectedEOF
}

func (w *shortResponseWriter) Header() http.Header { return w.header }
func (w *shortResponseWriter) WriteHeader(int)     {}
func (w *shortResponseWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return w.buf.Write(p[:1])
}

func newQuotaForRegressionTest(t *testing.T, quotaBytes int64) *trafficQuotaState {
	t.Helper()
	app := newTestApp(t)
	site, err := app.db.CreateSite("quota-regression", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", quotaBytes, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	return &trafficQuotaState{pm: app.pm, inst: &ProxyInstance{Site: *site}}
}

func TestMeteredReaderDoesNotTreatOrdinaryShortReadAsQuota(t *testing.T) {
	quota := newQuotaForRegressionTest(t, 100)
	reader := &meteredReader{
		ReadCloser: &shortReadCloser{data: []byte("x")},
		quota:      quota,
	}
	buf := make([]byte, 4)
	n, err := reader.Read(buf)
	if n != 1 || err != nil {
		t.Fatalf("short read = (%d, %v), want (1, nil)", n, err)
	}
	quota.mu.Lock()
	usage := quota.usage
	quota.mu.Unlock()
	if usage != 1 {
		t.Fatalf("quota usage after short read = %d, want 1", usage)
	}
}

func TestMeteredWriterDoesNotTreatOrdinaryShortWriteAsQuota(t *testing.T) {
	quota := newQuotaForRegressionTest(t, 100)
	writer := &meteredWriter{
		ResponseWriter: &shortResponseWriter{header: make(http.Header)},
		quota:          quota,
	}
	n, err := writer.Write([]byte("abcd"))
	if n != 1 || err != nil {
		t.Fatalf("short write = (%d, %v), want (1, nil)", n, err)
	}
	quota.mu.Lock()
	usage := quota.usage
	quota.mu.Unlock()
	if usage != 1 {
		t.Fatalf("quota usage after short write = %d, want 1", usage)
	}
}

func TestWriterAdaptersSettleQuotaUsingActualBytes(t *testing.T) {
	tests := []struct {
		name      string
		write     func(*trafficQuotaState) (int, error)
		wantError bool
	}{
		{
			name: "unpaced rate-limited writer",
			write: func(quota *trafficQuotaState) (int, error) {
				writer := &rateLimitedWriter{ResponseWriter: &shortResponseWriter{header: make(http.Header)}, quota: quota}
				return writer.Write([]byte("abcd"))
			},
		},
		{
			name: "paced rate-limited writer",
			write: func(quota *trafficQuotaState) (int, error) {
				writer := &rateLimitedWriter{
					ResponseWriter: &shortErrorResponseWriter{header: make(http.Header)},
					bytesPerSec:    1024,
					quota:          quota,
					start:          time.Now().Add(-time.Second),
				}
				return writer.Write([]byte("abcd"))
			},
			wantError: true,
		},
		{
			name: "unpaced tunnel writer",
			write: func(quota *trafficQuotaState) (int, error) {
				writer := &tunnelWriter{dst: &shortResponseWriter{header: make(http.Header)}, quota: quota}
				return writer.Write([]byte("abcd"))
			},
		},
		{
			name: "paced tunnel writer",
			write: func(quota *trafficQuotaState) (int, error) {
				writer := &tunnelWriter{
					dst:         &shortErrorResponseWriter{header: make(http.Header)},
					bytesPerSec: 1024,
					quota:       quota,
					start:       time.Now().Add(-time.Second),
				}
				return writer.Write([]byte("abcd"))
			},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			quota := newQuotaForRegressionTest(t, 100)
			written, err := test.write(quota)
			if written != 1 {
				t.Fatalf("written = %d, want 1", written)
			}
			if test.wantError && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("error = %v, want io.ErrUnexpectedEOF", err)
			}
			if !test.wantError && err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
			quota.mu.Lock()
			usage := quota.usage
			quota.mu.Unlock()
			if usage != 1 {
				t.Fatalf("quota usage = %d, want 1", usage)
			}
		})
	}
}

func TestPanelListenerSpecsDefaultToLoopback(t *testing.T) {
	specs, err := panelListenerSpecs("", 9090)
	if err != nil || len(specs) != 1 || specs[0].network != "tcp4" || !strings.Contains(specs[0].address, "127.0.0.1") {
		t.Fatalf("default panel listeners = %#v, %v; want loopback tcp4", specs, err)
	}
}

func TestSSERejectsNonGET(t *testing.T) {
	app := newTestApp(t)
	rr := httptest.NewRecorder()
	app.handleSSE(rr, httptest.NewRequest(http.MethodPost, "/api/events", nil))
	if rr.Code != http.StatusMethodNotAllowed || rr.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("SSE POST = status %d allow %q, want 405/GET", rr.Code, rr.Header().Get("Allow"))
	}
}

func TestTelegramReportHTTPClientRejectsRedirects(t *testing.T) {
	if telegramReportHTTPClient == nil || telegramReportHTTPClient.CheckRedirect == nil {
		t.Fatal("Telegram report client must define a redirect policy")
	}
	if err := telegramReportHTTPClient.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy error = %v, want ErrUseLastResponse", err)
	}
}

func TestTelegramAndSystemSettingsJSONRejectUnknownAndTrailingData(t *testing.T) {
	app := newTestApp(t)

	for name, handler := range map[string]func(http.ResponseWriter, *http.Request){
		"telegram": app.handleTelegramReport,
		"system":   app.handleSystemSettings,
	} {
		t.Run(name+" unknown", func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(`{"unknown_field":true}`))
			handler(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("unknown field status = %d, want 400", rr.Code)
			}
		})
		t.Run(name+" trailing", func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(`{} {}`))
			handler(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("trailing JSON status = %d, want 400", rr.Code)
			}
		})
	}
}
