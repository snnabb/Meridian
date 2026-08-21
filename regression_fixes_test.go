package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	reader := &meteredReader{
		ReadCloser: &shortReadCloser{data: []byte("x")},
		quota:      newQuotaForRegressionTest(t, 100),
	}
	buf := make([]byte, 4)
	n, err := reader.Read(buf)
	if n != 1 || err != nil {
		t.Fatalf("short read = (%d, %v), want (1, nil)", n, err)
	}
}

func TestMeteredWriterDoesNotTreatOrdinaryShortWriteAsQuota(t *testing.T) {
	writer := &meteredWriter{
		ResponseWriter: &shortResponseWriter{header: make(http.Header)},
		quota:          newQuotaForRegressionTest(t, 100),
	}
	n, err := writer.Write([]byte("abcd"))
	if n != 1 || err != nil {
		t.Fatalf("short write = (%d, %v), want (1, nil)", n, err)
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
