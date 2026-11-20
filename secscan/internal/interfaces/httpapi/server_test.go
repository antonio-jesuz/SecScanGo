package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/antonio-jesuz/secscan/internal/application"
	"github.com/antonio-jesuz/secscan/internal/domain"
	"github.com/antonio-jesuz/secscan/internal/infrastructure/observability"
	"github.com/antonio-jesuz/secscan/internal/infrastructure/storage"
)

func newTestServer(apiKey string) http.Handler {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo := storage.NewMemoryRepository()
	m := observability.NewMetrics()
	svc := application.NewService([]domain.Scanner{}, repo, application.TargetPolicy{}, log, time.Second, m)
	return New(svc, repo, log, apiKey, m.Handler()).Handler()
}

func TestAuthRequiredWhenKeyConfigured(t *testing.T) {
	h := newTestServer("secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/scans", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("sem key: %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/v1/scans", nil)
	req.Header.Set("X-API-Key", "secret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("com key: %d", rec.Code)
	}
}

func TestCreateScanBlocksLoopback(t *testing.T) {
	h := newTestServer("")
	req := httptest.NewRequest("POST", "/v1/scans", strings.NewReader(`{"host":"127.0.0.1"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("esperava 403 (SSRF guard), veio %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHealthAndNotFound(t *testing.T) {
	h := newTestServer("")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("healthz: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/scans/nao-existe", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("get inexistente: %d", rec.Code)
	}
}
