package scanners

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/antonio-jesuz/secscan/internal/domain"
)

func ids(fs []domain.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.ID] = true
	}
	return m
}

func TestHeadersScannerFlagsInsecureServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/7.4")
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "x"})
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := NewHeadersScanner().Scan(ctx, domain.Target{Host: strings.TrimPrefix(srv.URL, "http://")})
	if err != nil {
		t.Fatal(err)
	}
	have := ids(got)
	for _, want := range []string{"HDR-000", "HDR-002", "HDR-007", "HDR-008", "HDR-COOKIE-sid"} {
		if !have[want] {
			t.Errorf("faltou o achado %s; vieram %v", want, have)
		}
	}
}

func TestHeadersScannerHardenedServerHasNoCSPFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=()")
	}))
	defer srv.Close()

	got, err := NewHeadersScanner().Scan(context.Background(), domain.Target{Host: strings.TrimPrefix(srv.URL, "http://")})
	if err != nil {
		t.Fatal(err)
	}
	have := ids(got)
	for _, notWant := range []string{"HDR-002", "HDR-003", "HDR-004", "HDR-005"} {
		if have[notWant] {
			t.Errorf("não deveria ter %s", notWant)
		}
	}
}
