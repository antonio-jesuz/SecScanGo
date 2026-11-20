package scanners

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/antonio-jesuz/secscan/internal/domain"
)

func TestTLSScannerFlagsSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := NewTLSScanner().Scan(ctx, domain.Target{Host: srv.Listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	have := ids(got)
	if !have["TLS-001"] {
		t.Errorf("certificado autoassinado deveria gerar TLS-001; vieram %v", have)
	}
	if have["TLS-LEGACY-301"] || have["TLS-LEGACY-302"] {
		t.Error("servidor Go moderno não deveria aceitar TLS 1.0/1.1")
	}
}

func TestTLSScannerNoTLSIsInfoNotError(t *testing.T) {
	got, err := NewTLSScanner().Scan(context.Background(), domain.Target{Host: "127.0.0.1:1"})
	if err != nil {
		t.Fatalf("sem TLS não deve ser erro: %v", err)
	}
	if len(got) != 1 || got[0].ID != "TLS-000" {
		t.Errorf("esperava TLS-000, veio %+v", got)
	}
}
