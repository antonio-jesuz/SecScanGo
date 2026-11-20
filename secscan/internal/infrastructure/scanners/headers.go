package scanners

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/antonio-jesuz/secscan/internal/domain"
)

const headersScanner = "http-headers"

var versionRe = regexp.MustCompile(`\d+\.\d+`)

// HeadersScanner audita cabeçalhos de segurança HTTP e flags de cookies.
type HeadersScanner struct {
	Client *http.Client
}

func NewHeadersScanner() *HeadersScanner {
	return &HeadersScanner{Client: &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}}
}

func (h *HeadersScanner) Name() string { return headersScanner }

func (h *HeadersScanner) Scan(ctx context.Context, t domain.Target) ([]domain.Finding, error) {
	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+t.Host, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "secscan/1.0 (avaliação de segurança autorizada)")
		resp, err := h.Client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		return analyzeHeaders(resp), nil
	}
	return nil, fmt.Errorf("sem resposta HTTP(S): %w", lastErr)
}

func analyzeHeaders(resp *http.Response) []domain.Finding {
	hd := resp.Header
	secure := resp.TLS != nil
	var out []domain.Finding
	add := func(sev domain.Severity, id, title, desc, evidence, fix string) {
		out = append(out, domain.Finding{ID: id, Scanner: headersScanner, Severity: sev,
			Title: title, Description: desc, Evidence: evidence, Remediation: fix})
	}

	if !secure {
		add(domain.SeverityMedium, "HDR-000", "Resposta servida sem TLS",
			"O conteúdo trafega em texto claro e pode ser interceptado ou alterado.",
			"URL final usou HTTP", "Habilite HTTPS e redirecione todo o tráfego HTTP.")
	} else if hd.Get("Strict-Transport-Security") == "" {
		add(domain.SeverityMedium, "HDR-001", "HSTS ausente",
			"Sem Strict-Transport-Security, navegadores podem ser vítimas de downgrade para HTTP.",
			"cabeçalho ausente", "Adicione Strict-Transport-Security: max-age=31536000; includeSubDomains.")
	}

	csp := hd.Get("Content-Security-Policy")
	if csp == "" {
		add(domain.SeverityMedium, "HDR-002", "Content-Security-Policy ausente",
			"CSP reduz drasticamente o impacto de XSS.",
			"cabeçalho ausente", "Defina uma CSP restritiva (default-src 'self').")
	}
	if !strings.EqualFold(hd.Get("X-Content-Type-Options"), "nosniff") {
		add(domain.SeverityLow, "HDR-003", "X-Content-Type-Options ausente",
			"Permite MIME sniffing pelo navegador.",
			"cabeçalho ausente ou inválido", "Adicione X-Content-Type-Options: nosniff.")
	}
	if hd.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		add(domain.SeverityMedium, "HDR-004", "Sem proteção contra clickjacking",
			"A página pode ser embutida em iframes de terceiros.",
			"X-Frame-Options e CSP frame-ancestors ausentes", "Use X-Frame-Options: DENY ou CSP frame-ancestors 'none'.")
	}
	if hd.Get("Referrer-Policy") == "" {
		add(domain.SeverityLow, "HDR-005", "Referrer-Policy ausente",
			"URLs completas podem vazar em cabeçalhos Referer.",
			"cabeçalho ausente", "Adicione Referrer-Policy: strict-origin-when-cross-origin.")
	}
	if hd.Get("Permissions-Policy") == "" {
		add(domain.SeverityInfo, "HDR-006", "Permissions-Policy ausente",
			"Recursos do navegador (câmera, geolocalização) não são restringidos.",
			"cabeçalho ausente", "Defina Permissions-Policy com apenas o necessário.")
	}

	if v := hd.Get("Server"); versionRe.MatchString(v) {
		add(domain.SeverityLow, "HDR-007", "Versão de software exposta no cabeçalho Server",
			"Facilita a busca por CVEs específicos da versão.",
			"Server: "+v, "Oculte versões (ex.: server_tokens off).")
	}
	if v := hd.Get("X-Powered-By"); v != "" {
		add(domain.SeverityLow, "HDR-008", "Tecnologia exposta em X-Powered-By",
			"Revela a stack e ajuda reconhecimento do atacante.",
			"X-Powered-By: "+v, "Remova o cabeçalho.")
	}

	for _, c := range resp.Cookies() {
		var issues []string
		if secure && !c.Secure {
			issues = append(issues, "sem Secure")
		}
		if !c.HttpOnly {
			issues = append(issues, "sem HttpOnly")
		}
		if c.SameSite == 0 {
			issues = append(issues, "sem SameSite")
		}
		if len(issues) > 0 {
			add(domain.SeverityMedium, "HDR-COOKIE-"+c.Name, "Cookie "+c.Name+" com flags inseguras",
				"Cookies sem flags adequadas ficam expostos a XSS, CSRF e interceptação.",
				strings.Join(issues, ", "), "Defina Secure; HttpOnly; SameSite=Lax (ou Strict).")
		}
	}
	return out
}
