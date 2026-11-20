package scanners

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/antonio-jesuz/secscan/internal/domain"
)

const tlsScanner = "tls-check"

// TLSScanner inspeciona certificado, validade, cadeia e protocolos obsoletos.
type TLSScanner struct {
	Timeout    time.Duration
	ExpiryWarn time.Duration
}

func NewTLSScanner() *TLSScanner {
	return &TLSScanner{Timeout: 5 * time.Second, ExpiryWarn: 30 * 24 * time.Hour}
}

func (s *TLSScanner) Name() string { return tlsScanner }

func (s *TLSScanner) dial(ctx context.Context, addr, serverName string, minV, maxV uint16) (*tls.Conn, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: s.Timeout},
		// InsecureSkipVerify é intencional: queremos INSPECIONAR certificados inválidos.
		// A validação da cadeia é feita manualmente mais abaixo e reportada como achado.
		Config: &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: minV, MaxVersion: maxV}, //nolint:gosec
	}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return c.(*tls.Conn), nil
}

func (s *TLSScanner) Scan(ctx context.Context, t domain.Target) ([]domain.Finding, error) {
	addr := hostWithPort(t.Host, "443")
	host := hostOnly(t.Host)

	var out []domain.Finding
	add := func(sev domain.Severity, id, title, desc, evidence, fix string) {
		out = append(out, domain.Finding{ID: id, Scanner: tlsScanner, Severity: sev,
			Title: title, Description: desc, Evidence: evidence, Remediation: fix})
	}

	conn, err := s.dial(ctx, addr, host, tls.VersionTLS12, tls.VersionTLS13)
	if err != nil {
		add(domain.SeverityInfo, "TLS-000", "TLS não disponível",
			"Não foi possível negociar TLS 1.2+ no endpoint.", err.Error(), "Se o serviço é público, habilite TLS.")
		return out, nil
	}
	state := conn.ConnectionState()
	_ = conn.Close()

	add(domain.SeverityInfo, "TLS-INFO", "Parâmetros TLS negociados", "Protocolo e cipher suite acordados.",
		fmt.Sprintf("%s / %s", tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite)), "")

	if len(state.PeerCertificates) == 0 {
		return out, nil
	}
	leaf := state.PeerCertificates[0]

	opts := x509.VerifyOptions{DNSName: host, Intermediates: x509.NewCertPool()}
	for _, c := range state.PeerCertificates[1:] {
		opts.Intermediates.AddCert(c)
	}
	if _, verr := leaf.Verify(opts); verr != nil {
		var inv x509.CertificateInvalidError
		if !(errors.As(verr, &inv) && inv.Reason == x509.Expired) {
			add(domain.SeverityHigh, "TLS-001", "Certificado não confiável ou inválido para o host",
				"Clientes verão alertas de segurança e ficam suscetíveis a MITM.",
				verr.Error(), "Emita um certificado de uma CA confiável cobrindo o hostname.")
		}
	}

	now := time.Now()
	switch {
	case now.After(leaf.NotAfter):
		add(domain.SeverityHigh, "TLS-002", "Certificado expirado", "O certificado já passou da validade.",
			"expirou em "+leaf.NotAfter.Format(time.RFC3339), "Renove imediatamente e automatize (ACME).")
	case leaf.NotAfter.Sub(now) < s.ExpiryWarn:
		add(domain.SeverityMedium, "TLS-003", "Certificado perto de expirar", "Risco de indisponibilidade iminente.",
			"expira em "+leaf.NotAfter.Format(time.RFC3339), "Renove e automatize a renovação (ACME).")
	}

	if leaf.SignatureAlgorithm == x509.SHA1WithRSA || leaf.SignatureAlgorithm == x509.ECDSAWithSHA1 {
		add(domain.SeverityMedium, "TLS-004", "Certificado assinado com SHA-1", "SHA-1 é considerado quebrado.",
			leaf.SignatureAlgorithm.String(), "Reemita com SHA-256 ou superior.")
	}

	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		if c, derr := s.dial(ctx, addr, host, v, v); derr == nil {
			_ = c.Close()
			add(domain.SeverityHigh, fmt.Sprintf("TLS-LEGACY-%x", v), tls.VersionName(v)+" habilitado",
				"Protocolo obsoleto, vulnerável a ataques como BEAST e POODLE.",
				"handshake concluído com "+tls.VersionName(v), "Desative versões abaixo de TLS 1.2.")
		}
	}
	return out, nil
}
