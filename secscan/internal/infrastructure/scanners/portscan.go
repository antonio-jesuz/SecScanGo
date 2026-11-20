package scanners

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/antonio-jesuz/secscan/internal/domain"
)

type portRisk struct {
	Service  string
	Severity domain.Severity
	Why      string
	Fix      string
}

var riskyPorts = map[int]portRisk{
	21:    {"FTP", domain.SeverityMedium, "FTP transmite credenciais em texto claro.", "Troque por SFTP/FTPS ou restrinja por firewall."},
	22:    {"SSH", domain.SeverityInfo, "Serviço de administração remota exposto.", "Use chaves, desative login por senha e limite origens."},
	23:    {"Telnet", domain.SeverityHigh, "Telnet não tem criptografia e é alvo comum de botnets.", "Desative e use SSH."},
	25:    {"SMTP", domain.SeverityInfo, "Servidor de e-mail exposto.", "Garanta que não é open relay e exija STARTTLS."},
	53:    {"DNS", domain.SeverityInfo, "Servidor DNS exposto.", "Desative recursão aberta e transferências de zona."},
	80:    {"HTTP", domain.SeverityInfo, "Serviço web sem TLS.", "Redirecione para HTTPS."},
	110:   {"POP3", domain.SeverityLow, "POP3 em texto claro.", "Use POP3S ou migre para IMAPS."},
	143:   {"IMAP", domain.SeverityLow, "IMAP em texto claro.", "Use IMAPS (993)."},
	443:   {"HTTPS", domain.SeverityInfo, "Serviço web com TLS.", "Valide configuração TLS e cabeçalhos."},
	445:   {"SMB", domain.SeverityHigh, "SMB exposto é vetor clássico de ransomware.", "Bloqueie na borda; nunca exponha à internet."},
	3306:  {"MySQL", domain.SeverityHigh, "Banco de dados acessível pela rede.", "Restrinja a redes internas/VPN."},
	3389:  {"RDP", domain.SeverityHigh, "RDP exposto é alvo frequente de força bruta.", "Use VPN/gateway com MFA."},
	5432:  {"PostgreSQL", domain.SeverityHigh, "Banco de dados acessível pela rede.", "Restrinja a redes internas/VPN."},
	5900:  {"VNC", domain.SeverityHigh, "VNC costuma ter autenticação fraca.", "Tunele via SSH/VPN."},
	6379:  {"Redis", domain.SeverityHigh, "Redis sem autenticação permite execução remota em muitos casos.", "Bind em localhost/rede interna e exija senha/ACL."},
	8080:  {"HTTP-alt", domain.SeverityInfo, "Serviço web alternativo (painéis, proxies).", "Confirme se deveria ser público."},
	8443:  {"HTTPS-alt", domain.SeverityInfo, "Serviço HTTPS alternativo.", "Confirme se deveria ser público."},
	9200:  {"Elasticsearch", domain.SeverityHigh, "API do Elasticsearch costuma vazar dados sem auth.", "Habilite segurança e restrinja a rede."},
	11211: {"Memcached", domain.SeverityHigh, "Memcached exposto permite vazamento e amplificação DDoS.", "Bind interno e desative UDP."},
	27017: {"MongoDB", domain.SeverityHigh, "MongoDB exposto sem auth é incidente recorrente.", "Habilite auth e restrinja a rede."},
}

// PortScanner faz varredura TCP concorrente (worker pool) com leitura passiva de banner.
type PortScanner struct {
	Timeout time.Duration
	Workers int
}

func NewPortScanner() *PortScanner {
	return &PortScanner{Timeout: 1500 * time.Millisecond, Workers: 100}
}

func (p *PortScanner) Name() string { return "port-scan" }

func (p *PortScanner) Scan(ctx context.Context, t domain.Target) ([]domain.Finding, error) {
	host := hostOnly(t.Host)
	ports := t.Ports
	if len(ports) == 0 {
		ports = domain.DefaultPorts
	}
	workers := p.Workers
	if workers <= 0 {
		workers = 50
	}

	jobs := make(chan int)
	results := make(chan domain.Finding)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				if f, ok := p.probe(ctx, host, port); ok {
					select {
					case results <- f:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, port := range ports {
			select {
			case jobs <- port:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	var findings []domain.Finding
	for f := range results {
		findings = append(findings, f)
	}
	return findings, ctx.Err()
}

func (p *PortScanner) probe(ctx context.Context, host string, port int) (domain.Finding, bool) {
	d := net.Dialer{Timeout: p.Timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return domain.Finding{}, false
	}
	defer conn.Close()

	banner := grabBanner(conn)

	risk, known := riskyPorts[port]
	if !known {
		risk = portRisk{Service: "desconhecido", Severity: domain.SeverityInfo,
			Why: "Porta TCP aberta fora da lista de serviços conhecidos.", Fix: "Confirme se o serviço precisa estar exposto."}
	}
	evidence := fmt.Sprintf("%s:%d/tcp aceitou conexão", host, port)
	if banner != "" {
		evidence += "; banner: " + banner
	}
	return domain.Finding{
		ID:          fmt.Sprintf("PORT-%d", port),
		Scanner:     "port-scan",
		Title:       fmt.Sprintf("Porta %d/tcp aberta (%s)", port, risk.Service),
		Description: risk.Why,
		Severity:    risk.Severity,
		Evidence:    evidence,
		Remediation: risk.Fix,
	}, true
}

// grabBanner lê passivamente (sem enviar dados) o que o serviço anuncia, ex.: SSH.
func grabBanner(conn net.Conn) string {
	_ = conn.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	clean := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, string(buf[:n]))
	return strings.TrimSpace(clean)
}
