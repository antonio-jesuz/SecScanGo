package domain

import (
	"context"
	"errors"
	"time"
)

// Finding é um achado de segurança produzido por um Scanner.
type Finding struct {
	ID          string   `json:"id"`
	Scanner     string   `json:"scanner"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// Target descreve o alvo de uma varredura.
type Target struct {
	Host  string `json:"host"`
	Ports []int  `json:"ports,omitempty"`
}

// DefaultPorts são as portas verificadas quando nenhuma é informada.
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389,
	5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017,
}

type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

// ScanResult é o agregado raiz: uma execução completa de varredura.
type ScanResult struct {
	ID         string     `json:"id"`
	Target     Target     `json:"target"`
	Status     Status     `json:"status"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Findings   []Finding  `json:"findings"`
	Errors     []string   `json:"errors,omitempty"`
}

// Summary conta achados por severidade.
func (r ScanResult) Summary() map[string]int {
	out := make(map[string]int, len(severityNames))
	for _, n := range severityNames {
		out[n] = 0
	}
	for _, f := range r.Findings {
		out[f.Severity.String()]++
	}
	return out
}

// MaxSeverity devolve a maior severidade encontrada (false se não houver achados).
func (r ScanResult) MaxSeverity() (Severity, bool) {
	if len(r.Findings) == 0 {
		return SeverityInfo, false
	}
	highest := r.Findings[0].Severity
	for _, f := range r.Findings[1:] {
		if f.Severity > highest {
			highest = f.Severity
		}
	}
	return highest, true
}

// Scanner é a porta (contrato) que todo módulo de varredura implementa.
// Novos scanners são plugados sem alterar o núcleo da aplicação (Open/Closed).
type Scanner interface {
	Name() string
	Scan(ctx context.Context, t Target) ([]Finding, error)
}

// ErrNotFound é devolvido quando uma varredura não existe.
var ErrNotFound = errors.New("varredura não encontrada")

// ErrLeaseLost indica que o worker perdeu a posse do job (lease expirou e outro worker assumiu).
var ErrLeaseLost = errors.New("lease do job perdido")

// ScanRepository é a porta de persistência.
type ScanRepository interface {
	Save(ctx context.Context, r ScanResult) error
	Get(ctx context.Context, id string) (ScanResult, error)
	List(ctx context.Context) ([]ScanResult, error)
}
