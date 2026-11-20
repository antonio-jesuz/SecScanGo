// Package domain contém as entidades e contratos centrais do SecScan.
// Esta camada NÃO depende de nenhuma outra camada do projeto.
package domain

import (
	"fmt"
	"strings"
)

// Severity classifica o impacto de um achado.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "UNKNOWN"
	}
	return severityNames[s]
}

// MarshalText faz o JSON exibir "HIGH" em vez de 3.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity converte texto (case-insensitive) em Severity.
func ParseSeverity(v string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(n, strings.TrimSpace(v)) {
			return Severity(i), nil
		}
	}
	return SeverityInfo, fmt.Errorf("severidade inválida: %q", v)
}

// UnmarshalText permite reler do banco/JSON o texto "HIGH" como Severity.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}
