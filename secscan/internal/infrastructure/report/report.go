// Package report renderiza ScanResult em vários formatos.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/antonio-jesuz/secscan/internal/domain"
)

var severityOrder = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

func Supported(format string) bool {
	switch format {
	case "json", "markdown", "text":
		return true
	}
	return false
}

func Write(w io.Writer, format string, r domain.ScanResult) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "markdown":
		return writeMarkdown(w, r)
	case "text":
		return writeText(w, r)
	}
	return fmt.Errorf("formato desconhecido: %q (use text, json ou markdown)", format)
}

func summaryLine(r domain.ScanResult) string {
	s := r.Summary()
	parts := make([]string, 0, len(severityOrder))
	for _, n := range severityOrder {
		parts = append(parts, fmt.Sprintf("%s=%d", n, s[n]))
	}
	return strings.Join(parts, "  ")
}

func writeText(w io.Writer, r domain.ScanResult) error {
	fmt.Fprintf(w, "SecScan | alvo: %s | status: %s | id: %s\n", r.Target.Host, r.Status, r.ID)
	fmt.Fprintf(w, "Resumo: %s\n\n", summaryLine(r))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERIDADE\tID\tTÍTULO")
	for _, f := range r.Findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", f.Severity, f.ID, f.Title)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, e := range r.Errors {
		fmt.Fprintf(w, "\n[aviso] %s\n", e)
	}
	return nil
}

func writeMarkdown(w io.Writer, r domain.ScanResult) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Relatório SecScan\n\n")
	fmt.Fprintf(&b, "- **Alvo:** `%s`\n- **ID:** `%s`\n- **Status:** %s\n- **Início:** %s\n",
		r.Target.Host, r.ID, r.Status, r.StartedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "- **Resumo:** %s\n\n## Achados\n\n", summaryLine(r))
	if len(r.Findings) == 0 {
		b.WriteString("Nenhum achado.\n")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "### [%s] %s (`%s`)\n\n%s\n\n", f.Severity, f.Title, f.ID, f.Description)
		if f.Evidence != "" {
			fmt.Fprintf(&b, "**Evidência:** `%s`\n\n", f.Evidence)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "**Correção:** %s\n\n", f.Remediation)
		}
	}
	if len(r.Errors) > 0 {
		b.WriteString("## Avisos\n\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "- %s\n", e)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
