// Package observability expõe métricas no formato texto do Prometheus (sem dependências).
package observability

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/antonio-jesuz/secscan/internal/domain"
)

type Metrics struct {
	mu       sync.Mutex
	scans    map[string]uint64
	findings map[string]uint64
	durSum   float64
	durCount uint64
}

func NewMetrics() *Metrics {
	return &Metrics{scans: map[string]uint64{}, findings: map[string]uint64{}}
}

// ScanFinished implementa application.Observer.
func (m *Metrics) ScanFinished(d time.Duration, r domain.ScanResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scans[string(r.Status)]++
	for _, f := range r.Findings {
		m.findings[f.Severity.String()]++
	}
	m.durSum += d.Seconds()
	m.durCount++
}

func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintln(w, "# HELP secscan_scans_total Varreduras finalizadas por status.")
		fmt.Fprintln(w, "# TYPE secscan_scans_total counter")
		for _, k := range sortedKeys(m.scans) {
			fmt.Fprintf(w, "secscan_scans_total{status=%q} %d\n", k, m.scans[k])
		}
		fmt.Fprintln(w, "# HELP secscan_findings_total Achados por severidade.")
		fmt.Fprintln(w, "# TYPE secscan_findings_total counter")
		for _, k := range sortedKeys(m.findings) {
			fmt.Fprintf(w, "secscan_findings_total{severity=%q} %d\n", k, m.findings[k])
		}
		fmt.Fprintln(w, "# HELP secscan_scan_duration_seconds Duração das varreduras.")
		fmt.Fprintln(w, "# TYPE secscan_scan_duration_seconds summary")
		fmt.Fprintf(w, "secscan_scan_duration_seconds_sum %f\n", m.durSum)
		fmt.Fprintf(w, "secscan_scan_duration_seconds_count %d\n", m.durCount)
	})
}

func sortedKeys(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
