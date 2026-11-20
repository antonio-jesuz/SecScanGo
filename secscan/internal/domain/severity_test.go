package domain

import "testing"

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"info": SeverityInfo, "HIGH": SeverityHigh, " Medium ": SeverityMedium} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v; quer %v", in, got, err, want)
		}
	}
	if _, err := ParseSeverity("banana"); err == nil {
		t.Error("esperava erro para severidade inválida")
	}
}

func TestMaxSeverityAndSummary(t *testing.T) {
	r := ScanResult{Findings: []Finding{{Severity: SeverityLow}, {Severity: SeverityHigh}, {Severity: SeverityHigh}}}
	if m, ok := r.MaxSeverity(); !ok || m != SeverityHigh {
		t.Errorf("MaxSeverity = %v, %v", m, ok)
	}
	if r.Summary()["HIGH"] != 2 {
		t.Errorf("Summary HIGH = %d", r.Summary()["HIGH"])
	}
	if _, ok := (ScanResult{}).MaxSeverity(); ok {
		t.Error("sem achados deveria retornar ok=false")
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	var s Severity
	if err := s.UnmarshalText([]byte("CRITICAL")); err != nil || s != SeverityCritical {
		t.Errorf("UnmarshalText = %v, %v", s, err)
	}
}
