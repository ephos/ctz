package hints

import (
	"testing"

	"ctz/internal/model"
)

func TestSortedAndExposure(t *testing.T) {
	var c Collector
	c.Exposure("b.example.com", []int{3389, 22, 80})
	c.Exposure("a.example.com", []int{22})
	got := c.Sorted()
	if len(got) != 3 {
		t.Fatalf("want 3 hints, got %d", len(got))
	}
	if got[0].SeverityHint != "high" || got[1].Target != "a.example.com" || got[2].Target != "b.example.com" {
		t.Errorf("unexpected order: %+v", got)
	}
}

func TestNucleiAndZapThresholds(t *testing.T) {
	var c Collector
	p := "443"
	c.Nuclei([]model.NucleiFinding{
		{Severity: "info", Name: "x"},
		{Severity: "high", Name: "Bad", MatchedAt: "https://h", Port: &p},
	})
	c.Zap([]model.ZapAlert{{Risk: "Informational", Target: "t"}, {Risk: "Medium (High)", Target: "t", Alert: "A"}})
	got := c.Sorted()
	if len(got) != 2 {
		t.Fatalf("want 2 hints, got %d: %+v", len(got), got)
	}
	if got[0].Port == nil || *got[0].Port != 443 {
		t.Errorf("nuclei port not parsed: %+v", got[0])
	}
	if ZapSeverity("Medium (Medium)") != "medium" || ZapSeverity(nil) != "info" {
		t.Error("ZapSeverity mapping wrong")
	}
}

func TestTLS(t *testing.T) {
	var c Collector
	d := 5
	c.TLS("h", []model.TLSCertificate{
		{Ports: []int{443}, Expired: true},
		{Ports: []int{8443}, ExpiresSoon: true, DaysUntilExpiration: &d},
		{Ports: []int{9443}},
	})
	if got := c.Sorted(); len(got) != 2 {
		t.Errorf("want 2, got %d", len(got))
	}
}
