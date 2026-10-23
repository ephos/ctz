package nuclei

import "testing"

func TestParseDedupesAndReportsBadLines(t *testing.T) {
	line := `{"template-id":"t1","info":{"name":"Thing","severity":"high"},"matched-at":"https://h","host":"h","port":443,"type":"http"}`
	findings, errs := Parse([]string{line, line, "", "garbage"})
	if len(findings) != 1 || len(errs) != 1 {
		t.Fatalf("findings=%d errs=%v", len(findings), errs)
	}
	f := findings[0]
	if f.TemplateID != "t1" || f.Name != "Thing" || f.Severity != "high" || f.Port == nil || *f.Port != "443" {
		t.Errorf("normalized wrong: %+v", f)
	}
	if f.Raw["host"] != "h" {
		t.Error("raw not preserved")
	}
}
