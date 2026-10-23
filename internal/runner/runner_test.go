package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"ctz/internal/config"
	"ctz/internal/execx"
	"ctz/internal/report"
)

// fakeExec stands in for subfinder, nmap, nuclei and friends.
func fakeExec(port string) execx.Runner {
	return func(ctx context.Context, name string, args ...string) (execx.Result, error) {
		flag := func(f string) string {
			for i, a := range args {
				if a == f && i+1 < len(args) {
					return args[i+1]
				}
			}
			return ""
		}
		switch name {
		case "subfinder":
			return execx.Result{}, os.WriteFile(flag("-o"), []byte("localhost\nunrelated.example.org\n"), 0o600)
		case "nmap":
			xml := fmt.Sprintf(`<nmaprun><host><ports><port protocol="tcp" portid="%s"><state state="open"/><service name="http" product="Go" version="1"/></port></ports></host></nmaprun>`, port)
			return execx.Result{}, os.WriteFile(flag("-oX"), []byte(xml), 0o600)
		case "nuclei":
			line := `{"template-id":"t1","info":{"name":"Thing","severity":"high"},"matched-at":"http://localhost","host":"localhost","port":80,"type":"http"}`
			return execx.Result{}, os.WriteFile(flag("-o"), []byte(line+"\n"+line+"\nnot json\n"), 0o600)
		}
		return execx.Result{}, fmt.Errorf("unexpected command %s", name)
	}
}

func TestRunEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/7.4.33")
		fmt.Fprint(w, "<title>Hi</title>")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	cfg := config.Default()
	cfg.Domain = "localhost"
	cfg.HTTPEvidence, cfg.ServiceVersion, cfg.Nuclei = true, true, true
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	var events []Event
	r := &Runner{Cfg: cfg, Exec: fakeExec(u.Port()), Emit: func(e Event) { events = append(events, e) }}
	out, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Domain != "localhost" || len(out.Results) != 1 {
		t.Fatalf("unexpected output: %+v", out)
	}
	res := out.Results[0]
	if !res.Resolved || !res.Connected || len(res.HTTP.Endpoints) != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	ep := res.HTTP.Endpoints[0]
	if !ep.Reachable || len(ep.PHPCVEFindings) != 2 {
		t.Errorf("endpoint: %+v", ep)
	}
	if len(out.Nuclei.Findings) != 1 || len(out.Nuclei.Errors) != 1 {
		t.Errorf("nuclei dedupe/errors: %+v", out.Nuclei)
	}
	var sawPHP, sawNuclei, sawVersion bool
	for _, h := range out.PrioritizationHint {
		switch h.Category {
		case "PHP CVE Exposure":
			sawPHP = true
		case "nuclei":
			sawNuclei = true
		case "service-version":
			sawVersion = true
		}
	}
	if !sawPHP || !sawNuclei || !sawVersion {
		t.Errorf("hints missing: php=%v nuclei=%v version=%v", sawPHP, sawNuclei, sawVersion)
	}
	var progress bool
	for _, e := range events {
		if e.Total == 1 && e.Index == 1 {
			progress = true
		}
	}
	if !progress {
		t.Error("no progress event emitted")
	}

	// JSON shape: same top-level keys as the original schema.
	data, err := report.JSON(out)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"domain", "source_ip", "run_datetime", "results", "nuclei", "zap", "prioritization_hints", "tool_metadata"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing top-level key %q", k)
		}
	}
	if !strings.Contains(string(data), `"schema_version": "2.0"`) {
		t.Error("schema_version missing")
	}
	var feat struct {
		ToolMetadata struct {
			FeaturesEnabled map[string]bool `json:"features_enabled"`
		} `json:"tool_metadata"`
	}
	_ = json.Unmarshal(data, &feat)
	if !feat.ToolMetadata.FeaturesEnabled["http_evidence"] || feat.ToolMetadata.FeaturesEnabled["zap"] {
		t.Errorf("features: %v", feat.ToolMetadata.FeaturesEnabled)
	}
	// Key order within features_enabled matches the original script.
	if i, j := strings.Index(string(data), `"service_version"`), strings.Index(string(data), `"zap": false`); i < 0 || j < i {
		t.Error("features_enabled order not preserved")
	}
}

func TestRunSubfinderFailure(t *testing.T) {
	cfg := config.Default()
	cfg.Domain = "example.com"
	r := &Runner{Cfg: cfg, Exec: func(context.Context, string, ...string) (execx.Result, error) {
		return execx.Result{ExitCode: 1}, nil
	}}
	if _, err := r.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "subfinder failed for example.com") {
		t.Errorf("err = %v", err)
	}
}

func TestSaveAndColorize(t *testing.T) {
	cfg := config.Default()
	cfg.Domain = "localhost"
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	r := &Runner{Cfg: cfg, Exec: fakeExec(u.Port())}
	out, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir() + "/nested"
	path, err := report.Save(out, dir)
	if err != nil || !strings.HasSuffix(path, "connectivity-results.json") {
		t.Fatalf("path=%q err=%v", path, err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "\x1b[") || !json.Valid(data) {
		t.Error("saved JSON must be plain and valid")
	}
	colored := report.Colorize(data)
	if !strings.Contains(colored, "\x1b[") {
		t.Error("expected ANSI colors on console output")
	}
	if stripped := stripANSI(colored); stripped != string(data) {
		t.Error("colorized output must equal plain JSON once ANSI is stripped")
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
