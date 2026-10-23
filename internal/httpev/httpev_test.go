package httpev

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"ctz/internal/model"
)

func assess(version string) []model.PHPFinding {
	return AssessPHPCVE(map[string]string{"x-powered-by": "PHP/" + version})
}

func TestPHPSupportedBranchBoundaries(t *testing.T) {
	for minor, fixed := range map[int]int{2: 35, 3: 36, 4: 27, 5: 12} {
		f := assess(fmt.Sprintf("8.%d.%d", minor, fixed-1))
		if len(f) != 2 {
			t.Fatalf("8.%d.%d: want 2 findings, got %d", minor, fixed-1, len(f))
		}
		cves := map[string]bool{f[0].CVE: true, f[1].CVE: true}
		if !cves["CVE-2026-109618"] || !cves["CVE-2026-109619"] {
			t.Errorf("unexpected CVEs %v", cves)
		}
		if f[0].Assessment != "potentially_affected" {
			t.Errorf("assessment = %s", f[0].Assessment)
		}
		want := fmt.Sprintf("8.%d.%d", minor, fixed)
		if f[0].FixedVersion == nil || *f[0].FixedVersion != want {
			t.Errorf("fixed_version = %v, want %s", f[0].FixedVersion, want)
		}
		if got := assess(want); len(got) != 0 {
			t.Errorf("%s should be fixed, got %d findings", want, len(got))
		}
		if got := assess(fmt.Sprintf("8.%d.%d", minor, fixed+1)); len(got) != 0 {
			t.Errorf("above fixed should be clean")
		}
	}
}

func TestPHPLegacyAndVendorBanners(t *testing.T) {
	for _, v := range []string{"5.4.45", "5.6.40", "7.4.33", "8.0.30", "8.1.34", "8.2.34-1ubuntu1"} {
		f := assess(v)
		if len(f) != 2 {
			t.Errorf("%s: want 2 findings, got %d", v, len(f))
			continue
		}
		if !contains(f[0].Validation, "backports") {
			t.Errorf("validation should mention backports")
		}
	}
}

func TestPHPUnrecognizedVersions(t *testing.T) {
	if len(AssessPHPCVE(nil)) != 0 {
		t.Error("nil headers should yield nothing")
	}
	for _, v := range []string{"", "8.4", "8.6.0", "9.0.0", "4.4.9", "8.4.26.1"} {
		if f := assess(v); len(f) != 0 {
			t.Errorf("%q: want none, got %d", v, len(f))
		}
	}
}

func TestPHPServerBannerAndDedupe(t *testing.T) {
	f := AssessPHPCVE(map[string]string{"server": "Apache/2.4.65 php/8.4.26", "x-powered-by": "PHP/8.4.26"})
	if len(f) != 2 {
		t.Fatalf("want 2 deduped findings, got %d", len(f))
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func candidateFor(t *testing.T, srv *httptest.Server) Candidate {
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return Candidate{URL: srv.URL, Port: port, Scheme: "http"}
}

func TestFetchSingleGETWithFindings(t *testing.T) {
	var calls, gets int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.Method == http.MethodGet {
			atomic.AddInt32(&gets, 1)
		}
		w.Header().Set("X-Powered-By", "PHP/8.4.26")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><title> Example\n Page </title></html>")
	}))
	defer srv.Close()
	ep := Fetch(context.Background(), Client(2*time.Second), candidateFor(t, srv))
	if !ep.Reachable || *ep.StatusCode != 200 {
		t.Fatalf("unexpected endpoint: %+v", ep)
	}
	if calls != 1 || gets != 1 {
		t.Errorf("calls=%d gets=%d, want single GET", calls, gets)
	}
	if ep.Title == nil || *ep.Title != "Example Page" {
		t.Errorf("title = %v", ep.Title)
	}
	if len(ep.PHPCVEFindings) != 2 {
		t.Errorf("php findings = %d", len(ep.PHPCVEFindings))
	}
	if len(ep.SecurityHeaderFindings) == 0 {
		t.Error("header findings should be preserved alongside PHP findings")
	}
}

func TestFetchStatusAndUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.4.26")
		w.WriteHeader(http.StatusForbidden)
	}))
	cand := candidateFor(t, srv)
	ep := Fetch(context.Background(), Client(2*time.Second), cand)
	if !ep.Reachable || *ep.StatusCode != 403 || len(ep.PHPCVEFindings) != 2 {
		t.Errorf("403 should be a reachable response with findings: %+v", ep)
	}
	srv.Close()
	ep = Fetch(context.Background(), Client(2*time.Second), cand)
	if ep.Reachable || ep.Error == nil || len(ep.PHPCVEFindings) != 0 {
		t.Errorf("closed server should be unreachable: %+v", ep)
	}
}

func TestAssessSecurityHeaders(t *testing.T) {
	good := map[string]string{
		"strict-transport-security":    "max-age=63072000",
		"content-security-policy":      "default-src 'self'; frame-ancestors 'none'",
		"x-content-type-options":       "nosniff",
		"referrer-policy":              "same-origin",
		"permissions-policy":           "geolocation=()",
		"cross-origin-opener-policy":   "same-origin",
		"cross-origin-embedder-policy": "require-corp",
		"cross-origin-resource-policy": "same-site",
		"cache-control":                "no-store",
	}
	res, sum, findings := AssessSecurityHeaders(good, "https", "https://x", 443)
	if sum.Score != 12 || sum.Rating != "Good" || len(findings) != 0 {
		t.Errorf("good headers: %+v findings=%v", sum, findings)
	}
	if r, _ := res.Get("x_frame_options"); r.Assessment != "not_applicable" {
		t.Errorf("xfo with frame-ancestors = %s", r.Assessment)
	}

	_, sum, findings = AssessSecurityHeaders(map[string]string{}, "https", "https://x", 443)
	if sum.Rating != "Needs Attention" && sum.Rating != "Needs Review" {
		t.Errorf("empty rating = %s", sum.Rating)
	}
	if len(sum.MissingHeaders) == 0 || len(findings) == 0 {
		t.Error("expected missing headers and findings")
	}

	weak := map[string]string{
		"access-control-allow-origin": "*", "access-control-allow-credentials": "true",
		"server": "nginx/1.24.0", "strict-transport-security": "max-age=10",
	}
	res, _, findings = AssessSecurityHeaders(weak, "https", "https://x", 443)
	if r, _ := res.Get("access_control_allow_origin"); r.Assessment != "potentially_misconfigured" {
		t.Errorf("cors = %s", r.Assessment)
	}
	if r, _ := res.Get("server"); r.Assessment != "informational_exposure" {
		t.Errorf("server = %s", r.Assessment)
	}
	if r, _ := res.Get("strict_transport_security"); r.Assessment != "weak" {
		t.Errorf("hsts = %s", r.Assessment)
	}
	var sawMedium bool
	for _, f := range findings {
		if f.SeverityHint == "medium" {
			sawMedium = true
		}
	}
	if !sawMedium {
		t.Error("expected medium finding for CORS")
	}

	res, _, _ = AssessSecurityHeaders(map[string]string{}, "http", "http://x", 80)
	if r, _ := res.Get("strict_transport_security"); r.Assessment != "not_applicable" {
		t.Errorf("hsts over http = %s", r.Assessment)
	}
}

func TestCandidates(t *testing.T) {
	name := func(s string) *string { return &s }
	svcs := []model.Service{
		{Port: 8443, Name: name("https-alt"), Tunnel: name("ssl")},
		{Port: 3000, Name: name("http")},
		{Port: 22, Name: name("ssh")},
	}
	got := Candidates("h", []int{22, 80, 3000, 8443}, svcs)
	want := []string{"http://h", "http://h:3000", "https://h:8443"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i, c := range got {
		if c.URL != want[i] {
			t.Errorf("candidate %d = %s, want %s", i, c.URL, want[i])
		}
	}
}

func TestPHPBanner(t *testing.T) {
	for _, c := range []struct {
		h    map[string]string
		want string
	}{
		{map[string]string{"x-powered-by": "PHP/8.2.10"}, "8.2.10"},
		{map[string]string{"server": "Apache/2.4.58 (Ubuntu) PHP/8.1.2-1ubuntu"}, "8.1.2"},
		{map[string]string{"x-powered-by": "ASP.NET"}, ""},
		{map[string]string{"server": "PHP/8.2.10.4"}, ""},
	} {
		if got := PHPBanner(c.h); got != c.want {
			t.Errorf("PHPBanner(%v) = %q, want %q", c.h, got, c.want)
		}
	}
}
