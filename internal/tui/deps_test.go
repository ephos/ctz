package tui

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"ctz/internal/config"
	"ctz/internal/model"
	"ctz/internal/runner"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func look(have ...string) func(string) (string, error) {
	return func(n string) (string, error) {
		for _, h := range have {
			if h == n {
				return "/bin/" + n, nil
			}
		}
		return "", errors.New("not found")
	}
}

func TestRenderDeps(t *testing.T) {
	cfg := config.Default()
	cfg.Nuclei = true
	out := ansi.ReplaceAllString(renderDeps(cfg.DependencyReport(look("nmap")), "dnf"), "")
	for _, want := range []string{
		"subfinder", "nmap", "dnsx", "gobuster", "wafw00f", "whois", "nuclei", "docker",
		"/bin/nmap", "MISSING (required)", "not found (optional)",
		"2 required tool(s) missing: subfinder, nuclei", "optional tool(s) missing", "Install missing tools", "sudo dnf install -y gobuster whois moby-engine golang pipx", "sudo pacman -S --needed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("popup missing %q:\n%s", want, out)
		}
	}
	all := cfg.DependencyReport(look("subfinder", "nmap", "nuclei"))
	out = ansi.ReplaceAllString(renderDeps(all, ""), "")
	if !strings.Contains(out, "All tools required") || depWarning(all) != "" {
		t.Errorf("expected all-clear:\n%s", out)
	}
}

func TestFormToggleChangesRequirement(t *testing.T) {
	f := newForm()
	required := func() bool {
		cfg := f.lenientConfig()
		for _, d := range cfg.DependencyReport(look()) {
			if d.Name == "nuclei" {
				return d.Required
			}
		}
		return false
	}
	if required() {
		t.Fatal("nuclei should be optional by default")
	}
	for _, fd := range f.fields {
		if fd.label == "Nuclei" {
			fd.on = true
		}
	}
	if !required() {
		t.Error("enabling Nuclei should make it required")
	}
	// Garbage in a numeric field must not break the lenient config.
	for _, fd := range f.fields {
		if fd.label == "HTTP timeout (s)" {
			fd.input.SetValue("abc")
		}
	}
	_ = f.lenientConfig()
}

func TestToggleAll(t *testing.T) {
	f := newForm()
	count := func() (on, total int) {
		for _, fd := range f.fields {
			if fd.kind == kindToggle && !fd.output {
				total++
				if fd.on {
					on++
				}
			}
		}
		return
	}
	_, save := fieldByLabel(t, f, "Save JSON")
	saveBefore := save.on
	f.toggleAll()
	if on, total := count(); on != total {
		t.Fatalf("expected all %d on, got %d", total, on)
	}
	if save.on != saveBefore {
		t.Fatal("output toggle should be untouched")
	}
	f.toggleAll()
	if on, _ := count(); on != 0 {
		t.Fatalf("expected all off, got %d", on)
	}
}

func TestIPInfoKeyIsMasked(t *testing.T) {
	f := newForm()
	for i, fd := range f.fields {
		if fd.label == "ipinfo API key" {
			f.cursor = i
			fd.input.SetValue("s3cr3t-token")
		}
	}
	if strings.Contains(f.view(100), "s3cr3t-token") {
		t.Fatal("API key is visible in the form view")
	}
	cfg, _ := f.config()
	if cfg.IPInfoKey != "s3cr3t-token" {
		t.Fatalf("key not passed to config: %q", cfg.IPInfoKey)
	}
}

func TestBrowseFinishedTargetsWhileRunning(t *testing.T) {
	m := New()
	m.phase = phaseRunning
	m.cancel = func() {}
	m.events = make(chan tea.Msg, 1)
	m.width, m.height = 120, 40
	m.total = 2
	tab := tea.KeyMsg{Type: tea.KeyTab}

	next, _ := m.updateRunning(tab)
	if next.(Model).browse {
		t.Fatal("browse should be unavailable before any target finishes")
	}

	done := runner.Event{Done: &model.TargetResult{Target: "a.example.com", Resolved: true, IPAddress: "192.0.2.1"}}
	next, _ = m.updateRunning(eventMsg(done))
	m = next.(Model)
	next, _ = m.updateRunning(tab)
	m = next.(Model)
	if !m.browse {
		t.Fatal("tab should enter browse mode once a target has finished")
	}
	if v := ansi.ReplaceAllString(m.View(), ""); !strings.Contains(v, "a.example.com") || !strings.Contains(v, "192.0.2.1") {
		t.Fatalf("browse view missing finished target:\n%s", v)
	}
	next, _ = m.updateRunning(tab)
	if next.(Model).browse {
		t.Fatal("tab should return to the live view")
	}
}

func TestIPInfoKeyIsBoxed(t *testing.T) {
	v := ansi.ReplaceAllString(newForm().view(100), "")
	if !strings.Contains(v, "╭") || !strings.Contains(v, "ipinfo API key") {
		t.Fatalf("API key field should be drawn in a bordered box:\n%s", v)
	}
}

func fieldByLabel(t *testing.T, f *form, label string) (int, *field) {
	t.Helper()
	for i, fd := range f.fields {
		if fd.label == label {
			return i, fd
		}
	}
	t.Fatalf("no field %q", label)
	return 0, nil
}

func TestFormDefaultsAndExposedOptions(t *testing.T) {
	f := newForm()
	_, d := fieldByLabel(t, f, "Domain")
	d.input.SetValue("example.com")
	cfg, err := f.config()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ServiceVersion || !cfg.HTTPEvidence || cfg.NSE || cfg.Nuclei || cfg.Zap {
		t.Errorf("unexpected default toggles: %+v", cfg)
	}
	if cfg.NSEScripts != "default,safe" || cfg.ZapMaxEndpoints != 10 || cfg.VhostScheme != "https" {
		t.Errorf("unexpected default values: %+v", cfg)
	}
	_, nse := fieldByLabel(t, f, "NSE script set")
	nse.input.SetValue("http-title,http-headers")
	_, z := fieldByLabel(t, f, "ZAP max endpoints")
	z.input.SetValue("3")
	cfg, err = f.config()
	if err != nil || cfg.NSEScripts != "http-title,http-headers" || cfg.ZapMaxEndpoints != 3 {
		t.Errorf("options not applied: %v %+v", err, cfg)
	}
}

func TestFormScrollsToCursor(t *testing.T) {
	f := newForm()
	f.height = 24
	f.cursor = len(f.fields) - 1
	_, last := fieldByLabel(t, f, "ipinfo API key")
	v := ansi.ReplaceAllString(f.view(100), "")
	if !strings.Contains(v, last.label) || !strings.Contains(v, "↑") {
		t.Errorf("cursor row not visible or no scroll hint:\n%s", v)
	}
	if strings.Contains(v, "Domains file") {
		t.Errorf("top rows should be scrolled off:\n%s", v)
	}
	if n := strings.Count(v, "\n"); n > 24 {
		t.Errorf("view is %d lines, want <= 24", n)
	}
}

func TestEditingDependentFieldEnablesFeature(t *testing.T) {
	f := newFormFor(func(string) (string, error) { return "", errors.New("missing") }, func(string) string { return "" })
	on := func(label string) bool { _, fd := fieldByLabel(t, f, label); return fd.on }
	if on("Nuclei") || on("OWASP ZAP baseline") || on("Vhost enumeration") || on("NSE scripts") {
		t.Fatal("dependent features should start off")
	}
	set := func(label, v string) {
		i, fd := fieldByLabel(t, f, label)
		f.cursor = i
		f.focus()
		fd.input.SetValue("")
		f.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(v)})
	}
	set("Nuclei severities", "high")
	set("ZAP max endpoints", "3")
	set("Vhost base URL", "https://192.0.2.10")
	set("NSE script set", "http-title")
	for _, l := range []string{"Nuclei", "OWASP ZAP baseline", "Vhost enumeration", "NSE scripts"} {
		if !on(l) {
			t.Errorf("%s should be enabled by its option", l)
		}
	}
}

func TestEnvironmentAwareDefaults(t *testing.T) {
	have := map[string]bool{"wafw00f": true, "whois": true}
	look := func(n string) (string, error) {
		if have[n] {
			return "/usr/bin/" + n, nil
		}
		return "", errors.New("missing")
	}
	f := newFormFor(look, func(k string) string {
		if k == "IPINFO_API_KEY" {
			return "key"
		}
		return ""
	})
	for _, l := range []string{"WAF detection", "Registration (RDAP/whois)", "ipinfo.io", "Save JSON"} {
		if _, fd := fieldByLabel(t, f, l); !fd.on {
			t.Errorf("%s should default on when available", l)
		}
	}
	f = newFormFor(func(string) (string, error) { return "", errors.New("missing") }, func(string) string { return "" })
	for _, l := range []string{"WAF detection", "Registration (RDAP/whois)", "ipinfo.io"} {
		if _, fd := fieldByLabel(t, f, l); fd.on {
			t.Errorf("%s should default off when unavailable", l)
		}
	}
}

func scriptsTarget() model.TargetResult {
	errOut := "ERROR: Script execution failed (use -d to debug)"
	return model.TargetResult{
		Target: "example.com", Resolved: true, Connected: true, Ports: []int{80, 443},
		Services: []model.Service{
			{Port: 80, Protocol: "tcp", NSE: []model.NSEEntry{
				{Port: 80, ScriptID: "http-title", Output: "Welcome"},
				{Port: 80, ScriptID: "http-server-header", Output: errOut},
				{Port: 80, ScriptID: "http-date", Output: "Thu, 22 Oct 2026"},
				{Port: 80, ScriptID: "hnap-info", Output: errOut},
			}},
			{Port: 443, Protocol: "tcp", NSE: []model.NSEEntry{{Port: 443, ScriptID: "ssl-cert", Output: "Subject: x"}}},
		},
	}
}

func TestScriptsAreGroupedRanThenFailed(t *testing.T) {
	v := ansi.ReplaceAllString(renderOverview(scriptsTarget(), nseRun{scripts: "default,safe", versionDetect: true}, 100), "")
	for _, want := range []string{
		"Scripts that ran (2)", "• http-date: Thu, 22 Oct 2026", "• http-title: Welcome",
		"Scripts that failed (2)", "• hnap-info\n", "• http-server-header\n",
		"Scripts that ran (1)", "• ssl-cert: Subject: x",
		"Repeat the run with debug",
		"$ nmap -sT -Pn -p 80 -sV --version-light \\", "--script default,safe --script-timeout 30s \\", "-d example.com 2>&1 \\", "| grep -A4 'threw an error'",
	} {
		if !strings.Contains(v, want) {
			t.Errorf("missing %q in:\n%s", want, v)
		}
	}
	// Sorted within a group, ran listed before failed, and the cause hint and
	// command appear once per port that has failures rather than once per script.
	if strings.Index(v, "http-date") > strings.Index(v, "http-title") {
		t.Errorf("scripts should be sorted by name:\n%s", v)
	}
	if strings.Index(v, "Scripts that ran (2)") > strings.Index(v, "Scripts that failed (2)") {
		t.Errorf("ran group should come first:\n%s", v)
	}
	if n := strings.Count(v, "Repeat the run with debug"); n != 1 {
		t.Errorf("hint appears %d times, want once (only port 80 has failures):\n%s", n, v)
	}
	if strings.Contains(v, "ERROR: Script execution failed") {
		t.Errorf("failed scripts should be listed by name, not repeat the error text:\n%s", v)
	}
}

func TestScriptsNeverExceedPaneWidth(t *testing.T) {
	for _, width := range []int{50, 80} {
		v := ansi.ReplaceAllString(renderOverview(scriptsTarget(), nseRun{scripts: "default,safe", versionDetect: true}, width), "")
		for _, line := range strings.Split(v, "\n") {
			if w := lipgloss.Width(line); w > width {
				t.Errorf("width %d: line is %d columns: %q", width, w, line)
			}
		}
	}
}

func TestResultsPaneContentFitsViewport(t *testing.T) {
	// The pane pads one column each side, so the viewport must be 2 narrower
	// than the pane or the last characters of long lines wrap and get cut off.
	m := resultsModel(120, "a.example.com")
	paneInner := m.detail.Width
	if got := lipgloss.Width(stylePane.Width(m.detail.Width + 2).Render(strings.Repeat("x", paneInner))); got != paneInner+4 {
		t.Errorf("rendered pane is %d columns, want %d", got, paneInner+4)
	}
	line := strings.Repeat("x", paneInner)
	rendered := stylePane.Width(m.detail.Width + 2).Render(line)
	if strings.Count(rendered, "\n") != 2 { // top border + one content row + bottom border
		t.Errorf("a full-width line should fit on one row without wrapping:\n%s", rendered)
	}
}

func resultsModel(width int, targets ...string) Model {
	m := New()
	m.phase = phaseResults
	m.width, m.height = width, 30
	m.out = &model.Output{}
	for _, t := range targets {
		m.out.Results = append(m.out.Results, model.TargetResult{Target: t, Resolved: true, Connected: true})
	}
	m.resizeDetail()
	m.refreshDetail()
	return m
}

func TestTargetListDoesNotWrap(t *testing.T) {
	names := []string{"askcompliance.ralliant.com", "magnet.review.ralliant.com", "a-really-long-hostname-that-cannot-fit.subdomain.ralliant.com", "ralliant.com"}
	m := resultsModel(100, names...)
	lw := m.listWidth()
	rows := 0
	for _, line := range strings.Split(ansi.ReplaceAllString(m.resultsBody(), ""), "\n") {
		if strings.HasPrefix(line, "│") && strings.Contains(line, "ralliant.com") || strings.Contains(line, "…") {
			rows++
		}
	}
	if rows != len(names) {
		t.Errorf("expected %d single-line rows, got %d (lw=%d):\n%s", len(names), rows, lw, ansi.ReplaceAllString(m.resultsBody(), ""))
	}
}

func TestResizeListKeys(t *testing.T) {
	m := resultsModel(140, "a.example.com")
	base := m.listWidth()
	m.navigate(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{']'}})
	if m.listWidth() != base+listStep {
		t.Errorf("] should widen the list: %d -> %d", base, m.listWidth())
	}
	for i := 0; i < 50; i++ {
		m.navigate(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'['}})
	}
	if m.listWidth() < 14 {
		t.Errorf("list shrank below its minimum: %d", m.listWidth())
	}
	m.navigate(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{']'}})
	if w := m.listWidth(); w <= 14 || w > 14+listStep {
		t.Errorf("one ] after hitting the minimum should widen by at most a step; repeated [ must not wind the delta up: %d", w)
	}
}

func TestPHPSummary(t *testing.T) {
	hdr := func(v string) *model.Ordered[*string] {
		o := model.NewOrdered[*string]()
		o.Set("x-powered-by", &v)
		return o
	}
	strip := func(s string) string { return ansi.ReplaceAllString(s, "") }
	none := model.TargetResult{}
	if phpSummary(none) != "" {
		t.Error("no HTTP evidence should give no PHP line")
	}
	nd := model.TargetResult{HTTP: model.HTTPResult{Checked: true, Endpoints: []model.HTTPEndpoint{{Headers: hdr("")}}}}
	if !strings.Contains(strip(phpSummary(nd)), "not disclosed") {
		t.Errorf("got %q", strip(phpSummary(nd)))
	}
	ok := model.TargetResult{HTTP: model.HTTPResult{Checked: true, Endpoints: []model.HTTPEndpoint{{Headers: hdr("PHP/8.5.20")}}}}
	if !strings.Contains(strip(phpSummary(ok)), "PHP 8.5.20") || !strings.Contains(strip(phpSummary(ok)), "not in the flagged range") {
		t.Errorf("got %q", strip(phpSummary(ok)))
	}
	hit := model.TargetResult{HTTP: model.HTTPResult{Checked: true, Endpoints: []model.HTTPEndpoint{{
		Headers: hdr("PHP/8.2.10"), PHPCVEFindings: []model.PHPFinding{{CVE: "CVE-2026-109618", Version: "8.2.10"}, {CVE: "CVE-2026-109619", Version: "8.2.10"}},
	}}}}
	if v := strip(phpSummary(hit)); !strings.Contains(v, "PHP 8.2.10") || !strings.Contains(v, "CVE-2026-109618") || !strings.Contains(v, "CVE-2026-109619") {
		t.Errorf("got %q", v)
	}
}

func TestDNSWordlistDefaultsToEmbeddedWhenDnsxInstalled(t *testing.T) {
	val := func(have bool) string {
		look := func(n string) (string, error) {
			if n == "dnsx" && have {
				return "/usr/bin/dnsx", nil
			}
			return "", errors.New("missing")
		}
		_, fd := fieldByLabel(t, newFormFor(look, func(string) string { return "" }), "DNS wordlist")
		return fd.input.Value()
	}
	if val(true) != config.DefaultWordlist {
		t.Error("DNS wordlist should default to the embedded list when dnsx is installed")
	}
	if val(false) != "" {
		t.Error("DNS wordlist should be empty when dnsx is missing")
	}
}

func summaryTarget() model.TargetResult {
	str := func(s string) *string { return &s }
	days := -3
	left := 40
	hdr := model.NewOrdered[*string]()
	hdr.Set("x-powered-by", str("PHP/8.2.10"))
	return model.TargetResult{
		Target: "shop.example.com", IPAddress: "192.0.2.7", Resolved: true, Connected: true,
		Ports: []int{80, 443},
		Services: []model.Service{
			{Port: 80, Protocol: "tcp", Name: str("http"), Product: str("nginx"), Version: str("1.24.0")},
			{Port: 443, Protocol: "tcp", Name: str("https"), NSE: []model.NSEEntry{{Port: 443, ScriptID: "hnap-info", Output: "ERROR: Script execution failed (use -d to debug)"}}},
		},
		TLSCertificates: []model.TLSCertificate{
			{Ports: []int{443}, Subject: "commonName=shop.example.com", Issuer: "organizationName=Let's Encrypt, commonName=R11",
				SubjectAlternativeNames: []string{"shop.example.com", "example.com"}, Expiration: "January 1, 2026", Expired: true, DaysUntilExpiration: &days},
			{Ports: []int{8443}, Subject: "commonName=other.example.com", Issuer: "commonName=Internal CA",
				Expiration: "December 1, 2026", DaysUntilExpiration: &left},
		},
		WAF: model.WAFResult{Checked: true, Detected: true, Products: []string{"Cloudflare"}},
		HTTP: model.HTTPResult{Checked: true, Endpoints: []model.HTTPEndpoint{{
			Port: 443, Reachable: true, Server: str("nginx/1.24.0"), Headers: hdr,
			SecurityHeaderSummary: model.HeaderSummary{Rating: "Fair", Score: 7, MaxScore: 12},
			PHPCVEFindings:        []model.PHPFinding{{CVE: "CVE-2026-109618", Version: "8.2.10"}},
		}}},
	}
}

func TestSummaryTab(t *testing.T) {
	r := summaryTarget()
	r.Services = append(r.Services, model.Service{Port: 3389, Protocol: "tcp", Name: func() *string { s := "ms-wbt-server"; return &s }()})
	p := 3389
	out := &model.Output{Results: []model.TargetResult{r}, PrioritizationHint: []model.Hint{
		{Target: "shop.example.com", SeverityHint: "high", Port: &p, Category: "rdp", Reason: "External RDP service is reachable."},
		{Target: "shop.example.com", SeverityHint: "high", Category: "PHP CVE Exposure", Reason: "PHP banner"},
		{Target: "shop.example.com", SeverityHint: "low", Category: "tls", Reason: "cert"},
		{Target: "other.example.com", SeverityHint: "high", Category: "elsewhere", Reason: "not ours"},
	}}
	v := ansi.ReplaceAllString(renderDetail(out, r, 0, 100), "")
	for _, want := range []string{
		"● CONNECTED", "✗ CERT EXPIRED", "WAF Cloudflare", "⚠ PHP 8.2.10", "2 HIGH", "1 LOW",
		"Open ports (3)", "‹80 http›", "‹443 https›", "‹3389 ms-wbt-server›",
		"shop.example.com", "port 443", "Let's Encrypt (R11)", "EXPIRED 3 days ago", "✓ covers shop.example.com", "(2 name(s))",
		"other.example.com", "port 8443", "40 days left", "✗ does not cover shop.example.com",
		"‹nginx/1.24.0›", "‹PHP/8.2.10›", "potentially affected by CVE-2026-109618",
		"detected: Cloudflare", "headers Fair (7/12)",
		"External RDP service is reachable.", "1 script(s) errored",
	} {
		if !strings.Contains(v, want) {
			t.Errorf("summary missing %q:\n%s", want, v)
		}
	}
	if strings.Contains(v, "not ours") {
		t.Errorf("findings must only include this target's hints:\n%s", v)
	}
	if strings.Contains(v, "nginx 1.24.0") {
		t.Errorf("nmap and header banners for the same server should be merged:\n%s", v)
	}
	for _, line := range strings.Split(v, "\n") {
		if w := lipgloss.Width(line); w > 100 {
			t.Errorf("line is %d columns, wider than the pane content (%d): %q", w, 100, line)
		}
	}
}

func TestSummaryFitsNarrowPane(t *testing.T) {
	r := summaryTarget()
	v := ansi.ReplaceAllString(renderSummary(&model.Output{}, r, 60), "")
	for _, line := range strings.Split(v, "\n") {
		if w := lipgloss.Width(line); w > 60 {
			t.Errorf("line is %d columns in a 60-wide pane: %q", w, line)
		}
	}
}

func TestCertCovers(t *testing.T) {
	c := func(sans ...string) model.TLSCertificate {
		return model.TLSCertificate{SubjectAlternativeNames: sans, Subject: "commonName=fallback.example.com"}
	}
	for _, tc := range []struct {
		cert model.TLSCertificate
		host string
		want bool
	}{
		{c("example.com", "www.example.com"), "www.example.com", true},
		{c("*.example.com"), "shop.example.com", true},
		{c("*.example.com"), "a.b.example.com", false}, // a wildcard covers one label only
		{c("*.example.com"), "example.com", false},
		{c(), "fallback.example.com", true}, // no SANs: fall back to the common name
		{c("other.org"), "shop.example.com", false},
		{c("EXAMPLE.com"), "example.COM", true},
	} {
		if got := certCovers(tc.cert, tc.host); got != tc.want {
			t.Errorf("certCovers(%v, %q) = %v, want %v", tc.cert.SubjectAlternativeNames, tc.host, got, tc.want)
		}
	}
}

func TestSummaryCertStates(t *testing.T) {
	days := func(n int) *int { return &n }
	base := model.TargetResult{Target: "a.example.com", Resolved: true}
	check := func(name string, c model.TLSCertificate, want string) {
		r := base
		r.TLSCertificates = []model.TLSCertificate{c}
		if v := ansi.ReplaceAllString(renderSummary(nil, r, 100), ""); !strings.Contains(v, want) {
			t.Errorf("%s: missing %q:\n%s", name, want, v)
		}
	}
	ok := model.TLSCertificate{Ports: []int{443}, Subject: "commonName=a.example.com", Issuer: "commonName=CA", SubjectAlternativeNames: []string{"a.example.com"}, DaysUntilExpiration: days(60)}
	check("valid", ok, "✓ CERT VALID")
	soon := ok
	soon.ExpiresSoon, soon.DaysUntilExpiration = true, days(5)
	check("soon", soon, "expires in 5 days")
	self := ok
	self.Issuer = self.Subject
	check("self-signed", self, "SELF-SIGNED")
}

func TestSummaryEmptyStates(t *testing.T) {
	r := model.TargetResult{Target: "x.example.com", IPAddress: "192.0.2.1", Resolved: true}
	v := ansi.ReplaceAllString(renderSummary(nil, r, 100), "")
	for _, want := range []string{"○ NO OPEN PORTS", "NO TLS", "none", "no certificate observed", "none identified", "not checked", "nothing flagged"} {
		if !strings.Contains(v, want) {
			t.Errorf("missing %q:\n%s", want, v)
		}
	}
	if v := ansi.ReplaceAllString(renderSummary(nil, model.TargetResult{Target: "gone.example.com"}, 100), ""); !strings.Contains(v, "Did not resolve") {
		t.Errorf("unresolved target: %s", v)
	}
}

func TestSummaryIsFirstTabAndKeysFollow(t *testing.T) {
	if tabNames[0] != "Summary" || len(tabNames) != 5 {
		t.Fatalf("tabs = %v", tabNames)
	}
	m := resultsModel(120, "a.example.com")
	if m.tab != 0 {
		t.Fatalf("results should open on the Summary tab, got %d", m.tab)
	}
	m.navigate(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'5'}})
	if m.tab != 4 || tabNames[m.tab] != "Hints" {
		t.Errorf("key 5 should select Hints, got %d", m.tab)
	}
	m.navigate(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	if m.tab != 0 {
		t.Errorf("key 1 should select Summary, got %d", m.tab)
	}
}
