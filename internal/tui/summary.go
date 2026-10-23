package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"ctz/internal/model"
	"ctz/internal/scan"
)

// certLifetimeDays is the span the certificate gauge fills over; 90 days is a
// typical automated-issuance lifetime.
const certLifetimeDays = 90

var sevRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

func sevColor(sev string) lipgloss.TerminalColor {
	switch sev {
	case "critical", "high":
		return colBad
	case "medium":
		return colWarn
	case "low":
		return colInfo
	}
	return colMuted
}

// renderSummary is the at-a-glance first tab: status badges, then cards for
// open ports, TLS, web and technology, and findings. It repeats data found on
// the other tabs and is TUI-only; nothing here is written to the JSON output.
func renderSummary(out *model.Output, r model.TargetResult, width int) string {
	if width <= 0 {
		width = 80
	}
	w := max(44, min(width, 100))
	var b strings.Builder
	b.WriteString(styleHeading.Render(r.Target) + "\n")
	if !r.Resolved {
		b.WriteString("\n" + styleWarn.Render("Did not resolve.") + "\n")
		return b.String()
	}
	meta := []string{r.IPAddress}
	if info := r.IPInfo; info != nil {
		meta = append(meta, strings.TrimSpace(fmt.Sprint(info["asn"], " ", info["as_name"])), fmt.Sprint(info["country"]))
	}
	b.WriteString(styleSubtle.Render(strings.Join(meta, " · ")) + "\n\n")

	hints := targetHints(out, r.Target)
	b.WriteString(strings.Join(wrapTokens(badges(r, hints), " ", w), "\n") + "\n\n")
	for _, c := range []string{portsCard(r, hints, w), tlsCard(r, w), webCard(r, w), findingsCard(r, hints, w)} {
		if c != "" {
			b.WriteString(c + "\n")
		}
	}
	return b.String()
}

// targetHints returns the prioritization hints for target, highest severity first.
func targetHints(out *model.Output, target string) []model.Hint {
	if out == nil {
		return nil
	}
	var hs []model.Hint
	for _, h := range out.PrioritizationHint {
		if h.Target == target {
			hs = append(hs, h)
		}
	}
	sort.SliceStable(hs, func(i, j int) bool { return sevRank[hs[i].SeverityHint] > sevRank[hs[j].SeverityHint] })
	return hs
}

// badges is the headline row: connectivity, certificate state, WAF, PHP and
// finding counts.
func badges(r model.TargetResult, hints []model.Hint) []string {
	var out []string
	if r.Connected {
		out = append(out, pill("● CONNECTED", colGood))
	} else {
		out = append(out, pill("○ NO OPEN PORTS", colWarn))
	}
	switch worst := worstCert(r); {
	case len(r.TLSCertificates) == 0:
		out = append(out, pill("NO TLS", colMuted))
	case worst == certBad:
		out = append(out, pill("✗ CERT EXPIRED", colBad))
	case worst == certWarn:
		out = append(out, pill("! CERT ATTENTION", colWarn))
	default:
		out = append(out, pill("✓ CERT VALID", colGood))
	}
	switch {
	case r.WAF.Detected:
		out = append(out, pill("WAF "+strings.Join(r.WAF.Products, ", "), colInfo))
	case r.WAF.Checked:
		out = append(out, pill("NO WAF", colMuted))
	}
	if st := phpInfo(r); len(st.cves) > 0 {
		out = append(out, pill("⚠ PHP "+st.version, colBad))
	} else if st.version != "" {
		out = append(out, pill("PHP "+st.version, colAccent))
	}
	counts := map[string]int{}
	for _, h := range hints {
		counts[h.SeverityHint]++
	}
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			out = append(out, pill(fmt.Sprintf("%d %s", n, strings.ToUpper(sev)), sevColor(sev)))
		}
	}
	return out
}

func portsCard(r model.TargetResult, hints []model.Hint, w int) string {
	if len(r.Services) == 0 {
		return card("Open ports", []string{styleSubtle.Render("none")}, w, colMuted)
	}
	worst := 0
	var chips []string
	for _, s := range r.Services {
		sev := "info"
		for _, h := range hints {
			if h.Port != nil && *h.Port == s.Port && sevRank[h.SeverityHint] > sevRank[sev] {
				sev = h.SeverityHint
			}
		}
		worst = max(worst, sevRank[sev])
		label := fmt.Sprint(s.Port)
		if name := ptr(s.Name); name != "" {
			label += " " + name
		}
		col := lipgloss.TerminalColor(colGood)
		if sevRank[sev] > 0 {
			col = sevColor(sev)
		}
		chips = append(chips, chip(label, col))
	}
	border := lipgloss.TerminalColor(colGood)
	switch {
	case worst >= sevRank["high"]:
		border = colBad
	case worst >= sevRank["medium"]:
		border = colWarn
	}
	body := wrapTokens(chips, " ", w-4)
	if worst > 0 {
		body = append(body, styleSubtle.Render("amber / red ports are flagged as externally exposed services"))
	}
	return card(fmt.Sprintf("Open ports (%d)", len(r.Services)), body, w, border)
}

type certState int

const (
	certOK certState = iota
	certWarn
	certBad
)

// certState classifies one certificate for host: expired is bad; expiring soon,
// self-signed, or not covering host is a warning.
func classifyCert(c model.TLSCertificate, host string) certState {
	switch {
	case c.Expired:
		return certBad
	case c.ExpiresSoon, c.Subject == c.Issuer, !certCovers(c, host):
		return certWarn
	}
	return certOK
}

func worstCert(r model.TargetResult) certState {
	worst := certOK
	for _, c := range r.TLSCertificates {
		worst = max(worst, classifyCert(c, r.Target))
	}
	return worst
}

// certCovers reports whether the certificate's SANs (or, lacking any, its
// common name) match host, including single-label wildcards.
func certCovers(c model.TLSCertificate, host string) bool {
	names := c.SubjectAlternativeNames
	if len(names) == 0 {
		for _, part := range strings.Split(c.Subject, ", ") {
			if k, v, ok := strings.Cut(part, "="); ok && k == "commonName" {
				names = append(names, v)
			}
		}
	}
	host = strings.ToLower(host)
	for _, n := range names {
		n = strings.ToLower(n)
		if n == host {
			return true
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if label, tail, found := strings.Cut(host, "."); found && label != "" && tail == rest {
				return true
			}
		}
	}
	return false
}

func tlsCard(r model.TargetResult, w int) string {
	if len(r.TLSCertificates) == 0 {
		return card("TLS", []string{styleSubtle.Render("no certificate observed")}, w, colMuted)
	}
	var body []string
	for i, c := range r.TLSCertificates {
		if i > 0 {
			body = append(body, "")
		}
		ports := make([]string, len(c.Ports))
		for j, p := range c.Ports {
			ports[j] = fmt.Sprint(p)
		}
		head := lipgloss.NewStyle().Bold(true).Render(certName(c.Subject)) + styleSubtle.Render("  port "+strings.Join(ports, ", "))
		if c.Subject == c.Issuer {
			head += " " + pill("SELF-SIGNED", colWarn)
		}
		body = append(body, head, styleSubtle.Render("issuer  ")+certName(c.Issuer), certExpiryLine(c))
		if certCovers(c, r.Target) {
			body = append(body, styleGood.Render("✓ covers "+r.Target)+styleSubtle.Render(fmt.Sprintf("  (%d name(s))", len(c.SubjectAlternativeNames))))
		} else {
			body = append(body, styleWarn.Render("✗ does not cover "+r.Target))
		}
	}
	border := lipgloss.TerminalColor(colGood)
	switch worstCert(r) {
	case certBad:
		border = colBad
	case certWarn:
		border = colWarn
	}
	return card("TLS", body, w, border)
}

// certExpiryLine is the lifetime gauge plus a plain-language state.
func certExpiryLine(c model.TLSCertificate) string {
	days := 0
	if c.DaysUntilExpiration != nil {
		days = *c.DaysUntilExpiration
	}
	date := styleSubtle.Render("  " + c.Expiration)
	switch {
	case c.Expired:
		return gauge(0, certLifetimeDays, 14, colBad) + " " + styleBad.Bold(true).Render(fmt.Sprintf("EXPIRED %d days ago", -days)) + date
	case c.ExpiresSoon:
		return gauge(days, certLifetimeDays, 14, colWarn) + " " + styleWarn.Render(fmt.Sprintf("expires in %d days", days)) + date
	}
	return gauge(min(days, certLifetimeDays), certLifetimeDays, 14, colGood) + " " + styleGood.Render(fmt.Sprintf("%d days left", days)) + date
}

// certName shortens an X.509 name ("k=v, k=v") to its organization and common
// name.
func certName(name string) string {
	var org, cn string
	for _, part := range strings.Split(name, ", ") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch k {
		case "organizationName":
			org = v
		case "commonName":
			cn = v
		}
	}
	switch {
	case org != "" && cn != "":
		return org + " (" + cn + ")"
	case cn != "":
		return cn
	case org != "":
		return org
	}
	if name == "" {
		return "-"
	}
	return name
}

// techItems lists what the target discloses: web server banners and
// nmap-identified products (merged), and X-Powered-By values.
func techItems(r model.TargetResult) (servers, powered []string) {
	seen := map[string]bool{}
	add := func(list *[]string, v string) {
		// "nginx/1.24.0" (header) and "nginx 1.24.0" (nmap) are the same thing.
		key := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(v), "/", " "))
		if v = strings.TrimSpace(v); v != "" && !seen[key] {
			seen[key] = true
			*list = append(*list, v)
		}
	}
	for _, e := range r.HTTP.Endpoints {
		add(&servers, deref(e.Server))
		if e.Headers != nil {
			if v := e.Headers.Values["x-powered-by"]; v != nil {
				add(&powered, *v)
			}
		}
	}
	for _, s := range r.Services {
		if p := strings.TrimSpace(ptr(s.Product) + " " + ptr(s.Version)); p != "" {
			add(&servers, p)
		}
	}
	sort.Strings(servers)
	return servers, powered
}

func webCard(r model.TargetResult, w int) string {
	var body []string
	servers, powered := techItems(r)
	var tech []string
	for _, v := range servers {
		tech = append(tech, chip(v, colAccent))
	}
	for _, v := range powered {
		tech = append(tech, chip(v, colAccent))
	}
	if st := phpInfo(r); st.checked && st.version != "" && len(powered) == 0 {
		tech = append(tech, chip("PHP "+st.version, colAccent))
	}
	label := styleSubtle.Render("technology  ")
	if len(tech) == 0 {
		body = append(body, label+styleSubtle.Render("none identified"))
	} else {
		for i, l := range wrapTokens(tech, " ", w-4-12) {
			prefix := label
			if i > 0 {
				prefix = strings.Repeat(" ", 12)
			}
			body = append(body, prefix+l)
		}
	}
	if st := phpInfo(r); len(st.cves) > 0 {
		body = append(body, styleBad.Render("⚠ PHP "+st.version+" potentially affected by "+strings.Join(st.cves, ", "))+styleSubtle.Render(" (banner only)"))
	}

	waf := styleSubtle.Render("not checked")
	switch {
	case r.WAF.Detected:
		waf = styleGood.Render("detected: ") + strings.Join(r.WAF.Products, ", ")
	case r.WAF.Checked:
		waf = styleSubtle.Render("none detected")
	}
	body = append(body, styleSubtle.Render("waf         ")+waf)

	if r.HTTP.Checked {
		body = append(body, "")
		for _, e := range r.HTTP.Endpoints {
			body = append(body, endpointLines(e)...)
		}
	}
	border := lipgloss.TerminalColor(colAccent)
	if len(phpInfo(r).cves) > 0 {
		border = colBad
	}
	return card("Web & technology", body, w, border)
}

// endpointLines is the status line for one HTTP endpoint plus its header gauge.
func endpointLines(e model.HTTPEndpoint) []string {
	if !e.Reachable {
		return []string{styleBad.Render(fmt.Sprintf("%d  unreachable", e.Port))}
	}
	code := 0
	if e.StatusCode != nil {
		code = *e.StatusCode
	}
	codeStyle := styleGood
	switch {
	case code >= 500:
		codeStyle = styleBad
	case code >= 300:
		codeStyle = styleWarn
	}
	line := fmt.Sprintf("%s  %s", lipgloss.NewStyle().Bold(true).Render(fmt.Sprintf("%-5d", e.Port)), codeStyle.Render(fmt.Sprint(code)))
	if t := deref(e.Title); t != "-" {
		line += "  " + t
	}
	lines := []string{line}
	if f := deref(e.FinalURL); f != "-" && f != e.URL {
		lines = append(lines, styleSubtle.Render("       → "+f))
	}
	s := e.SecurityHeaderSummary
	col := lipgloss.TerminalColor(colBad)
	switch s.Rating {
	case "Good":
		col = colGood
	case "Fair":
		col = colWarn
	}
	lines = append(lines, "       "+gauge(s.Score, s.MaxScore, 12, col)+" "+lipgloss.NewStyle().Foreground(col).Render(fmt.Sprintf("headers %s (%d/%d)", s.Rating, s.Score, s.MaxScore)))
	return lines
}

func findingsCard(r model.TargetResult, hints []model.Hint, w int) string {
	var body []string
	border := lipgloss.TerminalColor(colGood)
	const shown = 5
	for i, h := range hints {
		if i == shown {
			body = append(body, styleSubtle.Render(fmt.Sprintf("+ %d more on the Hints tab", len(hints)-shown)))
			break
		}
		port := ""
		if h.Port != nil {
			port = fmt.Sprintf("%d ", *h.Port)
		}
		tag := lipgloss.NewStyle().Bold(true).Foreground(sevColor(h.SeverityHint)).Render(fmt.Sprintf("%-8s", strings.ToUpper(h.SeverityHint)))
		body = append(body, tag+styleSubtle.Render(port+h.Category+"  ")+h.Reason)
	}
	if len(hints) > 0 {
		switch sevRank[hints[0].SeverityHint] {
		case 4, 3:
			border = colBad
		case 2:
			border = colWarn
		case 1:
			border = colInfo
		default:
			border = colMuted
		}
	}
	for _, e := range r.ScanErrors {
		body = append(body, styleWarn.Render("SCAN    ")+e)
		border = worse(border, colWarn)
	}
	if n := failedScripts(r); n > 0 {
		body = append(body, styleScriptErr.Render(fmt.Sprintf("NSE     %d script(s) errored", n))+styleSubtle.Render("  nmap-side; see the Overview tab"))
	}
	if len(body) == 0 {
		body = []string{styleGood.Render("✓ ") + styleSubtle.Render("nothing flagged by the checks that ran")}
	}
	return card("Findings", body, w, border)
}

// worse keeps a red border over an amber one.
func worse(cur, next lipgloss.TerminalColor) lipgloss.TerminalColor {
	if cur == lipgloss.TerminalColor(colBad) {
		return cur
	}
	return next
}

func failedScripts(r model.TargetResult) int {
	n := 0
	for _, s := range r.Services {
		for _, e := range s.NSE {
			if scan.IsScriptError(e.Output) {
				n++
			}
		}
	}
	for _, e := range r.HostNSE {
		if scan.IsScriptError(e.Output) {
			n++
		}
	}
	return n
}
