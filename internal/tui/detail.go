package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	xansi "github.com/charmbracelet/x/ansi"

	"ctz/internal/config"
	"ctz/internal/httpev"
	"ctz/internal/model"
	"ctz/internal/scan"
)

func kv(b *strings.Builder, k, v string) {
	fmt.Fprintf(b, "%s %s\n", styleSubtle.Render(fmt.Sprintf("%-14s", k)), v)
}

func deref(s *string) string {
	if s == nil || *s == "" {
		return "-"
	}
	return *s
}

// nseRun is the part of the scan settings needed to rebuild an nmap command.
type nseRun struct {
	scripts       string
	versionDetect bool
}

func nseRunFromConfig(c config.Config) nseRun {
	return nseRun{scripts: c.NSEScripts, versionDetect: c.ServiceVersion}
}

func nseRunFromOutput(out *model.Output) nseRun {
	n := nseRun{scripts: config.DefaultNSEScripts}
	if out == nil {
		return n
	}
	if s := out.ToolMetadata.Options.NSEScripts; s != nil {
		n.scripts = *s
	}
	if out.ToolMetadata.FeaturesEnabled != nil {
		n.versionDetect, _ = out.ToolMetadata.FeaturesEnabled.Get("service_version")
	}
	return n
}

func renderDetail(out *model.Output, r model.TargetResult, tab, width int) string {
	switch tab {
	case 0:
		return renderSummary(out, r, width)
	case 2:
		return renderTLS(r)
	case 3:
		return renderHTTP(r)
	case 4:
		return renderHints(out, r)
	}
	return renderOverview(r, nseRunFromOutput(out), width)
}

func renderOverview(r model.TargetResult, nr nseRun, width int) string {
	var b strings.Builder
	b.WriteString(styleHeading.Render(r.Target) + "\n\n")
	if !r.Resolved {
		b.WriteString(styleWarn.Render("Did not resolve.") + "\n")
		return b.String()
	}
	kv(&b, "IP address", r.IPAddress)
	conn := styleWarn.Render("no open ports")
	if r.Connected {
		conn = styleGood.Render("connected")
	}
	kv(&b, "Status", conn)
	for _, e := range r.ScanErrors {
		kv(&b, "Scan issue", styleWarn.Render(e))
	}
	if info := r.IPInfo; info != nil {
		kv(&b, "ASN", fmt.Sprint(info["asn"], " ", info["as_name"]))
		kv(&b, "Country", fmt.Sprint(info["country"]))
	}
	if r.WAF.Checked {
		w := "none detected"
		if r.WAF.Detected {
			w = strings.Join(r.WAF.Products, ", ")
		}
		kv(&b, "WAF", w)
	}
	if v := phpSummary(r); v != "" {
		kv(&b, "PHP", v)
	}
	b.WriteString("\n" + styleHeading.Render("Open ports") + "\n")
	if len(r.Services) == 0 {
		b.WriteString(styleSubtle.Render("none") + "\n")
	}
	for i, s := range r.Services {
		if i > 0 {
			b.WriteString("\n")
		}
		desc := strings.TrimSpace(strings.Join([]string{ptr(s.Name), ptr(s.Product), ptr(s.Version)}, " "))
		fmt.Fprintf(&b, "%s  %s\n", styleAccent.Render(fmt.Sprintf("%5d/%s", s.Port, s.Protocol)), desc)
		writeScripts(&b, "  ", s.NSE, width, scan.NmapCommand(r.Target, s.Port, nr.scripts, nr.versionDetect))
	}
	if len(r.HostNSE) > 0 {
		b.WriteString("\n" + styleHeading.Render("Host scripts") + "\n")
		entries := make([]model.NSEEntry, len(r.HostNSE))
		for i, n := range r.HostNSE {
			entries[i] = model.NSEEntry{ScriptID: n.ScriptID, Output: n.Output}
		}
		cmd := ""
		if len(r.Ports) > 0 {
			cmd = scan.NmapCommand(r.Target, r.Ports[0], nr.scripts, nr.versionDetect)
		}
		writeScripts(&b, "", entries, width, cmd)
	}
	return b.String()
}

const scriptErrorHint = "nmap itself raised an error in these scripts (likely an nmap bug in nmap.version_intensity(), not the target). Repeat the run with debug to see the errors:"

// writeScripts lists NSE results as bullets, grouped into scripts that ran and
// scripts that errored. The cause hint and a reproduce command appear once for
// the failed group rather than once per script. Lines are truncated to width.
func writeScripts(b *strings.Builder, indent string, entries []model.NSEEntry, width int, cmd string) {
	var ran, failed []model.NSEEntry
	for _, n := range entries {
		if scan.IsScriptError(n.Output) {
			failed = append(failed, n)
		} else {
			ran = append(ran, n)
		}
	}
	byID := func(s []model.NSEEntry) {
		sort.Slice(s, func(i, j int) bool { return s[i].ScriptID < s[j].ScriptID })
	}
	byID(ran)
	byID(failed)
	room := max(20, width-lipgloss.Width(indent)-4)
	line := func(prefix, text string) {
		fmt.Fprintf(b, "%s%s%s\n", indent, prefix, xansi.Truncate(text, room, "…"))
	}

	if len(ran) > 0 {
		line("", styleGood.Render(fmt.Sprintf("Scripts that ran (%d)", len(ran))))
		for _, n := range ran {
			out := firstLine(n.Output)
			if out == "" {
				out = styleSubtle.Render("(no output)")
			}
			line("  • ", styleSubtle.Render(n.ScriptID+":")+" "+out)
		}
	}
	if len(failed) > 0 {
		if len(ran) > 0 {
			b.WriteString("\n")
		}
		line("", styleScriptErr.Bold(true).Render(fmt.Sprintf("Scripts that failed (%d)", len(failed))))
		for _, n := range failed {
			line("  • ", styleScriptErr.Render(n.ScriptID))
		}
		for _, l := range strings.Split(xansi.Wordwrap(scriptErrorHint, room-2, ""), "\n") {
			line("  ", styleScriptErr.Render(l))
		}
		if cmd != "" {
			for i, l := range strings.Split(cmd, "\n") {
				prefix := "    "
				if i == 0 {
					prefix = "  $ "
				}
				line(prefix, styleSubtle.Render(l))
			}
		}
	}
}

// phpState is what HTTP evidence says about PHP for one target.
type phpState struct {
	checked bool     // HTTP evidence ran
	version string   // banner version, or ""
	cves    []string // CVEs the banner version is flagged for
}

func phpInfo(r model.TargetResult) phpState {
	st := phpState{checked: r.HTTP.Checked}
	for _, e := range r.HTTP.Endpoints {
		if len(e.PHPCVEFindings) > 0 {
			st.version = e.PHPCVEFindings[0].Version
			st.cves = nil
			for _, f := range e.PHPCVEFindings {
				st.cves = append(st.cves, f.CVE)
			}
			return st
		}
		flat := map[string]string{"server": deref(e.Server)}
		if e.Headers != nil {
			if v := e.Headers.Values["x-powered-by"]; v != nil {
				flat["x-powered-by"] = *v
			}
		}
		if v := httpev.PHPBanner(flat); v != "" && st.version == "" {
			st.version = v
		}
	}
	return st
}

// phpSummary reports what the HTTP evidence says about PHP: the banner version
// and whether it falls in the range flagged for the tracked CVEs. It is empty
// when HTTP evidence was not collected.
func phpSummary(r model.TargetResult) string {
	st := phpInfo(r)
	switch {
	case !st.checked:
		return ""
	case len(st.cves) > 0:
		return styleBad.Render("PHP "+st.version+" potentially affected by "+strings.Join(st.cves, ", ")) +
			styleSubtle.Render(" (banner only)")
	case st.version != "":
		return "PHP " + st.version + styleSubtle.Render(" (banner; not in the flagged range)")
	}
	return styleSubtle.Render("version not disclosed in Server / X-Powered-By")
}

func ptr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}

func renderTLS(r model.TargetResult) string {
	if len(r.TLSCertificates) == 0 {
		return styleSubtle.Render("No TLS certificates observed.")
	}
	var b strings.Builder
	for i, c := range r.TLSCertificates {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s\n", styleHeading.Render(fmt.Sprintf("Certificate on port(s) %v", c.Ports)))
		kv(&b, "Subject", c.Subject)
		kv(&b, "Issuer", c.Issuer)
		kv(&b, "SANs", strings.Join(c.SubjectAlternativeNames, ", "))
		kv(&b, "Thumbprint", c.Thumbprint)
		exp := c.Expiration
		switch {
		case c.Expired:
			exp = styleBad.Render(exp + " (expired)")
		case c.ExpiresSoon:
			exp = styleWarn.Render(exp + " (expires soon)")
		default:
			exp = styleGood.Render(exp)
		}
		kv(&b, "Expires", exp)
		if c.DaysUntilExpiration != nil {
			kv(&b, "Days left", fmt.Sprint(*c.DaysUntilExpiration))
		}
	}
	return b.String()
}

func renderHTTP(r model.TargetResult) string {
	if !r.HTTP.Checked {
		return styleSubtle.Render("HTTP evidence was not collected (enable it in the form).")
	}
	if len(r.HTTP.Endpoints) == 0 {
		return styleSubtle.Render("No HTTP/HTTPS endpoints.")
	}
	var b strings.Builder
	for i, e := range r.HTTP.Endpoints {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(styleHeading.Render(e.URL) + "\n")
		if !e.Reachable {
			b.WriteString(styleBad.Render("unreachable: "+deref(e.Error)) + "\n")
			continue
		}
		kv(&b, "Status", fmt.Sprint(*e.StatusCode))
		kv(&b, "Final URL", deref(e.FinalURL))
		kv(&b, "Title", deref(e.Title))
		kv(&b, "Server", deref(e.Server))
		s := e.SecurityHeaderSummary
		rating := fmt.Sprintf("%s (%d/%d)", s.Rating, s.Score, s.MaxScore)
		switch s.Rating {
		case "Good":
			rating = styleGood.Render(rating)
		case "Fair":
			rating = styleWarn.Render(rating)
		default:
			rating = styleBad.Render(rating)
		}
		kv(&b, "Headers", rating)
		if len(s.MissingHeaders) > 0 {
			kv(&b, "Missing", strings.Join(s.MissingHeaders, ", "))
		}
		for _, f := range e.PHPCVEFindings {
			fmt.Fprintf(&b, "%s PHP %s: potential %s\n", severityStyle("high").Render("[high]"), f.Version, f.CVE)
		}
		for _, f := range e.SecurityHeaderFindings {
			fmt.Fprintf(&b, "%s %s\n", severityStyle(f.SeverityHint).Render("["+f.SeverityHint+"]"), f.Title)
		}
	}
	return b.String()
}

func renderHints(out *model.Output, r model.TargetResult) string {
	var b strings.Builder
	n := 0
	for _, h := range out.PrioritizationHint {
		if h.Target != r.Target && !strings.Contains(h.Target, "://"+r.Target) {
			continue
		}
		n++
		port := ""
		if h.Port != nil {
			port = fmt.Sprintf(":%d", *h.Port)
		}
		fmt.Fprintf(&b, "%s %s%s\n", severityStyle(h.SeverityHint).Render("["+h.SeverityHint+"]"),
			lipgloss.NewStyle().Bold(true).Render(h.Category), styleSubtle.Render(port))
		fmt.Fprintf(&b, "  %s\n  %s\n\n", h.Reason, styleSubtle.Render(h.Validation))
	}
	if n == 0 {
		return styleSubtle.Render("No prioritization hints for this target.")
	}
	return b.String()
}
