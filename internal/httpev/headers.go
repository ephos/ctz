// Package httpev collects HTTP response evidence and assesses security headers.
package httpev

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"ctz/internal/model"
)

type headerDef struct{ key, name string }

// headerLookup lists every assessed header in output order.
var headerLookup = []headerDef{
	{"strict_transport_security", "Strict-Transport-Security"},
	{"content_security_policy", "Content-Security-Policy"},
	{"x_frame_options", "X-Frame-Options"},
	{"x_content_type_options", "X-Content-Type-Options"},
	{"referrer_policy", "Referrer-Policy"},
	{"permissions_policy", "Permissions-Policy"},
	{"cross_origin_opener_policy", "Cross-Origin-Opener-Policy"},
	{"cross_origin_embedder_policy", "Cross-Origin-Embedder-Policy"},
	{"cross_origin_resource_policy", "Cross-Origin-Resource-Policy"},
	{"access_control_allow_origin", "Access-Control-Allow-Origin"},
	{"access_control_allow_credentials", "Access-Control-Allow-Credentials"},
	{"cache_control", "Cache-Control"},
	{"server", "Server"},
	{"x_powered_by", "X-Powered-By"},
}

var scoreKeys = []string{
	"strict_transport_security",
	"content_security_policy",
	"x_frame_options",
	"x_content_type_options",
	"referrer_policy",
	"permissions_policy",
	"cross_origin_opener_policy",
	"cross_origin_embedder_policy",
	"cross_origin_resource_policy",
	"cache_control",
	"server",
	"x_powered_by",
}

// ScoreMax is the maximum advisory header score.
var ScoreMax = len(scoreKeys)

var headerName = func() map[string]string {
	m := map[string]string{}
	for _, h := range headerLookup {
		m[h.key] = h.name
	}
	return m
}()

var (
	hstsRe          = regexp.MustCompile(`(?i)(?:^|;)\s*max-age\s*=\s*(\d+)`)
	detailedVerRe   = regexp.MustCompile(`(?:/|\s)\d+(?:\.\d+)+`)
	frameAncestorRe = regexp.MustCompile(`(?i)(?:^|;)\s*frame-ancestors\b`)
	unsafeCSPRe     = regexp.MustCompile(`(?i)'unsafe-(?:inline|eval)'`)
	cacheGoodRe     = regexp.MustCompile(`(?i)\b(no-store|private|no-cache)\b`)
	cacheWeakRe     = regexp.MustCompile(`(?i)\bpublic\b|\bmax-age\s*=\s*[1-9]`)
)

func hsts(value string) (int, bool) {
	m := hstsRe.FindStringSubmatch(value)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

func res(value, assessment, rec string) model.HeaderResult {
	return model.HeaderResult{
		Present:        value != "",
		Value:          model.Str(value),
		Assessment:     assessment,
		Recommendation: model.Str(rec),
	}
}

// resP is like res but with an explicit present flag.
func resP(present bool, value, assessment, rec string) model.HeaderResult {
	r := res(value, assessment, rec)
	r.Present = present
	return r
}

func headerFinding(url string, port int, header string, r model.HeaderResult) *model.HeaderFinding {
	switch r.Assessment {
	case "good", "not_applicable", "not_present", "present":
		return nil
	}
	severity := "low"
	suffix := "requires review"
	switch r.Assessment {
	case "missing":
		suffix = "is missing"
	case "weak":
		suffix = "appears weak"
	case "misconfigured":
		suffix = "appears misconfigured"
	case "potentially_misconfigured":
		suffix = "may be misconfigured"
		severity = "medium"
	case "informational_exposure":
		suffix = "exposes implementation details"
		severity = "info"
	}
	ev := model.FindingEvidence{Header: header}
	if r.Value != nil {
		ev.Value = *r.Value
	}
	return &model.HeaderFinding{
		Category:       "HTTP Security Headers",
		SeverityHint:   severity,
		Title:          fmt.Sprintf("%s header %s", header, suffix),
		Target:         url,
		Port:           port,
		Evidence:       ev,
		Recommendation: r.Recommendation,
	}
}

// AssessSecurityHeaders scores the supplied (lower-cased name -> value)
// headers. Absent headers are the empty string.
func AssessSecurityHeaders(headers map[string]string, scheme, url string, port int) (*model.Ordered[model.HeaderResult], model.HeaderSummary, []model.HeaderFinding) {
	values := map[string]string{}
	for _, h := range headerLookup {
		values[h.key] = headers[strings.ToLower(h.name)]
	}
	results := model.NewOrdered[model.HeaderResult]()

	// Strict-Transport-Security
	hv := values["strict_transport_security"]
	age, ageOK := hsts(hv)
	switch {
	case scheme != "https":
		results.Set("strict_transport_security", resP(hv != "", hv, "not_applicable", ""))
	case hv == "":
		results.Set("strict_transport_security", res("", "missing", "Consider enabling Strict-Transport-Security for HTTPS endpoints."))
	case !ageOK || age < 31536000:
		results.Set("strict_transport_security", res(hv, "weak", "Consider an HSTS max-age of at least one year after validation."))
	default:
		results.Set("strict_transport_security", res(hv, "good", ""))
	}

	// Content-Security-Policy
	csp := values["content_security_policy"]
	switch {
	case csp == "":
		results.Set("content_security_policy", res("", "missing", "Consider implementing a Content-Security-Policy."))
	case unsafeCSPRe.MatchString(csp):
		results.Set("content_security_policy", res(csp, "weak", "Review whether unsafe CSP directives can be removed."))
	default:
		results.Set("content_security_policy", res(csp, "good", ""))
	}

	// X-Frame-Options
	xfo := values["x_frame_options"]
	nxfo := strings.ToUpper(strings.TrimSpace(xfo))
	switch {
	case xfo == "" && csp != "" && frameAncestorRe.MatchString(csp):
		results.Set("x_frame_options", resP(false, "", "not_applicable", ""))
	case xfo == "":
		results.Set("x_frame_options", res("", "missing", "Consider DENY, SAMEORIGIN, or CSP frame-ancestors for clickjacking protection."))
	case nxfo == "DENY" || nxfo == "SAMEORIGIN":
		results.Set("x_frame_options", res(xfo, "good", ""))
	case strings.HasPrefix(nxfo, "ALLOW-FROM"):
		results.Set("x_frame_options", res(xfo, "weak", "ALLOW-FROM is obsolete in modern browsers; prefer CSP frame-ancestors."))
	default:
		results.Set("x_frame_options", res(xfo, "misconfigured", "Use DENY or SAMEORIGIN, or define CSP frame-ancestors."))
	}

	// X-Content-Type-Options
	xcto := values["x_content_type_options"]
	switch {
	case xcto == "":
		results.Set("x_content_type_options", res("", "missing", "Consider setting X-Content-Type-Options to nosniff."))
	case strings.ToLower(strings.TrimSpace(xcto)) == "nosniff":
		results.Set("x_content_type_options", res(xcto, "good", ""))
	default:
		results.Set("x_content_type_options", res(xcto, "misconfigured", "Set X-Content-Type-Options to nosniff."))
	}

	// Referrer-Policy
	rp := values["referrer_policy"]
	switch {
	case rp == "":
		results.Set("referrer_policy", res("", "missing", "Consider defining a Referrer-Policy appropriate for the application."))
	case strings.Contains(strings.ToLower(rp), "unsafe-url"):
		results.Set("referrer_policy", res(rp, "weak", "Avoid unsafe-url unless the application explicitly requires it."))
	default:
		results.Set("referrer_policy", res(rp, "good", ""))
	}

	// Permissions-Policy
	pp := values["permissions_policy"]
	if pp == "" {
		results.Set("permissions_policy", res("", "missing", "Consider a Permissions-Policy that disables unneeded browser features."))
	} else {
		results.Set("permissions_policy", res(pp, "good", ""))
	}

	// COOP
	coop := values["cross_origin_opener_policy"]
	switch {
	case coop == "":
		results.Set("cross_origin_opener_policy", res("", "missing", "Consider Cross-Origin-Opener-Policy for stronger document isolation."))
	case strings.ToLower(strings.TrimSpace(coop)) == "same-origin":
		results.Set("cross_origin_opener_policy", res(coop, "good", ""))
	default:
		results.Set("cross_origin_opener_policy", res(coop, "weak", "Review whether same-origin is appropriate for this endpoint."))
	}

	// COEP
	coep := values["cross_origin_embedder_policy"]
	switch l := strings.ToLower(strings.TrimSpace(coep)); {
	case coep == "":
		results.Set("cross_origin_embedder_policy", res("", "missing", "Consider Cross-Origin-Embedder-Policy where isolation is required."))
	case l == "require-corp" || l == "credentialless":
		results.Set("cross_origin_embedder_policy", res(coep, "good", ""))
	default:
		results.Set("cross_origin_embedder_policy", res(coep, "weak", "Review the Cross-Origin-Embedder-Policy value."))
	}

	// CORP
	corp := values["cross_origin_resource_policy"]
	switch l := strings.ToLower(strings.TrimSpace(corp)); {
	case corp == "":
		results.Set("cross_origin_resource_policy", res("", "missing", "Consider Cross-Origin-Resource-Policy for resources that should be isolated."))
	case l == "same-origin" || l == "same-site":
		results.Set("cross_origin_resource_policy", res(corp, "good", ""))
	default:
		results.Set("cross_origin_resource_policy", res(corp, "weak", "Review whether this Cross-Origin-Resource-Policy value is intended."))
	}

	// CORS
	acao := values["access_control_allow_origin"]
	acac := values["access_control_allow_credentials"]
	acacTrue := strings.ToLower(strings.TrimSpace(acac)) == "true"
	acaoWild := strings.TrimSpace(acao) == "*"
	switch {
	case acao == "":
		results.Set("access_control_allow_origin", resP(false, "", "not_present", ""))
	case acaoWild && acacTrue:
		results.Set("access_control_allow_origin", res(acao, "potentially_misconfigured", "Avoid wildcard Access-Control-Allow-Origin with credentialed requests."))
	case acaoWild:
		results.Set("access_control_allow_origin", res(acao, "weak", "Review whether wildcard CORS is intended for this endpoint."))
	default:
		results.Set("access_control_allow_origin", res(acao, "good", ""))
	}
	switch {
	case acac == "":
		results.Set("access_control_allow_credentials", resP(false, "", "not_present", ""))
	case acacTrue && acao != "" && acaoWild:
		results.Set("access_control_allow_credentials", res(acac, "potentially_misconfigured", "Avoid credentialed CORS responses with wildcard origins."))
	case acacTrue:
		results.Set("access_control_allow_credentials", res(acac, "present", "Confirm credentialed CORS is required for this endpoint."))
	default:
		results.Set("access_control_allow_credentials", res(acac, "weak", "Use true only when credentialed CORS is explicitly required."))
	}

	// Cache-Control
	cc := values["cache_control"]
	switch {
	case cc == "":
		results.Set("cache_control", res("", "missing", "Consider Cache-Control directives for sensitive or authenticated responses."))
	case cacheGoodRe.MatchString(cc):
		results.Set("cache_control", res(cc, "good", ""))
	case cacheWeakRe.MatchString(cc):
		results.Set("cache_control", res(cc, "weak", "Review cacheability in the context of the response content."))
	default:
		results.Set("cache_control", res(cc, "present", ""))
	}

	// Server
	sv := values["server"]
	switch {
	case sv == "":
		results.Set("server", resP(false, "", "good", ""))
	case detailedVerRe.MatchString(sv):
		results.Set("server", res(sv, "informational_exposure", "Consider suppressing detailed server version information."))
	default:
		results.Set("server", res(sv, "present", ""))
	}

	// X-Powered-By
	xpb := values["x_powered_by"]
	if xpb == "" {
		results.Set("x_powered_by", resP(false, "", "good", ""))
	} else {
		results.Set("x_powered_by", res(xpb, "informational_exposure", "Consider suppressing X-Powered-By unless it is operationally required."))
	}

	score := 0
	var missing []string
	for _, k := range scoreKeys {
		r, _ := results.Get(k)
		switch r.Assessment {
		case "good", "not_applicable", "present":
			score++
		case "missing":
			missing = append(missing, headerName[k])
		}
	}
	if missing == nil {
		missing = []string{}
	}
	rating := "Needs Attention"
	switch {
	case score >= 10:
		rating = "Good"
	case score >= 7:
		rating = "Fair"
	case score >= 4:
		rating = "Needs Review"
	}
	summary := model.HeaderSummary{Score: score, MaxScore: len(scoreKeys), Rating: rating, MissingHeaders: missing}

	findings := []model.HeaderFinding{}
	for _, k := range results.Keys {
		r, _ := results.Get(k)
		if f := headerFinding(url, port, headerName[k], r); f != nil {
			findings = append(findings, *f)
		}
	}
	return results, summary, findings
}
