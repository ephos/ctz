// Package hints builds advisory prioritization hints.
package hints

import (
	"fmt"
	"sort"
	"strings"

	"ctz/internal/model"
)

type exposure struct {
	category, reason, severity string
}

var serviceExposure = map[int]exposure{
	22:    {"ssh", "External SSH service is reachable.", "medium"},
	445:   {"smb", "External SMB service is reachable.", "high"},
	3389:  {"rdp", "External RDP service is reachable.", "high"},
	5985:  {"winrm", "External WinRM service is reachable.", "high"},
	5986:  {"winrm", "External WinRM over TLS service is reachable.", "high"},
	1433:  {"database", "External Microsoft SQL Server service is reachable.", "high"},
	1521:  {"database", "External Oracle database service is reachable.", "high"},
	2379:  {"etcd", "External etcd service is reachable.", "high"},
	2380:  {"etcd", "External etcd peer service is reachable.", "high"},
	3306:  {"database", "External MySQL service is reachable.", "high"},
	5432:  {"database", "External PostgreSQL service is reachable.", "high"},
	5672:  {"messaging", "External AMQP/RabbitMQ service is reachable.", "medium"},
	6379:  {"redis", "External Redis service is reachable.", "high"},
	6443:  {"kubernetes", "External Kubernetes API service is reachable.", "high"},
	9200:  {"search", "External Elasticsearch service is reachable.", "high"},
	10250: {"kubernetes", "External kubelet service is reachable.", "high"},
	27017: {"database", "External MongoDB service is reachable.", "high"},
}

// Collector accumulates hints during a run.
type Collector struct {
	hints []model.Hint
}

// Add appends a hint.
func (c *Collector) Add(h model.Hint) { c.hints = append(c.hints, h) }

func intp(i int) *int { return &i }

// Exposure adds hints for externally reachable administrative services.
func (c *Collector) Exposure(target string, openPorts []int) {
	for _, p := range openPorts {
		e, ok := serviceExposure[p]
		if !ok {
			continue
		}
		c.Add(model.Hint{
			Target: target, Port: intp(p), SeverityHint: e.severity, Category: e.category, Reason: e.reason,
			Validation: "Manually confirm expected exposure, authentication, network controls, and business justification.",
		})
	}
}

// ServiceVersion adds info hints for observed product/version evidence.
func (c *Collector) ServiceVersion(target string, services []model.Service) {
	for _, s := range services {
		if s.Product == nil || s.Version == nil || *s.Product == "" || *s.Version == "" {
			continue
		}
		c.Add(model.Hint{
			Target: target, Port: intp(s.Port), SeverityHint: "info", Category: "service-version",
			Reason:     fmt.Sprintf("Service version evidence observed for %s %s; patch status requires validation.", *s.Product, *s.Version),
			Validation: "Confirm the detected version, vendor support status, and compensating controls before assigning risk.",
			Evidence:   map[string]any{"service": s.Name, "product": *s.Product, "version": *s.Version},
		})
	}
}

// TLS adds hints for expired or soon-to-expire certificates.
func (c *Collector) TLS(target string, certs []model.TLSCertificate) {
	for _, cert := range certs {
		var first *int
		if len(cert.Ports) > 0 {
			first = intp(cert.Ports[0])
		}
		switch {
		case cert.Expired:
			c.Add(model.Hint{
				Target: target, Port: first, SeverityHint: "medium", Category: "tls",
				Reason:     "A TLS certificate appears expired.",
				Validation: "Confirm certificate status and service ownership.",
				Evidence:   map[string]any{"expiration": cert.Expiration, "thumbprint": cert.Thumbprint, "ports": cert.Ports},
			})
		case cert.ExpiresSoon:
			c.Add(model.Hint{
				Target: target, Port: first, SeverityHint: "low", Category: "tls",
				Reason:     "A TLS certificate appears to expire within 30 days.",
				Validation: "Confirm renewal status and operational impact.",
				Evidence: map[string]any{
					"expiration": cert.Expiration, "days_until_expiration": cert.DaysUntilExpiration,
					"thumbprint": cert.Thumbprint, "ports": cert.Ports,
				},
			})
		}
	}
}

// HTTP adds PHP CVE and security-header hints for one endpoint.
func (c *Collector) HTTP(ep model.HTTPEndpoint) {
	for _, f := range ep.PHPCVEFindings {
		c.Add(model.Hint{
			Target: ep.URL, Port: intp(ep.Port), SeverityHint: "high", Category: "PHP CVE Exposure",
			Reason:     fmt.Sprintf("PHP %s banner indicates potential %s exposure; requires validation.", f.Version, f.CVE),
			Validation: f.Validation, Evidence: f,
		})
	}
	for _, f := range ep.SecurityHeaderFindings {
		c.Add(model.Hint{
			Target: ep.URL, Port: intp(ep.Port), SeverityHint: f.SeverityHint, Category: "HTTP Security Headers",
			Reason:     fmt.Sprintf("%s on %s; requires validation.", f.Title, ep.URL),
			Validation: "Treat as a hardening opportunity and confirm application context before reporting.",
			Evidence:   f.Evidence,
		})
	}
}

// Nuclei adds hints for medium+ nuclei findings.
func (c *Collector) Nuclei(findings []model.NucleiFinding) {
	for _, f := range findings {
		sev := strings.ToLower(fmt.Sprint(orEmpty(f.Severity)))
		if sev != "medium" && sev != "high" && sev != "critical" {
			continue
		}
		var port *int
		if f.Port != nil {
			var n int
			if _, err := fmt.Sscanf(*f.Port, "%d", &n); err == nil && isDigits(*f.Port) {
				port = &n
			}
		}
		title := firstNonEmpty(f.Name, f.TemplateID, "Nuclei finding")
		target := firstNonEmpty(f.MatchedAt, f.Host, "")
		c.Add(model.Hint{
			Target: target, Port: port, SeverityHint: sev, Category: "nuclei",
			Reason:     fmt.Sprintf("Nuclei reported %s finding '%s'. Treat this as a hypothesis requiring validation.", sev, title),
			Validation: "Manually confirm exploitability, application context, and whether the finding is a false positive.",
			Evidence:   map[string]any{"template_id": f.TemplateID, "matched_at": f.MatchedAt},
		})
	}
}

// Zap adds hints for low+ ZAP alerts.
func (c *Collector) Zap(alerts []model.ZapAlert) {
	for _, a := range alerts {
		sev := ZapSeverity(a.Risk)
		if sev == "info" {
			continue
		}
		title := firstNonEmpty(a.Alert, a.Name, "ZAP passive alert")
		c.Add(model.Hint{
			Target: a.Target, SeverityHint: sev, Category: "zap",
			Reason:     fmt.Sprintf("OWASP ZAP baseline reported '%s'. Treat this as passive-scan evidence requiring validation.", title),
			Validation: "Manually confirm the affected URLs, application context, and whether the passive alert is a false positive.",
			Evidence:   map[string]any{"plugin_id": a.PluginID, "risk": a.Risk, "confidence": a.Confidence},
		})
	}
}

// ZapSeverity maps a ZAP risk string onto a severity hint.
func ZapSeverity(risk any) string {
	n := strings.ToLower(strings.TrimSpace(fmt.Sprint(orEmpty(risk))))
	switch {
	case strings.Contains(n, "high"):
		return "high"
	case strings.Contains(n, "medium"):
		return "medium"
	case strings.Contains(n, "low"):
		return "low"
	}
	return "info"
}

// Sorted returns the hints ordered by severity string, category, target, port.
func (c *Collector) Sorted() []model.Hint {
	out := append([]model.Hint{}, c.hints...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.SeverityHint != b.SeverityHint {
			return a.SeverityHint < b.SeverityHint
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return portVal(a.Port) < portVal(b.Port)
	})
	return out
}

func portVal(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func orEmpty(v any) any {
	if v == nil {
		return ""
	}
	return v
}

func firstNonEmpty(vals ...any) string {
	for i, v := range vals {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
		if i == len(vals)-1 {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
