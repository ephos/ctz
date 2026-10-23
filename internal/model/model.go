// Package model defines the JSON result types shared by every stage.
package model

import (
	"bytes"
	"encoding/json"
)

// Ordered is a string-keyed map that marshals its keys in insertion order,
// matching Python's dict ordering in the original script's output.
type Ordered[T any] struct {
	Keys   []string
	Values map[string]T
}

// NewOrdered returns an empty Ordered.
func NewOrdered[T any]() *Ordered[T] {
	return &Ordered[T]{Values: map[string]T{}}
}

// Set inserts or replaces a key, preserving first-insertion order.
func (o *Ordered[T]) Set(key string, v T) {
	if _, ok := o.Values[key]; !ok {
		o.Keys = append(o.Keys, key)
	}
	o.Values[key] = v
}

// Get returns the value for key.
func (o *Ordered[T]) Get(key string) (T, bool) {
	v, ok := o.Values[key]
	return v, ok
}

// MarshalJSON implements json.Marshaler.
func (o Ordered[T]) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.Keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := json.Marshal(o.Values[k])
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON implements json.Unmarshaler (key order is preserved).
func (o *Ordered[T]) UnmarshalJSON(data []byte) error {
	o.Keys = nil
	o.Values = map[string]T{}
	dec := json.NewDecoder(bytes.NewReader(data))
	if _, err := dec.Token(); err != nil {
		return err
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return err
		}
		var v T
		if err := dec.Decode(&v); err != nil {
			return err
		}
		o.Set(kt.(string), v)
	}
	return nil
}

// Str returns a pointer to s, or nil when s is empty.
func Str(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// NSEEntry is one NSE script result attached to a port.
type NSEEntry struct {
	Port     int    `json:"port"`
	ScriptID string `json:"script_id"`
	Output   string `json:"output"`
}

// HostNSE is one host-level NSE script result.
type HostNSE struct {
	ScriptID string `json:"script_id"`
	Output   string `json:"output"`
}

// Service is an open port with nmap service data.
type Service struct {
	Port       int        `json:"port"`
	Protocol   string     `json:"protocol"`
	State      string     `json:"state"`
	Name       *string    `json:"name"`
	Product    *string    `json:"product"`
	Version    *string    `json:"version"`
	Extrainfo  *string    `json:"extrainfo"`
	Tunnel     *string    `json:"tunnel"`
	Confidence *string    `json:"confidence"`
	NSE        []NSEEntry `json:"nse,omitempty"`
}

// TLSCertificate is certificate metadata for one or more ports.
type TLSCertificate struct {
	Ports                   []int    `json:"ports"`
	Issuer                  string   `json:"issuer"`
	Subject                 string   `json:"subject"`
	SubjectAlternativeNames []string `json:"subject_alternative_names"`
	Thumbprint              string   `json:"thumbprint"`
	Expiration              string   `json:"expiration"`
	Expired                 bool     `json:"expired"`
	ExpiresSoon             bool     `json:"expires_soon"`
	DaysUntilExpiration     *int     `json:"days_until_expiration"`
}

// HeaderResult is the assessment of one security header.
type HeaderResult struct {
	Present        bool    `json:"present"`
	Value          *string `json:"value"`
	Assessment     string  `json:"assessment"`
	Recommendation *string `json:"recommendation"`
}

// HeaderSummary is the advisory security header score.
type HeaderSummary struct {
	Score          int      `json:"score"`
	MaxScore       int      `json:"max_score"`
	Rating         string   `json:"rating"`
	MissingHeaders []string `json:"missing_headers"`
}

// FindingEvidence is the evidence of a header finding.
type FindingEvidence struct {
	Header string `json:"header"`
	Value  string `json:"value,omitempty"`
}

// HeaderFinding is an advisory hardening observation.
type HeaderFinding struct {
	Category       string          `json:"category"`
	SeverityHint   string          `json:"severity_hint"`
	Title          string          `json:"title"`
	Target         string          `json:"target"`
	Port           int             `json:"port"`
	Evidence       FindingEvidence `json:"evidence"`
	Recommendation *string         `json:"recommendation"`
}

// PHPFinding is a banner-based PHP CVE exposure observation.
type PHPFinding struct {
	CVE             string  `json:"cve"`
	Version         string  `json:"version"`
	Assessment      string  `json:"assessment"`
	DetectionMethod string  `json:"detection_method"`
	Header          string  `json:"header"`
	Value           string  `json:"value"`
	FixedVersion    *string `json:"fixed_version"`
	Validation      string  `json:"validation"`
	Recommendation  string  `json:"recommendation"`
}

// HTTPEndpoint is the evidence collected from one HTTP(S) endpoint.
type HTTPEndpoint struct {
	URL                    string                 `json:"url"`
	Port                   int                    `json:"port"`
	Reachable              bool                   `json:"reachable"`
	StatusCode             *int                   `json:"status_code"`
	FinalURL               *string                `json:"final_url"`
	Title                  *string                `json:"title"`
	Server                 *string                `json:"server"`
	Headers                *Ordered[*string]      `json:"headers"`
	SecurityHeaders        *Ordered[HeaderResult] `json:"security_headers"`
	SecurityHeaderSummary  HeaderSummary          `json:"security_header_summary"`
	SecurityHeaderFindings []HeaderFinding        `json:"security_header_findings"`
	PHPCVEFindings         []PHPFinding           `json:"php_cve_findings"`
	Error                  *string                `json:"error"`
}

// HTTPResult is the per-target HTTP evidence container.
type HTTPResult struct {
	Checked   bool           `json:"checked"`
	Endpoints []HTTPEndpoint `json:"endpoints"`
}

// WAFEndpoint is the WAF detection result for one endpoint.
type WAFEndpoint struct {
	URL      string   `json:"url"`
	Port     int      `json:"port"`
	Checked  bool     `json:"checked"`
	Detected bool     `json:"detected"`
	Products []string `json:"products"`
}

// WAFResult is the per-target WAF container.
type WAFResult struct {
	Checked   bool          `json:"checked"`
	Detected  bool          `json:"detected"`
	Products  []string      `json:"products"`
	Endpoints []WAFEndpoint `json:"endpoints"`
}

// TargetResult is everything learned about one hostname.
type TargetResult struct {
	Target          string           `json:"target"`
	IPAddress       string           `json:"ipaddress"`
	Resolved        bool             `json:"resolved"`
	Connected       bool             `json:"connected"`
	Ports           []int            `json:"ports"`
	Services        []Service        `json:"services"`
	TLSCertificates []TLSCertificate `json:"tls_certificates"`
	WAF             WAFResult        `json:"waf"`
	HTTP            HTTPResult       `json:"http"`
	NSE             []NSEEntry       `json:"nse"`
	HostNSE         []HostNSE        `json:"host_nse"`
	IPInfo          map[string]any   `json:"ipinfo,omitempty"`
	ScanErrors      []string         `json:"scan_errors,omitempty"`
}

// Hint is an advisory prioritization hint.
type Hint struct {
	Target       string `json:"target"`
	Port         *int   `json:"port,omitempty"`
	SeverityHint string `json:"severity_hint"`
	Category     string `json:"category"`
	Reason       string `json:"reason"`
	Validation   string `json:"validation"`
	Evidence     any    `json:"evidence,omitempty"`
}

// NucleiFinding is a normalized nuclei result.
type NucleiFinding struct {
	TemplateID any            `json:"template_id"`
	Name       any            `json:"name"`
	Severity   any            `json:"severity"`
	MatchedAt  any            `json:"matched_at"`
	Host       any            `json:"host"`
	Port       *string        `json:"port"`
	Type       any            `json:"type"`
	Raw        map[string]any `json:"raw"`
}

// NucleiResult is the top-level nuclei container.
type NucleiResult struct {
	Checked    bool            `json:"checked"`
	Severities string          `json:"severities"`
	Findings   []NucleiFinding `json:"findings"`
	Errors     []string        `json:"errors"`
}

// ZapAlert is a normalized ZAP passive alert.
type ZapAlert struct {
	Target         string         `json:"target"`
	PluginID       string         `json:"plugin_id"`
	Alert          any            `json:"alert"`
	Name           any            `json:"name"`
	Risk           any            `json:"risk"`
	Confidence     any            `json:"confidence"`
	RiskDesc       any            `json:"risk_desc"`
	Description    any            `json:"description"`
	Solution       any            `json:"solution"`
	Reference      any            `json:"reference"`
	CWEID          string         `json:"cwe_id"`
	WASCID         string         `json:"wasc_id"`
	InstancesCount int            `json:"instances_count"`
	Instances      []any          `json:"instances"`
	Raw            map[string]any `json:"raw"`
}

// ZapFinding is the baseline scan result for one endpoint.
type ZapFinding struct {
	Target        string         `json:"target"`
	Mode          string         `json:"mode"`
	Alerts        []ZapAlert     `json:"alerts"`
	Errors        []string       `json:"errors"`
	ExitCode      *int           `json:"exit_code"`
	StdoutExcerpt string         `json:"stdout_excerpt,omitempty"`
	StderrExcerpt string         `json:"stderr_excerpt,omitempty"`
	RawSummary    map[string]any `json:"raw_summary,omitempty"`
}

// ZapResult is the top-level ZAP container.
type ZapResult struct {
	Checked        bool         `json:"checked"`
	Mode           string       `json:"mode"`
	Image          *string      `json:"image"`
	SpiderMinutes  int          `json:"spider_minutes"`
	TimeoutMinutes int          `json:"timeout_minutes"`
	MaxEndpoints   int          `json:"max_endpoints"`
	Findings       []ZapFinding `json:"findings"`
	Errors         []string     `json:"errors"`
}

// Registration is domain registration data (RDAP/WHOIS).
type Registration struct {
	RegistrarWhoisServer    *string `json:"registrar_whois_server"`
	RegistrarURL            *string `json:"registrar_url"`
	UpdatedDate             *string `json:"updated_date"`
	CreationDate            *string `json:"creation_date"`
	ExpirationDate          *string `json:"expiration_date"`
	Registrar               *string `json:"registrar"`
	RegistrantName          *string `json:"registrant_name"`
	RegistrantOrganization  *string `json:"registrant_organization"`
	RegistrantStreet        *string `json:"registrant_street"`
	RegistrantCity          *string `json:"registrant_city"`
	RegistrantStateProvince *string `json:"registrant_state_province"`
	RegistrantPostalCode    *string `json:"registrant_postal_code"`
	RegistrantCountry       *string `json:"registrant_country"`
	RegistrantPhone         *string `json:"registrant_phone"`
}

// Output is the top-level JSON document.
type Output struct {
	Domain             string                  `json:"domain,omitempty"`
	Domains            []string                `json:"domains,omitempty"`
	SourceIP           *string                 `json:"source_ip"`
	RunDatetime        string                  `json:"run_datetime"`
	Registration       *Registration           `json:"registration,omitempty"`
	Registrations      map[string]Registration `json:"registrations,omitempty"`
	Results            []TargetResult          `json:"results"`
	Nuclei             NucleiResult            `json:"nuclei"`
	Zap                ZapResult               `json:"zap"`
	PrioritizationHint []Hint                  `json:"prioritization_hints"`
	ToolMetadata       ToolMetadata            `json:"tool_metadata"`
}

// ToolMetadata describes the run for downstream report agents.
type ToolMetadata struct {
	SchemaVersion   string         `json:"schema_version"`
	FeaturesEnabled *Ordered[bool] `json:"features_enabled"`
	Options         ToolOptions    `json:"options"`
	Notes           []string       `json:"notes"`
}

// ToolOptions are the selected option values.
type ToolOptions struct {
	NSEScripts       *string `json:"nse_scripts"`
	HTTPTimeout      int     `json:"http_timeout"`
	NucleiSeverities *string `json:"nuclei_severities"`
	NucleiTemplates  *string `json:"nuclei_templates"`
	ZapImage         *string `json:"zap_image"`
	ZapSpiderMinutes *int    `json:"zap_spider_minutes"`
	ZapTimeoutMin    *int    `json:"zap_timeout_minutes"`
	ZapMaxEndpoints  *int    `json:"zap_max_endpoints"`
	RateDelay        float64 `json:"rate_delay"`
}
