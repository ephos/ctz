package httpev

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"ctz/internal/model"
)

// BodyLimitBytes caps how much of a response body is read.
const BodyLimitBytes = 512 * 1024

// PortSchemes maps well-known web ports to their scheme.
var PortSchemes = map[int]string{
	80: "http", 8000: "http", 8008: "http", 8080: "http", 8081: "http", 8888: "http", 9000: "http", 9080: "http",
	443: "https", 8433: "https", 8443: "https", 9443: "https", 10443: "https",
}

// Candidate is an HTTP(S) endpoint worth probing.
type Candidate struct {
	URL    string
	Port   int
	Scheme string
}

// EndpointURL renders scheme://host[:port], omitting default ports.
func EndpointURL(host string, port int, scheme string) string {
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return fmt.Sprintf("%s://%s", scheme, host)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

func schemeFromService(port int, svc *model.Service) string {
	mapped := PortSchemes[port]
	if svc == nil {
		return mapped
	}
	name, tunnel := "", ""
	if svc.Name != nil {
		name = strings.ToLower(*svc.Name)
	}
	if svc.Tunnel != nil {
		tunnel = strings.ToLower(*svc.Tunnel)
	}
	switch {
	case tunnel == "ssl" && (strings.Contains(name, "http") || port == 443 || port == 8443 || port == 9443 || port == 10443):
		return "https"
	case name == "https" || name == "ssl/http":
		return "https"
	case strings.Contains(name, "http"):
		if mapped != "" {
			return mapped
		}
		return "http"
	}
	return mapped
}

// Candidates picks the HTTP(S) endpoints among a host's open ports.
func Candidates(host string, openPorts []int, services []model.Service) []Candidate {
	byPort := map[int]*model.Service{}
	for i := range services {
		byPort[services[i].Port] = &services[i]
	}
	var out []Candidate
	for _, p := range openPorts {
		scheme := schemeFromService(p, byPort[p])
		if scheme == "" {
			continue
		}
		out = append(out, Candidate{URL: EndpointURL(host, p, scheme), Port: p, Scheme: scheme})
	}
	return out
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// ExtractTitle returns the whitespace-normalized page title, if any.
func ExtractTitle(body []byte) *string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return nil
	}
	t := html.UnescapeString(strings.ToValidUTF8(string(m[1]), ""))
	t = strings.Join(strings.Fields(t), " ")
	return model.Str(t)
}

var selectedHeaders = []string{
	"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
	"Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
	"Cross-Origin-Resource-Policy", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
	"Cache-Control", "X-Powered-By",
}

// SelectedHeaderValues extracts the headers recorded in the "headers" object.
func SelectedHeaderValues(h http.Header) *model.Ordered[*string] {
	o := model.NewOrdered[*string]()
	for _, name := range selectedHeaders {
		v := h.Get(name)
		o.Set(strings.ToLower(name), model.Str(v))
	}
	return o
}

// Client returns an HTTP client that tolerates untrusted certificates.
func Client(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // inventory of untrusted certs is intended
			DisableKeepAlives: true,
		},
	}
}

// Fetch performs one conservative GET and assesses the response.
func Fetch(ctx context.Context, client *http.Client, c Candidate) model.HTTPEndpoint {
	ep := model.HTTPEndpoint{
		URL:             c.URL,
		Port:            c.Port,
		Headers:         model.NewOrdered[*string](),
		SecurityHeaders: model.NewOrdered[model.HeaderResult](),
		SecurityHeaderSummary: model.HeaderSummary{
			MaxScore: ScoreMax, Rating: "Not Checked", MissingHeaders: []string{},
		},
		SecurityHeaderFindings: []model.HeaderFinding{},
		PHPCVEFindings:         []model.PHPFinding{},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		e := err.Error()
		ep.Error = &e
		return ep
	}
	req.Header.Set("User-Agent", "connectivity-test-zone")
	resp, err := client.Do(req)
	if err != nil {
		e := err.Error()
		ep.Error = &e
		return ep
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, BodyLimitBytes))

	server := resp.Header.Get("Server")
	selected := SelectedHeaderValues(resp.Header)
	flat := map[string]string{"server": server}
	for _, k := range selected.Keys {
		if v := selected.Values[k]; v != nil {
			flat[k] = *v
		}
	}
	status := resp.StatusCode
	final := resp.Request.URL.String()
	secHeaders, summary, findings := AssessSecurityHeaders(flat, c.Scheme, c.URL, c.Port)

	ep.Reachable = true
	ep.StatusCode = &status
	ep.FinalURL = &final
	ep.Title = ExtractTitle(body)
	ep.Server = model.Str(server)
	ep.Headers = selected
	ep.SecurityHeaders = secHeaders
	ep.SecurityHeaderSummary = summary
	ep.SecurityHeaderFindings = findings
	ep.PHPCVEFindings = AssessPHPCVE(flat)
	return ep
}
