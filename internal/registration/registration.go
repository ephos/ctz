// Package registration looks up domain registration data via RDAP and whois.
package registration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ctz/internal/execx"
	"ctz/internal/model"
)

var keys = []string{
	"registrar_whois_server", "registrar_url", "updated_date", "creation_date", "expiration_date", "registrar",
	"registrant_name", "registrant_organization", "registrant_street", "registrant_city",
	"registrant_state_province", "registrant_postal_code", "registrant_country", "registrant_phone",
}

type fields map[string]string

func (f fields) merge(fallback fields, overwrite bool) {
	for k, v := range fallback {
		if !overwrite && f[k] != "" {
			continue
		}
		if v == "" {
			continue
		}
		f[k] = v
	}
}

func (f fields) toModel() model.Registration {
	return model.Registration{
		RegistrarWhoisServer: model.Str(f["registrar_whois_server"]), RegistrarURL: model.Str(f["registrar_url"]),
		UpdatedDate: model.Str(f["updated_date"]), CreationDate: model.Str(f["creation_date"]),
		ExpirationDate: model.Str(f["expiration_date"]), Registrar: model.Str(f["registrar"]),
		RegistrantName: model.Str(f["registrant_name"]), RegistrantOrganization: model.Str(f["registrant_organization"]),
		RegistrantStreet: model.Str(f["registrant_street"]), RegistrantCity: model.Str(f["registrant_city"]),
		RegistrantStateProvince: model.Str(f["registrant_state_province"]),
		RegistrantPostalCode:    model.Str(f["registrant_postal_code"]),
		RegistrantCountry:       model.Str(f["registrant_country"]), RegistrantPhone: model.Str(f["registrant_phone"]),
	}
}

func firstWhois(m map[string][]string, names ...string) string {
	for _, n := range names {
		for _, v := range m[strings.ToLower(n)] {
			if v != "" {
				return v
			}
		}
	}
	return ""
}

// ParseWhois extracts registration fields from raw whois output.
func ParseWhois(raw string) map[string]string {
	m := map[string][]string{}
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.Join(strings.Fields(strings.ToLower(k)), " ")
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		m[k] = append(m[k], v)
	}
	return map[string]string{
		"registrar_whois_server": firstWhois(m, "registrar whois server", "whois server"),
		"registrar_url":          firstWhois(m, "registrar url", "url of the icann whois inaccuracy complaint form"),
		"updated_date":           firstWhois(m, "updated date", "last updated on"),
		"creation_date":          firstWhois(m, "creation date", "created on", "created"),
		"expiration_date": firstWhois(m, "registrar registration expiration date", "registry expiry date",
			"expiration date", "expires on", "expiry date"),
		"registrar":                 firstWhois(m, "registrar"),
		"registrant_name":           firstWhois(m, "registrant name"),
		"registrant_organization":   firstWhois(m, "registrant organization", "registrant org"),
		"registrant_street":         firstWhois(m, "registrant street", "registrant address"),
		"registrant_city":           firstWhois(m, "registrant city"),
		"registrant_state_province": firstWhois(m, "registrant state/province", "registrant state province", "registrant state"),
		"registrant_postal_code":    firstWhois(m, "registrant postal code", "registrant zip code"),
		"registrant_country":        firstWhois(m, "registrant country"),
		"registrant_phone":          firstWhois(m, "registrant phone", "registrant phone number"),
	}
}

// NormalizeWhoisServer reduces a server string or URL to a bare host.
func NormalizeWhoisServer(server string) string {
	s := strings.TrimSpace(server)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			if u.Host != "" {
				s = u.Host
			} else {
				s = u.Path
			}
		}
	}
	s, _, _ = strings.Cut(s, "/")
	return strings.TrimSpace(s)
}

// Client resolves registration data.
type Client struct {
	Run           execx.Runner
	HTTP          *http.Client
	BootstrapURL  string
	mu            sync.Mutex
	bootstrap     map[string]any
	bootstrapDone bool
	cache         map[string]model.Registration
}

// New returns a Client using the default runner and IANA bootstrap.
func New(run execx.Runner) *Client {
	return &Client{
		Run: run, HTTP: &http.Client{Timeout: 8 * time.Second},
		BootstrapURL: "https://data.iana.org/rdap/dns.json", cache: map[string]model.Registration{},
	}
}

func (c *Client) readJSON(ctx context.Context, u string) map[string]any {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "connectivity-test-zone")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var m map[string]any
	if json.NewDecoder(resp.Body).Decode(&m) != nil {
		return nil
	}
	return m
}

// BaseURL selects the RDAP endpoint for domain from a bootstrap document.
func BaseURL(bootstrap map[string]any, domain string) string {
	services, _ := bootstrap["services"].([]any)
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(domain, ".")), ".")
	for i := range labels {
		candidate := strings.Join(labels[i:], ".")
		for _, s := range services {
			pair, ok := s.([]any)
			if !ok || len(pair) < 2 {
				continue
			}
			tlds, _ := pair[0].([]any)
			urls, _ := pair[1].([]any)
			match := false
			for _, t := range tlds {
				if strings.ToLower(asString(t)) == candidate {
					match = true
				}
			}
			if !match {
				continue
			}
			for _, u := range urls {
				if us, ok := u.(string); ok && (strings.HasPrefix(us, "http://") || strings.HasPrefix(us, "https://")) {
					return strings.TrimRight(us, "/")
				}
			}
		}
	}
	return ""
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func eventDate(p map[string]any, actions ...string) string {
	events, _ := p["events"].([]any)
	for _, e := range events {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		a := strings.ToLower(asString(em["eventAction"]))
		d := asString(em["eventDate"])
		for _, want := range actions {
			if a == strings.ToLower(want) && d != "" {
				return d
			}
		}
	}
	return ""
}

func firstEntity(p map[string]any, role string) map[string]any {
	entities, _ := p["entities"].([]any)
	for _, e := range entities {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		roles, _ := em["roles"].([]any)
		for _, r := range roles {
			if strings.ToLower(asString(r)) == role {
				return em
			}
		}
	}
	return nil
}

func vcardValues(e map[string]any, name string) []any {
	vc, _ := e["vcardArray"].([]any)
	if len(vc) < 2 {
		return nil
	}
	items, _ := vc[1].([]any)
	var out []any
	for _, it := range items {
		l, ok := it.([]any)
		if !ok || len(l) < 4 {
			continue
		}
		if l[0] == name {
			out = append(out, l[3])
		}
	}
	return out
}

func joinNonEmpty(l []any) string {
	var parts []string
	for _, v := range l {
		if s := strings.TrimSpace(asAny(v)); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ", ")
}

func asAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return "None"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func vcardText(e map[string]any, name string) string {
	for _, v := range vcardValues(e, name) {
		switch t := v.(type) {
		case string:
			if s := strings.TrimSpace(t); s != "" {
				return s
			}
		case []any:
			if s := joinNonEmpty(t); s != "" {
				return s
			}
		}
	}
	return ""
}

func entityName(e map[string]any) string {
	if s := vcardText(e, "fn"); s != "" {
		return s
	}
	return vcardText(e, "name")
}

func linkHref(e map[string]any, rel string) string {
	links, _ := e["links"].([]any)
	for _, l := range links {
		lm, ok := l.(map[string]any)
		if ok && lm["rel"] == rel {
			if h := strings.TrimSpace(asString(lm["href"])); h != "" {
				return h
			}
		}
	}
	return ""
}

// FromRDAP converts an RDAP domain object to registration fields.
func FromRDAP(p map[string]any) map[string]string {
	f := fields{}
	if s := strings.TrimSpace(asString(p["port43"])); s != "" {
		f["registrar_whois_server"] = s
	}
	f["updated_date"] = eventDate(p, "last changed", "last update of RDAP database")
	f["creation_date"] = eventDate(p, "registration")
	f["expiration_date"] = eventDate(p, "expiration")
	if r := firstEntity(p, "registrar"); r != nil {
		f["registrar"] = entityName(r)
		f["registrar_url"] = vcardText(r, "url")
		if f["registrar_url"] == "" {
			f["registrar_url"] = linkHref(r, "about")
		}
	}
	if r := firstEntity(p, "registrant"); r != nil {
		f["registrant_name"] = entityName(r)
		f["registrant_organization"] = vcardText(r, "org")
		f["registrant_phone"] = vcardText(r, "tel")
		for _, v := range vcardValues(r, "adr") {
			l, ok := v.([]any)
			if !ok || len(l) < 7 {
				continue
			}
			switch s := l[2].(type) {
			case []any:
				f["registrant_street"] = joinNonEmpty(s)
			case string:
				f["registrant_street"] = strings.TrimSpace(s)
			}
			f["registrant_city"] = strings.TrimSpace(asAny(l[3]))
			f["registrant_state_province"] = strings.TrimSpace(asAny(l[4]))
			f["registrant_postal_code"] = strings.TrimSpace(asAny(l[5]))
			f["registrant_country"] = strings.TrimSpace(asAny(l[6]))
			break
		}
	}
	return f
}

func (c *Client) whois(ctx context.Context, domain, server string) fields {
	args := []string{}
	if s := NormalizeWhoisServer(server); s != "" {
		args = append(args, "-h", s)
	}
	args = append(args, domain)
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r, err := c.Run(cctx, "whois", args...)
	if err != nil || r.Stdout == "" {
		return fields{}
	}
	return ParseWhois(r.Stdout)
}

// Lookup returns registration data for domain: RDAP first, then registry
// whois, then the referred registrar's whois (which overrides earlier values).
func (c *Client) Lookup(ctx context.Context, domain string) model.Registration {
	c.mu.Lock()
	if r, ok := c.cache[domain]; ok {
		c.mu.Unlock()
		return r
	}
	if !c.bootstrapDone {
		c.bootstrap = c.readJSON(ctx, c.BootstrapURL)
		c.bootstrapDone = true
	}
	bootstrap := c.bootstrap
	c.mu.Unlock()

	reg := fields{}
	if bootstrap != nil {
		if base := BaseURL(bootstrap, domain); base != "" {
			if p := c.readJSON(ctx, base+"/domain/"+url.PathEscape(strings.TrimSuffix(domain, "."))); p != nil {
				reg.merge(FromRDAP(p), false)
			}
		}
	}
	reg.merge(c.whois(ctx, domain, ""), false)
	if srv := reg["registrar_whois_server"]; srv != "" {
		reg.merge(c.whois(ctx, domain, srv), true)
	}
	out := reg.toModel()
	c.mu.Lock()
	c.cache[domain] = out
	c.mu.Unlock()
	return out
}
