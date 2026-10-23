// Package waf runs wafw00f and normalizes its output.
package waf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"ctz/internal/config"
	"ctz/internal/execx"
	"ctz/internal/httpev"
	"ctz/internal/model"
)

// Default is the unchecked WAF result.
func Default() model.WAFResult {
	return model.WAFResult{Products: []string{}, Endpoints: []model.WAFEndpoint{}}
}

func normalizeProduct(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "none", "unknown", "generic":
		return ""
	}
	return s
}

func formatProduct(product, manufacturer string) string {
	if manufacturer == "" {
		return product
	}
	if strings.EqualFold(product, manufacturer) || strings.Contains(strings.ToLower(product), strings.ToLower(manufacturer)) {
		return product
	}
	return fmt.Sprintf("%s (%s)", product, manufacturer)
}

var skipKeys = map[string]bool{"firewall": true, "waf": true, "name": true, "product": true, "manufacturer": true}

func collectProducts(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		if p := normalizeProduct(t); p != "" {
			out = append(out, p)
		}
	case []any:
		for _, item := range t {
			out = append(out, collectProducts(item)...)
		}
	case map[string]any:
		manufacturer := normalizeProduct(t["manufacturer"])
		var direct []string
		for _, k := range []string{"firewall", "waf", "name", "product"} {
			direct = append(direct, collectProducts(t[k])...)
		}
		if len(direct) > 0 {
			for _, p := range direct {
				out = append(out, formatProduct(p, manufacturer))
			}
		} else if manufacturer != "" {
			out = append(out, manufacturer)
		}
		for _, k := range sortedKeys(t) {
			if skipKeys[k] {
				continue
			}
			switch t[k].(type) {
			case map[string]any, []any:
				out = append(out, collectProducts(t[k])...)
			}
		}
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Detection extracts (detected, products) from a decoded wafw00f payload.
func Detection(payload any) (bool, []string) {
	detected := false
	var products []string
	var entries []any
	if l, ok := payload.([]any); ok {
		entries = l
	} else {
		entries = []any{payload}
	}
	for _, e := range entries {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		for _, k := range []string{"detected", "identified", "is_waf"} {
			if b, ok := m[k].(bool); ok {
				if b {
					detected = true
					products = append(products, collectProducts(m)...)
				}
				break
			}
		}
		for _, k := range sortedKeys(m) {
			if skipKeys[k] {
				continue
			}
			switch m[k].(type) {
			case map[string]any, []any:
				d, p := Detection(m[k])
				detected = detected || d
				products = append(products, p...)
			}
		}
	}
	set := map[string]bool{}
	for _, p := range products {
		set[p] = true
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return detected, out
}

// ParseJSON decodes wafw00f output, tolerating leading banner text.
func ParseJSON(output string) (any, error) {
	s := strings.TrimSpace(output)
	if s == "" {
		return nil, fmt.Errorf("empty wafw00f output")
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err == nil {
		return v, nil
	}
	start := -1
	for _, c := range []string{"[", "{"} {
		if i := strings.Index(s, c); i >= 0 && (start < 0 || i < start) {
			start = i
		}
	}
	if start < 0 {
		return nil, fmt.Errorf("wafw00f output contains no JSON")
	}
	dec := json.NewDecoder(strings.NewReader(s[start:]))
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func requestURL(host string, port int, scheme string) string {
	return httpev.EndpointURL(host, port, scheme)
}

func serverHeader(ctx context.Context, url string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "connectivity-test-zone")
	resp, err := httpev.Client(5 * time.Second).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	return normalizeProduct(resp.Header.Get("Server"))
}

func scanEndpoint(ctx context.Context, run execx.Runner, host string, port int, scheme string) model.WAFEndpoint {
	ep := model.WAFEndpoint{URL: fmt.Sprintf("%s://%s", scheme, host), Port: port, Products: []string{}}
	reqURL := requestURL(host, port, scheme)
	cctx, cancel := context.WithTimeout(ctx, config.Wafw00fTimeoutSeconds*time.Second)
	defer cancel()
	res, err := run(cctx, "wafw00f", "-f", "json", "-o", "-", reqURL)
	if err != nil {
		return ep
	}
	if res.ExitCode != 0 && res.ExitCode != 1 && strings.TrimSpace(res.Stdout) == "" {
		return ep
	}
	payload, err := ParseJSON(res.Stdout)
	if err != nil {
		return ep
	}
	detected, products := Detection(payload)
	if detected && len(products) == 0 {
		if sh := serverHeader(ctx, reqURL); sh != "" {
			products = []string{sh}
		} else {
			products = []string{"unknown"}
		}
	}
	if products == nil {
		products = []string{}
	}
	ep.Checked, ep.Detected, ep.Products = true, detected, products
	return ep
}

// Scan runs wafw00f on every open web port of host.
func Scan(ctx context.Context, run execx.Runner, cfg *config.Config, host string, openPorts []int) model.WAFResult {
	if !cfg.WAF {
		return Default()
	}
	res := Default()
	set := map[string]bool{}
	for _, p := range openPorts {
		scheme, ok := httpev.PortSchemes[p]
		if !ok {
			continue
		}
		ep := scanEndpoint(ctx, run, host, p, scheme)
		res.Endpoints = append(res.Endpoints, ep)
		if ep.Checked {
			res.Checked = true
			res.Detected = res.Detected || ep.Detected
			for _, pr := range ep.Products {
				set[pr] = true
			}
		}
	}
	for p := range set {
		res.Products = append(res.Products, p)
	}
	sort.Strings(res.Products)
	return res
}
