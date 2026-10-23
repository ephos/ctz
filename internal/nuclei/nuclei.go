// Package nuclei runs nuclei and normalizes its JSONL output.
package nuclei

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ctz/internal/config"
	"ctz/internal/execx"
	"ctz/internal/model"
)

func first(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil && v != "" {
			return v
		}
	}
	return nil
}

// Normalize converts a raw nuclei finding.
func Normalize(f map[string]any) model.NucleiFinding {
	info, _ := f["info"].(map[string]any)
	if info == nil {
		info = map[string]any{}
	}
	var port *string
	if p, ok := f["port"]; ok && p != nil {
		s := fmt.Sprint(p)
		port = &s
	}
	return model.NucleiFinding{
		TemplateID: first(f, "template-id", "template_id"),
		Name:       or(first(info, "name"), first(f, "name")),
		Severity:   or(first(info, "severity"), first(f, "severity")),
		MatchedAt:  first(f, "matched-at", "matched_at", "matched", "url"),
		Host:       f["host"],
		Port:       port,
		Type:       f["type"],
		Raw:        f,
	}
}

func or(a, b any) any {
	if a != nil {
		return a
	}
	return b
}

// Parse decodes JSONL lines into deduplicated findings and parse errors.
func Parse(lines []string) ([]model.NucleiFinding, []string) {
	findings := []model.NucleiFinding{}
	var errs []string
	seen := map[string]bool{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			errs = append(errs, "Unable to parse one nuclei JSONL line.")
			continue
		}
		f := Normalize(m)
		port := ""
		if f.Port != nil {
			port = *f.Port
		}
		key := fmt.Sprint(f.TemplateID, "|", f.MatchedAt, "|", f.Host, "|", port, "|", f.Type)
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, f)
	}
	return findings, errs
}

// Run executes nuclei against urls.
func Run(ctx context.Context, run execx.Runner, cfg *config.Config, tmpDir string, urls []string, logf func(string, ...any)) model.NucleiResult {
	res := model.NucleiResult{Checked: cfg.Nuclei, Severities: cfg.NucleiSeverities, Findings: []model.NucleiFinding{}, Errors: []string{}}
	if !cfg.Nuclei {
		return res
	}
	urls = uniqueSorted(urls)
	if len(urls) == 0 {
		msg := "No HTTP/HTTPS endpoints discovered; nuclei was not run."
		logf("[!] --nuclei requested but %s", msg)
		res.Errors = append(res.Errors, msg)
		return res
	}
	targets := filepath.Join(tmpDir, "nuclei-targets.txt")
	out := filepath.Join(tmpDir, "nuclei-results.jsonl")
	if err := os.WriteFile(targets, []byte(strings.Join(urls, "\n")+"\n"), 0o600); err != nil {
		res.Errors = append(res.Errors, "nuclei failed to start: "+err.Error())
		return res
	}
	args := []string{"-list", targets, "-jsonl", "-severity", cfg.NucleiSeverities, "-silent", "-o", out}
	if cfg.NucleiTemplates != "" {
		args = append(args, "-t", cfg.NucleiTemplates)
	}
	logf("Running nuclei against %d endpoint(s)", len(urls))

	timeout := len(urls) * 45
	if timeout < 120 {
		timeout = 120
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	r, err := run(cctx, "nuclei", args...)
	started := true
	switch {
	case cctx.Err() != nil:
		res.Errors = append(res.Errors, "nuclei timed out; partial JSONL output was preserved.")
	case err != nil:
		res.Errors = append(res.Errors, "nuclei failed to start: "+err.Error())
		started = false
	case r.ExitCode != 0:
		msg := fmt.Sprintf("nuclei exited with status %d", r.ExitCode)
		if s := strings.TrimSpace(r.Stderr); s != "" {
			msg += ": " + truncate(s, 1000)
		}
		res.Errors = append(res.Errors, msg)
	}
	var lines []string
	if b, err := os.ReadFile(out); err == nil {
		lines = append(lines, strings.Split(string(b), "\n")...)
	}
	if started && strings.TrimSpace(r.Stdout) != "" {
		lines = append(lines, strings.Split(r.Stdout, "\n")...)
	}
	findings, errs := Parse(lines)
	res.Findings = findings
	res.Errors = append(res.Errors, errs...)
	return res
}

func uniqueSorted(in []string) []string {
	set := map[string]bool{}
	for _, s := range in {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
