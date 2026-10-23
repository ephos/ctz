// Package zap runs the OWASP ZAP baseline scan through Docker.
package zap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"ctz/internal/config"
	"ctz/internal/execx"
	"ctz/internal/hints"
	"ctz/internal/model"
)

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil && v != "" {
			return fmt.Sprint(v)
		}
	}
	return ""
}

func get(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil && v != "" {
			return v
		}
	}
	return nil
}

// NormalizeAlert converts a raw ZAP alert.
func NormalizeAlert(alert map[string]any, target string) model.ZapAlert {
	instances, _ := alert["instances"].([]any)
	count := len(instances)
	if len(instances) > 10 {
		instances = instances[:10]
	}
	if instances == nil {
		instances = []any{}
	}
	return model.ZapAlert{
		Target:         target,
		PluginID:       str(alert, "pluginid", "pluginId"),
		Alert:          get(alert, "alert", "name"),
		Name:           get(alert, "name", "alert"),
		Risk:           get(alert, "risk", "riskdesc"),
		Confidence:     alert["confidence"],
		RiskDesc:       alert["riskdesc"],
		Description:    alert["desc"],
		Solution:       alert["solution"],
		Reference:      alert["reference"],
		CWEID:          str(alert, "cweid"),
		WASCID:         str(alert, "wascid"),
		InstancesCount: count,
		Instances:      instances,
		Raw:            alert,
	}
}

// AlertsFromReport extracts alerts from a ZAP JSON report.
func AlertsFromReport(report map[string]any, target string) []model.ZapAlert {
	alerts := []model.ZapAlert{}
	var sites []any
	switch s := report["site"].(type) {
	case []any:
		sites = s
	case map[string]any:
		sites = []any{s}
	}
	for _, s := range sites {
		site, ok := s.(map[string]any)
		if !ok {
			continue
		}
		list, _ := site["alerts"].([]any)
		for _, a := range list {
			if am, ok := a.(map[string]any); ok {
				alerts = append(alerts, NormalizeAlert(am, target))
			}
		}
	}
	return alerts
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func runOne(ctx context.Context, run execx.Runner, cfg *config.Config, url string, index int) model.ZapFinding {
	res := model.ZapFinding{Target: url, Mode: "baseline-passive", Alerts: []model.ZapAlert{}, Errors: []string{}}
	dir, err := os.MkdirTemp("/tmp", "zap-")
	if err != nil {
		res.Errors = append(res.Errors, "OWASP ZAP failed to start through Docker: "+err.Error())
		return res
	}
	defer os.RemoveAll(dir)
	_ = os.Chmod(dir, 0o777) //nolint:gosec // container user must be able to write the report
	reportName := fmt.Sprintf("zap-%d.json", index)
	reportPath := filepath.Join(dir, reportName)
	args := []string{
		"run", "--rm", "-v", dir + ":/zap/wrk/:rw", "-t", cfg.ZapImage,
		"zap-baseline.py", "-t", url, "-J", reportName, "-I",
		"-m", strconv.Itoa(cfg.ZapSpiderMinutes), "-T", strconv.Itoa(cfg.ZapTimeoutMinutes),
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.ZapTimeoutMinutes*60+120)*time.Second)
	defer cancel()
	r, err := run(cctx, "docker", args...)
	if cctx.Err() != nil {
		res.Errors = append(res.Errors, "OWASP ZAP baseline scan timed out.")
		return res
	}
	if err != nil {
		res.Errors = append(res.Errors, "OWASP ZAP failed to start through Docker: "+err.Error())
		return res
	}
	code := r.ExitCode
	res.ExitCode = &code
	if code != 0 && code != 1 && code != 2 {
		msg := fmt.Sprintf("OWASP ZAP exited with status %d", code)
		if s := strings.TrimSpace(r.Stderr); s != "" {
			msg += ": " + trunc(s, 1000)
		}
		res.Errors = append(res.Errors, msg)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		res.StdoutExcerpt = trunc(strings.TrimSpace(r.Stdout), 4000)
		res.StderrExcerpt = trunc(strings.TrimSpace(r.Stderr), 4000)
		res.Errors = append(res.Errors, "OWASP ZAP did not produce a JSON report.")
		return res
	}
	var report map[string]any
	if err := json.Unmarshal(data, &report); err != nil {
		res.Errors = append(res.Errors, "Unable to parse OWASP ZAP JSON report.")
		return res
	}
	res.Alerts = AlertsFromReport(report, url)
	res.RawSummary = map[string]any{
		"generated": get(report, "@generated", "generated"),
		"version":   get(report, "@version", "version"),
	}
	return res
}

// Run performs a baseline scan of up to ZapMaxEndpoints URLs.
func Run(ctx context.Context, run execx.Runner, cfg *config.Config, urls []string, hc *hints.Collector, delay func(), logf func(string, ...any)) model.ZapResult {
	res := model.ZapResult{
		Checked: cfg.Zap, Mode: "baseline-passive", SpiderMinutes: cfg.ZapSpiderMinutes,
		TimeoutMinutes: cfg.ZapTimeoutMinutes, MaxEndpoints: cfg.ZapMaxEndpoints,
		Findings: []model.ZapFinding{}, Errors: []string{},
	}
	if cfg.Zap {
		img := cfg.ZapImage
		res.Image = &img
	}
	if !cfg.Zap {
		return res
	}
	set := map[string]bool{}
	for _, u := range urls {
		set[u] = true
	}
	urls = urls[:0]
	for u := range set {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	if len(urls) == 0 {
		msg := "No HTTP/HTTPS endpoints discovered; OWASP ZAP was not run."
		logf("[!] --zap requested but %s", msg)
		res.Errors = append(res.Errors, msg)
		return res
	}
	if len(urls) > cfg.ZapMaxEndpoints {
		res.Errors = append(res.Errors, fmt.Sprintf("OWASP ZAP limited to first %d endpoint(s).", cfg.ZapMaxEndpoints))
		urls = urls[:cfg.ZapMaxEndpoints]
	}
	logf("Running OWASP ZAP baseline against %d endpoint(s)", len(urls))
	for i, u := range urls {
		if ctx.Err() != nil {
			break
		}
		delay()
		f := runOne(ctx, run, cfg, u, i+1)
		hc.Zap(f.Alerts)
		res.Findings = append(res.Findings, f)
	}
	return res
}
