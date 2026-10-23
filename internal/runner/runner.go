// Package runner orchestrates a full scan and reports progress as events.
package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"ctz/internal/config"
	"ctz/internal/enum"
	"ctz/internal/execx"
	"ctz/internal/hints"
	"ctz/internal/httpev"
	"ctz/internal/ipinfo"
	"ctz/internal/model"
	"ctz/internal/nuclei"
	"ctz/internal/registration"
	"ctz/internal/scan"
	"ctz/internal/tlsinfo"
	"ctz/internal/waf"
	"ctz/internal/zap"
)

// Level classifies an event for display.
type Level int

const (
	// Info is a normal progress message ([+]).
	Info Level = iota
	// Warn is a warning ([!]).
	Warn
)

// Event is a progress notification emitted during a run.
type Event struct {
	Level Level
	Msg   string
	// Index/Total are set (>0) when the event reports target progress.
	Index, Total int
	Target       string
	// Stage names the step now running for Target; Partial holds what has
	// been learned about Target so far. Both are set only on stage events.
	Stage   string
	Partial *model.TargetResult
	// Done is set when Target has finished; Hints is a snapshot of every
	// prioritization hint collected so far, so the UI can show a finished
	// target's hints before the run completes.
	Done  *model.TargetResult
	Hints []model.Hint
}

func (r *Runner) done(tr model.TargetResult, hc *hints.Collector) {
	if r.Emit != nil {
		r.Emit(Event{Target: tr.Target, Done: &tr, Hints: hc.Sorted()})
	}
}

// Stages lists the per-target steps in the order they run.
var Stages = []string{"Resolve DNS", "Port scan", "TLS certificates", "WAF detection", "HTTP evidence", "IP info"}

func (r *Runner) stage(target, stage string, partial model.TargetResult) {
	if r.Emit != nil {
		r.Emit(Event{Target: target, Stage: stage, Partial: &partial})
	}
}

// Runner executes scans.
type Runner struct {
	Cfg    config.Config
	Exec   execx.Runner
	Emit   func(Event)
	APIKey string // ipinfo key; defaults to $IPINFO_API_KEY
}

// New returns a Runner using the real command executor.
func New(cfg config.Config, emit func(Event)) *Runner {
	return &Runner{Cfg: cfg, Exec: execx.Run, Emit: emit, APIKey: strings.TrimSpace(os.Getenv("IPINFO_API_KEY"))}
}

func (r *Runner) info(format string, a ...any) {
	if r.Emit != nil {
		r.Emit(Event{Level: Info, Msg: fmt.Sprintf(format, a...)})
	}
}

func (r *Runner) warn(format string, a ...any) {
	if r.Emit != nil {
		r.Emit(Event{Level: Warn, Msg: fmt.Sprintf(format, a...)})
	}
}

func (r *Runner) sleep(ctx context.Context) {
	if r.Cfg.RateDelay <= 0 {
		return
	}
	select {
	case <-time.After(time.Duration(r.Cfg.RateDelay * float64(time.Second))):
	case <-ctx.Done():
	}
}

// Run performs the scan described by the Runner's Config.
func (r *Runner) Run(ctx context.Context) (*model.Output, error) {
	cfg := &r.Cfg
	var ipc *ipinfo.Client
	if cfg.IPInfo {
		if cfg.IPInfoKey != "" {
			r.APIKey = cfg.IPInfoKey
		}
		if r.APIKey == "" {
			r.warn("--ipinfo requested but no ipinfo API key is set; ipinfo JSON will be omitted.")
			cfg.IPInfo = false
		} else {
			ipc = ipinfo.New(r.APIKey)
		}
	}

	work, err := os.MkdirTemp("", "ctz-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)

	domains, err := enum.LoadDomains(cfg)
	if err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains found in domains file: %s", cfg.DomainsFile)
	}
	r.info("Loaded %d DNS zone(s).", len(domains))

	all := map[string]bool{}
	for _, root := range domains {
		set := map[string]bool{root: true}

		r.info("Running passive enumeration for %s...", root)
		subs, err := enum.Subfinder(ctx, r.Exec, work, root)
		if err != nil {
			return nil, fmt.Errorf("subfinder failed for %s", root)
		}
		r.info("Passive enumeration found %d target(s) for %s.", len(subs), root)
		addAll(set, subs)

		if cfg.Wordlist != "" {
			r.info("Running active DNS enumeration for %s...", root)
			found, err := enum.Dnsx(ctx, r.Exec, cfg, work, root)
			if err != nil {
				return nil, fmt.Errorf("dnsx failed for %s", root)
			}
			r.info("Active DNS enumeration found %d target(s) for %s.", len(found), root)
			addAll(set, found)
		}
		if cfg.Vhosts {
			r.info("Running vhost enumeration for %s...", root)
			found, warning := enum.Gobuster(ctx, r.Exec, cfg, work, root)
			if warning != "" {
				r.warn("Vhost enumeration failed for %s; continuing. %s", root, warning)
			} else {
				r.info("Vhost enumeration found %d target(s) for %s.", len(found), root)
			}
			addAll(set, found)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r.info("Found %d unique targets for %s.", len(set), root)
		addAll(all, keys(set))
	}

	targets := keys(all)
	if len(targets) == 0 {
		return nil, errors.New("no targets found")
	}
	r.info("Found %d unique targets.", len(targets))
	r.info("Testing connectivity...")

	hc := &hints.Collector{}
	client := httpev.Client(time.Duration(cfg.HTTPTimeout) * time.Second)
	results := make([]model.TargetResult, 0, len(targets))
	var httpURLs []string

	for i, target := range targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if r.Emit != nil {
			r.Emit(Event{Level: Info, Msg: fmt.Sprintf("[%d/%d] Testing %s", i+1, len(targets), target), Index: i + 1, Total: len(targets), Target: target})
		}
		r.stage(target, Stages[0], model.TargetResult{Target: target})
		ip := scan.Resolve(ctx, target)
		if ip == "" {
			tr := model.TargetResult{
				Target: target, Ports: []int{}, Services: []model.Service{}, TLSCertificates: []model.TLSCertificate{},
				WAF: waf.Default(), HTTP: model.HTTPResult{Endpoints: []model.HTTPEndpoint{}},
				NSE: []model.NSEEntry{}, HostNSE: []model.HostNSE{},
			}
			results = append(results, tr)
			r.done(tr, hc)
			continue
		}
		part := model.TargetResult{Target: target, IPAddress: ip, Resolved: true}
		r.stage(target, Stages[1], part)
		nm := scan.Host(ctx, r.Exec, cfg, work, target)
		part.Ports, part.Services, part.Connected = nm.OpenPorts, nm.Services, len(nm.OpenPorts) > 0
		part.ScanErrors = nm.Errors
		for _, e := range nm.Errors {
			r.warn("%s: %s", target, e)
		}
		r.stage(target, Stages[2], part)
		certs := tlsinfo.Scan(ctx, target, nm.OpenPorts)
		part.TLSCertificates = certs
		r.stage(target, Stages[3], part)
		w := waf.Scan(ctx, r.Exec, cfg, target, nm.OpenPorts)
		part.WAF = w
		cands := httpev.Candidates(target, nm.OpenPorts, nm.Services)
		for _, c := range cands {
			httpURLs = append(httpURLs, c.URL)
		}
		httpRes := model.HTTPResult{Endpoints: []model.HTTPEndpoint{}}
		if cfg.HTTPEvidence {
			httpRes.Checked = true
			part.HTTP = httpRes
			r.stage(target, Stages[4], part)
			for _, c := range cands {
				r.sleep(ctx)
				ep := httpev.Fetch(ctx, client, c)
				hc.HTTP(ep)
				httpRes.Endpoints = append(httpRes.Endpoints, ep)
				part.HTTP = httpRes
				r.stage(target, Stages[4], part)
			}
		}
		r.stage(target, Stages[5], part)
		hc.Exposure(target, nm.OpenPorts)
		if cfg.ServiceVersion {
			hc.ServiceVersion(target, nm.Services)
		}
		hc.TLS(target, certs)
		tr := model.TargetResult{
			Target: target, IPAddress: ip, Resolved: true, Connected: len(nm.OpenPorts) > 0,
			Ports: nm.OpenPorts, Services: nm.Services, TLSCertificates: certs, WAF: w, HTTP: httpRes,
			NSE: nm.NSE, HostNSE: nm.HostNSE, ScanErrors: nm.Errors,
		}
		if info := ipc.Lookup(ctx, ip); info != nil {
			tr.IPInfo = info
		}
		results = append(results, tr)
		r.done(tr, hc)
		r.sleep(ctx)
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].Target < results[j].Target })

	nr := nuclei.Run(ctx, r.Exec, cfg, work, httpURLs, r.info)
	hc.Nuclei(nr.Findings)
	zr := zap.Run(ctx, r.Exec, cfg, httpURLs, hc, func() { r.sleep(ctx) }, r.info)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	out := &model.Output{
		SourceIP:           scan.SourceIP(),
		RunDatetime:        time.Now().Format("1/2/2006 3:04 PM MST"),
		Results:            results,
		Nuclei:             nr,
		Zap:                zr,
		PrioritizationHint: hc.Sorted(),
		ToolMetadata:       toolMetadata(cfg),
	}
	reg := registration.New(r.Exec)
	if len(domains) == 1 {
		out.Domain = domains[0]
		if cfg.Whois {
			v := reg.Lookup(ctx, domains[0])
			out.Registration = &v
		}
	} else {
		out.Domains = domains
		if cfg.Whois {
			out.Registrations = map[string]model.Registration{}
			for _, d := range domains {
				out.Registrations[d] = reg.Lookup(ctx, d)
			}
		}
	}
	return out, nil
}

func toolMetadata(cfg *config.Config) model.ToolMetadata {
	feat := model.NewOrdered[bool]()
	feat.Set("service_version", cfg.ServiceVersion)
	feat.Set("nse", cfg.NSE)
	feat.Set("http_evidence", cfg.HTTPEvidence)
	feat.Set("nuclei", cfg.Nuclei)
	feat.Set("zap", cfg.Zap)
	opt := model.ToolOptions{HTTPTimeout: cfg.HTTPTimeout, NucleiTemplates: model.Str(cfg.NucleiTemplates), RateDelay: cfg.RateDelay}
	if cfg.NSE {
		opt.NSEScripts = &cfg.NSEScripts
	}
	if cfg.Nuclei {
		opt.NucleiSeverities = &cfg.NucleiSeverities
	}
	if cfg.Zap {
		opt.ZapImage = &cfg.ZapImage
		opt.ZapSpiderMinutes = &cfg.ZapSpiderMinutes
		opt.ZapTimeoutMin = &cfg.ZapTimeoutMinutes
		opt.ZapMaxEndpoints = &cfg.ZapMaxEndpoints
	}
	return model.ToolMetadata{
		SchemaVersion: "2.0", FeaturesEnabled: feat, Options: opt,
		Notes: []string{
			"Nuclei findings are hypotheses requiring analyst validation.",
			"OWASP ZAP baseline findings are passive-scan evidence requiring validation.",
			"Prioritization hints are advisory and do not replace analyst judgment.",
		},
	}
}

func addAll(set map[string]bool, items []string) {
	for _, i := range items {
		set[i] = true
	}
}

func keys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
