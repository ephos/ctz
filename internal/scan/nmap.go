// Package scan resolves hosts and drives nmap.
package scan

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ctz/internal/config"
	"ctz/internal/execx"
	"ctz/internal/model"
)

// Resolve returns the first resolved IP for hostname, or "" when unresolved.
func Resolve(ctx context.Context, hostname string) string {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	return addrs[0].IP.String()
}

// SourceIP returns the local outbound IPv4 address, or nil.
func SourceIP() *string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return nil
	}
	return &host
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service *struct {
		Name      *string `xml:"name,attr"`
		Product   *string `xml:"product,attr"`
		Version   *string `xml:"version,attr"`
		Extrainfo *string `xml:"extrainfo,attr"`
		Tunnel    *string `xml:"tunnel,attr"`
		Conf      *string `xml:"conf,attr"`
	} `xml:"service"`
	Scripts []nmapScript `xml:"script"`
}

type nmapRun struct {
	Hosts []struct {
		Ports       []nmapPort   `xml:"ports>port"`
		HostScripts []nmapScript `xml:"hostscript>script"`
	} `xml:"host"`
}

// Result is the parsed output of an nmap run.
type Result struct {
	OpenPorts []int
	Services  []model.Service
	NSE       []model.NSEEntry
	HostNSE   []model.HostNSE
	// HostsSeen is the number of <host> elements nmap reported; zero means nmap
	// skipped the host (host timeout) or never finished.
	HostsSeen int
	// Errors lists scan failures so an empty result can be told from a failed one.
	Errors []string
}

// ParseXML parses nmap -oX output.
func ParseXML(data []byte) (Result, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return Result{}, err
	}
	res := Result{OpenPorts: []int{}, Services: []model.Service{}, NSE: []model.NSEEntry{}, HostNSE: []model.HostNSE{}}
	res.HostsSeen = len(run.Hosts)
	seen := map[int]bool{}
	for _, h := range run.Hosts {
		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			id, err := strconv.Atoi(p.PortID)
			if err != nil {
				continue
			}
			if !seen[id] {
				seen[id] = true
				res.OpenPorts = append(res.OpenPorts, id)
			}
			proto := p.Protocol
			if proto == "" {
				proto = "tcp"
			}
			svc := model.Service{Port: id, Protocol: proto, State: p.State.State}
			if p.Service != nil {
				svc.Name, svc.Product, svc.Version = p.Service.Name, p.Service.Product, p.Service.Version
				svc.Extrainfo, svc.Tunnel, svc.Confidence = p.Service.Extrainfo, p.Service.Tunnel, p.Service.Conf
			}
			for _, s := range p.Scripts {
				if id := strings.TrimSpace(s.ID); id != "" {
					e := model.NSEEntry{Port: svc.Port, ScriptID: id, Output: strings.TrimSpace(s.Output)}
					svc.NSE = append(svc.NSE, e)
					res.NSE = append(res.NSE, e)
				}
			}
			res.Services = append(res.Services, svc)
		}
		for _, s := range h.HostScripts {
			if id := strings.TrimSpace(s.ID); id != "" {
				res.HostNSE = append(res.HostNSE, model.HostNSE{ScriptID: id, Output: strings.TrimSpace(s.Output)})
			}
		}
	}
	sort.Ints(res.OpenPorts)
	sort.SliceStable(res.Services, func(i, j int) bool { return res.Services[i].Port < res.Services[j].Port })
	return res, nil
}

// EffectiveTimeout returns the per-host nmap timeout in seconds.
func EffectiveTimeout(cfg *config.Config) int {
	t := config.NmapTimeoutSeconds
	switch {
	case cfg.NSE && t < 180:
		return 180
	case cfg.ServiceVersion && t < 90:
		return 90
	}
	return t
}

// Args builds the nmap argument list for hostname, writing XML to xmlPath.
// Discovery scans only probe ports; detail scans add -sV and NSE.
func Args(cfg *config.Config, scanType, xmlPath, hostname, ports string, detail bool, timeout int) []string {
	args := []string{
		scanType, "-Pn", "--open",
		"--host-timeout", strconv.Itoa(timeout) + "s",
		"-p", ports, "-oX", xmlPath,
	}
	if detail && cfg.ServiceVersion {
		args = append(args, "-sV", "--version-light")
	}
	if detail && cfg.NSE {
		args = append(args, "--script", cfg.NSEScripts, "--script-timeout", "30s")
	}
	return append(args, hostname)
}

// ScanType is -sS as root, -sT otherwise.
func ScanType() string {
	if os.Geteuid() == 0 {
		return "-sS"
	}
	return "-sT"
}

// IsScriptError reports whether an NSE script's output is nmap's error marker
// rather than a finding.
func IsScriptError(output string) bool {
	return strings.HasPrefix(strings.TrimSpace(output), "ERROR:")
}

// NmapCommand returns a shell command, split over lines with trailing
// backslashes so it pastes cleanly, that repeats an NSE run on one port with
// debug on and shows only the "threw an error" blocks. The whole script set is
// rerun on purpose: the failures seen so far do not reproduce when a script
// runs alone.
func NmapCommand(hostname string, port int, scripts string, versionDetect bool) string {
	first := "nmap " + ScanType() + " -Pn -p " + strconv.Itoa(port)
	if versionDetect {
		first += " -sV --version-light"
	}
	return strings.Join([]string{
		first + " \\",
		"  --script " + scripts + " --script-timeout 30s \\",
		"  -d " + hostname + " 2>&1 \\",
		"  | grep -A4 'threw an error'",
	}, "\n")
}

func emptyResult() Result {
	return Result{OpenPorts: []int{}, Services: []model.Service{}, NSE: []model.NSEEntry{}, HostNSE: []model.HostNSE{}}
}

// run executes one nmap invocation and returns the parsed result; failures are
// reported in Result.Errors rather than dropped.
func run(ctx context.Context, exec execx.Runner, cfg *config.Config, tmpDir, hostname, label, ports string, detail bool, timeout int) Result {
	fail := func(format string, a ...any) Result {
		r := emptyResult()
		r.Errors = []string{label + ": " + fmt.Sprintf(format, a...)}
		return r
	}
	f, err := os.CreateTemp(tmpDir, "nmap-*.xml")
	if err != nil {
		return fail("cannot create temp file: %v", err)
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)

	cctx, cancel := contextWithTimeout(ctx, timeout+10)
	defer cancel()
	out, err := exec(cctx, "nmap", Args(cfg, ScanType(), filepath.Clean(path), hostname, ports, detail, timeout)...)
	if err != nil {
		if cctx.Err() != nil && ctx.Err() == nil {
			return fail("nmap did not finish within %ds", timeout+10)
		}
		return fail("nmap failed: %v", err)
	}
	if out.ExitCode != 0 {
		return fail("nmap exited %d: %s", out.ExitCode, firstLine(out.Stderr))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fail("cannot read nmap output: %v", err)
	}
	res, err := ParseXML(data)
	if err != nil {
		return fail("cannot parse nmap output: %v", err)
	}
	if res.HostsSeen == 0 {
		return fail("nmap reported no host (host timeout after %ds?)", timeout)
	}
	return res
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func portList(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

// Host scans hostname in two phases so a stalled detail scan cannot discard
// basic results: fast port discovery first, then service/NSE detection on only
// the open ports. If nmap finds nothing, a direct TCP connect probe backs it up.
// Failures are collected in Result.Errors.
func Host(ctx context.Context, exec execx.Runner, cfg *config.Config, tmpDir, hostname string) Result {
	res := run(ctx, exec, cfg, tmpDir, hostname, "nmap discovery", cfg.Ports, false, config.NmapTimeoutSeconds)
	errs := res.Errors

	if len(res.OpenPorts) == 0 && ctx.Err() == nil {
		if open := ConnectProbe(ctx, hostname, cfg.Ports); len(open) > 0 {
			errs = append(errs, fmt.Sprintf("connect probe found open ports %s that nmap did not report", portList(open)))
			res = emptyResult()
			for _, p := range open {
				res.OpenPorts = append(res.OpenPorts, p)
				res.Services = append(res.Services, model.Service{Port: p, Protocol: "tcp", State: "open"})
			}
		}
	}

	if len(res.OpenPorts) > 0 && (cfg.ServiceVersion || cfg.NSE) && ctx.Err() == nil {
		detail := run(ctx, exec, cfg, tmpDir, hostname, "nmap detail", portList(res.OpenPorts), true, EffectiveTimeout(cfg))
		errs = append(errs, detail.Errors...)
		if len(detail.Errors) == 0 && len(detail.OpenPorts) > 0 {
			res = detail
		}
	}
	res.Errors = errs
	return res
}

// ConnectProbe tries a plain TCP connect to each port in the comma-separated
// list (ranges are skipped) and returns the ones that accept, sorted.
func ConnectProbe(ctx context.Context, hostname, ports string) []int {
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		open []int
		sem  = make(chan struct{}, 16)
	)
	for _, f := range strings.Split(ports, ",") {
		p, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer func() { <-sem; wg.Done() }()
			d := net.Dialer{Timeout: 3 * time.Second}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(hostname, strconv.Itoa(p)))
			if err != nil {
				return
			}
			c.Close()
			mu.Lock()
			open = append(open, p)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Ints(open)
	return open
}
