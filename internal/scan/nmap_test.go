package scan

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"ctz/internal/config"
	"ctz/internal/execx"
)

const sample = `<?xml version="1.0"?>
<nmaprun><host>
<ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" product="nginx" version="1.24.0" tunnel="ssl" conf="10"/>
<script id="http-title" output="Example App"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="23"><state state="closed"/></port>
</ports>
<hostscript><script id="clock-skew" output="mean: 0s"/></hostscript>
</host></nmaprun>`

func TestParseXML(t *testing.T) {
	r, err := ParseXML([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.OpenPorts) != 2 || r.OpenPorts[0] != 22 || r.OpenPorts[1] != 443 {
		t.Errorf("ports = %v", r.OpenPorts)
	}
	if r.Services[1].Product == nil || *r.Services[1].Product != "nginx" || *r.Services[1].Tunnel != "ssl" {
		t.Errorf("service = %+v", r.Services[1])
	}
	if r.Services[0].Product != nil {
		t.Error("missing attributes must stay null")
	}
	if len(r.NSE) != 1 || len(r.Services[1].NSE) != 1 || len(r.HostNSE) != 1 {
		t.Errorf("nse = %v host = %v", r.NSE, r.HostNSE)
	}
}

func TestParseXMLInvalid(t *testing.T) {
	if _, err := ParseXML([]byte("not xml")); err == nil {
		t.Error("want error")
	}
}

// nmapStub returns a Runner that writes xml (when non-empty) to the -oX path.
func nmapStub(xml string, calls *[]string) execx.Runner {
	return func(ctx context.Context, name string, args ...string) (execx.Result, error) {
		*calls = append(*calls, strings.Join(args, " "))
		if xml != "" {
			for i, a := range args {
				if a == "-oX" {
					_ = os.WriteFile(args[i+1], []byte(xml), 0o600)
				}
			}
		}
		return execx.Result{}, nil
	}
}

func TestHostReportsHostTimeout(t *testing.T) {
	var calls []string
	cfg := config.Default()
	cfg.Ports = "1" // nothing listens; keeps the connect probe quiet
	res := Host(context.Background(), nmapStub(`<nmaprun></nmaprun>`, &calls), &cfg, t.TempDir(), "127.0.0.1")
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0], "no host") {
		t.Errorf("errors = %v", res.Errors)
	}
}

func TestHostFallsBackToConnectProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	var calls []string
	cfg := config.Default()
	cfg.Ports = strconv.Itoa(port)
	cfg.ServiceVersion, cfg.NSE = false, false
	res := Host(context.Background(), nmapStub(`<nmaprun></nmaprun>`, &calls), &cfg, t.TempDir(), "127.0.0.1")
	if len(res.OpenPorts) != 1 || res.OpenPorts[0] != port {
		t.Errorf("ports = %v errors = %v", res.OpenPorts, res.Errors)
	}
	if len(res.Errors) != 2 {
		t.Errorf("errors = %v", res.Errors)
	}
}

func TestHostDetailFailureKeepsDiscovery(t *testing.T) {
	var calls []string
	cfg := config.Default()
	cfg.ServiceVersion = true
	n := 0
	stub := nmapStub(sample, &calls)
	exec := func(ctx context.Context, name string, args ...string) (execx.Result, error) {
		n++
		if n == 2 {
			calls = append(calls, strings.Join(args, " "))
			return execx.Result{}, context.DeadlineExceeded
		}
		return stub(ctx, name, args...)
	}
	res := Host(context.Background(), exec, &cfg, t.TempDir(), "example.test")
	if len(res.OpenPorts) != 2 || len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "nmap detail") {
		t.Errorf("ports = %v errors = %v", res.OpenPorts, res.Errors)
	}
	if strings.Contains(calls[0], "-sV") || !strings.Contains(calls[1], "-sV") || !strings.Contains(calls[1], "-p 22,443") {
		t.Errorf("calls = %q", calls)
	}
}

func TestIsScriptError(t *testing.T) {
	for out, want := range map[string]bool{
		"ERROR: Script execution failed (use -d to debug)": true,
		"  ERROR: Script timeout":                          true,
		"Did not follow redirect":                          false,
		"":                                                 false,
	} {
		if got := IsScriptError(out); got != want {
			t.Errorf("IsScriptError(%q) = %v", out, got)
		}
	}
}

func TestNmapCommand(t *testing.T) {
	got := NmapCommand("example.com", 443, "default,safe", true)
	want := "nmap " + ScanType() + " -Pn -p 443 -sV --version-light \\\n" +
		"  --script default,safe --script-timeout 30s \\\n" +
		"  -d example.com 2>&1 \\\n" +
		"  | grep -A4 'threw an error'"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(NmapCommand("example.com", 80, "default", false), "-sV") {
		t.Error("-sV should only appear when version detection was on")
	}
}
