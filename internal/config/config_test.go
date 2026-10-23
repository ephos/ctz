package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	_ = os.WriteFile(wl, []byte("www\n"), 0o600)

	cases := []struct {
		name   string
		mutate func(*Config)
		errSub string
	}{
		{"ok", func(c *Config) { c.Domain = "example.com" }, ""},
		{"missing domain", func(c *Config) {}, "missing required domain"},
		{"both", func(c *Config) { c.Domain = "a.com"; c.DomainsFile = wl }, "not both"},
		{"domains file missing", func(c *Config) { c.DomainsFile = filepath.Join(dir, "nope") }, "does not exist"},
		{"resolvers without wordlist", func(c *Config) { c.Domain = "a.com"; c.Resolvers = "1.1.1.1" }, "--resolvers"},
		{"wordlist ok", func(c *Config) { c.Domain = "a.com"; c.Wordlist = wl; c.Resolvers = "1.1.1.1" }, ""},
		{"bad scheme", func(c *Config) { c.Domain = "a.com"; c.VhostScheme = "ftp" }, "vhost-scheme"},
		{"bad timeout", func(c *Config) { c.Domain = "a.com"; c.HTTPTimeout = 0 }, "http-timeout"},
		{"negative delay", func(c *Config) { c.Domain = "a.com"; c.RateDelay = -1 }, "rate-delay"},
		{"empty nse scripts", func(c *Config) { c.Domain = "a.com"; c.NSE = true; c.NSEScripts = " " }, "nse-scripts"},
		{"zap minutes", func(c *Config) { c.Domain = "a.com"; c.ZapSpiderMinutes = 0 }, "zap-spider-minutes"},
		{"bad ports", func(c *Config) { c.Domain = "a.com"; c.Ports = "80;443" }, "--ports"},
		{"port range", func(c *Config) { c.Domain = "a.com"; c.Ports = "80,70000" }, "invalid port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			tc.mutate(&c)
			err := c.Validate()
			if tc.errSub == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.errSub != "" && (err == nil || !strings.Contains(err.Error(), tc.errSub)) {
				t.Fatalf("error = %v, want containing %q", err, tc.errSub)
			}
		})
	}
}

func TestRequiredCommands(t *testing.T) {
	c := Default()
	if got := strings.Join(c.RequiredCommands(), ","); got != "subfinder,nmap" {
		t.Errorf("base = %s", got)
	}
	c.Wordlist, c.Vhosts, c.WAF, c.Whois, c.Nuclei, c.Zap = "x", true, true, true, true, true
	if got := strings.Join(c.RequiredCommands(), ","); got != "subfinder,nmap,dnsx,gobuster,wafw00f,whois,nuclei,docker" {
		t.Errorf("all = %s", got)
	}
}

func fakeLook(have ...string) func(string) (string, error) {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	return func(n string) (string, error) {
		if set[n] {
			return "/usr/bin/" + n, nil
		}
		return "", os.ErrNotExist
	}
}

func TestDependencyReport(t *testing.T) {
	c := Default()
	r := c.DependencyReport(fakeLook("nmap", "docker"))
	if len(r) != 8 {
		t.Fatalf("want 8 tools, got %d", len(r))
	}
	by := map[string]Dependency{}
	for _, d := range r {
		by[d.Name] = d
	}
	if !by["subfinder"].Required || by["subfinder"].Found {
		t.Errorf("subfinder: %+v", by["subfinder"])
	}
	if !by["nmap"].Found || by["nmap"].Path != "/usr/bin/nmap" {
		t.Errorf("nmap: %+v", by["nmap"])
	}
	if by["nuclei"].Required || by["docker"].Required {
		t.Error("optional tools must not be required by default")
	}
	c.Nuclei, c.Zap = true, true
	by = map[string]Dependency{}
	for _, d := range c.DependencyReport(fakeLook("nmap", "docker")) {
		by[d.Name] = d
	}
	if !by["nuclei"].Required || by["nuclei"].Found || !by["docker"].Required || !by["docker"].Found {
		t.Errorf("nuclei=%+v docker=%+v", by["nuclei"], by["docker"])
	}
}

func TestValidateAcceptsDefaultWordlist(t *testing.T) {
	c := Default()
	c.Domain, c.Wordlist = "example.com", DefaultWordlist
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Wordlist = "/nonexistent/list.txt"
	if err := c.Validate(); err == nil {
		t.Fatal("a missing wordlist file should still fail")
	}
}
