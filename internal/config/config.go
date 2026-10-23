// Package config holds the scan options and their validation.
package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const (
	DefaultPorts            = "20,21,22,23,25,53,80,88,111,135,139,389,443,445,464,593,636,1433,1521,2049,2379,2380,3268,3269,3306,3389,5432,5672,5900,5985,5986,6379,6443,8000,8080,8081,8433,8443,9000,9200,9389,10250,27017"
	DefaultNSEScripts       = "default,safe"
	DefaultNucleiSeverities = "info,low,medium,high,critical"
	DefaultZapImage         = "ghcr.io/zaproxy/zaproxy:stable"
	DefaultVhostScheme      = "https"
	// DefaultWordlist is the --wordlist value that selects the embedded DNS wordlist.
	DefaultWordlist          = "default"
	DefaultHTTPTimeout       = 10
	DefaultZapSpiderMinutes  = 1
	DefaultZapTimeoutMinutes = 5
	DefaultZapMaxEndpoints   = 10
	JSONFilename             = "connectivity-results.json"
	NmapTimeoutSeconds       = 60
	Wafw00fTimeoutSeconds    = 30
)

// Config is the full set of scan options.
type Config struct {
	Domain      string
	DomainsFile string

	Wordlist  string
	Resolvers string

	Vhosts        bool
	VhostWordlist string
	VhostScheme   string
	VhostURL      string

	WAF            bool
	IPInfo         bool
	IPInfoKey      string // secret; overrides $IPINFO_API_KEY. Never serialize or log.
	Whois          bool
	ServiceVersion bool
	NSE            bool
	NSEScripts     string

	HTTPEvidence bool
	HTTPTimeout  int

	Nuclei           bool
	NucleiSeverities string
	NucleiTemplates  string

	Zap               bool
	ZapImage          string
	ZapSpiderMinutes  int
	ZapTimeoutMinutes int
	ZapMaxEndpoints   int

	RateDelay float64
	Ports     string

	OutJSON bool
	OutDir  string
}

// Default returns a Config populated with the documented defaults.
func Default() Config {
	return Config{
		VhostScheme:       DefaultVhostScheme,
		NSEScripts:        DefaultNSEScripts,
		HTTPTimeout:       DefaultHTTPTimeout,
		NucleiSeverities:  DefaultNucleiSeverities,
		ZapImage:          DefaultZapImage,
		ZapSpiderMinutes:  DefaultZapSpiderMinutes,
		ZapTimeoutMinutes: DefaultZapTimeoutMinutes,
		ZapMaxEndpoints:   DefaultZapMaxEndpoints,
		Ports:             DefaultPorts,
	}
}

var portsRe = regexp.MustCompile(`^\s*\d+\s*(,\s*\d+\s*)*$`)

func readable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return f.Close()
}

func fileCheck(label, path string) error {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return fmt.Errorf("%s does not exist: %s", label, path)
	}
	if err := readable(path); err != nil {
		return fmt.Errorf("%s is not readable: %s", label, path)
	}
	return nil
}

// Validate mirrors the validate_input checks of the original script. It may
// fill in defaults (the vhost wordlist is left empty to mean "embedded").
func (c *Config) Validate() error {
	if c.Domain != "" && c.DomainsFile != "" {
		return errors.New("use either --domain or --domains-file, not both")
	}
	if c.Domain == "" && c.DomainsFile == "" {
		return errors.New("missing required domain or domains file")
	}
	if c.DomainsFile != "" {
		if err := fileCheck("Domains file", c.DomainsFile); err != nil {
			return err
		}
	}
	if c.Wordlist != "" && c.Wordlist != DefaultWordlist {
		if err := fileCheck("Wordlist", c.Wordlist); err != nil {
			return err
		}
	}
	if c.Resolvers != "" && c.Wordlist == "" {
		return errors.New("--resolvers can only be used with --wordlist")
	}
	if c.Vhosts && c.VhostWordlist != "" {
		if err := fileCheck("Vhost wordlist", c.VhostWordlist); err != nil {
			return err
		}
	}
	if c.VhostScheme != "http" && c.VhostScheme != "https" {
		return errors.New("--vhost-scheme must be either http or https")
	}
	if c.HTTPTimeout < 1 {
		return errors.New("--http-timeout must be a positive integer")
	}
	if c.RateDelay < 0 {
		return errors.New("--rate-delay must be a non-negative number")
	}
	if c.NSE && strings.TrimSpace(c.NSEScripts) == "" {
		return errors.New("--nse-scripts cannot be empty when --nse is used")
	}
	if c.Nuclei && strings.TrimSpace(c.NucleiSeverities) == "" {
		return errors.New("--nuclei-severities cannot be empty when --nuclei is used")
	}
	if c.ZapSpiderMinutes < 1 {
		return errors.New("--zap-spider-minutes must be a positive integer")
	}
	if c.ZapTimeoutMinutes < 1 {
		return errors.New("--zap-timeout-minutes must be a positive integer")
	}
	if c.ZapMaxEndpoints < 1 {
		return errors.New("--zap-max-endpoints must be a positive integer")
	}
	if c.Zap && strings.TrimSpace(c.ZapImage) == "" {
		return errors.New("--zap-image cannot be empty when --zap is used")
	}
	if !portsRe.MatchString(c.Ports) {
		return errors.New("--ports must be a comma-separated list of port numbers")
	}
	for _, p := range strings.Split(c.Ports, ",") {
		n, _ := strconv.Atoi(strings.TrimSpace(p))
		if n < 1 || n > 65535 {
			return fmt.Errorf("--ports contains an invalid port: %s", strings.TrimSpace(p))
		}
	}
	c.Ports = strings.ReplaceAll(c.Ports, " ", "")
	return nil
}

// RequiredCommands returns the external binaries needed by the enabled features.
func (c *Config) RequiredCommands() []string {
	cmds := []string{"subfinder", "nmap"}
	if c.Wordlist != "" {
		cmds = append(cmds, "dnsx")
	}
	if c.Vhosts {
		cmds = append(cmds, "gobuster")
	}
	if c.WAF {
		cmds = append(cmds, "wafw00f")
	}
	if c.Whois {
		cmds = append(cmds, "whois")
	}
	if c.Nuclei {
		cmds = append(cmds, "nuclei")
	}
	if c.Zap {
		cmds = append(cmds, "docker")
	}
	return cmds
}

// Dependency describes one external tool and whether it is available.
type Dependency struct {
	Name     string
	Feature  string // option that needs the tool, or "always"
	Path     string // resolved path when found
	Found    bool
	Required bool // needed by the currently selected options
}

var allDependencies = []struct{ name, feature string }{
	{"subfinder", "always"},
	{"nmap", "always"},
	{"dnsx", "--wordlist"},
	{"gobuster", "--vhosts"},
	{"wafw00f", "--waf"},
	{"whois", "--whois"},
	{"nuclei", "--nuclei"},
	{"docker", "--zap"},
}

// DependencyReport lists every external tool with its availability and
// whether the current options require it.
func (c *Config) DependencyReport(lookPath func(string) (string, error)) []Dependency {
	required := map[string]bool{}
	for _, cmd := range c.RequiredCommands() {
		required[cmd] = true
	}
	report := make([]Dependency, 0, len(allDependencies))
	for _, d := range allDependencies {
		path, err := lookPath(d.name)
		report = append(report, Dependency{
			Name: d.name, Feature: d.feature, Path: path, Found: err == nil, Required: required[d.name],
		})
	}
	return report
}

// MissingDependencies returns the required commands not found on PATH.
func (c *Config) MissingDependencies() []string {
	var missing []string
	for _, d := range c.DependencyReport(exec.LookPath) {
		if d.Required && !d.Found {
			missing = append(missing, d.Name)
		}
	}
	return missing
}
