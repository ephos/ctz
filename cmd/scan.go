package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"ctz/internal/config"
	"ctz/internal/install"
	"ctz/internal/report"
	"ctz/internal/runner"
)

const (
	green  = "\x1b[32m"
	red    = "\x1b[31m"
	reset  = "\x1b[0m"
	infoPx = "[" + green + "+" + reset + "]"
	warnPx = "[" + red + "!" + reset + "]"
)

type scanCmd struct {
	cmd *cobra.Command
	cfg *config.Config
}

func newScanCmd() *scanCmd {
	cfg := config.Default()
	s := &scanCmd{cfg: &cfg}
	s.cmd = &cobra.Command{
		Use:   "scan",
		Short: "Run enumeration and evidence collection from the command line",
		Example: `  ctz scan --domain example.com
  ctz scan -d example.com -oj -sv -he
  ctz scan --domains-file domains.txt --wordlist wordlist.txt --outjson
  ctz scan -d example.com --ports 22,80,443 --outjson --outdir ./results`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          func(c *cobra.Command, _ []string) error { return s.run(c) },
	}
	addScanFlags(s.cmd, s.cfg)
	return s
}

// addScanFlags registers every scan option on c, bound to cfg.
func addScanFlags(c *cobra.Command, cfg *config.Config) {
	f := c.Flags()
	f.StringVarP(&cfg.Domain, "domain", "d", "", "DNS zone / root domain to enumerate")
	f.StringVar(&cfg.DomainsFile, "domains-file", "", "text file containing DNS zones to enumerate (-df)")
	f.StringVar(&cfg.Wordlist, "wordlist", "", "DNS brute-force wordlist file, or \"default\" for the embedded list; runs dnsx in addition to subfinder (-wl)")
	f.StringVarP(&cfg.Resolvers, "resolvers", "r", "", "resolver list for dnsx: comma-separated or a file")
	f.BoolVar(&cfg.Vhosts, "vhosts", false, "run vhost enumeration with the bundled wordlist (-vh)")
	f.StringVar(&cfg.VhostWordlist, "vhost-wordlist", "", "vhost wordlist; implies --vhosts (-vwl)")
	f.StringVar(&cfg.VhostScheme, "vhost-scheme", cfg.VhostScheme, "URL scheme for vhost checks: http or https (-vs)")
	f.StringVar(&cfg.VhostURL, "vhost-url", "", "base URL for vhost checks; implies --vhosts (-vu)")
	f.BoolVar(&cfg.WAF, "waf", false, "run wafw00f against open HTTP/HTTPS endpoints (-wf)")
	f.BoolVar(&cfg.IPInfo, "ipinfo", false, "add ipinfo.io Lite data; requires IPINFO_API_KEY (-ii)")
	f.BoolVar(&cfg.Whois, "whois", false, "add RDAP/whois registration data for each zone (-wi)")
	f.BoolVar(&cfg.ServiceVersion, "service-version", false, "run nmap -sV --version-light (-sv)")
	f.BoolVar(&cfg.NSE, "nse", false, "run nmap NSE scripts")
	f.StringVar(&cfg.NSEScripts, "nse-scripts", cfg.NSEScripts, "NSE script set; implies --nse")
	f.BoolVar(&cfg.HTTPEvidence, "http-evidence", false, "collect HTTP response evidence and header assessments (-he)")
	f.IntVar(&cfg.HTTPTimeout, "http-timeout", cfg.HTTPTimeout, "HTTP request timeout in seconds")
	f.BoolVar(&cfg.Nuclei, "nuclei", false, "run nuclei against discovered HTTP/HTTPS endpoints (-nu)")
	f.StringVar(&cfg.NucleiSeverities, "nuclei-severities", cfg.NucleiSeverities, "nuclei severities to include; implies --nuclei")
	f.StringVar(&cfg.NucleiTemplates, "nuclei-templates", "", "nuclei template path; implies --nuclei")
	f.BoolVar(&cfg.Zap, "zap", false, "run OWASP ZAP baseline scans through Docker (-zap)")
	f.StringVar(&cfg.ZapImage, "zap-image", cfg.ZapImage, "Docker image for ZAP baseline scans; implies --zap")
	f.IntVar(&cfg.ZapSpiderMinutes, "zap-spider-minutes", cfg.ZapSpiderMinutes, "minutes of ZAP spidering per endpoint; implies --zap")
	f.IntVar(&cfg.ZapTimeoutMinutes, "zap-timeout-minutes", cfg.ZapTimeoutMinutes, "max minutes per ZAP baseline scan; implies --zap")
	f.IntVar(&cfg.ZapMaxEndpoints, "zap-max-endpoints", cfg.ZapMaxEndpoints, "max endpoints to scan with ZAP; implies --zap")
	f.Float64Var(&cfg.RateDelay, "rate-delay", 0, "delay in seconds between optional evidence requests")
	f.StringVarP(&cfg.Ports, "ports", "p", cfg.Ports, "comma-separated ports to test")
	f.BoolVar(&cfg.OutJSON, "outjson", false, "save JSON output to connectivity-results.json (-oj)")
	f.StringVar(&cfg.OutDir, "outdir", "", "output directory for the JSON file (-od)")
}

// applyImplied turns on features implied by their option flags.
func applyImplied(c *cobra.Command, cfg *config.Config) {
	changed := func(names ...string) bool {
		for _, n := range names {
			if c.Flags().Changed(n) {
				return true
			}
		}
		return false
	}
	if changed("vhost-wordlist", "vhost-url") {
		cfg.Vhosts = true
	}
	if changed("nse-scripts") {
		cfg.NSE = true
	}
	if changed("nuclei-severities", "nuclei-templates") {
		cfg.Nuclei = true
	}
	if changed("zap-image", "zap-spider-minutes", "zap-timeout-minutes", "zap-max-endpoints") {
		cfg.Zap = true
	}
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func (s *scanCmd) run(c *cobra.Command) error {
	cfg := *s.cfg
	applyImplied(c, &cfg)
	if err := cfg.Validate(); err != nil {
		return err
	}
	if missing := cfg.MissingDependencies(); len(missing) > 0 {
		var b strings.Builder
		b.WriteString("missing required dependencies:")
		for _, m := range missing {
			b.WriteString("\n    - " + m)
		}
		if hint := install.Hint(missing, install.DetectLocal()); hint != "" {
			b.WriteString("\n\nInstall with:\n" + hint)
		}
		b.WriteString("\n\nInstall the missing dependencies and run ctz again.")
		return errors.New(b.String())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	r := runner.New(cfg, func(e runner.Event) {
		if e.Level == runner.Warn {
			fmt.Fprintf(os.Stderr, "%s %s\n", warnPx, e.Msg)
			return
		}
		fmt.Fprintf(os.Stderr, "%s %s\n", infoPx, e.Msg)
	})
	out, err := r.Run(ctx)
	if err != nil {
		return err
	}
	data, err := report.JSON(out)
	if err != nil {
		return err
	}
	if isTerminal(os.Stdout) {
		fmt.Print(report.Colorize(data))
	} else {
		os.Stdout.Write(data)
	}
	if cfg.OutJSON {
		path, err := report.Save(out, cfg.OutDir)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%s JSON saved to: %s\n", infoPx, path)
	}
	fmt.Fprintf(os.Stderr, "%s Done.\n", infoPx)
	return nil
}
