// Package cmd defines the ctz command line.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// legacyShorts maps the multi-character short options of the original shell
// script onto their long forms, since pflag only supports one-letter shorthands.
var legacyShorts = map[string]string{
	"-df": "--domains-file", "-wl": "--wordlist", "-vh": "--vhosts", "-vwl": "--vhost-wordlist",
	"-vs": "--vhost-scheme", "-vu": "--vhost-url", "-wf": "--waf", "-ii": "--ipinfo", "-wi": "--whois",
	"-sv": "--service-version", "-he": "--http-evidence", "-nu": "--nuclei", "-zap": "--zap",
	"-oj": "--outjson", "-od": "--outdir",
}

func rewriteLegacy(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "--" {
			copy(out[i:], args[i:])
			return out
		}
		if long, ok := legacyShorts[a]; ok {
			a = long
		}
		out[i] = a
	}
	return out
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "ctz",
		Short: "Enumerate subdomains and collect connectivity/security evidence",
		Long: `ctz enumerates DNS subdomains for one or more target domains, resolves each
hostname, tests selected TCP ports, collects TLS certificate metadata, and emits
JSON-first results for authorized asset inventory and security assessment
evidence collection.

Use only for authorized security testing, asset inventory, and network
administration. See DISCLAIMER.md.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	scan := newScanCmd()
	// `ctz -d example.com` behaves like `ctz scan -d example.com`.
	addScanFlags(root, scan.cfg)
	root.RunE = func(c *cobra.Command, args []string) error {
		if len(os.Args) <= 1 {
			return c.Help()
		}
		return scan.run(c)
	}
	root.AddCommand(scan.cmd, newTUICmd())
	return root
}

// Execute runs the CLI and exits non-zero on error.
func Execute() {
	root := newRootCmd()
	root.SetArgs(rewriteLegacy(os.Args[1:]))
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}
