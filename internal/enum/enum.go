// Package enum discovers hostnames for the target zones.
package enum

import (
	"bufio"
	"context"
	_ "embed"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"ctz/internal/config"
	"ctz/internal/execx"
)

//go:embed vhost-wordlist.txt
var defaultVhostWordlist []byte

//go:embed wordlist.txt
var defaultDNSWordlist []byte

// LoadDomains reads, lowercases, trims and de-duplicates root domains.
func LoadDomains(cfg *config.Config) ([]string, error) {
	if cfg.DomainsFile == "" {
		return []string{strings.ToLower(strings.TrimSuffix(cfg.Domain, "."))}, nil
	}
	f, err := os.Open(cfg.DomainsFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	set := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(sc.Text()), "."))
		if d != "" {
			set[d] = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return sortedSet(set), nil
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FilterDomainHosts keeps lower-cased hosts equal to or under root.
func FilterDomainHosts(lines []string, root string) []string {
	re := regexp.MustCompile(`(^|\.)` + regexp.QuoteMeta(root) + `$`)
	var out []string
	for _, l := range lines {
		l = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(l), "."))
		if l != "" && re.MatchString(l) {
			out = append(out, l)
		}
	}
	return out
}

// Candidates turns wordlist labels into fully-qualified candidate names.
func Candidates(words []string, root string) []string {
	root = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(root)), ".")
	suffix := "." + root
	set := map[string]bool{}
	for _, w := range words {
		w = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(w)), ".")
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		if w == root || strings.HasSuffix(w, suffix) {
			set[w] = true
		} else {
			set[w+suffix] = true
		}
	}
	return sortedSet(set)
}

// VhostHosts extracts hostnames under root from gobuster output.
func VhostHosts(raw, root string) []string {
	root = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(root)), ".")
	label := `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`
	re := regexp.MustCompile(`\b` + label + `(?:\.` + label + `)*\.` + regexp.QuoteMeta(root) + `\b`)
	set := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSuffix(strings.ToLower(line), ".")
		for _, m := range re.FindAllString(line, -1) {
			m = strings.TrimSuffix(m, ".")
			if m == root || strings.HasSuffix(m, "."+root) {
				set[m] = true
			}
		}
	}
	return sortedSet(set)
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(b), "\n"), nil
}

// Subfinder runs passive enumeration for root.
func Subfinder(ctx context.Context, run execx.Runner, tmp, root string) ([]string, error) {
	out := filepath.Join(tmp, "subfinder-"+root+".raw.txt")
	r, err := run(ctx, "subfinder", "-d", root, "-silent", "-o", out)
	if err != nil {
		return nil, err
	}
	if r.ExitCode != 0 {
		return nil, errFailed("subfinder", root)
	}
	lines, _ := readLines(out)
	return FilterDomainHosts(lines, root), nil
}

// Dnsx runs active DNS brute-forcing for root using the configured wordlist.
func Dnsx(ctx context.Context, run execx.Runner, cfg *config.Config, tmp, root string) ([]string, error) {
	var words []string
	if cfg.Wordlist == config.DefaultWordlist {
		words = strings.Split(string(defaultDNSWordlist), "\n")
	} else {
		var err error
		if words, err = readLines(cfg.Wordlist); err != nil {
			return nil, err
		}
	}
	cand := filepath.Join(tmp, "dnsx-"+root+".candidates.txt")
	out := filepath.Join(tmp, "dnsx-"+root+".raw.txt")
	if err := os.WriteFile(cand, []byte(strings.Join(Candidates(words, root), "\n")+"\n"), 0o600); err != nil {
		return nil, err
	}
	args := []string{"-l", cand, "-silent", "-o", out}
	if cfg.Resolvers != "" {
		args = append(args, "-r", cfg.Resolvers)
	}
	r, err := run(ctx, "dnsx", args...)
	if err != nil {
		return nil, err
	}
	if r.ExitCode != 0 {
		return nil, errFailed("dnsx", root)
	}
	lines, _ := readLines(out)
	return FilterDomainHosts(lines, root), nil
}

// Gobuster runs vhost enumeration for root. Failures are returned as warnings
// (non-fatal) via the second result; unresolved/timeouts are silently ignored.
func Gobuster(ctx context.Context, run execx.Runner, cfg *config.Config, tmp, root string) (hosts []string, warning string) {
	wl := cfg.VhostWordlist
	if wl == "" {
		wl = filepath.Join(tmp, "vhost-wordlist.txt")
		if err := os.WriteFile(wl, defaultVhostWordlist, 0o600); err != nil {
			return nil, err.Error()
		}
	}
	out := filepath.Join(tmp, "gobuster-"+root+".raw.txt")
	url := cfg.VhostURL
	if url == "" {
		url = cfg.VhostScheme + "://" + root
	}
	r, err := run(ctx, "gobuster", "vhost", "--url", url, "--wordlist", wl, "--append-domain", "--domain", root,
		"--quiet", "--no-progress", "--no-error", "--no-color", "--output", out)
	if err != nil {
		return nil, err.Error()
	}
	if r.ExitCode != 0 {
		if strings.Contains(r.Stderr, "no such host") || strings.Contains(r.Stderr, "timeout occurred during the request") {
			return nil, ""
		}
		first, _, _ := strings.Cut(strings.TrimSpace(r.Stderr), "\n")
		return nil, first
	}
	b, _ := os.ReadFile(out)
	return VhostHosts(string(b), root), ""
}

type failedErr struct{ tool, root string }

func (e failedErr) Error() string { return e.tool + " failed for " + e.root }

func errFailed(tool, root string) error { return failedErr{tool, root} }
