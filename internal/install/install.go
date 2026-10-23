// Package install suggests commands for installing missing external tools.
package install

import (
	"fmt"
	"os"
	"strings"
)

// Package managers we target.
const (
	Apt    = "apt"
	Dnf    = "dnf"
	Pacman = "pacman"
)

// Managers lists the supported managers in display order.
var Managers = []string{Apt, Dnf, Pacman}

type pkgs struct{ apt, dnf, pacman string }

// systemPkgs maps tools available from distro repositories.
var systemPkgs = map[string]pkgs{
	"nmap":     {"nmap", "nmap", "nmap"},
	"gobuster": {"gobuster", "gobuster", "gobuster"},
	"whois":    {"whois", "whois", "whois"},
	"docker":   {"docker.io", "moby-engine", "docker"},
}

// goModules maps ProjectDiscovery tools to their `go install` paths.
var goModules = map[string]string{
	"subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
	"dnsx":      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
	"nuclei":    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
}

var goOrder = []string{"subfinder", "dnsx", "nuclei"}

// Detect returns the package manager for an os-release file's content, or ""
// when the distribution is not recognized.
func Detect(osRelease string) string {
	var ids []string
	for _, line := range strings.Split(osRelease, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || (k != "ID" && k != "ID_LIKE") {
			continue
		}
		ids = append(ids, strings.Fields(strings.ToLower(strings.Trim(v, `"'`)))...)
	}
	for _, id := range ids {
		switch id {
		case "debian", "ubuntu", "kali", "linuxmint", "pop", "raspbian":
			return Apt
		case "fedora", "rhel", "centos", "rocky", "almalinux", "amzn":
			return Dnf
		case "arch", "manjaro", "endeavouros", "cachyos", "artix":
			return Pacman
		}
	}
	return ""
}

// DetectLocal inspects /etc/os-release.
func DetectLocal() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	return Detect(string(b))
}

// Command is one install command line.
type Command struct {
	Label string // "apt", "dnf", "pacman", "go", "pipx"
	Line  string
}

// Plan returns the commands that install the given missing tools: one
// command per package manager for repository packages, plus go/pipx lines for
// tools that are not packaged. Empty when nothing needs installing.
func Plan(missing []string) []Command {
	var sys []string
	var goTools []string
	pipx := false
	has := map[string]bool{}
	for _, m := range missing {
		has[m] = true
	}
	for _, m := range []string{"nmap", "gobuster", "whois", "docker"} {
		if has[m] {
			sys = append(sys, m)
		}
	}
	for _, m := range goOrder {
		if has[m] {
			goTools = append(goTools, m)
		}
	}
	pipx = has["wafw00f"]

	var cmds []Command
	pick := func(mgr string, p pkgs) string {
		switch mgr {
		case Apt:
			return p.apt
		case Dnf:
			return p.dnf
		}
		return p.pacman
	}
	extras := map[string]pkgs{
		"go":   {"golang-go", "golang", "go"},
		"pipx": {"pipx", "pipx", "python-pipx"},
	}
	for _, mgr := range Managers {
		var list []string
		for _, s := range sys {
			list = append(list, pick(mgr, systemPkgs[s]))
		}
		if len(goTools) > 0 {
			list = append(list, pick(mgr, extras["go"]))
		}
		if pipx {
			list = append(list, pick(mgr, extras["pipx"]))
		}
		if len(list) == 0 {
			continue
		}
		verb := map[string]string{
			Apt:    "sudo apt install -y",
			Dnf:    "sudo dnf install -y",
			Pacman: "sudo pacman -S --needed",
		}[mgr]
		cmds = append(cmds, Command{Label: mgr, Line: verb + " " + strings.Join(list, " ")})
	}
	for i, t := range goTools {
		line := "go install " + goModules[t]
		if i == len(goTools)-1 {
			line += "   # then add ~/go/bin to PATH"
		}
		cmds = append(cmds, Command{Label: "go", Line: line})
	}
	if pipx {
		cmds = append(cmds, Command{Label: "pipx", Line: "pipx install wafw00f"})
	}
	return cmds
}

// Hint formats the plan as indented text, marking the detected manager.
func Hint(missing []string, detected string) string {
	var b strings.Builder
	for _, c := range Plan(missing) {
		mark := " "
		if c.Label == detected {
			mark = "▸"
		}
		fmt.Fprintf(&b, "%s %-6s %s\n", mark, c.Label, c.Line)
	}
	return strings.TrimRight(b.String(), "\n")
}
