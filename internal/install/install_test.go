package install

import (
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	cases := map[string]string{
		"ID=ubuntu\nID_LIKE=debian": Apt,
		"ID=kali\nID_LIKE=debian":   Apt,
		"ID=fedora":                 Dnf,
		`ID="rocky"` + "\n" + `ID_LIKE="rhel centos fedora"`: Dnf,
		"ID=arch":                  Pacman,
		"ID=cachyos\nID_LIKE=arch": Pacman,
		"ID=nixos":                 "",
		"":                         "",
	}
	for in, want := range cases {
		if got := Detect(in); got != want {
			t.Errorf("Detect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPlan(t *testing.T) {
	if len(Plan(nil)) != 0 {
		t.Error("nothing missing -> no commands")
	}
	cmds := Plan([]string{"subfinder", "nmap", "docker", "wafw00f", "nuclei"})
	by := map[string]string{}
	for _, c := range cmds {
		by[c.Label] += c.Line + "\n"
	}
	by[Apt], by[Dnf], by[Pacman] = strings.TrimSpace(by[Apt]), strings.TrimSpace(by[Dnf]), strings.TrimSpace(by[Pacman])
	by["pipx"] = strings.TrimSpace(by["pipx"])
	if by[Apt] != "sudo apt install -y nmap docker.io golang-go pipx" {
		t.Errorf("apt = %q", by[Apt])
	}
	if by[Dnf] != "sudo dnf install -y nmap moby-engine golang pipx" {
		t.Errorf("dnf = %q", by[Dnf])
	}
	if by[Pacman] != "sudo pacman -S --needed nmap docker go python-pipx" {
		t.Errorf("pacman = %q", by[Pacman])
	}
	if !strings.Contains(by["go"], "subfinder/v2/cmd/subfinder@latest") || !strings.Contains(by["go"], "nuclei/v3/cmd/nuclei@latest") || strings.Contains(by["go"], "dnsx") {
		t.Errorf("go = %q", by["go"])
	}
	if by["pipx"] != "pipx install wafw00f" {
		t.Errorf("pipx = %q", by["pipx"])
	}
	// Only go tools missing: no distro packages beyond the Go toolchain.
	only := Plan([]string{"dnsx"})
	if only[0].Line != "sudo apt install -y golang-go" {
		t.Errorf("got %q", only[0].Line)
	}
	if !strings.Contains(Hint([]string{"nmap"}, Dnf), "▸ dnf") {
		t.Error("detected manager not marked")
	}
}
