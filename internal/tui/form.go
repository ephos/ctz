package tui

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"ctz/internal/config"
)

type fieldKind int

const (
	kindText fieldKind = iota
	kindToggle
)

type field struct {
	label  string
	help   string
	kind   fieldKind
	input  textinput.Model
	on     bool
	secret bool // masked input, drawn as a bordered box
	output bool // not a scan option; ctrl+a leaves it alone
	// implies names the toggle that switches on when this text field is edited
	// away from base, like the CLI's "implies --vhosts" style flags.
	implies string
	base    string
	toggle  func(c *config.Config, on bool)
	text    func(c *config.Config, v string) error
}

type form struct {
	fields []*field
	cursor int // len(fields) is the Run button
	err    string
	height int // terminal rows available to the form; 0 means unlimited
}

func textField(label, help, placeholder, value string, set func(*config.Config, string) error) *field {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.CharLimit = 512
	ti.Prompt = ""
	ti.Width = 40
	ti.SetValue(value) // after Width so long values are clipped, not drawn in full
	return &field{label: label, help: help, kind: kindText, input: ti, text: set}
}

// secretField is a text field whose value is masked on screen.
func secretField(label, help, placeholder string, set func(*config.Config, string) error) *field {
	fd := textField(label, help, placeholder, "", set)
	fd.secret = true
	fd.input.EchoMode = textinput.EchoPassword
	fd.input.EchoCharacter = '•'
	return fd
}

func toggleField(label, help string, on bool, set func(*config.Config, bool)) *field {
	return &field{label: label, help: help, kind: kindToggle, on: on, toggle: set}
}

// impliesToggle marks a text field as enabling the toggle labelled label once
// its value differs from the initial one.
func impliesToggle(label string, fds ...*field) []*field {
	for _, fd := range fds {
		fd.implies = label
		fd.base = strings.TrimSpace(fd.input.Value())
	}
	return fds
}

// syncImplied switches on toggles implied by edited dependent fields, so what
// the form shows matches what will run.
func (f *form) syncImplied() {
	for _, fd := range f.fields {
		if fd.implies == "" || strings.TrimSpace(fd.input.Value()) == fd.base {
			continue
		}
		for _, t := range f.fields {
			if t.kind == kindToggle && t.label == fd.implies {
				t.on = true
			}
		}
	}
}

func outputToggle(fd *field) *field {
	fd.output = true
	return fd
}

// toggleAll turns every scan option on, or off again if they are all on.
func (f *form) toggleAll() {
	all := true
	for _, fd := range f.fields {
		if fd.kind == kindToggle && !fd.output && !fd.on {
			all = false
		}
	}
	for _, fd := range f.fields {
		if fd.kind == kindToggle && !fd.output {
			fd.on = !all
		}
	}
}

func ipinfoPlaceholder(getenv func(string) string) string {
	if getenv("IPINFO_API_KEY") != "" {
		return "using $IPINFO_API_KEY"
	}
	return "optional"
}

// dnsWordlistDefault starts DNS brute-forcing with the embedded wordlist when
// dnsx is installed; otherwise the field is empty so a default run still works.
func dnsWordlistDefault(have func(string) bool) string {
	if have("dnsx") {
		return config.DefaultWordlist
	}
	return ""
}

func newForm() *form { return newFormFor(exec.LookPath, os.Getenv) }

// newFormFor builds the form with defaults suited to the environment: optional
// features start on when their tool (or API key) is already available.
func newFormFor(lookPath func(string) (string, error), getenv func(string) string) *form {
	d := config.Default()
	have := func(tool string) bool { _, err := lookPath(tool); return err == nil }
	intSet := func(name string, set func(*config.Config, int)) func(*config.Config, string) error {
		return func(c *config.Config, v string) error {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("%s must be a number", name)
			}
			set(c, n)
			return nil
		}
	}
	strSet := func(set func(*config.Config, string)) func(*config.Config, string) error {
		return func(c *config.Config, v string) error { set(c, strings.TrimSpace(v)); return nil }
	}
	fl := []*field{
		textField("Domain", "DNS zone to enumerate", "example.com", "", func(c *config.Config, v string) error { c.Domain = strings.TrimSpace(v); return nil }),
		textField("Domains file", "file with one zone per line (instead of Domain)", "domains.txt", "", func(c *config.Config, v string) error { c.DomainsFile = strings.TrimSpace(v); return nil }),
		textField("Ports", "comma-separated TCP ports", "", d.Ports, func(c *config.Config, v string) error { c.Ports = strings.TrimSpace(v); return nil }),
		textField("DNS wordlist", "file path, or \"default\" for the embedded list; set to enable dnsx brute-force", "optional", dnsWordlistDefault(have), strSet(func(c *config.Config, v string) { c.Wordlist = v })),
		textField("Resolvers", "dnsx resolvers (needs wordlist)", "optional", "", func(c *config.Config, v string) error { c.Resolvers = strings.TrimSpace(v); return nil }),
		toggleField("Vhost enumeration", "gobuster vhost with bundled wordlist", false, func(c *config.Config, on bool) { c.Vhosts = on }),
		impliesToggle("Vhost enumeration", textField("Vhost wordlist", "setting this turns Vhost enumeration on", "bundled", "", strSet(func(c *config.Config, v string) { c.VhostWordlist = v })))[0],
		textField("Vhost scheme", "http or https", "", d.VhostScheme, strSet(func(c *config.Config, v string) { c.VhostScheme = v })),
		impliesToggle("Vhost enumeration", textField("Vhost base URL", "setting this turns Vhost enumeration on; useful if the zone does not resolve", "optional", "", strSet(func(c *config.Config, v string) { c.VhostURL = v })))[0],
		toggleField("Service versions", "nmap -sV --version-light", true, func(c *config.Config, on bool) { c.ServiceVersion = on }),
		toggleField("NSE scripts", "nmap NSE scripts (slower; some may error on busy hosts)", false, func(c *config.Config, on bool) { c.NSE = on }),
		impliesToggle("NSE scripts", textField("NSE script set", "editing this turns NSE scripts on", "", d.NSEScripts, strSet(func(c *config.Config, v string) { c.NSEScripts = v })))[0],
		toggleField("HTTP evidence", "GET endpoints, assess security headers", true, func(c *config.Config, on bool) { c.HTTPEvidence = on }),
		toggleField("WAF detection", "wafw00f on web endpoints", have("wafw00f"), func(c *config.Config, on bool) { c.WAF = on }),
		toggleField("ipinfo.io", "needs an API key (field below or $IPINFO_API_KEY)", getenv("IPINFO_API_KEY") != "", func(c *config.Config, on bool) { c.IPInfo = on }),
		toggleField("Registration (RDAP/whois)", "per zone", have("whois"), func(c *config.Config, on bool) { c.Whois = on }),
		toggleField("Nuclei", "run nuclei on web endpoints", false, func(c *config.Config, on bool) { c.Nuclei = on }),
		impliesToggle("Nuclei", textField("Nuclei severities", "editing this turns Nuclei on", "", d.NucleiSeverities, strSet(func(c *config.Config, v string) { c.NucleiSeverities = v })))[0],
		impliesToggle("Nuclei", textField("Nuclei templates", "setting this turns Nuclei on", "default templates", "", strSet(func(c *config.Config, v string) { c.NucleiTemplates = v })))[0],
		toggleField("OWASP ZAP baseline", "via Docker", false, func(c *config.Config, on bool) { c.Zap = on }),
		impliesToggle("OWASP ZAP baseline", textField("ZAP image", "editing this turns ZAP on", "", d.ZapImage, strSet(func(c *config.Config, v string) { c.ZapImage = v })))[0],
		impliesToggle("OWASP ZAP baseline", textField("ZAP spider (min)", "per endpoint; editing this turns ZAP on", "", strconv.Itoa(d.ZapSpiderMinutes), intSet("ZAP spider minutes", func(c *config.Config, n int) { c.ZapSpiderMinutes = n })))[0],
		impliesToggle("OWASP ZAP baseline", textField("ZAP timeout (min)", "per baseline scan; editing this turns ZAP on", "", strconv.Itoa(d.ZapTimeoutMinutes), intSet("ZAP timeout minutes", func(c *config.Config, n int) { c.ZapTimeoutMinutes = n })))[0],
		impliesToggle("OWASP ZAP baseline", textField("ZAP max endpoints", "editing this turns ZAP on", "", strconv.Itoa(d.ZapMaxEndpoints), intSet("ZAP max endpoints", func(c *config.Config, n int) { c.ZapMaxEndpoints = n })))[0],
		textField("HTTP timeout (s)", "", "", strconv.Itoa(d.HTTPTimeout), intSet("HTTP timeout", func(c *config.Config, n int) { c.HTTPTimeout = n })),
		textField("Rate delay (s)", "between evidence requests", "", "0", func(c *config.Config, v string) error {
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil {
				return fmt.Errorf("Rate delay must be a number")
			}
			c.RateDelay = f
			return nil
		}),
		outputToggle(toggleField("Save JSON", "write connectivity-results.json", true, func(c *config.Config, on bool) { c.OutJSON = on })),
		textField("Output directory", "used when Save JSON is on", "current directory", "", func(c *config.Config, v string) error { c.OutDir = strings.TrimSpace(v); return nil }),
		secretField("ipinfo API key", "for the ipinfo.io option · hidden · or: export IPINFO_API_KEY=<key> before ctz", ipinfoPlaceholder(getenv), func(c *config.Config, v string) error { c.IPInfoKey = strings.TrimSpace(v); return nil }),
	}
	f := &form{fields: fl}
	f.focus()
	return f
}

func (f *form) focus() {
	for i, fd := range f.fields {
		if fd.kind != kindText {
			continue
		}
		if i == f.cursor {
			fd.input.Focus()
		} else {
			fd.input.Blur()
		}
	}
}

// config builds a Config from the current field values.
func (f *form) config() (config.Config, error) {
	cfg := config.Default()
	for _, fd := range f.fields {
		switch fd.kind {
		case kindText:
			if err := fd.text(&cfg, fd.input.Value()); err != nil {
				return cfg, err
			}
		case kindToggle:
			fd.toggle(&cfg, fd.on)
		}
	}
	return cfg, cfg.Validate()
}

// update handles a key; returns true when the user asked to run.
func (f *form) update(msg tea.Msg) (run bool, cmd tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "up", "shift+tab":
			f.move(-1)
			return false, nil
		case "down", "tab":
			f.move(1)
			return false, nil
		case "ctrl+a":
			f.toggleAll()
			return false, nil
		case "ctrl+r":
			return true, nil
		case "enter":
			if f.cursor == len(f.fields) {
				return true, nil
			}
			if f.fields[f.cursor].kind == kindToggle {
				f.fields[f.cursor].on = !f.fields[f.cursor].on
			} else {
				f.move(1)
			}
			return false, nil
		case " ":
			if f.cursor < len(f.fields) && f.fields[f.cursor].kind == kindToggle {
				f.fields[f.cursor].on = !f.fields[f.cursor].on
				return false, nil
			}
		}
	}
	if f.cursor < len(f.fields) && f.fields[f.cursor].kind == kindText {
		var c tea.Cmd
		f.fields[f.cursor].input, c = f.fields[f.cursor].input.Update(msg)
		f.syncImplied()
		return false, c
	}
	return false, nil
}

func (f *form) move(d int) {
	f.cursor = (f.cursor + d + len(f.fields) + 1) % (len(f.fields) + 1)
	f.focus()
}

func (f *form) view(width int) string {
	rows := make([]string, len(f.fields))
	for i, fd := range f.fields {
		rows[i] = f.row(i, fd)
	}
	var b strings.Builder
	b.WriteString(f.window(rows))
	btn := "[ Run scan ]"
	if f.cursor == len(f.fields) {
		btn = styleTabOn.Render("Run scan")
	} else {
		btn = styleTabOff.Render(btn)
	}
	b.WriteString("\n  " + btn + "\n")
	if f.err != "" {
		b.WriteString("\n  " + styleBad.Render(f.err) + "\n")
	}
	return b.String()
}

// formChrome is the number of terminal rows used around the field list: title,
// frame, button, error, scroll hints, dependency warning and help line.
const formChrome = 12

// window clips rows to the available height, keeping the cursor row visible.
func (f *form) window(rows []string) string {
	lines := make([]string, 0, len(rows))
	rowStart := make([]int, len(rows)+1)
	for i, r := range rows {
		rowStart[i] = len(lines)
		lines = append(lines, strings.Split(r, "\n")...)
	}
	rowStart[len(rows)] = len(lines)
	avail := f.height - formChrome
	if f.height == 0 || avail >= len(lines) {
		return strings.Join(lines, "\n") + "\n"
	}
	avail = max(avail, 3)
	cur := min(f.cursor, len(rows)-1)
	top := rowStart[cur] + (rowStart[cur+1]-rowStart[cur])/2 - avail/2
	top = max(0, min(top, len(lines)-avail))
	var b strings.Builder
	if top > 0 {
		b.WriteString(styleSubtle.Render(fmt.Sprintf("  ↑ %d more", top)) + "\n")
	}
	b.WriteString(strings.Join(lines[top:top+avail], "\n") + "\n")
	if below := len(lines) - top - avail; below > 0 {
		b.WriteString(styleSubtle.Render(fmt.Sprintf("  ↓ %d more", below)) + "\n")
	}
	return b.String()
}

// row renders one field, without a trailing newline.
func (f *form) row(i int, fd *field) string {
	cur := i == f.cursor
	marker := "  "
	label := fd.label
	if fd.kind == kindText {
		label = fmt.Sprintf("%-26s", label)
	}
	if cur {
		marker = styleAccent.Render("> ")
		label = styleSelected.Render(label)
	}
	var b strings.Builder
	switch fd.kind {
	case kindToggle:
		box := styleSubtle.Render("[ ]")
		if fd.on {
			box = styleGood.Render("[x]")
		}
		fmt.Fprintf(&b, "%s%s %s", marker, box, label)
	case kindText:
		if fd.secret {
			b.WriteString(secretBox(marker+label+" ", fd.input.View(), cur))
			if cur && fd.help != "" {
				b.WriteString("\n" + strings.Repeat(" ", 2) + styleSubtle.Render(fd.help))
			}
			return b.String()
		}
		fmt.Fprintf(&b, "%s%s %s", marker, label, fd.input.View())
	}
	if cur && fd.help != "" {
		b.WriteString("  " + styleSubtle.Render(fd.help))
	}
	return b.String()
}

// secretBox draws a secret input inside a rounded border beside its label;
// the border turns accent-coloured while the field has focus.
func secretBox(label, input string, focused bool) string {
	col := colMuted
	if focused {
		col = colAccent
	}
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(col).Padding(0, 1).Render(input)
	return lipgloss.JoinHorizontal(lipgloss.Center, label, box)
}

func textinputBlink() tea.Cmd { return textinput.Blink }

// lenientConfig builds a Config from the current fields, ignoring parse and
// validation errors. It is only used to work out which tools are needed.
func (f *form) lenientConfig() config.Config {
	cfg := config.Default()
	for _, fd := range f.fields {
		switch fd.kind {
		case kindText:
			_ = fd.text(&cfg, fd.input.Value())
		case kindToggle:
			fd.toggle(&cfg, fd.on)
		}
	}
	return cfg
}
