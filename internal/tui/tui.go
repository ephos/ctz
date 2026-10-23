// Package tui implements the interactive terminal UI.
package tui

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	xansi "github.com/charmbracelet/x/ansi"

	"ctz/internal/config"
	"ctz/internal/install"
	"ctz/internal/model"
	"ctz/internal/report"
	"ctz/internal/runner"
)

type phase int

const (
	phaseForm phase = iota
	phaseRunning
	phaseResults
)

type (
	eventMsg runner.Event
	doneMsg  struct {
		out *model.Output
		err error
	}
)

const maxLog = 200

// Model is the root bubbletea model.
type Model struct {
	phase         phase
	width, height int
	listDelta     int // user adjustment of the target list width, via [ and ]

	form *form
	cfg  config.Config

	// running
	spin     spinner.Model
	bar      progress.Model
	log      []string
	index    int
	total    int
	current  string
	stage    string
	partial  *model.TargetResult
	events   chan tea.Msg
	cancel   context.CancelFunc
	startMsg string

	// results
	out    *model.Output
	browse bool // reviewing finished targets while the scan is still running
	live   bool // out holds an unfinished scan (running, cancelled or failed)
	cursor int
	tab    int
	detail viewport.Model
	status string

	// dependency popup
	deps     []config.Dependency
	showDeps bool
}

var tabNames = []string{"Summary", "Overview", "TLS", "HTTP", "Hints"}

// New returns the initial model.
func New() Model {
	sp := spinner.New(spinner.WithSpinner(spinner.Dot))
	sp.Style = styleAccent
	m := Model{
		form: newForm(), spin: sp, bar: progress.New(progress.WithDefaultGradient()),
		detail: viewport.New(60, 20), width: 100, height: 30,
	}
	m.refreshDeps()
	// Warn immediately when a tool every scan needs is missing.
	req, _ := depCounts(m.deps)
	m.showDeps = len(req) > 0
	return m
}

// refreshDeps recomputes tool availability for the currently selected options.
func (m *Model) refreshDeps() {
	cfg := m.form.lenientConfig()
	m.deps = cfg.DependencyReport(exec.LookPath)
}

// Run starts the TUI.
func Run() error {
	_, err := tea.NewProgram(New(), tea.WithAltScreen()).Run()
	return err
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd { return textinputBlink() }

func (m Model) startScan(cfg config.Config) (Model, tea.Cmd) {
	m.refreshDeps()
	if req, _ := depCounts(m.deps); len(req) > 0 {
		m.form.err = "missing dependencies: " + strings.Join(req, ", ")
		m.showDeps = true
		return m, nil
	}
	m.cfg = cfg
	m.phase = phaseRunning
	m.log, m.index, m.total, m.current, m.status = nil, 0, 0, "", ""
	m.stage, m.partial = "", nil
	m.out, m.browse, m.live = nil, false, false
	m.out, m.browse, m.live = nil, false, false
	m.events = make(chan tea.Msg, 256)
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	ch := m.events
	go func() {
		r := runner.New(cfg, func(e runner.Event) { ch <- eventMsg(e) })
		out, err := r.Run(ctx)
		ch <- doneMsg{out: out, err: err}
	}()
	return m, tea.Batch(m.spin.Tick, waitForEvent(ch))
}

func waitForEvent(ch chan tea.Msg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.form.height = msg.Height
		m.bar.Width = max(10, min(60, msg.Width-10))
		m.resizeDetail()
		m.refreshDetail()
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		}
		if m.showDeps {
			switch msg.String() {
			case "esc", "d", "ctrl+d", "enter", "q":
				m.showDeps = false
			}
			return m, nil
		}
		if msg.String() == "ctrl+d" || (m.phase == phaseResults && msg.String() == "d") {
			m.refreshDeps()
			m.showDeps = true
			return m, nil
		}
	}
	switch m.phase {
	case phaseForm:
		return m.updateForm(msg)
	case phaseRunning:
		return m.updateRunning(msg)
	default:
		return m.updateResults(msg)
	}
}

func (m Model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			return m, tea.Quit
		case "ctrl+o":
			if m.out != nil {
				m.phase, m.cursor = phaseResults, 0
				m.resizeDetail()
				m.refreshDetail()
			}
			return m, nil
		}
	}
	run, cmd := m.form.update(msg)
	if _, isKey := msg.(tea.KeyMsg); isKey {
		m.refreshDeps()
	}
	if run {
		cfg, err := m.form.config()
		if err != nil {
			m.form.err = err.Error()
			return m, cmd
		}
		m.form.err = ""
		return m.startScan(cfg)
	}
	return m, cmd
}

func (m Model) updateRunning(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		var c tea.Cmd
		m.spin, c = m.spin.Update(msg)
		return m, c
	case tea.KeyMsg:
		if m.browse {
			switch msg.String() {
			case "tab", "esc":
				m.browse = false
			default:
				m.navigate(msg)
			}
			return m, nil
		}
		switch msg.String() {
		case "esc":
			m.cancel()
			m.phase = phaseForm
			m.form.err = "scan cancelled; ctrl+o reviews its finished targets"
			return m, nil
		case "tab":
			if m.out != nil && len(m.out.Results) > 0 {
				m.browse = true
				m.resizeDetail()
				m.refreshDetail()
			}
		}
		return m, nil
	case eventMsg:
		if msg.Done != nil {
			if m.out == nil {
				m.out = &model.Output{}
				m.live = true
			}
			m.out.Results = append(m.out.Results, *msg.Done)
			m.out.PrioritizationHint = msg.Hints
			if m.browse {
				m.resizeDetail()
				// keep the viewport where the user is reading
				y := m.detail.YOffset
				m.refreshDetail()
				m.detail.SetYOffset(y)
			}
			return m, waitForEvent(m.events)
		}
		if msg.Total > 0 {
			m.index, m.total, m.current = msg.Index, msg.Total, msg.Target
			m.stage, m.partial = "", nil
		}
		if msg.Stage != "" {
			m.stage, m.partial = msg.Stage, msg.Partial
			return m, waitForEvent(m.events)
		}
		prefix := styleGood.Render("[+]")
		if msg.Level == runner.Warn {
			prefix = styleBad.Render("[!]")
		}
		m.log = append(m.log, prefix+" "+msg.Msg)
		if len(m.log) > maxLog {
			m.log = m.log[len(m.log)-maxLog:]
		}
		return m, waitForEvent(m.events)
	case doneMsg:
		m.cancel()
		if msg.err != nil {
			m.phase = phaseForm
			m.form.err = "scan failed: " + msg.err.Error()
			return m, nil
		}
		m.out, m.live, m.browse = msg.out, false, false
		m.phase, m.cursor, m.tab = phaseResults, 0, 0
		m.resizeDetail()
		m.refreshDetail()
		if m.cfg.OutJSON {
			m.save()
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) save() {
	path, err := report.Save(m.out, m.cfg.OutDir)
	if err != nil {
		m.status = styleBad.Render("save failed: " + err.Error())
		return
	}
	m.status = styleGood.Render("JSON saved to " + path)
}

func (m Model) updateResults(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		var c tea.Cmd
		m.detail, c = m.detail.Update(msg)
		return m, c
	}
	switch k.String() {
	case "q", "esc":
		return m, tea.Quit
	case "n":
		m.phase = phaseForm
		return m, nil
	case "s":
		if m.live {
			m.status = styleWarn.Render("scan did not finish; nothing to save")
		} else {
			m.save()
		}
		return m, nil
	}
	c := m.navigate(msg)
	return m, c
}

// navigate handles target selection, tab switching and scrolling shared by
// the results screen and the browse view of a running scan.
func (m *Model) navigate(msg tea.Msg) tea.Cmd {
	k, ok := msg.(tea.KeyMsg)
	if !ok || m.out == nil {
		return nil
	}
	n := len(m.out.Results)
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
			m.refreshDetail()
		}
	case "down", "j":
		if m.cursor < n-1 {
			m.cursor++
			m.refreshDetail()
		}
	case "tab", "right", "l":
		m.tab = (m.tab + 1) % len(tabNames)
		m.refreshDetail()
	case "shift+tab", "left", "h":
		m.tab = (m.tab + len(tabNames) - 1) % len(tabNames)
		m.refreshDetail()
	case "1", "2", "3", "4", "5":
		m.tab = int(k.String()[0] - '1')
		m.refreshDetail()
	case "[", "]":
		before := m.listWidth()
		step := listStep
		if k.String() == "[" {
			step = -listStep
		}
		m.listDelta += step
		if m.listWidth() == before { // at a limit; don't wind the delta up
			m.listDelta -= step
		}
		m.resizeDetail()
		m.refreshDetail()
	default:
		var c tea.Cmd
		m.detail, c = m.detail.Update(msg)
		return c
	}
	return nil
}

// listStep is how many columns [ and ] move the list/detail divider.
const listStep = 4

func (m *Model) listWidth() int {
	w := 28
	if m.out != nil {
		for _, r := range m.out.Results {
			w = max(w, len(r.Target)+5)
		}
	}
	w = min(w, max(20, m.width/3)) + m.listDelta
	return max(14, min(w, m.width-40))
}

func (m *Model) resizeDetail() {
	// The pane pads one column each side; the viewport fills what is inside.
	m.detail.Width = max(20, m.width-m.listWidth()-8) - 2
	m.detail.Height = max(5, m.height-9)
}

func (m *Model) refreshDetail() {
	if m.out == nil || len(m.out.Results) == 0 {
		m.detail.SetContent("No targets.")
		return
	}
	m.detail.SetContent(renderDetail(m.out, m.out.Results[m.cursor], m.tab, m.detail.Width))
	m.detail.GotoTop()
}

// View implements tea.Model.
func (m Model) View() string {
	if m.showDeps {
		return placeCentered(m.width, m.height, renderDeps(m.deps, install.DetectLocal()))
	}
	title := styleTitle.Render("ctz") + " " + styleSubtle.Render("connectivity test zone")
	switch m.phase {
	case phaseForm:
		warn := depWarning(m.deps)
		if warn != "" {
			warn += "\n"
		}
		return title + "\n" + styleFrame.Render(strings.TrimRight(m.form.view(m.width), "\n")) + "\n" + warn +
			styleHelp.Render("↑/↓ move · space/enter toggle · ctrl+a all options · ctrl+r run · ctrl+d dependencies"+m.reviewHint()+" · esc quit")
	case phaseRunning:
		return m.viewRunning(title)
	}
	return m.viewResults(title)
}

func (m Model) viewRunning(title string) string {
	if m.browse && m.out != nil && len(m.out.Results) > 0 {
		hdr := fmt.Sprintf("%s  %s", title, styleSubtle.Render(fmt.Sprintf("scan running · %d/%d targets finished", len(m.out.Results), m.total)))
		return hdr + "\n\n" + m.resultsBody() + "\n" +
			styleHelp.Render("↑/↓ target · ←/→ tab · pgup/pgdn scroll · tab/esc back to live scan · ctrl+c quit")
	}
	var b strings.Builder
	b.WriteString(title + "\n\n")
	status := "Enumerating targets…"
	if m.total > 0 {
		status = fmt.Sprintf("Testing %s (%d/%d)", m.current, m.index, m.total)
	}
	if m.out != nil && len(m.out.Results) > 0 {
		status += "  " + styleAccent.Render(fmt.Sprintf("· press tab to review %d finished", len(m.out.Results)))
	}
	b.WriteString(m.spin.View() + " " + status + "\n\n")
	pct := 0.0
	if m.total > 0 {
		pct = float64(m.index-1) / float64(m.total)
		if pct < 0 {
			pct = 0
		}
	}
	b.WriteString(m.bar.ViewAs(pct) + "\n\n")
	room := max(3, m.height-9)
	lines := m.log
	if len(lines) > room {
		lines = lines[len(lines)-room:]
	}
	if m.width < 100 {
		b.WriteString(stylePane.Width(max(20, m.width-4)).Render(strings.Join(lines, "\n")))
	} else {
		lw := (m.width - 8) * 2 / 5
		rw := m.width - 8 - lw
		left := stylePane.Width(lw).Height(room).Render(clipLines(lines, lw-2))
		right := stylePane.Width(rw).Height(room).Render(m.renderProgress(rw, room))
		b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right))
	}
	help := "esc cancel · ctrl+c quit"
	if m.out != nil && len(m.out.Results) > 0 {
		help = fmt.Sprintf("tab review %d finished · ", len(m.out.Results)) + help
	}
	b.WriteString("\n" + styleHelp.Render(help))
	return b.String()
}

// clipLines truncates each line to width so long messages don't wrap and
// break the pane layout.
func clipLines(lines []string, width int) string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = xansi.Truncate(l, width, "…")
	}
	return strings.Join(out, "\n")
}

// renderProgress renders the right-hand pane: the stage checklist for the
// target in progress followed by what has been learned about it so far.
func (m Model) renderProgress(width, height int) string {
	if m.current == "" {
		return styleSubtle.Render("Waiting for the first target…")
	}
	var b strings.Builder
	b.WriteString(styleHeading.Render(m.current) + "\n\n")
	cur := -1
	for i, s := range runner.Stages {
		if s == m.stage {
			cur = i
		}
	}
	for i, s := range runner.Stages {
		switch {
		case i < cur:
			b.WriteString(styleGood.Render("✓ ") + s + "\n")
		case i == cur:
			b.WriteString(m.spin.View() + " " + styleAccent.Render(s) + "\n")
		default:
			b.WriteString(styleSubtle.Render("○ "+s) + "\n")
		}
	}
	if m.partial != nil && m.partial.Resolved {
		b.WriteString("\n" + renderOverview(*m.partial, nseRunFromConfig(m.cfg), width-2))
	}
	lines := strings.Split(b.String(), "\n")
	if len(lines) > height {
		lines = append(lines[:height-1], styleSubtle.Render("…"))
	}
	return clipLines(lines, width-2)
}

func (m Model) viewResults(title string) string {
	if m.out == nil || len(m.out.Results) == 0 {
		return title + "\n\nNo targets.\n" + styleHelp.Render("n new scan · q quit")
	}
	hdrInfo := fmt.Sprintf("%d targets · %s", len(m.out.Results), m.out.RunDatetime)
	if m.live {
		hdrInfo = fmt.Sprintf("%d targets finished · scan did not complete", len(m.out.Results))
	}
	hdr := fmt.Sprintf("%s  %s", title, styleSubtle.Render(hdrInfo))
	foot := styleHelp.Render("↑/↓ target · ←/→ tab · pgup/pgdn scroll · [/] resize list · s save JSON · n new scan · d deps · q quit")
	if m.status != "" {
		foot = m.status + "\n" + foot
	}
	return hdr + "\n\n" + m.resultsBody() + "\n" + foot
}

// resultsBody renders the target list beside the tabbed detail pane.
func (m Model) resultsBody() string {
	lw := m.listWidth()
	listRows := max(3, m.height-8)
	start := 0
	if m.cursor >= listRows {
		start = m.cursor - listRows + 1
	}
	var rows []string
	for i := start; i < len(m.out.Results) && i < start+listRows; i++ {
		r := m.out.Results[i]
		dot := styleSubtle.Render("○")
		switch {
		case r.Connected:
			dot = styleGood.Render("●")
		case r.Resolved:
			dot = styleWarn.Render("●")
		}
		// Pane content is lw-2 wide (padding); the marker, dot and space take 3.
		name := xansi.Truncate(r.Target, lw-5, "…")
		line := dot + " " + name
		if i == m.cursor {
			line = styleSelected.Render("▌") + dot + " " + styleSelected.Render(name)
		} else {
			line = " " + line
		}
		rows = append(rows, line)
	}
	left := stylePane.Width(lw).Height(listRows).Render(strings.Join(rows, "\n"))

	var tabs []string
	for i, t := range tabNames {
		if i == m.tab {
			tabs = append(tabs, styleTabOn.Render(t))
		} else {
			tabs = append(tabs, styleTabOff.Render(t))
		}
	}
	right := lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.JoinHorizontal(lipgloss.Top, tabs...),
		stylePane.Width(m.detail.Width+2).Render(m.detail.View()),
	)
	return lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
}

func (m Model) reviewHint() string {
	if m.out != nil {
		return " · ctrl+o last results"
	}
	return ""
}
