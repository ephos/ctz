package tui

import "github.com/charmbracelet/lipgloss"

var (
	colAccent = lipgloss.AdaptiveColor{Light: "#5A56E0", Dark: "#7D79F6"}
	colMuted  = lipgloss.AdaptiveColor{Light: "#7A7A85", Dark: "#8A8A96"}
	colGood   = lipgloss.AdaptiveColor{Light: "#1A7F37", Dark: "#3FB950"}
	colWarn   = lipgloss.AdaptiveColor{Light: "#9A6700", Dark: "#D29922"}
	colBad    = lipgloss.AdaptiveColor{Light: "#CF222E", Dark: "#F85149"}
	colInfo   = lipgloss.AdaptiveColor{Light: "#0969DA", Dark: "#58A6FF"}
	colMaroon = lipgloss.AdaptiveColor{Light: "#800000", Dark: "#C0504D"}

	styleTitle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(colAccent).Padding(0, 1)
	styleSubtle    = lipgloss.NewStyle().Foreground(colMuted)
	styleAccent    = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	styleGood      = lipgloss.NewStyle().Foreground(colGood)
	styleWarn      = lipgloss.NewStyle().Foreground(colWarn)
	styleBad       = lipgloss.NewStyle().Foreground(colBad)
	styleScriptErr = lipgloss.NewStyle().Foreground(colMaroon).Italic(true)
	styleHeading   = lipgloss.NewStyle().Bold(true).Underline(true)
	styleSelected  = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	styleTabOn     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(colAccent).Padding(0, 1)
	styleTabOff    = lipgloss.NewStyle().Foreground(colMuted).Padding(0, 1)
	stylePane      = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colMuted).Padding(0, 1)
	styleFrame     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colAccent).Padding(0, 1)
	styleHelp      = lipgloss.NewStyle().Foreground(colMuted)
)

func severityStyle(sev string) lipgloss.Style {
	switch sev {
	case "critical", "high":
		return styleBad.Bold(true)
	case "medium":
		return styleWarn
	case "low":
		return lipgloss.NewStyle().Foreground(colInfo)
	}
	return styleSubtle
}
