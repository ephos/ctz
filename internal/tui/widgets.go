package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	xansi "github.com/charmbracelet/x/ansi"
)

// colOnPill is the text colour on a filled pill: white on the light theme's
// darker fills, near-black on the dark theme's lighter ones.
var colOnPill = lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#0D1117"}

// pill renders label as a filled badge.
func pill(label string, bg lipgloss.TerminalColor) string {
	return lipgloss.NewStyle().Bold(true).Foreground(colOnPill).Background(bg).Padding(0, 1).Render(label)
}

// chip is a quieter badge: coloured text on a bordered-by-colour background-less
// tag, used for lists of ports and technologies.
func chip(label string, col lipgloss.TerminalColor) string {
	return lipgloss.NewStyle().Foreground(col).Bold(true).Render("‹" + label + "›")
}

// wrapTokens joins already-rendered tokens with sep, starting a new line
// whenever the next token would pass width.
func wrapTokens(tokens []string, sep string, width int) []string {
	var lines []string
	cur, curW := "", 0
	for _, t := range tokens {
		w := lipgloss.Width(t)
		switch {
		case cur == "":
			cur, curW = t, w
		case curW+lipgloss.Width(sep)+w > width:
			lines = append(lines, cur)
			cur, curW = t, w
		default:
			cur += sep + t
			curW += lipgloss.Width(sep) + w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// gauge draws a fixed-width bar with filled of total cells lit.
func gauge(filled, total, cells int, col lipgloss.TerminalColor) string {
	if total <= 0 {
		total = 1
	}
	n := filled * cells / total
	n = max(0, min(n, cells))
	return lipgloss.NewStyle().Foreground(col).Render(strings.Repeat("█", n)) +
		styleSubtle.Render(strings.Repeat("░", cells-n))
}

// card draws body inside a rounded box of exactly width columns with title in
// the top border. Lines are truncated, never wrapped, so the layout holds in a
// narrow pane.
func card(title string, body []string, width int, col lipgloss.TerminalColor) string {
	width = max(width, 12)
	inner := width - 4
	edge := lipgloss.NewStyle().Foreground(col)
	t := " " + title + " "
	var b strings.Builder
	b.WriteString(edge.Render("╭─") + lipgloss.NewStyle().Bold(true).Foreground(col).Render(t) +
		edge.Render(strings.Repeat("─", max(0, width-3-lipgloss.Width(t)))+"╮") + "\n")
	for _, l := range body {
		l = xansi.Truncate(l, inner, "…")
		b.WriteString(edge.Render("│") + " " + l + strings.Repeat(" ", max(0, inner-lipgloss.Width(l))) + " " + edge.Render("│") + "\n")
	}
	b.WriteString(edge.Render("╰" + strings.Repeat("─", width-2) + "╯"))
	return b.String()
}
