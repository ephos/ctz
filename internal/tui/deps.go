package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"ctz/internal/config"
	"ctz/internal/install"
)

const depBoxWidth = 96

// depCounts returns the missing-required and missing-optional tool names.
func depCounts(report []config.Dependency) (required, optional []string) {
	for _, d := range report {
		switch {
		case d.Found:
		case d.Required:
			required = append(required, d.Name)
		default:
			optional = append(optional, d.Name)
		}
	}
	return required, optional
}

// renderDeps draws the dependency box: green = found, red = missing and
// needed by the selected options, yellow = missing but optional.
func renderDeps(report []config.Dependency, detected string) string {
	var b strings.Builder
	b.WriteString(styleHeading.Render("Dependencies") + "\n\n")
	for _, d := range report {
		var dot, state string
		switch {
		case d.Found:
			dot, state = styleGood.Render("●"), styleGood.Render(fmt.Sprintf("%-22s", d.Path))
		case d.Required:
			dot, state = styleBad.Render("●"), styleBad.Render(fmt.Sprintf("%-22s", "MISSING (required)"))
		default:
			dot, state = styleWarn.Render("●"), styleWarn.Render(fmt.Sprintf("%-22s", "not found (optional)"))
		}
		feature := d.Feature
		if feature == "always" {
			feature = "required"
		}
		fmt.Fprintf(&b, "%s %-10s %s %s\n", dot, d.Name, state, styleSubtle.Render(feature))
	}
	req, opt := depCounts(report)
	b.WriteString("\n")
	switch {
	case len(req) > 0:
		b.WriteString(styleBad.Render(fmt.Sprintf("%d required tool(s) missing: %s", len(req), strings.Join(req, ", "))) + "\n")
		b.WriteString(styleSubtle.Render("A scan with the current options cannot run.") + "\n")
	default:
		b.WriteString(styleGood.Render("All tools required for the current options are installed.") + "\n")
	}
	if len(opt) > 0 {
		b.WriteString(styleWarn.Render(fmt.Sprintf("%d optional tool(s) missing: %s", len(opt), strings.Join(opt, ", "))) + "\n")
		b.WriteString(styleSubtle.Render("Only needed if you enable the matching option.") + "\n")
	}
	var missing []string
	for _, d := range report {
		if !d.Found {
			missing = append(missing, d.Name)
		}
	}
	if hint := install.Hint(missing, detected); hint != "" {
		b.WriteString("\n" + styleHeading.Render("Install missing tools") + "\n")
		if detected == "" {
			b.WriteString(styleSubtle.Render("Distribution not detected; pick your package manager:") + "\n")
		} else {
			b.WriteString(styleSubtle.Render("▸ marks your detected package manager") + "\n")
		}
		b.WriteString(hint + "\n")
	}
	b.WriteString("\n" + styleHelp.Render("esc / d / enter close"))
	return stylePane.BorderForeground(colAccent).Padding(1, 2).Width(depBoxWidth).Render(b.String())
}

// depWarning is the one-line form footer warning ("" when nothing is missing).
func depWarning(report []config.Dependency) string {
	req, _ := depCounts(report)
	if len(req) == 0 {
		return ""
	}
	return styleBad.Render("⚠ missing required: "+strings.Join(req, ", ")) + styleSubtle.Render("  (ctrl+d for details)")
}

func placeCentered(width, height int, box string) string {
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}
