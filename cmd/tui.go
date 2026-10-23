package cmd

import (
	"github.com/spf13/cobra"

	"ctz/internal/tui"
)

func newTUICmd() *cobra.Command {
	return &cobra.Command{
		Use:           "tui",
		Short:         "Interactive terminal UI: configure, run, and browse a scan",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          func(*cobra.Command, []string) error { return tui.Run() },
	}
}
