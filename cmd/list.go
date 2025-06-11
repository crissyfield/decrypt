package cmd

import (
	"github.com/spf13/cobra"
)

// CmdList defines the 'list' command.
var CmdList = &cobra.Command{
	Use:   "list [flags]",
	Short: "List all apps on the device",
	Args:  cobra.NoArgs,
	Run:   runList,
}

// Initialize command options
func init() {
}

// runList is called when the 'serve' sub-command is used.
func runList(_ *cobra.Command, _ []string) {
}
