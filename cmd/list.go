package cmd

import (
	"log/slog"
	"os"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"github.com/crissyfield/decrypt/internal/device"
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
	// Find the specified device
	device, err := device.Find()
	if err != nil {
		slog.Error("Failed to find device", "error", err)
		os.Exit(1)
	}

	// Ensure the device meets the requirements
	if device.Access != "full" || device.Platform != "darwin" || device.OS != "ios" || device.Arch != "arm64" {
		slog.Error("Jailbroken 64-bit iOS device required")
		os.Exit(1)
	}

	// List applications
	apps, err := device.ListApplications()
	if err != nil {
		slog.Error("Failed to list applications", "error", err)
		os.Exit(1)
	}

	// Render application list
	tableData := pterm.TableData{{"Bundle ID", "Name", "Version"}}

	for _, app := range apps {
		tableData = append(tableData, []string{app.Identifier, app.Name, app.Version})
	}

	err = pterm.DefaultTable.
		WithHasHeader().
		WithHeaderRowSeparator("-").
		WithData(tableData).
		Render()

	if err != nil {
		slog.Error("Failed render application list", "error", err)
		os.Exit(1)
	}
}
