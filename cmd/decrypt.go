package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/crissyfield/decrypt/internal/decrypt"
)

// CmdDecrypt defines the 'decrypt' command.
var CmdDecrypt = &cobra.Command{
	Use:   "decrypt [flags] bundle_id",
	Short: "Decrypt an iOS application",
	Args:  cobra.ExactArgs(1),
	Run:   runDecrypt,
}

// Initialize command options
func init() {
}

// runDecrypt is called when the 'decrypt' sub-command is used.
func runDecrypt(_ *cobra.Command, args []string) {
	// Find the specified device
	device, err := decrypt.FindDevice()
	if err != nil {
		slog.Error("Failed to find device", slog.Any("error", err))
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
		slog.Error("Failed to list applications", slog.Any("error", err))
		os.Exit(1)
	}

	// Find the application with the specified identifier
	var application *decrypt.Application

	for _, app := range apps {
		if app.Identifier == args[0] {
			application = app
			break
		}
	}

	if application == nil {
		slog.Error("Application not found", "identifier", "de.deutschepost.dhl")
		os.Exit(1)
	}

	// Dump the application
	err = application.Dump()
	if err != nil {
		slog.Error("Failed to dump application", slog.Any("error", err))
		os.Exit(1)
	}
}
