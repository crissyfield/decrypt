package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/crissyfield/decrypt/cmd"
)

var (
	Version = "(undefined)"
)

// CmdRoot defines the root command.
var CmdRoot = &cobra.Command{
	Use:               "decrypt [flags] [command]",
	Long:              "Decrypt iOS apps",
	Args:              cobra.NoArgs,
	Version:           Version,
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	PersistentPreRunE: setup,
}

// Initialize command options
func init() {
	// Logging
	CmdRoot.PersistentFlags().String("logging.level", "info", "verbosity of logging output")
	CmdRoot.PersistentFlags().Bool("logging.json", false, "change logging format to JSON")

	// Register sub-commands
	CmdRoot.AddCommand(cmd.CmdDecrypt)
	CmdRoot.AddCommand(cmd.CmdList)
}

// setup will set up configuration management and logging.
//
// Configuration options can be set via the command line, via a configuration file (in the current folder, at
// "/etc/decrypt/config.yaml" or at "~/.config/decrypt/config.yaml"), and via environment variables (all
// uppercase and prefixed with "DECRYPT_").
func setup(cmd *cobra.Command, _ []string) error {
	// Connect all options to Viper
	err := viper.BindPFlags(cmd.Flags())
	if err != nil {
		return fmt.Errorf("bind command line flags: %w", err)
	}

	// Environment variables
	viper.SetEnvPrefix("DECRYPT")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	// Configuration file
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/decrypt")
	viper.AddConfigPath("$HOME/.config/decrypt")
	viper.AddConfigPath(".")

	viper.ReadInConfig() //nolint:errcheck

	// Logging
	var level slog.Level

	err = level.UnmarshalText([]byte(viper.GetString("logging.level")))
	if err != nil {
		return fmt.Errorf("parse log level: %w", err)
	}

	var handler slog.Handler

	if viper.GetBool("logging.json") {
		// Use JSON handler
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	} else {
		// Use text handler
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	}

	slog.SetDefault(slog.New(handler))

	return nil
}

// main is the main entry point of the command.
func main() {
	if err := CmdRoot.Execute(); err != nil {
		slog.Error("Unable to execute command", slog.Any("error", err))
	}
}
