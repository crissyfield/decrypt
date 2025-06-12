package decrypt

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Extension represents a collection of extensions associated with an application.
type Extension struct {
	ID           string `mapstructure:"id"`           // ID of the extension
	Path         string `mapstructure:"path"`         // Path to the extension
	Executable   string `mapstructure:"executable"`   // Executable name of the extension
	AbsolutePath string `mapstructure:"absolutePath"` // Absolute path to the extension
}

// collectBinaries collects Mach-O binaries in the app bundle.
func collectBinaries(root string) ([]*MachOInfo, error) {
	// Collect binaries recursively
	var binaries []*MachOInfo

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, _ error) error {
		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Parse Mach-O binary
		info, err := parseMachO(path)
		if err != nil {
			slog.Warn("Failed to parse Mach-O binary", slog.String("path", path), slog.Any("error", err))
			return nil
		}

		if (info != nil) && (info.CryptID != 0) {
			// Fix the path to be relative to the app bundle root
			info.Path, _ = filepath.Rel(root, info.Path)

			// Append binary info
			binaries = append(binaries, info)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	return binaries, nil
}

// splitBinaries splits binaries into app and extension binaries.
func splitBinaries(binaries []*MachOInfo, main string, extensions []Extension) (map[string]*MachOInfo, map[string]map[string]*MachOInfo) {
	// Iterate over binaries
	appBinaries := make(map[string]*MachOInfo)
	extensionBinaries := make(map[string]map[string]*MachOInfo)

	for _, binary := range binaries {
		// Check if binary belongs to an extension
		foundExtension := false
		for _, ext := range extensions {
			if strings.HasPrefix(binary.Path, ext.Path) {
				if extensionBinaries[ext.ID] == nil {
					extensionBinaries[ext.ID] = make(map[string]*MachOInfo)
				}

				extensionBinaries[ext.ID][binary.Path] = binary
				foundExtension = true
				break
			}
		}

		if foundExtension {
			continue
		}

		// Check if binary is the main app binary
		if (binary.FileType == MH_EXECUTE) && (binary.Path != main) {
			slog.Info("Executable is not within an extension", slog.String("path", binary.Path))
			slog.Info("It is very likely that one of the extensions requires a MinimumOSVersion")
			slog.Info("that is higher than your OS. This will result in a binary that is left encrypted.")
		}

		appBinaries[binary.Path] = binary
	}

	return appBinaries, extensionBinaries
}
