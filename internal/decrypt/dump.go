package decrypt

import (
	"embed"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

//go:embed scripts/*
var scriptsFS embed.FS

var (
	// removeAppBundleFiles defines files to be removed from the app bundle's root directory.
	removeAppBundleFiles = map[string]bool{
		"iTunesMetadata.plist":     true, // Metadata file for iTunes
		"embedded.mobileprovision": true, // Embedded provisioning profile
	}

	// removeAppBundleDirs defines directories to be removed from the app bundle recursively.
	removeAppBundleDirs = map[string]bool{
		"SC_Info":        true, // Provisioning profile information
		"_CodeSignature": true, // Code signature information
	}
)

// Dump dumps the application.
func (app *Application) Dump() error {
	// Establish SSH connection
	sshClient, err := ssh.Dial(
		"tcp",
		"localhost:2222",
		&ssh.ClientConfig{
			User:            "mobile",
			Auth:            []ssh.AuthMethod{ssh.Password("alpine")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         30 * time.Second,
		},
	)

	if err != nil {
		return fmt.Errorf("establish SSH connect: %w", err)
	}

	defer sshClient.Close()

	// Establish SFTP connection
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return fmt.Errorf("establish SFTP connect: %w", err)
	}

	defer sftpClient.Close()

	// Recursively pull the remote directory to the local filesystem
	err = pullDir(sftpClient, app.Path, "./temp")
	if err != nil {
		return fmt.Errorf("pull app directory: %w", err)
	}

	// Clean up app bundle
	err = cleanupAppBundle("./temp")
	if err != nil {
		return fmt.Errorf("clean up app bundle: %w", err)
	}

	// Collect binaries from the app bundle
	binaries, err := collectBinaries("./temp")
	if err != nil {
		return fmt.Errorf("collect binaries: %w", err)
	}

	for _, binary := range binaries {
		slog.Info("Collected binary", slog.Any("binary", binary))
	}

	// Get process IDs for chronod
	chronodPID, err := app.device.GetProcessID("chronod")
	if err != nil {
		slog.Info("The 'chronod' service is not running on the device.")
		slog.Info("Please start it manually.")

		return fmt.Errorf("get process ID for chronod: %w", err)
	}

	slog.Info("Found chronod process ID", slog.Int("pid", chronodPID))

	// Load script into runningboardd process
	runningboarddContent, _ := scriptsFS.ReadFile("scripts/runningboardd.js")

	runningboardScript, err := app.device.LoadScriptIntoProcess(string(runningboarddContent), "runningboardd")
	if err != nil {
		return fmt.Errorf("load script into process: %w", err)
	}

	defer runningboardScript.Close()

	// Get main
	mainApp, ok := runningboardScript.Call("main", app.Identifier).(string)
	if !ok {
		return fmt.Errorf("decode main app path")
	}

	// Get extensions
	var extensions []Extension

	err = mapstructure.Decode(
		runningboardScript.Call("extensions", app.Identifier),
		&extensions,
	)

	if err != nil {
		return fmt.Errorf("decode extension paths: %w", err)
	}

	// Split binaries into main and extensions
	appBinaries, extensionBinaries := splitBinaries(binaries, mainApp, extensions)

	slog.Info("Found main app binaries", slog.Any("binaries", appBinaries))
	slog.Info("Found extension binaries", slog.Any("binaries", extensionBinaries))

	return nil
}

// pullDir recursively pulls a directory from the remote SFTP server to the local filesystem.
func pullDir(sftpClient *sftp.Client, remotePath string, localPath string) error {
	// Read remote directory
	entries, err := sftpClient.ReadDir(remotePath)
	if err != nil {
		return fmt.Errorf("read remote directory: %w", err)
	}

	for _, entry := range entries {
		// Entry paths
		remotePathEntry := remotePath + "/" + entry.Name()
		localPathEntry := filepath.Join(localPath, entry.Name())

		if entry.IsDir() {
			// Dive into directories recursively
			if err := pullDir(sftpClient, remotePathEntry, localPathEntry); err != nil {
				return err
			}
		} else {
			// Ensure local directory exists
			err := os.MkdirAll(localPath, 0755)
			if err != nil {
				return fmt.Errorf("ensure local directory exists: %w", err)
			}

			// Pull remote file
			if err := pullFile(sftpClient, remotePathEntry, localPathEntry); err != nil {
				return fmt.Errorf("pull file [%s]: %w", remotePathEntry, err)
			}
		}
	}

	return nil
}

// pullFile pulls a single file from the remote SFTP server to the local filesystem.
func pullFile(sftpClient *sftp.Client, remotePath string, localPath string) error {
	// Open remote file
	remoteFile, err := sftpClient.Open(remotePath)
	if err != nil {
		return fmt.Errorf("open remote file: %w", err)
	}

	defer remoteFile.Close()

	// Create local file
	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("create local file: %w", err)
	}

	defer localFile.Close()

	// Copy content
	_, err = io.Copy(localFile, remoteFile)
	if err != nil {
		return fmt.Errorf("copy content: %w", err)
	}

	// Set file permissions and timestamps
	remoteInfo, err := remoteFile.Stat()
	if err != nil {
		return fmt.Errorf("read remote stats: %w", err)
	}

	if err := os.Chmod(localPath, remoteInfo.Mode()); err != nil {
		slog.Warn("Failed to set file permissions", slog.String("path", localPath), slog.Any("error", err))
	}

	if err := os.Chtimes(localPath, remoteInfo.ModTime(), remoteInfo.ModTime()); err != nil {
		slog.Warn("Failed to set file timestamps", slog.String("path", localPath), slog.Any("error", err))
	}

	return nil
}

// cleanupAppBundle performs cleanup operations on the app bundle.
func cleanupAppBundle(root string) error {
	// Remove files in app bundle root
	for file := range removeAppBundleFiles {
		// Remove file
		path := filepath.Join(root, file)

		err := os.Remove(path)
		if err != nil && !os.IsNotExist(err) {
			slog.Warn("Failed to remove file", slog.String("path", path), slog.Any("error", err))
		}
	}

	// Remove directories recursively
	return filepath.WalkDir(root, func(path string, d os.DirEntry, _ error) error {
		// Skip if not what we're looking for
		if !d.IsDir() || !removeAppBundleDirs[filepath.Base(path)] {
			return nil
		}

		// Remove directory
		err := os.RemoveAll(path)
		if err != nil {
			slog.Warn("Failed to remove directory", slog.String("path", path), slog.Any("error", err))
		}

		return filepath.SkipDir
	})
}
