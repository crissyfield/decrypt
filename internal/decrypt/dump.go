package decrypt

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
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
