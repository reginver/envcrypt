package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SnapshotVault creates a timestamped backup copy of the vault file.
// Snapshots are stored in a .snapshots subdirectory next to the vault file.
func SnapshotVault(vaultPath string) (string, error) {
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("vault file not found: %s", vaultPath)
		}
		return "", fmt.Errorf("reading vault: %w", err)
	}

	dir := filepath.Dir(vaultPath)
	base := filepath.Base(vaultPath)
	snapshotDir := filepath.Join(dir, ".snapshots")

	if err := os.MkdirAll(snapshotDir, 0700); err != nil {
		return "", fmt.Errorf("creating snapshot directory: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102T150405Z")
	snapshotName := fmt.Sprintf("%s.%s", base, timestamp)
	snapshotPath := filepath.Join(snapshotDir, snapshotName)

	if err := os.WriteFile(snapshotPath, data, 0600); err != nil {
		return "", fmt.Errorf("writing snapshot: %w", err)
	}

	return snapshotPath, nil
}

// ListSnapshots returns all snapshot file paths for a given vault, sorted oldest first.
func ListSnapshots(vaultPath string) ([]string, error) {
	dir := filepath.Dir(vaultPath)
	base := filepath.Base(vaultPath)
	snapshotDir := filepath.Join(dir, ".snapshots")

	entries, err := os.ReadDir(snapshotDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading snapshot directory: %w", err)
	}

	var snapshots []string
	prefix := base + "."
	for _, e := range entries {
		if !e.IsDir() && len(e.Name()) > len(prefix) && e.Name()[:len(prefix)] == prefix {
			snapshots = append(snapshots, filepath.Join(snapshotDir, e.Name()))
		}
	}
	return snapshots, nil
}

// RestoreSnapshot replaces the vault file with the contents of the given snapshot.
func RestoreSnapshot(vaultPath, snapshotPath string) error {
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("snapshot not found: %s", snapshotPath)
		}
		return fmt.Errorf("reading snapshot: %w", err)
	}
	if err := os.WriteFile(vaultPath, data, 0600); err != nil {
		return fmt.Errorf("restoring vault: %w", err)
	}
	return nil
}
