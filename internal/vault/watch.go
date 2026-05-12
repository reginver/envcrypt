package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"
)

// WatchEvent describes a change detected in a vault file.
type WatchEvent struct {
	VaultPath string
	OldHash   string
	NewHash   string
	DetectedAt time.Time
}

// HashVaultFile computes a SHA-256 hex digest of the vault file contents.
func HashVaultFile(vaultPath string) (string, error) {
	f, err := os.Open(vaultPath)
	if err != nil {
		return "", fmt.Errorf("open vault: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash vault: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// WatchVault polls a vault file for changes, sending a WatchEvent on the
// returned channel whenever the file hash changes. It stops when done is closed.
func WatchVault(vaultPath string, interval time.Duration, done <-chan struct{}) (<-chan WatchEvent, error) {
	initialHash, err := HashVaultFile(vaultPath)
	if err != nil {
		return nil, err
	}

	events := make(chan WatchEvent, 4)
	go func() {
		defer close(events)
		current := initialHash
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				newHash, err := HashVaultFile(vaultPath)
				if err != nil {
					continue
				}
				if newHash != current {
					events <- WatchEvent{
						VaultPath:  vaultPath,
						OldHash:    current,
						NewHash:    newHash,
						DetectedAt: time.Now(),
					}
					current = newHash
				}
			}
		}
	}()
	return events, nil
}
