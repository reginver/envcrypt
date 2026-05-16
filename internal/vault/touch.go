package vault

import (
	"fmt"
	"os"
	"time"
)

// TouchResult holds metadata about a vault touch operation.
type TouchResult struct {
	Path      string
	PrevMtime time.Time
	NewMtime  time.Time
}

// TouchVault updates the modification timestamp of a vault file without
// altering its contents. Returns an error if the file does not exist.
func TouchVault(vaultPath string) (*TouchResult, error) {
	info, err := os.Stat(vaultPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("vault file not found: %s", vaultPath)
		}
		return nil, fmt.Errorf("stat vault: %w", err)
	}

	prevMtime := info.ModTime()
	now := time.Now()

	if err := os.Chtimes(vaultPath, now, now); err != nil {
		return nil, fmt.Errorf("touch vault: %w", err)
	}

	return &TouchResult{
		Path:      vaultPath,
		PrevMtime: prevMtime,
		NewMtime:  now,
	}, nil
}
