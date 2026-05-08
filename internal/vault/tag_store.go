package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// tagFilePath returns the sidecar file path for tag metadata.
func tagFilePath(vaultPath string) string {
	ext := filepath.Ext(vaultPath)
	base := vaultPath[:len(vaultPath)-len(ext)]
	return base + ".tags.json"
}

// loadTagMap reads the tag sidecar file. Returns an empty map if not found.
func loadTagMap(vaultPath string) (map[string][]string, error) {
	path := tagFilePath(vaultPath)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string][]string{}, nil
		}
		return nil, fmt.Errorf("load tag map: %w", err)
	}

	var m map[string][]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse tag map: %w", err)
	}
	return m, nil
}

// saveTagMap writes the tag map to the sidecar file.
func saveTagMap(vaultPath string, m map[string][]string) error {
	path := tagFilePath(vaultPath)
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal tag map: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write tag map: %w", err)
	}
	return nil
}
