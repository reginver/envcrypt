package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PinnedKey represents a single pinned key entry.
type PinnedKey struct {
	Key       string    `json:"key"`
	VaultFile string    `json:"vault_file"`
	PinnedAt  time.Time `json:"pinned_at"`
	Note      string    `json:"note,omitempty"`
}

func pinFilePath(vaultFile string) string {
	dir := filepath.Dir(vaultFile)
	base := filepath.Base(vaultFile)
	return filepath.Join(dir, "."+base+".pins.json")
}

// PinKey marks a key in the vault as pinned, storing metadata in a sidecar file.
func PinKey(vaultFile, key, note string) error {
	pins, err := loadPins(vaultFile)
	if err != nil {
		return err
	}
	for _, p := range pins {
		if p.Key == key {
			return fmt.Errorf("key %q is already pinned", key)
		}
	}
	pins = append(pins, PinnedKey{
		Key:       key,
		VaultFile: vaultFile,
		PinnedAt:  time.Now().UTC(),
		Note:      note,
	})
	return savePins(vaultFile, pins)
}

// UnpinKey removes a key from the pinned list.
func UnpinKey(vaultFile, key string) error {
	pins, err := loadPins(vaultFile)
	if err != nil {
		return err
	}
	newPins := pins[:0]
	found := false
	for _, p := range pins {
		if p.Key == key {
			found = true
			continue
		}
		newPins = append(newPins, p)
	}
	if !found {
		return fmt.Errorf("key %q is not pinned", key)
	}
	return savePins(vaultFile, newPins)
}

// ListPins returns all pinned keys for a vault file.
func ListPins(vaultFile string) ([]PinnedKey, error) {
	return loadPins(vaultFile)
}

func loadPins(vaultFile string) ([]PinnedKey, error) {
	path := pinFilePath(vaultFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return []PinnedKey{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading pin file: %w", err)
	}
	var pins []PinnedKey
	if err := json.Unmarshal(data, &pins); err != nil {
		return nil, fmt.Errorf("parsing pin file: %w", err)
	}
	return pins, nil
}

func savePins(vaultFile string, pins []PinnedKey) error {
	path := pinFilePath(vaultFile)
	data, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing pins: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}
