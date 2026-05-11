package vault

import (
	"fmt"
)

// IsPinned returns true if the given key is currently pinned in the vault.
func IsPinned(vaultFile, key string) (bool, error) {
	pins, err := loadPins(vaultFile)
	if err != nil {
		return false, err
	}
	for _, p := range pins {
		if p.Key == key {
			return true, nil
		}
	}
	return false, nil
}

// GuardPinnedKeys returns an error if any of the provided keys are pinned,
// preventing accidental mutation of protected secrets.
func GuardPinnedKeys(vaultFile string, keys []string) error {
	pins, err := loadPins(vaultFile)
	if err != nil {
		return err
	}
	pinSet := make(map[string]struct{}, len(pins))
	for _, p := range pins {
		pinSet[p.Key] = struct{}{}
	}
	for _, k := range keys {
		if _, pinned := pinSet[k]; pinned {
			return fmt.Errorf("key %q is pinned and cannot be modified; unpin it first with: envcrypt pin --remove %s", k, k)
		}
	}
	return nil
}
