package vault

import (
	"fmt"
	"os"

	"github.com/nicholasgasior/envcrypt/internal/env"
)

// StripKeys removes one or more keys from an encrypted vault file in place.
// The vault is decrypted, the specified keys are deleted, and the result is
// re-encrypted back to the same file.
func StripKeys(vaultPath, pubKeyPath, privKeyPath string, keys []string, auditHook func(string)) error {
	if len(keys) == 0 {
		return fmt.Errorf("no keys specified to strip")
	}

	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		return fmt.Errorf("vault file not found: %s", vaultPath)
	}

	pubKey, err := LoadPublicKey(pubKeyPath)
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}

	privKey, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	v := New(pubKey, privKey)

	entries, err := v.Decrypt(vaultPath)
	if err != nil {
		return fmt.Errorf("decrypt vault: %w", err)
	}

	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[k] = true
	}

	filtered := make([]env.Entry, 0, len(entries))
	removed := 0
	for _, e := range entries {
		if keySet[e.Key] {
			removed++
			continue
		}
		filtered = append(filtered, e)
	}

	if removed == 0 {
		return fmt.Errorf("none of the specified keys found in vault")
	}

	if err := v.Encrypt(vaultPath, filtered); err != nil {
		return fmt.Errorf("re-encrypt vault: %w", err)
	}

	if auditHook != nil {
		auditHook(fmt.Sprintf("strip: removed %d key(s) from %s", removed, vaultPath))
	}

	return nil
}
