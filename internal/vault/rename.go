package vault

import (
	"fmt"

	"github.com/nicholasgasior/envcrypt/internal/env"
)

// RenameKey renames a key inside an encrypted vault file.
// The vault is decrypted, the key is renamed, and the vault is re-encrypted.
// Returns an error if the old key does not exist or the new key already exists.
func RenameKey(vaultPath, privKeyPath, pubKeyPath, oldKey, newKey string) error {
	if oldKey == "" || newKey == "" {
		return fmt.Errorf("old and new key names must not be empty")
	}

	privKey, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	pubKey, err := LoadPublicKey(pubKeyPath)
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}

	v := New(pubKey, privKey)

	entries, err := v.Decrypt(vaultPath)
	if err != nil {
		return fmt.Errorf("decrypt vault: %w", err)
	}

	km := env.ToMap(entries)

	if _, ok := km[oldKey]; !ok {
		return fmt.Errorf("key %q not found in vault", oldKey)
	}
	if _, ok := km[newKey]; ok {
		return fmt.Errorf("key %q already exists in vault", newKey)
	}

	// Rebuild entries preserving order, replacing oldKey with newKey.
	for i, e := range entries {
		if e.Key == oldKey {
			entries[i].Key = newKey
			break
		}
	}

	if err := v.Encrypt(vaultPath, entries); err != nil {
		return fmt.Errorf("re-encrypt vault: %w", err)
	}

	return nil
}
