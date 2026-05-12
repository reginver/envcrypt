package vault

import (
	"fmt"

	"github.com/nicholasgasior/envcrypt/internal/env"
)

// SetKey sets or updates a single key-value pair in the vault.
// If the key already exists, its value is overwritten.
// If the key does not exist, it is appended.
func SetKey(vaultPath, pubKeyPath, privKeyPath, key, value string) error {
	if key == "" {
		return fmt.Errorf("key must not be empty")
	}

	pubKey, err := LoadPublicKey(pubKeyPath)
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}

	privKey, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	v := New(vaultPath, pubKey, privKey)

	entries, err := v.Decrypt()
	if err != nil {
		// If vault does not exist yet, start with empty entries
		entries = []env.Entry{}
	}

	updated := false
	for i, e := range entries {
		if e.Key == key {
			entries[i].Value = value
			updated = true
			break
		}
	}

	if !updated {
		entries = append(entries, env.Entry{Key: key, Value: value})
	}

	if err := v.Encrypt(entries); err != nil {
		return fmt.Errorf("encrypt vault: %w", err)
	}

	return nil
}

// DeleteKey removes a key from the vault. Returns an error if the key is not found.
func DeleteKey(vaultPath, pubKeyPath, privKeyPath, key string) error {
	if key == "" {
		return fmt.Errorf("key must not be empty")
	}

	pubKey, err := LoadPublicKey(pubKeyPath)
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}

	privKey, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	v := New(vaultPath, pubKey, privKey)

	entries, err := v.Decrypt()
	if err != nil {
		return fmt.Errorf("decrypt vault: %w", err)
	}

	filtered := entries[:0]
	found := false
	for _, e := range entries {
		if e.Key == key {
			found = true
			continue
		}
		filtered = append(filtered, e)
	}

	if !found {
		return fmt.Errorf("key %q not found in vault", key)
	}

	if err := v.Encrypt(filtered); err != nil {
		return fmt.Errorf("encrypt vault: %w", err)
	}

	return nil
}
