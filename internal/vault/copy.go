package vault

import (
	"fmt"

	"github.com/nicholasgasior/envcrypt/internal/env"
)

// CopyOptions controls the behaviour of CopyVault.
type CopyOptions struct {
	// Keys restricts which keys are copied. An empty slice means all keys.
	Keys []string
	// Overwrite controls whether existing keys in the destination are replaced.
	Overwrite bool
}

// CopyVault reads keys from srcVaultPath and merges them into dstVaultPath.
// The destination vault is created if it does not yet exist.
// src and dst may use different key pairs; srcPrivKey is used to decrypt the
// source and dstPubKey is used to re-encrypt into the destination.
func CopyVault(srcVaultPath, dstVaultPath, srcPrivKey, dstPubKey string, opts CopyOptions) error {
	// Decrypt source vault.
	srcEntries, err := decryptVault(srcVaultPath, srcPrivKey)
	if err != nil {
		return fmt.Errorf("copy: read source vault: %w", err)
	}

	// Optionally filter to requested keys.
	if len(opts.Keys) > 0 {
		srcEntries = env.FilterKeys(srcEntries, opts.Keys)
	}

	// Load existing destination entries (best-effort; empty if vault missing).
	dstEntries, _ := decryptVault(dstVaultPath, srcPrivKey)

	// Merge: source entries are the overlay; overwrite flag is respected.
	var merged []env.Entry
	if opts.Overwrite {
		// Source wins for duplicate keys.
		merged = env.MergeEntries(dstEntries, srcEntries)
	} else {
		// Destination wins for duplicate keys.
		merged = env.MergeEntries(srcEntries, dstEntries)
	}

	// Re-encrypt into destination vault.
	if err := encryptVault(dstVaultPath, dstPubKey, merged); err != nil {
		return fmt.Errorf("copy: write destination vault: %w", err)
	}

	return nil
}

// decryptVault is a thin helper that decrypts a vault file and returns its
// parsed entries. It is shared by several vault operations.
func decryptVault(vaultPath, privKeyPath string) ([]env.Entry, error) {
	v := New(vaultPath, "", privKeyPath)
	return v.Decrypt()
}

// encryptVault serialises entries and encrypts them into vaultPath.
func encryptVault(vaultPath, pubKeyPath string, entries []env.Entry) error {
	v := New(vaultPath, pubKeyPath, "")
	return v.Encrypt(entries)
}
