package vault

import (
	"fmt"
	"os"

	"github.com/nicholasgasior/envcrypt/internal/crypto"
	"github.com/nicholasgasior/envcrypt/internal/env"
)

// InjectOptions controls the behaviour of InjectVault.
type InjectOptions struct {
	// Overwrite existing environment variables when true.
	Overwrite bool
	// Keys restricts injection to the given keys (nil = all keys).
	Keys []string
}

// InjectVault decrypts the vault at vaultPath and injects its entries into
// the current process environment. It returns the number of variables set.
func InjectVault(vaultPath, privKeyPath string, opts InjectOptions) (int, error) {
	privKey, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return 0, fmt.Errorf("load private key: %w", err)
	}

	ciphertext, err := os.ReadFile(vaultPath)
	if err != nil {
		return 0, fmt.Errorf("read vault: %w", err)
	}

	plaintext, err := crypto.Decrypt(ciphertext, privKey)
	if err != nil {
		return 0, fmt.Errorf("decrypt vault: %w", err)
	}

	entries, err := env.Parse(string(plaintext))
	if err != nil {
		return 0, fmt.Errorf("parse vault contents: %w", err)
	}

	if len(opts.Keys) > 0 {
		entries = env.FilterKeys(entries, opts.Keys)
	}

	count := 0
	for _, e := range entries {
		if e.Comment || e.Key == "" {
			continue
		}
		if !opts.Overwrite {
			if _, exists := os.LookupEnv(e.Key); exists {
				continue
			}
		}
		if err := os.Setenv(e.Key, e.Value); err != nil {
			return count, fmt.Errorf("setenv %s: %w", e.Key, err)
		}
		count++
	}
	return count, nil
}
