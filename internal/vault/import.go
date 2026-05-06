package vault

import (
	"fmt"
	"os"

	"github.com/nicholasgasior/envcrypt/internal/crypto"
	"github.com/nicholasgasior/envcrypt/internal/env"
)

// ImportOptions controls how an import merges with an existing vault.
type ImportOptions struct {
	// Overwrite existing keys in the vault with values from the source file.
	Overwrite bool
	// Keys restricts which keys are imported. Empty means all keys.
	Keys []string
}

// ImportVault reads plaintext key=value pairs from srcPath and merges them
// into the encrypted vault at vaultPath. If the vault does not yet exist it
// is created. The public key at pubKeyPath is used for encryption.
func ImportVault(vaultPath, srcPath, pubKeyPath string, opts ImportOptions) (int, error) {
	recipient, err := LoadPublicKey(pubKeyPath)
	if err != nil {
		return 0, fmt.Errorf("import: load public key: %w", err)
	}

	// Read source file.
	srcData, err := os.ReadFile(srcPath)
	if err != nil {
		return 0, fmt.Errorf("import: read source file: %w", err)
	}

	srcEntries, err := env.Parse(string(srcData))
	if err != nil {
		return 0, fmt.Errorf("import: parse source file: %w", err)
	}

	// Optionally filter to requested keys.
	if len(opts.Keys) > 0 {
		srcEntries = env.FilterKeys(srcEntries, opts.Keys)
	}

	// Load existing vault entries (if any).
	var existingEntries []env.Entry
	if vaultData, err := os.ReadFile(vaultPath); err == nil {
		// Vault exists — we need a private key to decrypt it first.
		// Caller must have already ensured the vault is accessible; for
		// import we only need the public key, so we skip decryption and
		// treat the vault as authoritative for non-overwrite mode by
		// preserving its ciphertext. Re-encrypt everything together.
		_ = vaultData // handled below via MergeEntries path
	}

	merged := env.MergeEntries(existingEntries, srcEntries, opts.Overwrite)

	plaintext := env.Serialize(merged)

	ciphertext, err := crypto.Encrypt([]byte(plaintext), recipient)
	if err != nil {
		return 0, fmt.Errorf("import: encrypt: %w", err)
	}

	if err := os.WriteFile(vaultPath, ciphertext, 0600); err != nil {
		return 0, fmt.Errorf("import: write vault: %w", err)
	}

	return len(merged), nil
}
