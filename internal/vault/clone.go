package vault

import (
	"fmt"
	"os"
	"path/filepath"
)

// CloneVault decrypts a source vault using the source private key and
// re-encrypts it with a new recipient public key, writing the result to dst.
// If dst already exists and overwrite is false, an error is returned.
func CloneVault(src, dst, srcPrivKey, dstPubKey string, overwrite bool) error {
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return fmt.Errorf("source vault not found: %s", src)
	}

	if !overwrite {
		if _, err := os.Stat(dst); err == nil {
			return fmt.Errorf("destination vault already exists: %s (use --overwrite to replace)", dst)
		}
	}

	// Decrypt source vault
	entries, err := decryptVault(src, srcPrivKey)
	if err != nil {
		return fmt.Errorf("decrypt source vault: %w", err)
	}

	// Ensure destination directory exists
	if dir := filepath.Dir(dst); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create destination directory: %w", err)
		}
	}

	// Re-encrypt with new public key
	if err := encryptVault(entries, dst, dstPubKey); err != nil {
		return fmt.Errorf("encrypt destination vault: %w", err)
	}

	return nil
}
