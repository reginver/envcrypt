package vault

import (
	"errors"
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/crypto"
	"github.com/yourusername/envcrypt/internal/env"
)

// VerifyResult holds the outcome of a vault verification.
type VerifyResult struct {
	VaultPath  string
	EntryCount int
	Valid      bool
	Error      error
}

// VerifyVault attempts to decrypt the vault and validates its contents,
// returning a VerifyResult describing whether the vault is intact and readable.
func VerifyVault(vaultPath, privKeyPath string) (VerifyResult, error) {
	result := VerifyResult{VaultPath: vaultPath}

	if _, err := os.Stat(vaultPath); errors.Is(err, os.ErrNotExist) {
		return result, fmt.Errorf("vault file not found: %s", vaultPath)
	}

	identity, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return result, fmt.Errorf("load private key: %w", err)
	}

	ciphertext, err := os.ReadFile(vaultPath)
	if err != nil {
		return result, fmt.Errorf("read vault: %w", err)
	}

	plaintext, err := crypto.Decrypt(ciphertext, []interface{ Unwrap() ([]byte, error) }{identity})
	if err != nil {
		result.Valid = false
		result.Error = fmt.Errorf("decryption failed: %w", err)
		return result, nil
	}

	entries, err := env.Parse(string(plaintext))
	if err != nil {
		result.Valid = false
		result.Error = fmt.Errorf("parse error: %w", err)
		return result, nil
	}

	result.EntryCount = len(entries)
	result.Valid = true
	return result, nil
}
