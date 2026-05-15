package vault

import (
	"fmt"
	"os"

	"github.com/nicholasgasior/envcrypt/internal/crypto"
	"github.com/nicholasgasior/envcrypt/internal/env"
)

// TruncateVault removes all entries from the vault, leaving an empty encrypted file.
// If keys is non-empty, only those keys are removed (alias for StripKeys).
// If keys is empty, all entries are cleared.
func TruncateVault(vaultPath, pubKeyPath, privKeyPath string, keys []string) (int, error) {
	if len(keys) > 0 {
		return StripKeys(vaultPath, pubKeyPath, privKeyPath, keys)
	}

	pubKey, err := LoadPublicKey(pubKeyPath)
	if err != nil {
		return 0, fmt.Errorf("load public key: %w", err)
	}

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
		return 0, fmt.Errorf("parse vault: %w", err)
	}

	count := len(entries)

	newCiphertext, err := crypto.Encrypt([]byte(""), pubKey)
	if err != nil {
		return 0, fmt.Errorf("encrypt empty vault: %w", err)
	}

	if err := os.WriteFile(vaultPath, newCiphertext, 0600); err != nil {
		return 0, fmt.Errorf("write vault: %w", err)
	}

	return count, nil
}
