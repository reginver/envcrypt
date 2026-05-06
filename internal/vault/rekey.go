package vault

import (
	"fmt"
	"os"

	"github.com/nicholasgasior/envcrypt/internal/crypto"
	"github.com/nicholasgasior/envcrypt/internal/env"
)

// RekeyVault decrypts a vault using the old private key and re-encrypts it
// using a new public key. This is useful when transferring ownership or
// rotating to an externally generated key pair.
func RekeyVault(vaultPath, oldPrivKeyPath, newPubKeyPath string) error {
	// Load old private key for decryption
	oldPrivKey, err := LoadPrivateKey(oldPrivKeyPath)
	if err != nil {
		return fmt.Errorf("rekey: load old private key: %w", err)
	}

	// Load new public key for re-encryption
	newPubKey, err := LoadPublicKey(newPubKeyPath)
	if err != nil {
		return fmt.Errorf("rekey: load new public key: %w", err)
	}

	// Read encrypted vault
	ciphertext, err := os.ReadFile(vaultPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("rekey: vault file not found: %s", vaultPath)
		}
		return fmt.Errorf("rekey: read vault: %w", err)
	}

	// Decrypt with old key
	plaintext, err := crypto.Decrypt(ciphertext, oldPrivKey)
	if err != nil {
		return fmt.Errorf("rekey: decrypt vault: %w", err)
	}

	// Parse entries to validate content
	_, err = env.Parse(string(plaintext))
	if err != nil {
		return fmt.Errorf("rekey: parse decrypted content: %w", err)
	}

	// Re-encrypt with new public key
	newCiphertext, err := crypto.Encrypt(plaintext, newPubKey)
	if err != nil {
		return fmt.Errorf("rekey: re-encrypt vault: %w", err)
	}

	// Write back to vault file
	if err := os.WriteFile(vaultPath, newCiphertext, 0600); err != nil {
		return fmt.Errorf("rekey: write vault: %w", err)
	}

	return nil
}
