package vault

import (
	"fmt"
	"os"

	"github.com/user/envcrypt/internal/crypto"
	"github.com/user/envcrypt/internal/env"
)

// RotateKeys decrypts the vault using the old private key, then re-encrypts
// it using a newly generated key pair. The new keys are written to the
// provided paths, overwriting any existing files.
func RotateKeys(vaultPath, plaintextPath, newPubKeyPath, newPrivKeyPath string) error {
	oldPrivKey, err := LoadPrivateKey(newPrivKeyPath)
	if err != nil {
		return fmt.Errorf("rotate: load old private key: %w", err)
	}

	// Read and decrypt the existing vault.
	ciphertext, err := os.ReadFile(vaultPath)
	if err != nil {
		return fmt.Errorf("rotate: read vault: %w", err)
	}

	plaintext, err := crypto.Decrypt(ciphertext, oldPrivKey)
	if err != nil {
		return fmt.Errorf("rotate: decrypt vault: %w", err)
	}

	entries, err := env.Parse(string(plaintext))
	if err != nil {
		return fmt.Errorf("rotate: parse env: %w", err)
	}

	// Generate a fresh key pair.
	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("rotate: generate key pair: %w", err)
	}

	// Persist new keys.
	if err := os.WriteFile(newPubKeyPath, []byte(pub.String()), 0o644); err != nil {
		return fmt.Errorf("rotate: write public key: %w", err)
	}
	if err := os.WriteFile(newPrivKeyPath, []byte(priv.String()), 0o600); err != nil {
		return fmt.Errorf("rotate: write private key: %w", err)
	}

	// Re-encrypt with the new public key.
	newCiphertext, err := crypto.Encrypt([]byte(env.Serialize(entries)), pub)
	if err != nil {
		return fmt.Errorf("rotate: encrypt with new key: %w", err)
	}

	if err := os.WriteFile(vaultPath, newCiphertext, 0o644); err != nil {
		return fmt.Errorf("rotate: write vault: %w", err)
	}

	_ = plaintextPath // plaintext file is not modified during rotation
	return nil
}
