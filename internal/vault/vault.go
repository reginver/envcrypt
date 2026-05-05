// Package vault provides functionality for reading and writing encrypted .env vault files.
package vault

import (
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/crypto"
	"github.com/yourusername/envcrypt/internal/env"
)

// Vault represents an encrypted .env file on disk.
type Vault struct {
	Path string
}

// New creates a Vault referencing the given file path.
func New(path string) *Vault {
	return &Vault{Path: path}
}

// Encrypt reads a plaintext .env file, encrypts its contents, and writes
// the ciphertext to the vault path. recipients must contain at least one
// age public key string.
func (v *Vault) Encrypt(plaintextPath string, recipients []string) error {
	data, err := os.ReadFile(plaintextPath)
	if err != nil {
		return fmt.Errorf("vault: read plaintext: %w", err)
	}

	pubs := make([]crypto.PublicKey, 0, len(recipients))
	for _, r := range recipients {
		pub, err := crypto.ParsePublicKey(r)
		if err != nil {
			return fmt.Errorf("vault: parse recipient %q: %w", r, err)
		}
		pubs = append(pubs, pub)
	}

	ciphertext, err := crypto.Encrypt(data, pubs)
	if err != nil {
		return fmt.Errorf("vault: encrypt: %w", err)
	}

	if err := os.WriteFile(v.Path, ciphertext, 0o600); err != nil {
		return fmt.Errorf("vault: write vault: %w", err)
	}
	return nil
}

// Decrypt reads the vault file, decrypts it using one of the provided private
// key strings, and returns the parsed env entries.
func (v *Vault) Decrypt(identities []string) ([]env.Entry, error) {
	ciphertext, err := os.ReadFile(v.Path)
	if err != nil {
		return nil, fmt.Errorf("vault: read vault: %w", err)
	}

	ids := make([]crypto.PrivateKey, 0, len(identities))
	for _, id := range identities {
		priv, err := crypto.ParsePrivateKey(id)
		if err != nil {
			return nil, fmt.Errorf("vault: parse identity: %w", err)
		}
		ids = append(ids, priv)
	}

	plaintext, err := crypto.Decrypt(ciphertext, ids)
	if err != nil {
		return nil, fmt.Errorf("vault: decrypt: %w", err)
	}

	entries, err := env.Parse(string(plaintext))
	if err != nil {
		return nil, fmt.Errorf("vault: parse env: %w", err)
	}
	return entries, nil
}
