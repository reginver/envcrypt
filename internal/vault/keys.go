package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/user/envcrypt/internal/crypto"
)

const (
	DefaultKeyDir      = ".envcrypt"
	DefaultPublicKey   = "key.pub"
	DefaultPrivateKey  = "key.age"
)

// KeyPaths holds resolved paths for a key pair.
type KeyPaths struct {
	PublicKey  string
	PrivateKey string
}

// DefaultKeyPaths returns the default key paths relative to the user's home directory.
func DefaultKeyPaths() (KeyPaths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return KeyPaths{}, fmt.Errorf("could not determine home directory: %w", err)
	}
	dir := filepath.Join(home, DefaultKeyDir)
	return KeyPaths{
		PublicKey:  filepath.Join(dir, DefaultPublicKey),
		PrivateKey: filepath.Join(dir, DefaultPrivateKey),
	}, nil
}

// InitKeys generates a new key pair and writes them to the given paths.
// Returns an error if the files already exist unless overwrite is true.
func InitKeys(paths KeyPaths, overwrite bool) error {
	if !overwrite {
		if _, err := os.Stat(paths.PrivateKey); err == nil {
			return fmt.Errorf("private key already exists at %s (use --force to overwrite)", paths.PrivateKey)
		}
	}

	if err := os.MkdirAll(filepath.Dir(paths.PrivateKey), 0700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	if err := os.WriteFile(paths.PublicKey, []byte(pub.String()+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	if err := os.WriteFile(paths.PrivateKey, []byte(priv.String()+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// LoadPublicKey reads and parses a public key from a file.
func LoadPublicKey(path string) (*crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}
	return crypto.ParsePublicKey(strings.TrimSpace(string(data)))
}

// LoadPrivateKey reads and parses a private key from a file.
func LoadPrivateKey(path string) (*crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	return crypto.ParsePrivateKey(strings.TrimSpace(string(data)))
}
