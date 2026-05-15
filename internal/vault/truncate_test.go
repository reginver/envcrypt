package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/crypto"
	"github.com/nicholasgasior/envcrypt/internal/env"
	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func setupTruncateVault(t *testing.T) (dir, vaultPath, pubPath, privPath string) {
	t.Helper()
	dir = t.TempDir()
	vaultPath = filepath.Join(dir, ".env.age")
	pubPath = filepath.Join(dir, "key.pub")
	privPath = filepath.Join(dir, "key.txt")

	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("init keys: %v", err)
	}

	pubKey, err := vault.LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("load pub key: %v", err)
	}

	entries := []env.Entry{
		{Key: "FOO", Value: "bar"},
		{Key: "BAZ", Value: "qux"},
		{Key: "HELLO", Value: "world"},
	}
	plaintext := env.Serialize(entries)
	ciphertext, err := crypto.Encrypt([]byte(plaintext), pubKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := os.WriteFile(vaultPath, ciphertext, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}
	return
}

func TestTruncateVaultAll(t *testing.T) {
	_, vaultPath, pubPath, privPath := setupTruncateVault(t)

	count, err := vault.TruncateVault(vaultPath, pubPath, privPath, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 removed, got %d", count)
	}

	privKey, _ := vault.LoadPrivateKey(privPath)
	ciphertext, _ := os.ReadFile(vaultPath)
	plaintext, err := crypto.Decrypt(ciphertext, privKey)
	if err != nil {
		t.Fatalf("decrypt after truncate: %v", err)
	}
	entries, _ := env.Parse(string(plaintext))
	if len(entries) != 0 {
		t.Errorf("expected empty vault, got %d entries", len(entries))
	}
}

func TestTruncateVaultSelectiveKeys(t *testing.T) {
	_, vaultPath, pubPath, privPath := setupTruncateVault(t)

	count, err := vault.TruncateVault(vaultPath, pubPath, privPath, []string{"FOO", "BAZ"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 removed, got %d", count)
	}

	privKey, _ := vault.LoadPrivateKey(privPath)
	ciphertext, _ := os.ReadFile(vaultPath)
	plaintext, _ := crypto.Decrypt(ciphertext, privKey)
	entries, _ := env.Parse(string(plaintext))
	if len(entries) != 1 || entries[0].Key != "HELLO" {
		t.Errorf("expected only HELLO remaining, got %v", entries)
	}
}

func TestTruncateVaultMissingVault(t *testing.T) {
	_, _, pubPath, privPath := setupTruncateVault(t)
	_, err := vault.TruncateVault("/nonexistent/.env.age", pubPath, privPath, nil)
	if err == nil {
		t.Error("expected error for missing vault")
	}
}
