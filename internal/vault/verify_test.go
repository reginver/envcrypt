package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func setupVerifyVault(t *testing.T) (vaultPath, pubKey, privKey string) {
	t.Helper()
	dir := t.TempDir()
	pubKey = filepath.Join(dir, "pub.age")
	privKey = filepath.Join(dir, "priv.age")

	if err := vault.InitKeys(pubKey, privKey, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	vaultPath = filepath.Join(dir, "test.env.age")
	plainPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(plainPath, []byte("FOO=bar\nBAZ=qux\n"), 0600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}

	v, err := vault.New(pubKey, privKey)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	if err := v.Encrypt(plainPath, vaultPath); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return vaultPath, pubKey, privKey
}

func TestVerifyVaultValid(t *testing.T) {
	vaultPath, _, privKey := setupVerifyVault(t)

	result, err := vault.VerifyVault(vaultPath, privKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected Valid=true, got error: %v", result.Error)
	}
	if result.EntryCount != 2 {
		t.Errorf("expected 2 entries, got %d", result.EntryCount)
	}
}

func TestVerifyVaultMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := vault.VerifyVault(filepath.Join(dir, "missing.age"), "")
	if err == nil {
		t.Error("expected error for missing vault file")
	}
}

func TestVerifyVaultCorrupted(t *testing.T) {
	vaultPath, _, privKey := setupVerifyVault(t)

	if err := os.WriteFile(vaultPath, []byte("not-valid-age-ciphertext"), 0600); err != nil {
		t.Fatalf("corrupt vault: %v", err)
	}

	result, err := vault.VerifyVault(vaultPath, privKey)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if result.Valid {
		t.Error("expected Valid=false for corrupted vault")
	}
	if result.Error == nil {
		t.Error("expected result.Error to be set")
	}
}
