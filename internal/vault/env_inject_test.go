package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func setupInjectVault(t *testing.T) (vaultPath, privKeyPath string) {
	t.Helper()
	dir := t.TempDir()
	pubKeyPath := filepath.Join(dir, "pub.age")
	privKeyPath = filepath.Join(dir, "priv.age")
	vaultPath = filepath.Join(dir, "test.vault")

	if err := vault.InitKeys(pubKeyPath, privKeyPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	v, err := vault.New(pubKeyPath, privKeyPath)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}

	plaintext := "INJECT_FOO=bar\nINJECT_BAZ=qux\n"
	if err := v.Encrypt([]byte(plaintext), vaultPath); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return vaultPath, privKeyPath
}

func TestInjectVaultAll(t *testing.T) {
	vaultPath, privKeyPath := setupInjectVault(t)
	t.Setenv("INJECT_FOO", "")
	t.Setenv("INJECT_BAZ", "")

	n, err := vault.InjectVault(vaultPath, privKeyPath, vault.InjectOptions{Overwrite: true})
	if err != nil {
		t.Fatalf("InjectVault: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 vars injected, got %d", n)
	}
	if got := os.Getenv("INJECT_FOO"); got != "bar" {
		t.Errorf("INJECT_FOO = %q, want %q", got, "bar")
	}
	if got := os.Getenv("INJECT_BAZ"); got != "qux" {
		t.Errorf("INJECT_BAZ = %q, want %q", got, "qux")
	}
}

func TestInjectVaultNoOverwrite(t *testing.T) {
	vaultPath, privKeyPath := setupInjectVault(t)
	t.Setenv("INJECT_FOO", "original")

	_, err := vault.InjectVault(vaultPath, privKeyPath, vault.InjectOptions{Overwrite: false})
	if err != nil {
		t.Fatalf("InjectVault: %v", err)
	}
	if got := os.Getenv("INJECT_FOO"); got != "original" {
		t.Errorf("INJECT_FOO should not be overwritten, got %q", got)
	}
}

func TestInjectVaultFilterKeys(t *testing.T) {
	vaultPath, privKeyPath := setupInjectVault(t)

	n, err := vault.InjectVault(vaultPath, privKeyPath, vault.InjectOptions{
		Overwrite: true,
		Keys:      []string{"INJECT_FOO"},
	})
	if err != nil {
		t.Fatalf("InjectVault: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 var injected, got %d", n)
	}
}

func TestInjectVaultMissingVault(t *testing.T) {
	dir := t.TempDir()
	privKeyPath := filepath.Join(dir, "priv.age")
	if err := vault.InitKeys(filepath.Join(dir, "pub.age"), privKeyPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	_, err := vault.InjectVault(filepath.Join(dir, "missing.vault"), privKeyPath, vault.InjectOptions{})
	if err == nil {
		t.Fatal("expected error for missing vault")
	}
}
