package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func TestImportVaultCreatesNewVault(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "key.pub")
	privPath := filepath.Join(dir, "key")
	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("init keys: %v", err)
	}

	srcPath := filepath.Join(dir, "source.env")
	if err := os.WriteFile(srcPath, []byte("FOO=bar\nBAZ=qux\n"), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	vaultPath := filepath.Join(dir, ".env.age")
	n, err := vault.ImportVault(vaultPath, srcPath, pubPath, vault.ImportOptions{})
	if err != nil {
		t.Fatalf("ImportVault: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 imported entries, got %d", n)
	}

	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		t.Error("vault file was not created")
	}
}

func TestImportVaultFilterKeys(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "key.pub")
	privPath := filepath.Join(dir, "key")
	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("init keys: %v", err)
	}

	srcPath := filepath.Join(dir, "source.env")
	if err := os.WriteFile(srcPath, []byte("KEEP=yes\nSKIP=no\n"), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	vaultPath := filepath.Join(dir, ".env.age")
	n, err := vault.ImportVault(vaultPath, srcPath, pubPath, vault.ImportOptions{
		Keys: []string{"KEEP"},
	})
	if err != nil {
		t.Fatalf("ImportVault: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 imported entry, got %d", n)
	}
}

func TestImportVaultMissingSource(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "key.pub")
	privPath := filepath.Join(dir, "key")
	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("init keys: %v", err)
	}

	_, err := vault.ImportVault(
		filepath.Join(dir, ".env.age"),
		filepath.Join(dir, "nonexistent.env"),
		pubPath,
		vault.ImportOptions{},
	)
	if err == nil {
		t.Error("expected error for missing source file, got nil")
	}
}
