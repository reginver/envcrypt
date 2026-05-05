package vault_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func TestExportVaultRaw(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "pub.age")
	privPath := filepath.Join(dir, "priv.age")
	vaultPath := filepath.Join(dir, ".env.age")
	plainPath := filepath.Join(dir, ".env")

	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	if err := os.WriteFile(plainPath, []byte("FOO=bar\nBAZ=qux\n"), 0600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}

	v, err := vault.New(pubPath, privPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := v.Encrypt(plainPath, vaultPath); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	out, err := vault.ExportVault(vaultPath, privPath, vault.ExportOptions{Format: vault.FormatRaw})
	if err != nil {
		t.Fatalf("ExportVault: %v", err)
	}

	if !strings.Contains(out, "FOO=bar") || !strings.Contains(out, "BAZ=qux") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestExportVaultExportFormat(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "pub.age")
	privPath := filepath.Join(dir, "priv.age")
	vaultPath := filepath.Join(dir, ".env.age")
	plainPath := filepath.Join(dir, ".env")

	_ = vault.InitKeys(pubPath, privPath, false)
	_ = os.WriteFile(plainPath, []byte("HELLO=world\n"), 0600)

	v, _ := vault.New(pubPath, privPath)
	_ = v.Encrypt(plainPath, vaultPath)

	out, err := vault.ExportVault(vaultPath, privPath, vault.ExportOptions{Format: vault.FormatExport})
	if err != nil {
		t.Fatalf("ExportVault: %v", err)
	}
	if !strings.Contains(out, "export HELLO=world") {
		t.Errorf("expected 'export HELLO=world', got: %q", out)
	}
}

func TestExportVaultFilterKeys(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "pub.age")
	privPath := filepath.Join(dir, "priv.age")
	vaultPath := filepath.Join(dir, ".env.age")
	plainPath := filepath.Join(dir, ".env")

	_ = vault.InitKeys(pubPath, privPath, false)
	_ = os.WriteFile(plainPath, []byte("A=1\nB=2\nC=3\n"), 0600)

	v, _ := vault.New(pubPath, privPath)
	_ = v.Encrypt(plainPath, vaultPath)

	out, err := vault.ExportVault(vaultPath, privPath, vault.ExportOptions{
		Format: vault.FormatRaw,
		Keys:   []string{"A", "C"},
	})
	if err != nil {
		t.Fatalf("ExportVault: %v", err)
	}
	if strings.Contains(out, "B=2") {
		t.Errorf("key B should have been filtered out, got: %q", out)
	}
	if !strings.Contains(out, "A=1") || !strings.Contains(out, "C=3") {
		t.Errorf("expected A and C in output, got: %q", out)
	}
}

func TestExportVaultMissingFile(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.age")
	_ = vault.InitKeys(filepath.Join(dir, "pub.age"), privPath, false)

	_, err := vault.ExportVault(filepath.Join(dir, "nonexistent.age"), privPath, vault.ExportOptions{})
	if err == nil {
		t.Fatal("expected error for missing vault file")
	}
}
