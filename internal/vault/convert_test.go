package vault_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func setupConvertVault(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "pub.age")
	privPath := filepath.Join(dir, "priv.age")
	vaultPath := filepath.Join(dir, "test.env.age")

	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("init keys: %v", err)
	}

	v, err := vault.New(pubPath, privPath)
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}

	plain := filepath.Join(dir, ".env")
	if err := os.WriteFile(plain, []byte("DB_HOST=localhost\nDB_PORT=5432\nSECRET=abc123\n"), 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	if err := v.Encrypt(plain, vaultPath); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return dir, vaultPath, privPath
}

func TestConvertVaultDotenv(t *testing.T) {
	dir, vaultPath, privPath := setupConvertVault(t)
	out := filepath.Join(dir, "out.env")
	err := vault.ConvertVault(vault.ConvertOptions{
		VaultPath: vaultPath, PrivKeyPath: privPath,
		OutputPath: out, Format: vault.FormatDotenv,
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "DB_HOST=localhost") {
		t.Errorf("expected DB_HOST in output, got: %s", data)
	}
}

func TestConvertVaultJSON(t *testing.T) {
	_, vaultPath, privPath := setupConvertVault(t)
	err := vault.ConvertVault(vault.ConvertOptions{
		VaultPath: vaultPath, PrivKeyPath: privPath,
		OutputPath: "-", Format: vault.FormatJSON,
	})
	if err != nil {
		t.Fatalf("convert json: %v", err)
	}
}

func TestConvertVaultJSONOutput(t *testing.T) {
	dir, vaultPath, privPath := setupConvertVault(t)
	out := filepath.Join(dir, "out.json")
	err := vault.ConvertVault(vault.ConvertOptions{
		VaultPath: vaultPath, PrivKeyPath: privPath,
		OutputPath: out, Format: vault.FormatJSON,
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	data, _ := os.ReadFile(out)
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["DB_HOST"] != "localhost" {
		t.Errorf("expected DB_HOST=localhost, got %q", m["DB_HOST"])
	}
}

func TestConvertVaultExportFormat(t *testing.T) {
	dir, vaultPath, privPath := setupConvertVault(t)
	out := filepath.Join(dir, "out.sh")
	err := vault.ConvertVault(vault.ConvertOptions{
		VaultPath: vaultPath, PrivKeyPath: privPath,
		OutputPath: out, Format: vault.FormatExport,
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "export DB_HOST=") {
		t.Errorf("expected export statement, got: %s", data)
	}
}

func TestConvertVaultFilterKeys(t *testing.T) {
	dir, vaultPath, privPath := setupConvertVault(t)
	out := filepath.Join(dir, "filtered.env")
	err := vault.ConvertVault(vault.ConvertOptions{
		VaultPath: vaultPath, PrivKeyPath: privPath,
		OutputPath: out, Format: vault.FormatDotenv,
		Keys: []string{"DB_HOST"},
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	data, _ := os.ReadFile(out)
	if strings.Contains(string(data), "SECRET") {
		t.Errorf("SECRET should be filtered out, got: %s", data)
	}
}

func TestConvertVaultMissingVault(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.age")
	_ = vault.InitKeys(filepath.Join(dir, "pub.age"), privPath, false)
	err := vault.ConvertVault(vault.ConvertOptions{
		VaultPath: filepath.Join(dir, "missing.env.age"),
		PrivKeyPath: privPath, OutputPath: "-", Format: vault.FormatDotenv,
	})
	if err == nil {
		t.Error("expected error for missing vault")
	}
}
