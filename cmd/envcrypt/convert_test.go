package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func setupConvertTest(t *testing.T) (string, string, string) {
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
		t.Fatalf("vault new: %v", err)
	}
	plain := filepath.Join(dir, ".env")
	_ = os.WriteFile(plain, []byte("APP_ENV=production\nAPP_KEY=secret\n"), 0o600)
	if err := v.Encrypt(plain, vaultPath); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return dir, vaultPath, privPath
}

func TestRunConvertDotenv(t *testing.T) {
	dir, vaultPath, privPath := setupConvertTest(t)
	out := filepath.Join(dir, "out.env")
	err := vault.ConvertVault(vault.ConvertOptions{
		VaultPath: vaultPath, PrivKeyPath: privPath,
		OutputPath: out, Format: vault.FormatDotenv,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "APP_ENV=production") {
		t.Errorf("expected APP_ENV in output")
	}
}

func TestRunConvertJSON(t *testing.T) {
	dir, vaultPath, privPath := setupConvertTest(t)
	out := filepath.Join(dir, "out.json")
	err := vault.ConvertVault(vault.ConvertOptions{
		VaultPath: vaultPath, PrivKeyPath: privPath,
		OutputPath: out, Format: vault.FormatJSON,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(out)
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if m["APP_ENV"] != "production" {
		t.Errorf("expected APP_ENV=production, got %q", m["APP_ENV"])
	}
}

func TestRunConvertExport(t *testing.T) {
	dir, vaultPath, privPath := setupConvertTest(t)
	out := filepath.Join(dir, "out.sh")
	err := vault.ConvertVault(vault.ConvertOptions{
		VaultPath: vaultPath, PrivKeyPath: privPath,
		OutputPath: out, Format: vault.FormatExport,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(out)
	if !strings.HasPrefix(strings.Split(string(data), "\n")[0], "export ") {
		t.Errorf("expected export prefix, got: %s", data)
	}
}

func TestRunConvertMissingVault(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.age")
	_ = vault.InitKeys(filepath.Join(dir, "pub.age"), privPath, false)
	err := vault.ConvertVault(vault.ConvertOptions{
		VaultPath: filepath.Join(dir, "nope.env.age"),
		PrivKeyPath: privPath, OutputPath: "-", Format: vault.FormatDotenv,
	})
	if err == nil {
		t.Error("expected error for missing vault")
	}
}
