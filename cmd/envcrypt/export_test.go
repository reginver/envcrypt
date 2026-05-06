package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func TestRunExportRaw(t *testing.T) {
	dir := t.TempDir()
	publicKeyPath := filepath.Join(dir, "envcrypt.pub")
	privateKeyPath := filepath.Join(dir, "envcrypt.key")
	plaintextPath := filepath.Join(dir, ".env")
	vaultPath := filepath.Join(dir, ".env.age")

	// Initialize keys
	if err := vault.InitKeys(publicKeyPath, privateKeyPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	// Write a plaintext .env file
	envContent := "DB_HOST=localhost\nDB_PORT=5432\nSECRET=hunter2\n"
	if err := os.WriteFile(plaintextPath, []byte(envContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Encrypt it
	v, err := vault.New(publicKeyPath, privateKeyPath)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	if err := v.Encrypt(plaintextPath, vaultPath); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Export raw
	var buf strings.Builder
	opts := vault.ExportOptions{
		Format: "raw",
		Keys:   nil,
	}
	if err := vault.ExportVault(vaultPath, privateKeyPath, opts, &buf); err != nil {
		t.Fatalf("ExportVault: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "DB_HOST=localhost") {
		t.Errorf("expected DB_HOST in output, got: %s", out)
	}
	if !strings.Contains(out, "SECRET=hunter2") {
		t.Errorf("expected SECRET in output, got: %s", out)
	}
}

func TestRunExportJSON(t *testing.T) {
	dir := t.TempDir()
	publicKeyPath := filepath.Join(dir, "envcrypt.pub")
	privateKeyPath := filepath.Join(dir, "envcrypt.key")
	plaintextPath := filepath.Join(dir, ".env")
	vaultPath := filepath.Join(dir, ".env.age")

	if err := vault.InitKeys(publicKeyPath, privateKeyPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	envContent := "APP_NAME=envcrypt\nAPP_ENV=production\n"
	if err := os.WriteFile(plaintextPath, []byte(envContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	v, err := vault.New(publicKeyPath, privateKeyPath)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	if err := v.Encrypt(plaintextPath, vaultPath); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	var buf strings.Builder
	opts := vault.ExportOptions{
		Format: "json",
		Keys:   nil,
	}
	if err := vault.ExportVault(vaultPath, privateKeyPath, opts, &buf); err != nil {
		t.Fatalf("ExportVault: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"APP_NAME"`) {
		t.Errorf("expected APP_NAME in JSON output, got: %s", out)
	}
	if !strings.Contains(out, `"envcrypt"`) {
		t.Errorf("expected value envcrypt in JSON output, got: %s", out)
	}
}

func TestRunExportFilterKeys(t *testing.T) {
	dir := t.TempDir()
	publicKeyPath := filepath.Join(dir, "envcrypt.pub")
	privateKeyPath := filepath.Join(dir, "envcrypt.key")
	plaintextPath := filepath.Join(dir, ".env")
	vaultPath := filepath.Join(dir, ".env.age")

	if err := vault.InitKeys(publicKeyPath, privateKeyPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	envContent := "KEEP=yes\nDROP=no\n"
	if err := os.WriteFile(plaintextPath, []byte(envContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	v, err := vault.New(publicKeyPath, privateKeyPath)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	if err := v.Encrypt(plaintextPath, vaultPath); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	var buf strings.Builder
	opts := vault.ExportOptions{
		Format: "raw",
		Keys:   []string{"KEEP"},
	}
	if err := vault.ExportVault(vaultPath, privateKeyPath, opts, &buf); err != nil {
		t.Fatalf("ExportVault: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "KEEP=yes") {
		t.Errorf("expected KEEP in output, got: %s", out)
	}
	if strings.Contains(out, "DROP") {
		t.Errorf("expected DROP to be filtered out, got: %s", out)
	}
}

func TestRunExportMissingVault(t *testing.T) {
	dir := t.TempDir()
	privateKeyPath := filepath.Join(dir, "envcrypt.key")
	vaultPath := filepath.Join(dir, ".env.age")

	var buf strings.Builder
	opts := vault.ExportOptions{Format: "raw"}
	err := vault.ExportVault(vaultPath, privateKeyPath, opts, &buf)
	if err == nil {
		t.Error("expected error for missing vault file, got nil")
	}
}
