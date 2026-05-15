package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func setupTruncateTest(t *testing.T) (dir, vaultPath, pubKey, privKey string) {
	t.Helper()
	dir = t.TempDir()
	vaultPath = filepath.Join(dir, ".env.age")
	pubKey = filepath.Join(dir, "key.pub")
	privKey = filepath.Join(dir, "key.age")

	if err := vault.InitKeys(pubKey, privKey, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	plainPath := filepath.Join(dir, ".env")
	content := "FOO=bar\nBAZ=qux\nSECRET=topsecret\n"
	if err := os.WriteFile(plainPath, []byte(content), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}

	if err := vault.New(plainPath, vaultPath, pubKey, vault.NoopAuditHook); err != nil {
		t.Fatalf("vault.New: %v", err)
	}

	return dir, vaultPath, pubKey, privKey
}

func TestRunTruncateAll(t *testing.T) {
	_, vaultPath, pubKey, privKey := setupTruncateTest(t)

	args := []string{
		"--vault", vaultPath,
		"--pub", pubKey,
		"--priv", privKey,
	}

	if err := runTruncate(args); err != nil {
		t.Fatalf("runTruncate: %v", err)
	}

	// After truncating all keys, the vault should decrypt to empty
	tmp := t.TempDir()
	out := filepath.Join(tmp, ".env")
	if err := vault.Decrypt(vaultPath, out, privKey, vault.NoopAuditHook); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.TrimSpace(string(data)) != "" {
		t.Errorf("expected empty vault after truncate all, got: %q", string(data))
	}
}

func TestRunTruncateSelectiveKeys(t *testing.T) {
	_, vaultPath, pubKey, privKey := setupTruncateTest(t)

	args := []string{
		"--vault", vaultPath,
		"--pub", pubKey,
		"--priv", privKey,
		"--keys", "FOO,BAZ",
	}

	if err := runTruncate(args); err != nil {
		t.Fatalf("runTruncate: %v", err)
	}

	tmp := t.TempDir()
	out := filepath.Join(tmp, ".env")
	if err := vault.Decrypt(vaultPath, out, privKey, vault.NoopAuditHook); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if strings.Contains(string(data), "FOO") {
		t.Errorf("expected FOO to be truncated, but found in output")
	}
	if strings.Contains(string(data), "BAZ") {
		t.Errorf("expected BAZ to be truncated, but found in output")
	}
	if !strings.Contains(string(data), "SECRET") {
		t.Errorf("expected SECRET to remain, but not found in output")
	}
}

func TestRunTruncateMissingVault(t *testing.T) {
	dir := t.TempDir()

	args := []string{
		"--vault", filepath.Join(dir, "nonexistent.age"),
		"--pub", filepath.Join(dir, "key.pub"),
		"--priv", filepath.Join(dir, "key.age"),
	}

	if err := runTruncate(args); err == nil {
		t.Error("expected error for missing vault, got nil")
	}
}

func TestRunTruncateMissingArgs(t *testing.T) {
	// No args at all should return an error
	if err := runTruncate([]string{}); err == nil {
		t.Error("expected error for missing args, got nil")
	}
}
