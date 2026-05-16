package vault_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/your-org/envcrypt/internal/vault"
)

func setupTouchVault(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.env.age")
	if err := os.WriteFile(vaultPath, []byte("dummy-vault-content"), 0600); err != nil {
		t.Fatalf("setup: write vault: %v", err)
	}
	return dir, vaultPath
}

func TestTouchVaultUpdatesTimestamp(t *testing.T) {
	_, vaultPath := setupTouchVault(t)

	// Set an old mtime so we can detect the change.
	oldTime := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(vaultPath, oldTime, oldTime); err != nil {
		t.Fatalf("pre-set mtime: %v", err)
	}

	result, err := vault.TouchVault(vaultPath)
	if err != nil {
		t.Fatalf("TouchVault: %v", err)
	}

	if result.Path != vaultPath {
		t.Errorf("path mismatch: got %s, want %s", result.Path, vaultPath)
	}
	if !result.NewMtime.After(result.PrevMtime) {
		t.Errorf("expected new mtime %v to be after prev mtime %v", result.NewMtime, result.PrevMtime)
	}

	info, err := os.Stat(vaultPath)
	if err != nil {
		t.Fatalf("stat after touch: %v", err)
	}
	if info.ModTime().Before(oldTime.Add(time.Hour)) {
		t.Errorf("file mtime not updated on disk")
	}
}

func TestTouchVaultPreservesContents(t *testing.T) {
	_, vaultPath := setupTouchVault(t)

	before, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	if _, err := vault.TouchVault(vaultPath); err != nil {
		t.Fatalf("TouchVault: %v", err)
	}

	after, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("contents changed after touch")
	}
}

func TestTouchVaultMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := vault.TouchVault(filepath.Join(dir, "nonexistent.env.age"))
	if err == nil {
		t.Fatal("expected error for missing vault, got nil")
	}
}
