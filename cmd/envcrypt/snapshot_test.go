package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/user/envcrypt/internal/vault"
)

func setupSnapshotTest(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "key.pub")
	privPath := filepath.Join(dir, "key")
	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	vaultPath := filepath.Join(dir, ".env.vault")
	if err := vault.New(vaultPath, pubPath, map[string]string{
		"APP_ENV": "production",
		"DB_URL":  "postgres://localhost/mydb",
	}); err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	return dir, pubPath, privPath
}

func TestRunSnapshotCreate(t *testing.T) {
	dir, _, _ := setupSnapshotTest(t)
	vaultPath := filepath.Join(dir, ".env.vault")

	err := runSnapshot([]string{"create", vaultPath})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	snaps, err := vault.ListSnapshots(dir)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) == 0 {
		t.Fatal("expected at least one snapshot")
	}
}

func TestRunSnapshotList(t *testing.T) {
	dir, _, _ := setupSnapshotTest(t)
	vaultPath := filepath.Join(dir, ".env.vault")

	_ = runSnapshot([]string{"create", vaultPath})

	err := runSnapshot([]string{"list", vaultPath})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestRunSnapshotListEmpty(t *testing.T) {
	dir, _, _ := setupSnapshotTest(t)
	vaultPath := filepath.Join(dir, ".env.vault")

	err := runSnapshot([]string{"list", vaultPath})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestRunSnapshotMissingArgs(t *testing.T) {
	err := runSnapshot([]string{})
	if err == nil {
		t.Fatal("expected error for missing args")
	}
}

func TestRunSnapshotUnknownSubcommand(t *testing.T) {
	err := runSnapshot([]string{"bogus"})
	if err == nil || !strings.Contains(err.Error(), "unknown subcommand") {
		t.Fatalf("expected unknown subcommand error, got: %v", err)
	}
}

func TestRunSnapshotRestoreMissingArgs(t *testing.T) {
	err := runSnapshot([]string{"restore"})
	if err == nil {
		t.Fatal("expected error for missing restore args")
	}
}

func TestRunSnapshotRestore(t *testing.T) {
	dir, pubPath, privPath := setupSnapshotTest(t)
	vaultPath := filepath.Join(dir, ".env.vault")

	snapshotFile, err := vault.SnapshotVault(vaultPath)
	if err != nil {
		t.Fatalf("SnapshotVault: %v", err)
	}

	destVault := filepath.Join(dir, ".env.vault.restored")

	// Temporarily override DefaultKeyPaths by using the vault API directly
	err = vault.RestoreSnapshot(snapshotFile, destVault, pubPath, privPath)
	if err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}

	if _, err := os.Stat(destVault); err != nil {
		t.Fatalf("restored vault not found: %v", err)
	}
}
