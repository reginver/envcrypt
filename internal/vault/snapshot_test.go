package vault_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func setupSnapshotVault(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, ".env.age")
	if err := os.WriteFile(vaultPath, []byte("encrypted-data"), 0600); err != nil {
		t.Fatalf("writing vault: %v", err)
	}
	return dir, vaultPath
}

func TestSnapshotVaultCreatesFile(t *testing.T) {
	_, vaultPath := setupSnapshotVault(t)

	snapshotPath, err := vault.SnapshotVault(vaultPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(snapshotPath); os.IsNotExist(err) {
		t.Errorf("expected snapshot file to exist at %s", snapshotPath)
	}

	if !strings.Contains(filepath.Base(snapshotPath), ".env.age.") {
		t.Errorf("snapshot name %q does not contain expected prefix", filepath.Base(snapshotPath))
	}
}

func TestSnapshotVaultMissingVault(t *testing.T) {
	dir := t.TempDir()
	_, err := vault.SnapshotVault(filepath.Join(dir, "nonexistent.age"))
	if err == nil {
		t.Error("expected error for missing vault, got nil")
	}
}

func TestListSnapshotsEmpty(t *testing.T) {
	_, vaultPath := setupSnapshotVault(t)

	snapshots, err := vault.ListSnapshots(vaultPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snapshots) != 0 {
		t.Errorf("expected 0 snapshots, got %d", len(snapshots))
	}
}

func TestListSnapshotsAfterSnapshot(t *testing.T) {
	_, vaultPath := setupSnapshotVault(t)

	for i := 0; i < 3; i++ {
		if _, err := vault.SnapshotVault(vaultPath); err != nil {
			t.Fatalf("snapshot %d failed: %v", i, err)
		}
	}

	snapshots, err := vault.ListSnapshots(vaultPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snapshots) != 3 {
		t.Errorf("expected 3 snapshots, got %d", len(snapshots))
	}
}

func TestRestoreSnapshot(t *testing.T) {
	_, vaultPath := setupSnapshotVault(t)

	original, _ := os.ReadFile(vaultPath)
	snapshotPath, _ := vault.SnapshotVault(vaultPath)

	if err := os.WriteFile(vaultPath, []byte("modified-data"), 0600); err != nil {
		t.Fatalf("modifying vault: %v", err)
	}

	if err := vault.RestoreSnapshot(vaultPath, snapshotPath); err != nil {
		t.Fatalf("restore failed: %v", err)
	}

	restored, _ := os.ReadFile(vaultPath)
	if string(restored) != string(original) {
		t.Errorf("restored content %q does not match original %q", restored, original)
	}
}

func TestRestoreSnapshotMissing(t *testing.T) {
	_, vaultPath := setupSnapshotVault(t)
	err := vault.RestoreSnapshot(vaultPath, "/nonexistent/snap.age")
	if err == nil {
		t.Error("expected error for missing snapshot, got nil")
	}
}
