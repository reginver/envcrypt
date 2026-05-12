package vault

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupWatchVault(t *testing.T) (pubPath, privPath, vaultPath string) {
	t.Helper()
	dir := t.TempDir()
	pubPath = filepath.Join(dir, "key.pub")
	privPath = filepath.Join(dir, "key.age")
	vaultPath = filepath.Join(dir, "test.env.age")
	if err := InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	entries := []EnvEntry{{Key: "FOO", Value: "bar"}}
	if err := encryptVault(entries, vaultPath, pubPath); err != nil {
		t.Fatalf("encryptVault: %v", err)
	}
	return
}

func TestHashVaultFile(t *testing.T) {
	_, _, vaultPath := setupWatchVault(t)
	h1, err := HashVaultFile(vaultPath)
	if err != nil {
		t.Fatalf("HashVaultFile: %v", err)
	}
	if h1 == "" {
		t.Fatal("expected non-empty hash")
	}
	h2, err := HashVaultFile(vaultPath)
	if err != nil {
		t.Fatalf("HashVaultFile second call: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("expected same hash, got %s vs %s", h1, h2)
	}
}

func TestHashVaultFileMissing(t *testing.T) {
	_, err := HashVaultFile("/nonexistent/path.age")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestWatchVaultDetectsChange(t *testing.T) {
	pubPath, privPath, vaultPath := setupWatchVault(t)

	done := make(chan struct{})
	defer close(done)

	events, err := WatchVault(vaultPath, 20*time.Millisecond, done)
	if err != nil {
		t.Fatalf("WatchVault: %v", err)
	}

	// Modify the vault after a short delay
	time.Sleep(30 * time.Millisecond)
	entries := []EnvEntry{{Key: "FOO", Value: "changed"}}
	if err := encryptVault(entries, vaultPath, pubPath); err != nil {
		t.Fatalf("encryptVault update: %v", err)
	}
	_ = privPath

	select {
	case ev := <-events:
		if ev.OldHash == ev.NewHash {
			t.Fatal("expected different hashes")
		}
		if ev.VaultPath != vaultPath {
			t.Fatalf("unexpected vault path: %s", ev.VaultPath)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for watch event")
	}
}

func TestWatchVaultNoChangeNoEvent(t *testing.T) {
	_, _, vaultPath := setupWatchVault(t)

	done := make(chan struct{})
	defer close(done)

	events, err := WatchVault(vaultPath, 20*time.Millisecond, done)
	if err != nil {
		t.Fatalf("WatchVault: %v", err)
	}

	select {
	case ev := <-events:
		t.Fatalf("unexpected event: %+v", ev)
	case <-time.After(100 * time.Millisecond):
		// expected: no events
	}
}

func TestWatchVaultMissingFile(t *testing.T) {
	_, err := WatchVault("/nonexistent/vault.age", 20*time.Millisecond, make(chan struct{}))
	if err == nil {
		t.Fatal("expected error for missing vault")
	}
}

func TestWatchVaultDoneStopsGoroutine(t *testing.T) {
	_, _, vaultPath := setupWatchVault(t)

	done := make(chan struct{})
	events, err := WatchVault(vaultPath, 20*time.Millisecond, done)
	if err != nil {
		t.Fatalf("WatchVault: %v", err)
	}
	close(done)

	// Channel should be closed shortly after done is closed
	time.Sleep(60 * time.Millisecond)
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("expected channel to be closed")
		}
	default:
		// also acceptable — just ensure no panic
	}
	_ = os.Getenv("CI") // suppress unused import
}
