package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func setupStatsVault(t *testing.T, content string) (vaultPath, privPath string) {
	t.Helper()
	dir := t.TempDir()

	pubPath := filepath.Join(dir, "key.pub")
	privPath = filepath.Join(dir, "key")
	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	plainPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(plainPath, []byte(content), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}

	vaultPath = filepath.Join(dir, ".env.age")
	v := vault.New(pubPath, privPath)
	if err := v.Encrypt(plainPath, vaultPath); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return vaultPath, privPath
}

func TestStatsVaultBasic(t *testing.T) {
	content := "FOO=bar\nBAZ=qux\nEMPTY=\n"
	vaultPath, privPath := setupStatsVault(t, content)

	stats, err := vault.StatsVault(vaultPath, privPath)
	if err != nil {
		t.Fatalf("StatsVault: %v", err)
	}

	if stats.TotalKeys != 3 {
		t.Errorf("TotalKeys: want 3, got %d", stats.TotalKeys)
	}
	if stats.EmptyValues != 1 {
		t.Errorf("EmptyValues: want 1, got %d", stats.EmptyValues)
	}
}

func TestStatsVaultUniqueValues(t *testing.T) {
	content := "A=same\nB=same\nC=unique\n"
	vaultPath, privPath := setupStatsVault(t, content)

	stats, err := vault.StatsVault(vaultPath, privPath)
	if err != nil {
		t.Fatalf("StatsVault: %v", err)
	}

	// only C=unique has a unique value
	if stats.UniqueValues != 1 {
		t.Errorf("UniqueValues: want 1, got %d", stats.UniqueValues)
	}
}

func TestStatsVaultLongestShortest(t *testing.T) {
	content := "AB=1\nLONGKEY=2\nX=3\n"
	vaultPath, privPath := setupStatsVault(t, content)

	stats, err := vault.StatsVault(vaultPath, privPath)
	if err != nil {
		t.Fatalf("StatsVault: %v", err)
	}

	if stats.LongestKey != "LONGKEY" {
		t.Errorf("LongestKey: want LONGKEY, got %s", stats.LongestKey)
	}
	if stats.ShortestKey != "X" {
		t.Errorf("ShortestKey: want X, got %s", stats.ShortestKey)
	}
}

func TestStatsVaultMissingFile(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "key")
	pubPath := filepath.Join(dir, "key.pub")
	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	_, err := vault.StatsVault(filepath.Join(dir, "missing.age"), privPath)
	if err == nil {
		t.Error("expected error for missing vault, got nil")
	}
}
