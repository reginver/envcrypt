package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func setupSetVault(t *testing.T) (dir, vaultPath, pubPath, privPath string) {
	t.Helper()
	dir = t.TempDir()
	vaultPath = filepath.Join(dir, ".env.age")
	pubPath = filepath.Join(dir, "key.pub")
	privPath = filepath.Join(dir, "key")
	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	return
}

func TestSetKeyCreatesEntry(t *testing.T) {
	_, vaultPath, pubPath, privPath := setupSetVault(t)

	if err := vault.SetKey(vaultPath, pubPath, privPath, "FOO", "bar"); err != nil {
		t.Fatalf("SetKey: %v", err)
	}

	pubKey, _ := vault.LoadPublicKey(pubPath)
	privKey, _ := vault.LoadPrivateKey(privPath)
	v := vault.New(vaultPath, pubKey, privKey)
	entries, err := v.Decrypt()
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if len(entries) != 1 || entries[0].Key != "FOO" || entries[0].Value != "bar" {
		t.Errorf("unexpected entries: %+v", entries)
	}
}

func TestSetKeyUpdatesExisting(t *testing.T) {
	_, vaultPath, pubPath, privPath := setupSetVault(t)

	_ = vault.SetKey(vaultPath, pubPath, privPath, "FOO", "original")
	_ = vault.SetKey(vaultPath, pubPath, privPath, "FOO", "updated")

	pubKey, _ := vault.LoadPublicKey(pubPath)
	privKey, _ := vault.LoadPrivateKey(privPath)
	v := vault.New(vaultPath, pubKey, privKey)
	entries, err := v.Decrypt()
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if len(entries) != 1 || entries[0].Value != "updated" {
		t.Errorf("expected updated value, got %+v", entries)
	}
}

func TestSetKeyEmptyKeyError(t *testing.T) {
	_, vaultPath, pubPath, privPath := setupSetVault(t)
	if err := vault.SetKey(vaultPath, pubPath, privPath, "", "value"); err == nil {
		t.Error("expected error for empty key")
	}
}

func TestDeleteKeyRemovesEntry(t *testing.T) {
	_, vaultPath, pubPath, privPath := setupSetVault(t)

	_ = vault.SetKey(vaultPath, pubPath, privPath, "FOO", "bar")
	_ = vault.SetKey(vaultPath, pubPath, privPath, "BAZ", "qux")

	if err := vault.DeleteKey(vaultPath, pubPath, privPath, "FOO"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	pubKey, _ := vault.LoadPublicKey(pubPath)
	privKey, _ := vault.LoadPrivateKey(privPath)
	v := vault.New(vaultPath, pubKey, privKey)
	entries, err := v.Decrypt()
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if len(entries) != 1 || entries[0].Key != "BAZ" {
		t.Errorf("unexpected entries after delete: %+v", entries)
	}
}

func TestDeleteKeyNotFound(t *testing.T) {
	_, vaultPath, pubPath, privPath := setupSetVault(t)
	_ = vault.SetKey(vaultPath, pubPath, privPath, "FOO", "bar")
	if err := vault.DeleteKey(vaultPath, pubPath, privPath, "MISSING"); err == nil {
		t.Error("expected error for missing key")
	}
}

func TestDeleteKeyMissingVault(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, ".env.age")
	pubPath := filepath.Join(dir, "key.pub")
	privPath := filepath.Join(dir, "key")
	_ = vault.InitKeys(pubPath, privPath, false)
	_ = os.Remove(vaultPath)
	if err := vault.DeleteKey(vaultPath, pubPath, privPath, "FOO"); err == nil {
		t.Error("expected error for missing vault")
	}
}
