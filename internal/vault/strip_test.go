package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/env"
	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func setupStripVault(t *testing.T) (dir, vaultPath, pubPath, privPath string) {
	t.Helper()
	dir = t.TempDir()
	pubPath = filepath.Join(dir, "key.pub")
	privPath = filepath.Join(dir, "key")
	vaultPath = filepath.Join(dir, "test.env.age")

	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("init keys: %v", err)
	}

	pubKey, err := vault.LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("load pub key: %v", err)
	}
	privKey, err := vault.LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("load priv key: %v", err)
	}

	v := vault.New(pubKey, privKey)
	entries := []env.Entry{
		{Key: "FOO", Value: "bar"},
		{Key: "BAZ", Value: "qux"},
		{Key: "KEEP", Value: "me"},
	}
	if err := v.Encrypt(vaultPath, entries); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return
}

func TestStripKeyRemovesEntry(t *testing.T) {
	_, vaultPath, pubPath, privPath := setupStripVault(t)

	err := vault.StripKeys(vaultPath, pubPath, privPath, []string{"FOO"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pubKey, _ := vault.LoadPublicKey(pubPath)
	privKey, _ := vault.LoadPrivateKey(privPath)
	v := vault.New(pubKey, privKey)
	entries, err := v.Decrypt(vaultPath)
	if err != nil {
		t.Fatalf("decrypt after strip: %v", err)
	}

	for _, e := range entries {
		if e.Key == "FOO" {
			t.Errorf("expected FOO to be stripped but it still exists")
		}
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries after strip, got %d", len(entries))
	}
}

func TestStripKeyMultipleKeys(t *testing.T) {
	_, vaultPath, pubPath, privPath := setupStripVault(t)

	err := vault.StripKeys(vaultPath, pubPath, privPath, []string{"FOO", "BAZ"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pubKey, _ := vault.LoadPublicKey(pubPath)
	privKey, _ := vault.LoadPrivateKey(privPath)
	v := vault.New(pubKey, privKey)
	entries, err := v.Decrypt(vaultPath)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(entries) != 1 || entries[0].Key != "KEEP" {
		t.Errorf("expected only KEEP to remain, got %v", entries)
	}
}

func TestStripKeyNotFound(t *testing.T) {
	_, vaultPath, pubPath, privPath := setupStripVault(t)

	err := vault.StripKeys(vaultPath, pubPath, privPath, []string{"MISSING"}, nil)
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
}

func TestStripKeyMissingVault(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "key.pub")
	privPath := filepath.Join(dir, "key")
	_ = vault.InitKeys(pubPath, privPath, false)

	err := vault.StripKeys(filepath.Join(dir, "noexist.age"), pubPath, privPath, []string{"FOO"}, nil)
	if err == nil {
		t.Fatal("expected error for missing vault")
	}
}

func TestStripKeyNoKeysSpecified(t *testing.T) {
	dir := t.TempDir()
	err := vault.StripKeys(filepath.Join(dir, "x.age"), "", "", []string{}, nil)
	if err == nil {
		t.Fatal("expected error when no keys specified")
	}
}

func TestStripKeyAuditHook(t *testing.T) {
	_, vaultPath, pubPath, privPath := setupStripVault(t)

	var audited string
	hook := func(msg string) { audited = msg }

	err := vault.StripKeys(vaultPath, pubPath, privPath, []string{"FOO"}, hook)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if audited == "" {
		t.Error("expected audit hook to be called")
	}
	_ = os.Remove(vaultPath)
}
