package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func setupTagVault(t *testing.T) (vaultPath, pubKey, privKey string) {
	t.Helper()
	dir := t.TempDir()
	pubKey = filepath.Join(dir, "key.pub")
	privKey = filepath.Join(dir, "key")
	vaultPath = filepath.Join(dir, "test.env.age")

	if err := vault.InitKeys(pubKey, privKey, false); err != nil {
		t.Fatalf("init keys: %v", err)
	}

	src := filepath.Join(dir, ".env")
	if err := os.WriteFile(src, []byte("FOO=bar\nBAZ=qux\nSECRET=topsecret\n"), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	v, err := vault.New(vaultPath, pubKey, privKey)
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}
	if err := v.Encrypt(src); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return
}

func TestTagVaultAddTags(t *testing.T) {
	vaultPath, pubKey, privKey := setupTagVault(t)

	if err := vault.TagVault(vaultPath, privKey, pubKey, "FOO", []string{"prod", "public"}); err != nil {
		t.Fatalf("tag: %v", err)
	}

	entries, err := vault.ListTags(vaultPath)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 || entries[0].Key != "FOO" {
		t.Fatalf("expected FOO entry, got %v", entries)
	}
	if len(entries[0].Tags) != 2 {
		t.Fatalf("expected 2 tags, got %v", entries[0].Tags)
	}
}

func TestTagVaultKeyNotFound(t *testing.T) {
	vaultPath, pubKey, privKey := setupTagVault(t)
	err := vault.TagVault(vaultPath, privKey, pubKey, "NONEXISTENT", []string{"x"})
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestUntagVault(t *testing.T) {
	vaultPath, pubKey, privKey := setupTagVault(t)

	_ = vault.TagVault(vaultPath, privKey, pubKey, "FOO", []string{"prod", "staging"})
	if err := vault.UntagVault(vaultPath, privKey, "FOO", []string{"staging"}); err != nil {
		t.Fatalf("untag: %v", err)
	}

	entries, _ := vault.ListTags(vaultPath)
	if len(entries[0].Tags) != 1 || entries[0].Tags[0] != "prod" {
		t.Fatalf("expected only prod tag, got %v", entries[0].Tags)
	}
}

func TestFilterByTag(t *testing.T) {
	vaultPath, pubKey, privKey := setupTagVault(t)

	_ = vault.TagVault(vaultPath, privKey, pubKey, "FOO", []string{"prod"})
	_ = vault.TagVault(vaultPath, privKey, pubKey, "BAZ", []string{"dev"})
	_ = vault.TagVault(vaultPath, privKey, pubKey, "SECRET", []string{"prod", "secret"})

	keys, err := vault.FilterByTag(vaultPath, "prod")
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 prod keys, got %v", keys)
	}
}

func TestListTagsEmpty(t *testing.T) {
	vaultPath, _, _ := setupTagVault(t)
	entries, err := vault.ListTags(vaultPath)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected empty, got %v", entries)
	}
}
