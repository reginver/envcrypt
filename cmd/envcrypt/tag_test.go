package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func setupTagTest(t *testing.T) (vaultPath, pub, priv string) {
	t.Helper()
	dir := t.TempDir()
	pub = filepath.Join(dir, "key.pub")
	priv = filepath.Join(dir, "key")
	vaultPath = filepath.Join(dir, "test.env.age")

	if err := vault.InitKeys(pub, priv, false); err != nil {
		t.Fatalf("init keys: %v", err)
	}
	src := filepath.Join(dir, ".env")
	if err := os.WriteFile(src, []byte("FOO=bar\nBAZ=qux\n"), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	v, err := vault.New(vaultPath, pub, priv)
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}
	if err := v.Encrypt(src); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return
}

func TestRunTagAdd(t *testing.T) {
	vaultPath, pub, priv := setupTagTest(t)
	err := runTag([]string{
		"-vault", vaultPath,
		"-pub", pub,
		"-priv", priv,
		"FOO", "prod,critical",
	})
	if err != nil {
		t.Fatalf("runTag: %v", err)
	}

	entries, err := vault.ListTags(vaultPath)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 || entries[0].Key != "FOO" {
		t.Fatalf("unexpected entries: %v", entries)
	}
}

func TestRunTagRemove(t *testing.T) {
	vaultPath, pub, priv := setupTagTest(t)
	_ = vault.TagVault(vaultPath, priv, pub, "FOO", []string{"prod", "dev"})

	err := runTag([]string{
		"-vault", vaultPath,
		"-priv", priv,
		"-remove",
		"FOO", "dev",
	})
	if err != nil {
		t.Fatalf("runTag remove: %v", err)
	}

	entries, _ := vault.ListTags(vaultPath)
	if len(entries[0].Tags) != 1 || entries[0].Tags[0] != "prod" {
		t.Fatalf("expected prod only, got %v", entries[0].Tags)
	}
}

func TestRunTagMissingArgs(t *testing.T) {
	vaultPath, pub, priv := setupTagTest(t)
	err := runTag([]string{
		"-vault", vaultPath,
		"-pub", pub,
		"-priv", priv,
	})
	if err == nil {
		t.Fatal("expected error for missing args")
	}
}

func TestRunTagList(t *testing.T) {
	vaultPath, pub, priv := setupTagTest(t)
	_ = vault.TagVault(vaultPath, priv, pub, "BAZ", []string{"staging"})

	err := runTag([]string{
		"-vault", vaultPath,
		"-list",
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
}
