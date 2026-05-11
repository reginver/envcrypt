package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/env"
	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func setupCloneVault(t *testing.T) (srcVault, pubKey, privKey string) {
	t.Helper()
	dir := t.TempDir()
	pubKey = filepath.Join(dir, "age.pub")
	privKey = filepath.Join(dir, "age.key")

	if err := vault.InitKeys(pubKey, privKey, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	srcVault = filepath.Join(dir, "src.env.age")
	plaintext := filepath.Join(dir, "src.env")

	entries := []env.Entry{
		{Key: "APP_NAME", Value: "envcrypt"},
		{Key: "APP_ENV", Value: "production"},
	}
	data := env.Serialize(entries)
	if err := os.WriteFile(plaintext, []byte(data), 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}

	v, err := vault.New(pubKey, privKey)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	if err := v.Encrypt(plaintext, srcVault); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return srcVault, pubKey, privKey
}

func TestCloneVaultCreatesDestination(t *testing.T) {
	src, pubKey, privKey := setupCloneVault(t)
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.env.age")

	if err := vault.CloneVault(src, dst, privKey, pubKey, false); err != nil {
		t.Fatalf("CloneVault: %v", err)
	}

	if _, err := os.Stat(dst); os.IsNotExist(err) {
		t.Fatal("expected destination vault to exist")
	}
}

func TestCloneVaultNoOverwrite(t *testing.T) {
	src, pubKey, privKey := setupCloneVault(t)
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.env.age")

	// Create destination first
	if err := os.WriteFile(dst, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := vault.CloneVault(src, dst, privKey, pubKey, false)
	if err == nil {
		t.Fatal("expected error when destination exists and overwrite is false")
	}
}

func TestCloneVaultMissingSource(t *testing.T) {
	dir := t.TempDir()
	err := vault.CloneVault(
		filepath.Join(dir, "nonexistent.env.age"),
		filepath.Join(dir, "dst.env.age"),
		filepath.Join(dir, "age.key"),
		filepath.Join(dir, "age.pub"),
		false,
	)
	if err == nil {
		t.Fatal("expected error for missing source vault")
	}
}

func TestCloneVaultPreservesEntries(t *testing.T) {
	src, pubKey, privKey := setupCloneVault(t)
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.env.age")

	if err := vault.CloneVault(src, dst, privKey, pubKey, false); err != nil {
		t.Fatalf("CloneVault: %v", err)
	}

	v, err := vault.New(pubKey, privKey)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	out := filepath.Join(dir, "out.env")
	if err := v.Decrypt(dst, out); err != nil {
		t.Fatalf("Decrypt cloned vault: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := env.Parse(string(data))
	if err != nil {
		t.Fatal(err)
	}
	m := env.ToMap(entries)
	if m["APP_NAME"] != "envcrypt" {
		t.Errorf("expected APP_NAME=envcrypt, got %q", m["APP_NAME"])
	}
	if m["APP_ENV"] != "production" {
		t.Errorf("expected APP_ENV=production, got %q", m["APP_ENV"])
	}
}
