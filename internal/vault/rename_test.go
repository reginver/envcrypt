package vault_test

import (
	"os"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/env"
	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func setupRenameVault(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	pubPath := dir + "/age.pub"
	privPath := dir + "/age.key"
	vaultPath := dir + "/test.env.age"

	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("init keys: %v", err)
	}

	pubKey, _ := vault.LoadPublicKey(pubPath)
	privKey, _ := vault.LoadPrivateKey(privPath)
	v := vault.New(pubKey, privKey)

	entries := []env.Entry{
		{Key: "OLD_KEY", Value: "hello"},
		{Key: "ANOTHER", Value: "world"},
	}
	if err := v.Encrypt(vaultPath, entries); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	return vaultPath, privPath, pubPath
}

func TestRenameKey(t *testing.T) {
	vaultPath, privPath, pubPath := setupRenameVault(t)

	if err := vault.RenameKey(vaultPath, privPath, pubPath, "OLD_KEY", "NEW_KEY"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pubKey, _ := vault.LoadPublicKey(pubPath)
	privKey, _ := vault.LoadPrivateKey(privPath)
	v := vault.New(pubKey, privKey)
	entries, err := v.Decrypt(vaultPath)
	if err != nil {
		t.Fatalf("decrypt after rename: %v", err)
	}

	km := env.ToMap(entries)
	if _, ok := km["NEW_KEY"]; !ok {
		t.Error("expected NEW_KEY to exist")
	}
	if _, ok := km["OLD_KEY"]; ok {
		t.Error("expected OLD_KEY to be gone")
	}
	if km["NEW_KEY"] != "hello" {
		t.Errorf("expected value 'hello', got %q", km["NEW_KEY"])
	}
}

func TestRenameKeyNotFound(t *testing.T) {
	vaultPath, privPath, pubPath := setupRenameVault(t)
	err := vault.RenameKey(vaultPath, privPath, pubPath, "MISSING", "NEW_KEY")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestRenameKeyAlreadyExists(t *testing.T) {
	vaultPath, privPath, pubPath := setupRenameVault(t)
	err := vault.RenameKey(vaultPath, privPath, pubPath, "OLD_KEY", "ANOTHER")
	if err == nil {
		t.Fatal("expected error when target key already exists")
	}
}

func TestRenameKeyMissingVault(t *testing.T) {
	dir := t.TempDir()
	pubPath := dir + "/age.pub"
	privPath := dir + "/age.key"
	_ = vault.InitKeys(pubPath, privPath, false)

	err := vault.RenameKey(dir+"/nonexistent.env.age", privPath, pubPath, "A", "B")
	if err == nil {
		t.Fatal("expected error for missing vault")
	}
}

func TestRenameKeyEmptyNames(t *testing.T) {
	vaultPath, privPath, pubPath := setupRenameVault(t)
	if err := vault.RenameKey(vaultPath, privPath, pubPath, "", "NEW"); err == nil {
		t.Fatal("expected error for empty old key")
	}
	if err := vault.RenameKey(vaultPath, privPath, pubPath, "OLD_KEY", ""); err == nil {
		t.Fatal("expected error for empty new key")
	}
	_ = os.Remove(vaultPath)
}
