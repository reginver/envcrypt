package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/user/envcrypt/internal/env"
	"github.com/user/envcrypt/internal/vault"
)

func TestEditVault(t *testing.T) {
	dir := t.TempDir()
	pubPath, privPath := filepath.Join(dir, "pub.age"), filepath.Join(dir, "priv.age")
	t.Setenv("ENVCRYPT_PUBLIC_KEY", pubPath)
	t.Setenv("ENVCRYPT_PRIVATE_KEY", privPath)

	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	vaultPath := filepath.Join(dir, ".env.age")
	plainPath := filepath.Join(dir, ".env")

	original := "KEY1=hello\nKEY2=world\n"
	if err := os.WriteFile(plainPath, []byte(original), 0600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}

	pubKey, _ := vault.LoadPublicKey(pubPath)
	privKey, _ := vault.LoadPrivateKey(privPath)
	v, _ := vault.New(pubKey, privKey)
	if err := v.EncryptFile(plainPath, vaultPath); err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}

	// Use a script that appends a new key to simulate editing
	scriptPath := filepath.Join(dir, "fake-editor.sh")
	script := "#!/bin/sh\necho 'KEY3=added' >> \"$1\"\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("write editor script: %v", err)
	}

	if err := vault.EditVault(vaultPath, scriptPath); err != nil {
		t.Fatalf("EditVault: %v", err)
	}

	entries, err := v.DecryptFile(vaultPath)
	if err != nil {
		t.Fatalf("DecryptFile after edit: %v", err)
	}

	m := env.ToMap(entries)
	if m["KEY1"] != "hello" {
		t.Errorf("expected KEY1=hello, got %q", m["KEY1"])
	}
	if m["KEY3"] != "added" {
		t.Errorf("expected KEY3=added, got %q", m["KEY3"])
	}
}

func TestEditVaultMissingVault(t *testing.T) {
	dir := t.TempDir()
	pubPath, privPath := filepath.Join(dir, "pub.age"), filepath.Join(dir, "priv.age")
	t.Setenv("ENVCRYPT_PUBLIC_KEY", pubPath)
	t.Setenv("ENVCRYPT_PRIVATE_KEY", privPath)

	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	err := vault.EditVault(filepath.Join(dir, "nonexistent.age"), "vi")
	if err == nil {
		t.Error("expected error for missing vault, got nil")
	}
}
