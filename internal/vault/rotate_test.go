package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/user/envcrypt/internal/crypto"
	"github.com/user/envcrypt/internal/env"
	"github.com/user/envcrypt/internal/vault"
)

func TestRotateKeys(t *testing.T) {
	dir := t.TempDir()

	vaultPath := filepath.Join(dir, ".env.age")
	plaintextPath := filepath.Join(dir, ".env")
	newPubPath := filepath.Join(dir, "new_pub.age")
	newPrivPath := filepath.Join(dir, "new_priv.age")

	// Create initial key pair and encrypt a vault.
	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	initialEntries := []env.Entry{
		{Key: "SECRET", Value: "hunter2"},
		{Key: "API_KEY", Value: "abc123"},
	}
	ciphertext, err := crypto.Encrypt([]byte(env.Serialize(initialEntries)), pub)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := os.WriteFile(vaultPath, ciphertext, 0o644); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	// Write the OLD private key to the path that RotateKeys will read from.
	if err := os.WriteFile(newPrivPath, []byte(priv.String()), 0o600); err != nil {
		t.Fatalf("write priv key: %v", err)
	}

	// Perform rotation.
	if err := vault.RotateKeys(vaultPath, plaintextPath, newPubPath, newPrivPath); err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}

	// New key files must exist.
	if _, err := os.Stat(newPubPath); err != nil {
		t.Errorf("new public key not written: %v", err)
	}
	if _, err := os.Stat(newPrivPath); err != nil {
		t.Errorf("new private key not written: %v", err)
	}

	// Decrypt with the new private key and verify contents.
	newPriv, err := vault.LoadPrivateKey(newPrivPath)
	if err != nil {
		t.Fatalf("load new private key: %v", err)
	}
	newCiphertext, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read rotated vault: %v", err)
	}
	plaintext, err := crypto.Decrypt(newCiphertext, newPriv)
	if err != nil {
		t.Fatalf("decrypt with new key: %v", err)
	}
	entries, err := env.Parse(string(plaintext))
	if err != nil {
		t.Fatalf("parse entries: %v", err)
	}
	m := env.ToMap(entries)
	if m["SECRET"] != "hunter2" || m["API_KEY"] != "abc123" {
		t.Errorf("unexpected entries after rotation: %v", m)
	}
}

func TestRotateKeysMissingVault(t *testing.T) {
	dir := t.TempDir()
	err := vault.RotateKeys(
		filepath.Join(dir, "nonexistent.age"),
		filepath.Join(dir, ".env"),
		filepath.Join(dir, "pub.age"),
		filepath.Join(dir, "priv.age"),
	)
	if err == nil {
		t.Error("expected error for missing vault, got nil")
	}
}

func TestRotateKeysMissingPrivKey(t *testing.T) {
	dir := t.TempDir()

	// Create a valid (but empty) vault file so the error comes from the missing key.
	vaultPath := filepath.Join(dir, ".env.age")
	if err := os.WriteFile(vaultPath, []byte{}, 0o644); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	err := vault.RotateKeys(
		vaultPath,
		filepath.Join(dir, ".env"),
		filepath.Join(dir, "pub.age"),
		filepath.Join(dir, "nonexistent_priv.age"),
	)
	if err == nil {
		t.Error("expected error for missing private key, got nil")
	}
}
