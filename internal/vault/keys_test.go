package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/user/envcrypt/internal/vault"
)

func TestInitKeys(t *testing.T) {
	dir := t.TempDir()
	paths := vault.KeyPaths{
		PublicKey:  filepath.Join(dir, "key.pub"),
		PrivateKey: filepath.Join(dir, "key.age"),
	}

	if err := vault.InitKeys(paths, false); err != nil {
		t.Fatalf("InitKeys failed: %v", err)
	}

	if _, err := os.Stat(paths.PublicKey); err != nil {
		t.Errorf("public key file not created: %v", err)
	}
	if _, err := os.Stat(paths.PrivateKey); err != nil {
		t.Errorf("private key file not created: %v", err)
	}
}

func TestInitKeysNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	paths := vault.KeyPaths{
		PublicKey:  filepath.Join(dir, "key.pub"),
		PrivateKey: filepath.Join(dir, "key.age"),
	}

	if err := vault.InitKeys(paths, false); err != nil {
		t.Fatalf("first InitKeys failed: %v", err)
	}

	if err := vault.InitKeys(paths, false); err == nil {
		t.Error("expected error on second InitKeys without overwrite, got nil")
	}
}

func TestInitKeysOverwrite(t *testing.T) {
	dir := t.TempDir()
	paths := vault.KeyPaths{
		PublicKey:  filepath.Join(dir, "key.pub"),
		PrivateKey: filepath.Join(dir, "key.age"),
	}

	if err := vault.InitKeys(paths, false); err != nil {
		t.Fatalf("first InitKeys failed: %v", err)
	}
	if err := vault.InitKeys(paths, true); err != nil {
		t.Errorf("expected overwrite to succeed, got: %v", err)
	}
}

func TestLoadPublicKey(t *testing.T) {
	dir := t.TempDir()
	paths := vault.KeyPaths{
		PublicKey:  filepath.Join(dir, "key.pub"),
		PrivateKey: filepath.Join(dir, "key.age"),
	}

	if err := vault.InitKeys(paths, false); err != nil {
		t.Fatalf("InitKeys failed: %v", err)
	}

	pub, err := vault.LoadPublicKey(paths.PublicKey)
	if err != nil {
		t.Fatalf("LoadPublicKey failed: %v", err)
	}
	if pub == nil {
		t.Error("expected non-nil public key")
	}
}

func TestLoadPrivateKey(t *testing.T) {
	dir := t.TempDir()
	paths := vault.KeyPaths{
		PublicKey:  filepath.Join(dir, "key.pub"),
		PrivateKey: filepath.Join(dir, "key.age"),
	}

	if err := vault.InitKeys(paths, false); err != nil {
		t.Fatalf("InitKeys failed: %v", err)
	}

	priv, err := vault.LoadPrivateKey(paths.PrivateKey)
	if err != nil {
		t.Fatalf("LoadPrivateKey failed: %v", err)
	}
	if priv == nil {
		t.Error("expected non-nil private key")
	}
}

func TestLoadPublicKeyMissing(t *testing.T) {
	_, err := vault.LoadPublicKey("/nonexistent/path/key.pub")
	if err == nil {
		t.Error("expected error for missing public key file")
	}
}
