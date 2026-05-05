package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yourusername/envcrypt/internal/crypto"
	"github.com/yourusername/envcrypt/internal/env"
	"github.com/yourusername/envcrypt/internal/vault"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	plaintext := "APP_ENV=production\nDB_HOST=localhost\nDB_PORT=5432\n"

	tmpDir := t.TempDir()
	plaintextFile := filepath.Join(tmpDir, ".env")
	vaultFile := filepath.Join(tmpDir, ".env.age")

	if err := os.WriteFile(plaintextFile, []byte(plaintext), 0o600); err != nil {
		t.Fatalf("write plaintext file: %v", err)
	}

	v := vault.New(vaultFile)

	if err := v.Encrypt(plaintextFile, []string{pub.String()}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := os.Stat(vaultFile); err != nil {
		t.Fatalf("vault file not created: %v", err)
	}

	entries, err := v.Decrypt([]string{priv.String()})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	m := env.ToMap(entries)
	if m["APP_ENV"] != "production" {
		t.Errorf("APP_ENV: got %q, want %q", m["APP_ENV"], "production")
	}
	if m["DB_HOST"] != "localhost" {
		t.Errorf("DB_HOST: got %q, want %q", m["DB_HOST"], "localhost")
	}
	if m["DB_PORT"] != "5432" {
		t.Errorf("DB_PORT: got %q, want %q", m["DB_PORT"], "5432")
	}
}

func TestEncryptMissingPlaintextFile(t *testing.T) {
	_, _, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	v := vault.New(filepath.Join(t.TempDir(), ".env.age"))
	err = v.Encrypt("/nonexistent/.env", []string{"age1abc"})
	if err == nil {
		t.Fatal("expected error for missing plaintext file, got nil")
	}
}

func TestDecryptMissingVaultFile(t *testing.T) {
	v := vault.New("/nonexistent/.env.age")
	_, err := v.Decrypt([]string{"AGE-SECRET-KEY-1ABC"})
	if err == nil {
		t.Fatal("expected error for missing vault file, got nil")
	}
}
