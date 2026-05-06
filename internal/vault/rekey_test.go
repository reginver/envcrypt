package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func setupRekeyVault(t *testing.T) (dir, vaultPath, pubPath, privPath string) {
	t.Helper()
	dir = t.TempDir()

	pubPath = filepath.Join(dir, "age.pub")
	privPath = filepath.Join(dir, "age.key")
	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	plaintextPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(plaintextPath, []byte("APP_KEY=secret\nDB_URL=postgres://localhost/db\n"), 0600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}

	vaultPath = filepath.Join(dir, ".env.age")
	v, err := vault.New(pubPath, privPath)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	if err := v.Encrypt(plaintextPath, vaultPath); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	return dir, vaultPath, pubPath, privPath
}

func TestRekeyVault(t *testing.T) {
	dir, vaultPath, _, oldPrivPath := setupRekeyVault(t)

	// Generate new key pair
	newPubPath := filepath.Join(dir, "new_age.pub")
	newPrivPath := filepath.Join(dir, "new_age.key")
	if err := vault.InitKeys(newPubPath, newPrivPath, false); err != nil {
		t.Fatalf("InitKeys new: %v", err)
	}

	if err := vault.RekeyVault(vaultPath, oldPrivPath, newPubPath); err != nil {
		t.Fatalf("RekeyVault: %v", err)
	}

	// Verify new key can decrypt
	v, err := vault.New(newPubPath, newPrivPath)
	if err != nil {
		t.Fatalf("vault.New with new keys: %v", err)
	}
	out := filepath.Join(dir, ".env.out")
	if err := v.Decrypt(vaultPath, out); err != nil {
		t.Fatalf("Decrypt with new key: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(data) == "" {
		t.Error("expected non-empty decrypted content")
	}
}

func TestRekeyVaultMissingVault(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "age.pub")
	privPath := filepath.Join(dir, "age.key")
	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	err := vault.RekeyVault(filepath.Join(dir, "missing.age"), privPath, pubPath)
	if err == nil {
		t.Error("expected error for missing vault")
	}
}

func TestRekeyVaultInvalidOldKey(t *testing.T) {
	_, vaultPath, newPubPath, _ := setupRekeyVault(t)

	err := vault.RekeyVault(vaultPath, "/nonexistent/key", newPubPath)
	if err == nil {
		t.Error("expected error for invalid old private key")
	}
}
