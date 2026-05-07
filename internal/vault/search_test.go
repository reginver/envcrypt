package vault_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func setupSearchVault(t *testing.T) (dir, vaultPath, pubPath, privPath string) {
	t.Helper()
	dir = t.TempDir()
	pubPath = filepath.Join(dir, "key.pub")
	privPath = filepath.Join(dir, "key")
	vaultPath = filepath.Join(dir, "test.env.age")

	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	plainPath := filepath.Join(dir, ".env")
	content := "DB_HOST=localhost\nDB_PORT=5432\nAPI_SECRET=supersecret\nDEBUG=true\n"
	if err := os.WriteFile(plainPath, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	v, err := vault.New(vaultPath, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pub, err := vault.LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	data, _ := os.ReadFile(plainPath)
	if err := v.Encrypt(data, []interface{}{pub}); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return
}

func TestSearchVaultByKey(t *testing.T) {
	_, vaultPath, _, privPath := setupSearchVault(t)

	results, err := vault.SearchVault(vaultPath, privPath, "DB", vault.SearchOptions{})
	if err != nil {
		t.Fatalf("SearchVault: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestSearchVaultByValue(t *testing.T) {
	_, vaultPath, _, privPath := setupSearchVault(t)

	results, err := vault.SearchVault(vaultPath, privPath, "secret", vault.SearchOptions{})
	if err != nil {
		t.Fatalf("SearchVault: %v", err)
	}
	if len(results) != 1 || results[0].Key != "API_SECRET" {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestSearchVaultCaseInsensitive(t *testing.T) {
	_, vaultPath, _, privPath := setupSearchVault(t)

	results, err := vault.SearchVault(vaultPath, privPath, "db_host", vault.SearchOptions{CaseSensitive: false})
	if err != nil {
		t.Fatalf("SearchVault: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestSearchVaultNoMatch(t *testing.T) {
	_, vaultPath, _, privPath := setupSearchVault(t)

	results, err := vault.SearchVault(vaultPath, privPath, "NONEXISTENT", vault.SearchOptions{})
	if err != nil {
		t.Fatalf("SearchVault: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestSearchVaultKeysOnly(t *testing.T) {
	_, vaultPath, _, privPath := setupSearchVault(t)

	// "localhost" appears only in a value; keys-only mode should skip it
	results, err := vault.SearchVault(vaultPath, privPath, "localhost", vault.SearchOptions{KeysOnly: true})
	if err != nil {
		t.Fatalf("SearchVault: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results in keys-only mode, got %d", len(results))
	}
}

func TestSearchVaultMissingVault(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "key")
	vaultPath := filepath.Join(dir, "missing.env.age")

	_ = strings.NewReader("") // keep import
	_, err := vault.SearchVault(vaultPath, privPath, "anything", vault.SearchOptions{})
	if err == nil {
		t.Fatal("expected error for missing vault")
	}
}
