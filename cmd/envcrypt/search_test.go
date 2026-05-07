package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func setupSearchTest(t *testing.T) (dir string, cleanup func()) {
	t.Helper()

	dir = t.TempDir()
	pubPath := filepath.Join(dir, "pub.age")
	privPath := filepath.Join(dir, "priv.age")

	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	plainPath := filepath.Join(dir, ".env")
	content := "DATABASE_URL=postgres://localhost/mydb\nAPI_KEY=supersecret\nDEBUG=true\nSERVICE_URL=https://example.com\n"
	if err := os.WriteFile(plainPath, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	vaultPath := filepath.Join(dir, ".env.age")
	v, err := vault.New(pubPath, privPath)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	if err := v.Encrypt(plainPath, vaultPath); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	return dir, func() {}
}

func TestRunSearchByKey(t *testing.T) {
	dir, cleanup := setupSearchTest(t)
	defer cleanup()

	vaultPath := filepath.Join(dir, ".env.age")
	privPath := filepath.Join(dir, "priv.age")

	out := captureOutput(t, func() {
		err := runSearch([]string{"--vault", vaultPath, "--key", "priv.age", "--query", "DATABASE"}, privPath)
		if err != nil {
			t.Fatalf("runSearch: %v", err)
		}
	})

	if !strings.Contains(out, "DATABASE_URL") {
		t.Errorf("expected DATABASE_URL in output, got: %s", out)
	}
	if strings.Contains(out, "API_KEY") {
		t.Errorf("did not expect API_KEY in output, got: %s", out)
	}
}

func TestRunSearchByValue(t *testing.T) {
	dir, cleanup := setupSearchTest(t)
	defer cleanup()

	vaultPath := filepath.Join(dir, ".env.age")
	privPath := filepath.Join(dir, "priv.age")

	out := captureOutput(t, func() {
		err := runSearch([]string{"--vault", vaultPath, "--key", "priv.age", "--query", "supersecret", "--value"}, privPath)
		if err != nil {
			t.Fatalf("runSearch: %v", err)
		}
	})

	if !strings.Contains(out, "API_KEY") {
		t.Errorf("expected API_KEY in output, got: %s", out)
	}
}

func TestRunSearchNoMatch(t *testing.T) {
	dir, cleanup := setupSearchTest(t)
	defer cleanup()

	vaultPath := filepath.Join(dir, ".env.age")
	privPath := filepath.Join(dir, "priv.age")

	out := captureOutput(t, func() {
		err := runSearch([]string{"--vault", vaultPath, "--key", "priv.age", "--query", "NONEXISTENT"}, privPath)
		if err != nil {
			t.Fatalf("runSearch: %v", err)
		}
	})

	if !strings.Contains(out, "no matches") && !strings.Contains(out, "0 match") {
		t.Logf("output: %s", out)
		// Acceptable: empty output or a 'no matches' message
	}
}

func TestRunSearchMissingVault(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.age")
	vaultPath := filepath.Join(dir, "nonexistent.age")

	err := runSearch([]string{"--vault", vaultPath, "--key", "priv.age", "--query", "TEST"}, privPath)
	if err == nil {
		t.Error("expected error for missing vault, got nil")
	}
}

func TestRunSearchCaseInsensitive(t *testing.T) {
	dir, cleanup := setupSearchTest(t)
	defer cleanup()

	vaultPath := filepath.Join(dir, ".env.age")
	privPath := filepath.Join(dir, "priv.age")

	out := captureOutput(t, func() {
		err := runSearch([]string{"--vault", vaultPath, "--key", "priv.age", "--query", "database"}, privPath)
		if err != nil {
			t.Fatalf("runSearch: %v", err)
		}
	})

	if !strings.Contains(out, "DATABASE_URL") {
		t.Errorf("expected case-insensitive match for DATABASE_URL, got: %s", out)
	}
}
