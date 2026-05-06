package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func setupLintVault(t *testing.T, content string) (string, string) {
	t.Helper()
	dir := t.TempDir()

	pubPath := filepath.Join(dir, "pub.age")
	privPath := filepath.Join(dir, "priv.age")
	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("init keys: %v", err)
	}

	plainPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(plainPath, []byte(content), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}

	vaultPath := filepath.Join(dir, ".env.age")
	v, err := vault.New(vaultPath, pubPath)
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}
	if err := v.Encrypt(plainPath); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	return vaultPath, privPath
}

func TestLintVaultNoIssues(t *testing.T) {
	vaultPath, privPath := setupLintVault(t, "DB_HOST=localhost\nDB_PORT=5432\n")

	issues, err := vault.LintVault(vaultPath, privPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues, got %d: %v", len(issues), issues)
	}
}

func TestLintVaultEmptyValue(t *testing.T) {
	vaultPath, privPath := setupLintVault(t, "DB_HOST=\nDB_PORT=5432\n")

	issues, err := vault.LintVault(vaultPath, privPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}
	if issues[0].Key != "DB_HOST" || issues[0].Severity != "warn" {
		t.Errorf("unexpected issue: %v", issues[0])
	}
}

func TestLintVaultLowercaseKey(t *testing.T) {
	vaultPath, privPath := setupLintVault(t, "db_host=localhost\n")

	issues, err := vault.LintVault(vaultPath, privPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}
	if issues[0].Severity != "warn" {
		t.Errorf("expected warn severity, got %s", issues[0].Severity)
	}
}

func TestLintVaultPlaceholderValue(t *testing.T) {
	vaultPath, privPath := setupLintVault(t, "API_KEY=<CHANGE_ME>\n")

	issues, err := vault.LintVault(vaultPath, privPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) == 0 {
		t.Error("expected at least one issue for placeholder value")
	}
}

func TestLintIssueString(t *testing.T) {
	issue := vault.LintIssue{Key: "FOO", Message: "value is empty", Severity: "warn"}
	s := issue.String()
	if s != "[WARN] FOO: value is empty" {
		t.Errorf("unexpected string: %s", s)
	}
}
