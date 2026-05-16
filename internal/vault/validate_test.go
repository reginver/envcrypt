package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func setupValidateVault(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "pub.age")
	privPath := filepath.Join(dir, "priv.age")
	vaultPath := filepath.Join(dir, ".env.age")

	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	return pubPath, privPath, vaultPath
}

func writeValidateVault(t *testing.T, pubPath, privPath, vaultPath string, entries map[string]string) {
	t.Helper()
	v, err := vault.New(pubPath, privPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := v.Encrypt(entries, vaultPath); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
}

func TestValidateVaultNoIssues(t *testing.T) {
	pubPath, privPath, vaultPath := setupValidateVault(t)
	writeValidateVault(t, pubPath, privPath, vaultPath, map[string]string{
		"DATABASE_URL": "postgres://localhost/mydb",
		"API_KEY":      "abc123secret",
		"PORT":         "8080",
	})

	results, err := vault.ValidateVault(vaultPath, privPath, nil)
	if err != nil {
		t.Fatalf("ValidateVault: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected no issues, got %d: %+v", len(results), results)
	}
}

func TestValidateVaultEmptyValue(t *testing.T) {
	pubPath, privPath, vaultPath := setupValidateVault(t)
	writeValidateVault(t, pubPath, privPath, vaultPath, map[string]string{
		"DATABASE_URL": "",
		"API_KEY":      "abc123secret",
	})

	results, err := vault.ValidateVault(vaultPath, privPath, nil)
	if err != nil {
		t.Fatalf("ValidateVault: %v", err)
	}

	found := false
	for _, r := range results {
		if r.Key == "DATABASE_URL" {
			found = true
		}
	}
	if !found {
		t.Error("expected validation issue for empty DATABASE_URL")
	}
}

func TestValidateVaultLowercaseKey(t *testing.T) {
	pubPath, privPath, vaultPath := setupValidateVault(t)
	writeValidateVault(t, pubPath, privPath, vaultPath, map[string]string{
		"database_url": "postgres://localhost/mydb",
		"API_KEY":      "abc123",
	})

	results, err := vault.ValidateVault(vaultPath, privPath, nil)
	if err != nil {
		t.Fatalf("ValidateVault: %v", err)
	}

	found := false
	for _, r := range results {
		if r.Key == "database_url" {
			found = true
		}
	}
	if !found {
		t.Error("expected validation issue for lowercase key 'database_url'")
	}
}

func TestValidateVaultPlaceholderValue(t *testing.T) {
	pubPath, privPath, vaultPath := setupValidateVault(t)
	writeValidateVault(t, pubPath, privPath, vaultPath, map[string]string{
		"API_KEY":  "CHANGEME",
		"DB_PASS":  "your-password-here",
		"REAL_KEY": "abc123",
	})

	results, err := vault.ValidateVault(vaultPath, privPath, nil)
	if err != nil {
		t.Fatalf("ValidateVault: %v", err)
	}

	placeholderKeys := map[string]bool{}
	for _, r := range results {
		placeholderKeys[r.Key] = true
	}
	if !placeholderKeys["API_KEY"] {
		t.Error("expected validation issue for placeholder value in API_KEY")
	}
	if !placeholderKeys["DB_PASS"] {
		t.Error("expected validation issue for placeholder value in DB_PASS")
	}
}

func TestValidateVaultMissingFile(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.age")
	vaultPath := filepath.Join(dir, "missing.age")

	_, err := vault.ValidateVault(vaultPath, privPath, nil)
	if err == nil {
		t.Error("expected error for missing vault file")
	}
}

func TestFormatValidation(t *testing.T) {
	results := []vault.ValidationResult{
		{Key: "API_KEY", Rule: "placeholder", Message: "value appears to be a placeholder"},
		{Key: "db_url", Rule: "lowercase", Message: "key should be uppercase"},
	}

	output := vault.FormatValidation(results)
	if output == "" {
		t.Error("expected non-empty formatted output")
	}
	for _, r := range results {
		if !containsStr(output, r.Key) {
			t.Errorf("expected output to contain key %q", r.Key)
		}
	}
}

func TestFormatValidationEmpty(t *testing.T) {
	output := vault.FormatValidation(nil)
	if output == "" {
		t.Error("expected non-empty output even for empty results")
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

func TestValidateVaultCustomRule(t *testing.T) {
	pubPath, privPath, vaultPath := setupValidateVault(t)
	writeValidateVault(t, pubPath, privPath, vaultPath, map[string]string{
		"SHORT": "x",
		"NORMAL_KEY": "abc123",
	})

	customRule := vault.ValidationRule{
		Name: "min-length",
		Check: func(key, value string) (bool, string) {
			if len(value) < 3 {
				return false, "value is too short (min 3 chars)"
			}
			return true, ""
		},
	}

	results, err := vault.ValidateVault(vaultPath, privPath, []vault.ValidationRule{customRule})
	if err != nil {
		t.Fatalf("ValidateVault: %v", err)
	}

	found := false
	for _, r := range results {
		if r.Key == "SHORT" && r.Rule == "min-length" {
			found = true
		}
	}
	if !found {
		t.Error("expected custom rule to flag SHORT key")
	}
}

var _ = os.TempDir // ensure os import used
