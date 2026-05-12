package vault_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func setupTemplateVault(t *testing.T) (dir, vaultPath, pubKey, privKey string) {
	t.Helper()
	dir = t.TempDir()
	pubKey = filepath.Join(dir, "key.pub")
	privKey = filepath.Join(dir, "key")
	if err := vault.InitKeys(pubKey, privKey, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	vaultPath = filepath.Join(dir, ".env.age")
	src := filepath.Join(dir, ".env")
	if err := os.WriteFile(src, []byte("APP_NAME=envcrypt\nSECRET_KEY=abc123\n"), 0600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	v, err := vault.New(pubKey, privKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := v.Encrypt(src, vaultPath); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return
}

func TestRenderTemplateBasic(t *testing.T) {
	dir, vaultPath, _, privKey := setupTemplateVault(t)
	tmplPath := filepath.Join(dir, "config.tmpl")
	if err := os.WriteFile(tmplPath, []byte("name={{APP_NAME}} key={{SECRET_KEY}}"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := vault.RenderTemplate(tmplPath, vaultPath, privKey, false)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	if !strings.Contains(out, "name=envcrypt") || !strings.Contains(out, "key=abc123") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestRenderTemplateUnknownKeyPermissive(t *testing.T) {
	dir, vaultPath, _, privKey := setupTemplateVault(t)
	tmplPath := filepath.Join(dir, "config.tmpl")
	if err := os.WriteFile(tmplPath, []byte("x={{UNKNOWN_KEY}}"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := vault.RenderTemplate(tmplPath, vaultPath, privKey, false)
	if err != nil {
		t.Fatalf("expected no error in permissive mode, got: %v", err)
	}
	if !strings.Contains(out, "{{UNKNOWN_KEY}}") {
		t.Errorf("expected placeholder preserved, got: %q", out)
	}
}

func TestRenderTemplateStrictMissingKey(t *testing.T) {
	dir, vaultPath, _, privKey := setupTemplateVault(t)
	tmplPath := filepath.Join(dir, "config.tmpl")
	if err := os.WriteFile(tmplPath, []byte("x={{MISSING}}"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := vault.RenderTemplate(tmplPath, vaultPath, privKey, true)
	if err == nil {
		t.Fatal("expected error in strict mode")
	}
	if !strings.Contains(err.Error(), "MISSING") {
		t.Errorf("error should mention missing key, got: %v", err)
	}
}

func TestRenderTemplateMissingVault(t *testing.T) {
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "t.tmpl")
	_ = os.WriteFile(tmplPath, []byte("x={{A}}"), 0600)
	_, err := vault.RenderTemplate(tmplPath, filepath.Join(dir, "missing.age"), filepath.Join(dir, "key"), false)
	if err == nil {
		t.Fatal("expected error for missing vault")
	}
}
