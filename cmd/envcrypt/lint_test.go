package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

// setupLintTest creates a temporary directory with keys and a vault file
// containing the given env content, returning the dir path and a cleanup func.
func setupLintTest(t *testing.T, envContent string) (dir string, cleanup func()) {
	t.Helper()

	dir = t.TempDir()
	paths := vault.DefaultKeyPaths(dir)

	if err := vault.InitKeys(paths, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	vaultPath := filepath.Join(dir, ".env.vault")
	plainPath := filepath.Join(dir, ".env.plain")

	if err := os.WriteFile(plainPath, []byte(envContent), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}

	v := vault.New(vaultPath, paths.PublicKey, paths.PrivateKey)
	if err := v.Encrypt(plainPath); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_ = os.Remove(plainPath)

	cleanup = func() {} // t.TempDir handles removal
	return dir, cleanup
}

func TestRunLintNoIssues(t *testing.T) {
	dir, cleanup := setupLintTest(t, "APP_HOST=localhost\nAPP_PORT=8080\nSECRET_KEY=supersecret\n")
	defer cleanup()

	paths := vault.DefaultKeyPaths(dir)
	vaultPath := filepath.Join(dir, ".env.vault")

	out, err := captureOutput(t, func() error {
		return runLint(vaultPath, paths.PrivateKey, false)
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "No issues") {
		t.Errorf("expected 'No issues' in output, got: %s", out)
	}
}

func TestRunLintWithIssues(t *testing.T) {
	dir, cleanup := setupLintTest(t, "app_host=localhost\nAPP_PORT=\nSECRET_KEY=CHANGEME\n")
	defer cleanup()

	paths := vault.DefaultKeyPaths(dir)
	vaultPath := filepath.Join(dir, ".env.vault")

	out, err := captureOutput(t, func() error {
		return runLint(vaultPath, paths.PrivateKey, false)
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "app_host") {
		t.Errorf("expected lowercase key issue for 'app_host', got: %s", out)
	}
	if !strings.Contains(out, "APP_PORT") {
		t.Errorf("expected empty value issue for 'APP_PORT', got: %s", out)
	}
	if !strings.Contains(out, "SECRET_KEY") {
		t.Errorf("expected placeholder issue for 'SECRET_KEY', got: %s", out)
	}
}

func TestRunLintStrict(t *testing.T) {
	dir, cleanup := setupLintTest(t, "app_host=localhost\n")
	defer cleanup()

	paths := vault.DefaultKeyPaths(dir)
	vaultPath := filepath.Join(dir, ".env.vault")

	_, err := captureOutput(t, func() error {
		return runLint(vaultPath, paths.PrivateKey, true)
	})

	if err == nil {
		t.Error("expected error in strict mode with issues, got nil")
	}
}

func TestRunLintMissingVault(t *testing.T) {
	dir := t.TempDir()
	paths := vault.DefaultKeyPaths(dir)

	if err := vault.InitKeys(paths, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	vaultPath := filepath.Join(dir, "nonexistent.vault")

	_, err := captureOutput(t, func() error {
		return runLint(vaultPath, paths.PrivateKey, false)
	})

	if err == nil {
		t.Error("expected error for missing vault, got nil")
	}
}

// captureOutput captures stdout from fn, returning the output string and any error fn returns.
func captureOutput(t *testing.T, fn func() error) (string, error) {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	fnErr := fn()

	w.Close()
	os.Stdout = old

	var buf strings.Builder
	tmp := make([]byte, 1024)
	for {
		n, readErr := r.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if readErr != nil {
			break
		}
	}
	r.Close()

	return buf.String(), fnErr
}
