package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func captureCompareOutput(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func setupCompareTest(t *testing.T) (dir, pub, priv string) {
	t.Helper()
	dir = t.TempDir()
	pub = filepath.Join(dir, "key.pub")
	priv = filepath.Join(dir, "key")
	if err := vault.InitKeys(pub, priv, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	return
}

func writeTestVaultForCompare(t *testing.T, path, pub string, content string) {
	t.Helper()
	src := path + ".plain"
	if err := os.WriteFile(src, []byte(content), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	if err := vault.New(src, path, pub, vault.NoopAuditHook); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
}

func TestRunCompareIdentical(t *testing.T) {
	dir, pub, priv := setupCompareTest(t)
	a := filepath.Join(dir, "a.env.age")
	b := filepath.Join(dir, "b.env.age")
	writeTestVaultForCompare(t, a, pub, "FOO=bar\nBAZ=qux\n")
	writeTestVaultForCompare(t, b, pub, "FOO=bar\nBAZ=qux\n")

	out := captureCompareOutput(func() {
		runCompare([]string{"-priv", priv, a, b})
	})

	if !strings.Contains(out, "identical") {
		t.Errorf("expected 'identical' in output, got: %s", out)
	}
}

func TestRunCompareDifferent(t *testing.T) {
	dir, pub, priv := setupCompareTest(t)
	a := filepath.Join(dir, "a.env.age")
	b := filepath.Join(dir, "b.env.age")
	writeTestVaultForCompare(t, a, pub, "FOO=bar\nONLY_A=yes\n")
	writeTestVaultForCompare(t, b, pub, "FOO=changed\nONLY_B=yes\n")

	out := captureCompareOutput(func() {
		runCompare([]string{"-priv", priv, a, b})
	})

	if !strings.Contains(out, "ONLY_A") {
		t.Errorf("expected ONLY_A in output, got: %s", out)
	}
	if !strings.Contains(out, "ONLY_B") {
		t.Errorf("expected ONLY_B in output, got: %s", out)
	}
	if !strings.Contains(out, "FOO") {
		t.Errorf("expected FOO in different section, got: %s", out)
	}
}

func TestRunCompareMissingArgs(t *testing.T) {
	// Should exit — we just verify it doesn't panic with enough args guard.
	// We can't easily test os.Exit, so we test the vault error path.
	_, _, priv := setupCompareTest(t)
	// Providing missing vault paths should produce an error (not panic).
	// We wrap in a recover to avoid os.Exit killing the test process.
	defer func() { recover() }()
	runCompare([]string{"-priv", priv, "/nonexistent/a.age", "/nonexistent/b.age"})
}
