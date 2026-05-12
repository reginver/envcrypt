package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func setupTemplateTest(t *testing.T) (dir, vaultPath, privKey string) {
	t.Helper()
	dir = t.TempDir()
	pubKey := filepath.Join(dir, "key.pub")
	privKey = filepath.Join(dir, "key")
	if err := vault.InitKeys(pubKey, privKey, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	vaultPath = filepath.Join(dir, ".env.age")
	src := filepath.Join(dir, ".env")
	_ = os.WriteFile(src, []byte("GREETING=hello\nTARGET=world\n"), 0600)
	v, _ := vault.New(pubKey, privKey)
	if err := v.Encrypt(src, vaultPath); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return
}

func captureTemplateOutput(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestRunTemplateRendersToStdout(t *testing.T) {
	dir, vaultPath, privKey := setupTemplateTest(t)
	tmplPath := filepath.Join(dir, "msg.tmpl")
	_ = os.WriteFile(tmplPath, []byte("{{GREETING}}, {{TARGET}}!"), 0600)

	out := captureTemplateOutput(func() {
		runTemplate([]string{"-vault", vaultPath, "-priv", privKey, tmplPath})
	})
	if !strings.Contains(out, "hello, world!") {
		t.Errorf("expected rendered output, got: %q", out)
	}
}

func TestRunTemplateRendersToFile(t *testing.T) {
	dir, vaultPath, privKey := setupTemplateTest(t)
	tmplPath := filepath.Join(dir, "msg.tmpl")
	outPath := filepath.Join(dir, "rendered.txt")
	_ = os.WriteFile(tmplPath, []byte("{{GREETING}} {{TARGET}}"), 0600)

	runTemplate([]string{"-vault", vaultPath, "-priv", privKey, "-out", outPath, tmplPath})

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(data), "hello world") {
		t.Errorf("unexpected file content: %q", string(data))
	}
}

func TestRunTemplateMissingVault(t *testing.T) {
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "t.tmpl")
	_ = os.WriteFile(tmplPath, []byte("{{A}}"), 0600)

	// Should not panic; error goes to stderr and exits — we just verify no panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("unexpected panic: %v", r)
		}
	}()
	// We can't easily test os.Exit; just call vault.RenderTemplate directly
	_, err := vault.RenderTemplate(tmplPath, filepath.Join(dir, "missing.age"), filepath.Join(dir, "key"), false)
	if err == nil {
		t.Error("expected error for missing vault")
	}
}
