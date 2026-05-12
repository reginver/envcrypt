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

func captureWatchOutput(fn func()) string {
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

func setupWatchTest(t *testing.T) (pubPath, privPath, vaultPath string) {
	t.Helper()
	dir := t.TempDir()
	pubPath = filepath.Join(dir, "key.pub")
	privPath = filepath.Join(dir, "key.age")
	vaultPath = filepath.Join(dir, "test.env.age")
	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	v, err := vault.New(pubPath, privPath)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	if err := v.Encrypt(".env", vaultPath, func(s string) {}); err != nil {
		// .env missing is fine; create the vault directly via a temp file
		tmpEnv := filepath.Join(dir, ".env")
		if werr := os.WriteFile(tmpEnv, []byte("FOO=bar\n"), 0600); werr != nil {
			t.Fatalf("write .env: %v", werr)
		}
		if err2 := v.Encrypt(tmpEnv, vaultPath, func(s string) {}); err2 != nil {
			t.Fatalf("Encrypt: %v", err2)
		}
	}
	return
}

func TestRunWatchMissingVault(t *testing.T) {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exited := false
	origExit := osExit
	osExit = func(code int) { exited = true; panic("exit") }
	defer func() {
		recover()
		osExit = origExit
		w.Close()
		os.Stderr = old
		var buf bytes.Buffer
		io.Copy(&buf, r)
		if !exited {
			t.Error("expected os.Exit to be called")
		}
		if !strings.Contains(buf.String(), "error") {
			t.Errorf("expected error message, got: %s", buf.String())
		}
	}()

	runWatch([]string{"--vault", "/nonexistent/path.age", "--interval", "10ms"})
}

func TestHashVaultFileConsistency(t *testing.T) {
	_, _, vaultPath := setupWatchTest(t)
	h1, err := vault.HashVaultFile(vaultPath)
	if err != nil {
		t.Fatalf("HashVaultFile: %v", err)
	}
	h2, err := vault.HashVaultFile(vaultPath)
	if err != nil {
		t.Fatalf("HashVaultFile: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("hashes differ: %s vs %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("expected 64-char hex hash, got len %d", len(h1))
	}
}
