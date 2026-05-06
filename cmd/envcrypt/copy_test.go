package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func setupCopyTest(t *testing.T) (src, dst, privKey, pubKey string) {
	t.Helper()
	dir := t.TempDir()

	privKey = filepath.Join(dir, "key.txt")
	pubKey = filepath.Join(dir, "key.pub")

	if err := vault.InitKeys(privKey, pubKey, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	src = filepath.Join(dir, "source.env.age")
	dst = filepath.Join(dir, "dest.env.age")

	plain := filepath.Join(dir, ".env")
	if err := os.WriteFile(plain, []byte("FOO=bar\nBAZ=qux\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	v, err := vault.New(pubKey, privKey)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	if err := v.Encrypt(plain, src); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	return src, dst, privKey, pubKey
}

func TestRunCopyCreatesDestination(t *testing.T) {
	src, dst, privKey, pubKey := setupCopyTest(t)

	err := runCopy([]string{
		"-identity", privKey,
		"-recipient", pubKey,
		src, dst,
	})
	if err != nil {
		t.Fatalf("runCopy: %v", err)
	}

	if _, err := os.Stat(dst); os.IsNotExist(err) {
		t.Error("destination vault was not created")
	}
}

func TestRunCopyMissingArgs(t *testing.T) {
	err := runCopy([]string{})
	if err == nil {
		t.Error("expected error for missing args, got nil")
	}
}

func TestRunCopyNoOverwrite(t *testing.T) {
	src, dst, privKey, pubKey := setupCopyTest(t)

	// Create destination first
	if err := os.WriteFile(dst, []byte("existing"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err := runCopy([]string{
		"-identity", privKey,
		"-recipient", pubKey,
		src, dst,
	})
	if err == nil {
		t.Error("expected error when destination exists without overwrite flag")
	}
}
