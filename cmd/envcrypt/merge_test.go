package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yourusername/envcrypt/internal/env"
	"github.com/yourusername/envcrypt/internal/vault"
)

func setupMergeTest(t *testing.T) (srcPath, dstPath, pubPath, privPath string) {
	t.Helper()
	dir := t.TempDir()
	pubPath = filepath.Join(dir, "age.pub")
	privPath = filepath.Join(dir, "age.key")
	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	pub, _ := vault.LoadPublicKey(pubPath)
	priv, _ := vault.LoadPrivateKey(privPath)
	v := vault.New(pub, priv)

	srcPath = filepath.Join(dir, "src.env.age")
	v.Encrypt(srcPath, []env.Entry{{Key: "NEW_KEY", Value: "new_val"}, {Key: "CONFLICT", Value: "src"}})

	dstPath = filepath.Join(dir, "dst.env.age")
	v.Encrypt(dstPath, []env.Entry{{Key: "EXISTING", Value: "keep"}, {Key: "CONFLICT", Value: "dst"}})
	return
}

func TestRunMergeOurs(t *testing.T) {
	src, dst, pub, priv := setupMergeTest(t)
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	runMerge([]string{"--pub", pub, "--priv", priv, src, dst})
	w.Close()
	os.Stdout = old
	buf := make([]byte, 256)
	n, _ := r.Read(buf)
	out := string(buf[:n])
	if out == "" {
		t.Error("expected output from runMerge")
	}
	_ = dst
}

func TestRunMergeMissingArgs(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected os.Exit on missing args")
		}
	}()
	// Patch os.Exit to panic so we can catch it in tests
	origExit := osExit
	osExit = func(code int) { panic("exit") }
	defer func() { osExit = origExit }()
	runMerge([]string{})
}

func TestRunMergeTheirs(t *testing.T) {
	src, dst, pub, priv := setupMergeTest(t)
	_, err := vault.MergeVault(src, dst, pub, priv, vault.MergeStrategyTheirs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pubK, _ := vault.LoadPublicKey(pub)
	privK, _ := vault.LoadPrivateKey(priv)
	v := vault.New(pubK, privK)
	entries, _ := v.Decrypt(dst)
	m := env.ToMap(entries)
	if m["CONFLICT"] != "src" {
		t.Errorf("expected CONFLICT=src (theirs), got %s", m["CONFLICT"])
	}
}
