package vault_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/user/envcrypt/internal/vault"
)

func TestViewVault(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "pub.age")
	privPath := filepath.Join(dir, "priv.age")

	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	plaintext := "DB_HOST=localhost\nDB_PASS=secret\nAPP_ENV=production\n"
	vaultPath := filepath.Join(dir, ".env.age")

	pubKey, err := vault.LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	privKey, err := vault.LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}

	v := vault.New(pubKey, privKey)
	cipher, err := v.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := os.WriteFile(vaultPath, cipher, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Capture stdout via pipe.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = vault.ViewVault(vaultPath, privPath, vault.ViewOptions{})
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("ViewVault: %v", err)
	}

	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, e := r.Read(tmp)
		buf.Write(tmp[:n])
		if e != nil {
			break
		}
	}
	out := buf.String()

	for _, key := range []string{"DB_HOST", "DB_PASS", "APP_ENV"} {
		if !strings.Contains(out, key) {
			t.Errorf("expected key %q in output", key)
		}
	}
	if !strings.Contains(out, "localhost") {
		t.Error("expected value 'localhost' in output")
	}
}

func TestViewVaultMaskAll(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "pub.age")
	privPath := filepath.Join(dir, "priv.age")

	if err := vault.InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	plaintext := "SECRET=topsecret\n"
	vaultPath := filepath.Join(dir, ".env.age")

	pubKey, _ := vault.LoadPublicKey(pubPath)
	privKey, _ := vault.LoadPrivateKey(privPath)
	v := vault.New(pubKey, privKey)
	cipher, _ := v.Encrypt([]byte(plaintext))
	os.WriteFile(vaultPath, cipher, 0600)

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := vault.ViewVault(vaultPath, privPath, vault.ViewOptions{MaskAll: true})
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("ViewVault: %v", err)
	}

	tmp := make([]byte, 4096)
	n, _ := r.Read(tmp)
	out := string(tmp[:n])

	if strings.Contains(out, "topsecret") {
		t.Error("expected value to be masked")
	}
	if !strings.Contains(out, "***") {
		t.Error("expected *** mask in output")
	}
}

func TestViewVaultMissingFile(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.age")
	vaultPath := filepath.Join(dir, "missing.age")

	err := vault.ViewVault(vaultPath, privPath, vault.ViewOptions{})
	if err == nil {
		t.Fatal("expected error for missing vault")
	}
}
