package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func setupPromoteVaults(t *testing.T) (srcPath, dstPath, pubKey, privKey string) {
	t.Helper()
	dir := t.TempDir()

	pubKey = filepath.Join(dir, "age.pub")
	privKey = filepath.Join(dir, "age.key")
	if err := vault.InitKeys(pubKey, privKey, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	srcPath = filepath.Join(dir, "src.env.age")
	dstPath = filepath.Join(dir, "dst.env.age")

	v, err := vault.New(pubKey, privKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := v.Encrypt(filepath.Join(dir, "src.env"), srcPath); err != nil {
		// Write a plain .env first
		_ = os.WriteFile(filepath.Join(dir, "src.env"), []byte("FOO=bar\nBAZ=qux\nSECRET=s3cr3t\n"), 0600)
		if err2 := v.Encrypt(filepath.Join(dir, "src.env"), srcPath); err2 != nil {
			t.Fatalf("Encrypt src: %v", err2)
		}
	}
	return
}

func TestPromoteVaultAllKeys(t *testing.T) {
	src, dst, pub, priv := setupPromoteVaults(t)

	res, err := vault.PromoteVault(src, dst, priv, pub, vault.PromoteOptions{})
	if err != nil {
		t.Fatalf("PromoteVault: %v", err)
	}
	if len(res.Promoted) == 0 {
		t.Error("expected promoted keys, got none")
	}
	if _, err := os.Stat(dst); err != nil {
		t.Errorf("destination vault not created: %v", err)
	}
}

func TestPromoteVaultSelectiveKeys(t *testing.T) {
	src, dst, pub, priv := setupPromoteVaults(t)

	res, err := vault.PromoteVault(src, dst, priv, pub, vault.PromoteOptions{Keys: []string{"FOO"}})
	if err != nil {
		t.Fatalf("PromoteVault: %v", err)
	}
	if len(res.Promoted) != 1 || res.Promoted[0] != "FOO" {
		t.Errorf("expected [FOO] promoted, got %v", res.Promoted)
	}
}

func TestPromoteVaultNoOverwrite(t *testing.T) {
	src, dst, pub, priv := setupPromoteVaults(t)

	// First promote populates dst.
	if _, err := vault.PromoteVault(src, dst, priv, pub, vault.PromoteOptions{}); err != nil {
		t.Fatalf("first promote: %v", err)
	}
	// Second promote without overwrite should skip all.
	res, err := vault.PromoteVault(src, dst, priv, pub, vault.PromoteOptions{Overwrite: false})
	if err != nil {
		t.Fatalf("second promote: %v", err)
	}
	if len(res.Promoted) != 0 {
		t.Errorf("expected no promotions, got %v", res.Promoted)
	}
}

func TestPromoteVaultDryRun(t *testing.T) {
	src, dst, pub, priv := setupPromoteVaults(t)

	res, err := vault.PromoteVault(src, dst, priv, pub, vault.PromoteOptions{DryRun: true})
	if err != nil {
		t.Fatalf("PromoteVault dry-run: %v", err)
	}
	if len(res.Promoted) == 0 {
		t.Error("dry-run should report promoted keys")
	}
	if _, err := os.Stat(dst); err == nil {
		t.Error("dry-run must not create destination vault")
	}
}

func TestPromoteVaultMissingSource(t *testing.T) {
	dir := t.TempDir()
	_, err := vault.PromoteVault(
		filepath.Join(dir, "missing.age"),
		filepath.Join(dir, "dst.age"),
		filepath.Join(dir, "age.key"),
		filepath.Join(dir, "age.pub"),
		vault.PromoteOptions{},
	)
	if err == nil {
		t.Error("expected error for missing source vault")
	}
}
