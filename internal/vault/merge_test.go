package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yourusername/envcrypt/internal/env"
	"github.com/yourusername/envcrypt/internal/vault"
)

func setupMergeVaults(t *testing.T) (srcPath, dstPath, pubPath, privPath string) {
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
	srcEntries := []env.Entry{{Key: "SHARED", Value: "src_val"}, {Key: "SRC_ONLY", Value: "hello"}}
	if err := v.Encrypt(srcPath, srcEntries); err != nil {
		t.Fatalf("encrypt src: %v", err)
	}

	dstPath = filepath.Join(dir, "dst.env.age")
	dstEntries := []env.Entry{{Key: "SHARED", Value: "dst_val"}, {Key: "DST_ONLY", Value: "world"}}
	if err := v.Encrypt(dstPath, dstEntries); err != nil {
		t.Fatalf("encrypt dst: %v", err)
	}
	return
}

func TestMergeVaultOurs(t *testing.T) {
	src, dst, pub, priv := setupMergeVaults(t)
	n, err := vault.MergeVault(src, dst, pub, priv, vault.MergeStrategyOurs)
	if err != nil {
		t.Fatalf("MergeVault: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 added, got %d", n)
	}
	priv2, _ := vault.LoadPrivateKey(priv)
	pub2, _ := vault.LoadPublicKey(pub)
	v := vault.New(pub2, priv2)
	entries, _ := v.Decrypt(dst)
	m := env.ToMap(entries)
	if m["SHARED"] != "dst_val" {
		t.Errorf("expected SHARED=dst_val, got %s", m["SHARED"])
	}
	if m["SRC_ONLY"] != "hello" {
		t.Errorf("expected SRC_ONLY=hello, got %s", m["SRC_ONLY"])
	}
}

func TestMergeVaultTheirs(t *testing.T) {
	src, dst, pub, priv := setupMergeVaults(t)
	_, err := vault.MergeVault(src, dst, pub, priv, vault.MergeStrategyTheirs)
	if err != nil {
		t.Fatalf("MergeVault: %v", err)
	}
	priv2, _ := vault.LoadPrivateKey(priv)
	pub2, _ := vault.LoadPublicKey(pub)
	v := vault.New(pub2, priv2)
	entries, _ := v.Decrypt(dst)
	m := env.ToMap(entries)
	if m["SHARED"] != "src_val" {
		t.Errorf("expected SHARED=src_val, got %s", m["SHARED"])
	}
}

func TestMergeVaultMissingSource(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "age.pub")
	privPath := filepath.Join(dir, "age.key")
	vault.InitKeys(pubPath, privPath, false)
	_, err := vault.MergeVault(
		filepath.Join(dir, "missing.env.age"),
		filepath.Join(dir, "dst.env.age"),
		pubPath, privPath, vault.MergeStrategyOurs,
	)
	if err == nil {
		t.Error("expected error for missing source")
	}
	_ = os.Getenv("CI") // suppress unused import warning
}
