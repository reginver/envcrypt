package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func setupCompareVaults(t *testing.T) (dir, pubKey, privKey string) {
	t.Helper()
	dir = t.TempDir()
	pubKey = filepath.Join(dir, "key.pub")
	privKey = filepath.Join(dir, "key")
	if err := vault.InitKeys(pubKey, privKey, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	return
}

func writeCompareVault(t *testing.T, path, pubKey string, entries map[string]string) {
	t.Helper()
	env := ""
	for k, v := range entries {
		env += k + "=" + v + "\n"
	}
	src := path + ".plain"
	if err := os.WriteFile(src, []byte(env), 0600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	if err := vault.New(src, path, pubKey, vault.NoopAuditHook); err != nil {
		t.Fatalf("encrypt vault: %v", err)
	}
}

func TestCompareVaultsIdentical(t *testing.T) {
	dir, pub, priv := setupCompareVaults(t)
	a := filepath.Join(dir, "a.env.age")
	b := filepath.Join(dir, "b.env.age")
	entries := map[string]string{"FOO": "bar", "BAZ": "qux"}
	writeCompareVault(t, a, pub, entries)
	writeCompareVault(t, b, pub, entries)

	res, err := vault.CompareVaults(a, b, priv)
	if err != nil {
		t.Fatalf("CompareVaults: %v", err)
	}
	if len(res.Identical) != 2 {
		t.Errorf("expected 2 identical, got %d", len(res.Identical))
	}
	if len(res.Different) != 0 || len(res.OnlyInA) != 0 || len(res.OnlyInB) != 0 {
		t.Errorf("unexpected differences: %+v", res)
	}
}

func TestCompareVaultsDifferentValues(t *testing.T) {
	dir, pub, priv := setupCompareVaults(t)
	a := filepath.Join(dir, "a.env.age")
	b := filepath.Join(dir, "b.env.age")
	writeCompareVault(t, a, pub, map[string]string{"FOO": "bar"})
	writeCompareVault(t, b, pub, map[string]string{"FOO": "changed"})

	res, err := vault.CompareVaults(a, b, priv)
	if err != nil {
		t.Fatalf("CompareVaults: %v", err)
	}
	if len(res.Different) != 1 || res.Different[0] != "FOO" {
		t.Errorf("expected FOO in Different, got %v", res.Different)
	}
}

func TestCompareVaultsUniqueKeys(t *testing.T) {
	dir, pub, priv := setupCompareVaults(t)
	a := filepath.Join(dir, "a.env.age")
	b := filepath.Join(dir, "b.env.age")
	writeCompareVault(t, a, pub, map[string]string{"ONLY_A": "1", "SHARED": "x"})
	writeCompareVault(t, b, pub, map[string]string{"ONLY_B": "2", "SHARED": "x"})

	res, err := vault.CompareVaults(a, b, priv)
	if err != nil {
		t.Fatalf("CompareVaults: %v", err)
	}
	if len(res.OnlyInA) != 1 || res.OnlyInA[0] != "ONLY_A" {
		t.Errorf("expected ONLY_A in OnlyInA, got %v", res.OnlyInA)
	}
	if len(res.OnlyInB) != 1 || res.OnlyInB[0] != "ONLY_B" {
		t.Errorf("expected ONLY_B in OnlyInB, got %v", res.OnlyInB)
	}
	if len(res.Identical) != 1 || res.Identical[0] != "SHARED" {
		t.Errorf("expected SHARED identical, got %v", res.Identical)
	}
}

func TestCompareVaultsMissingFile(t *testing.T) {
	dir, _, priv := setupCompareVaults(t)
	a := filepath.Join(dir, "missing.env.age")
	b := filepath.Join(dir, "also_missing.env.age")
	_, err := vault.CompareVaults(a, b, priv)
	if err == nil {
		t.Error("expected error for missing vault files")
	}
}
