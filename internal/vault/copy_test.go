package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func setupCopyVaults(t *testing.T) (srcVault, dstVault, pub, priv string) {
	t.Helper()
	dir := t.TempDir()

	pub = filepath.Join(dir, "age.pub")
	priv = filepath.Join(dir, "age.key")
	if err := vault.InitKeys(pub, priv, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	srcVault = filepath.Join(dir, "src.env.age")
	dstVault = filepath.Join(dir, "dst.env.age")
	return
}

func TestCopyVaultCreatesDestination(t *testing.T) {
	srcVault, dstVault, pub, priv := setupCopyVaults(t)

	// Write a source vault with two keys.
	writeTestVault(t, srcVault, pub, "KEY_A=alpha\nKEY_B=beta\n")

	opts := vault.CopyOptions{Overwrite: true}
	if err := vault.CopyVault(srcVault, dstVault, priv, pub, opts); err != nil {
		t.Fatalf("CopyVault: %v", err)
	}

	if _, err := os.Stat(dstVault); err != nil {
		t.Fatalf("destination vault not created: %v", err)
	}

	entries := readTestVault(t, dstVault, priv)
	assertEntry(t, entries, "KEY_A", "alpha")
	assertEntry(t, entries, "KEY_B", "beta")
}

func TestCopyVaultFilterKeys(t *testing.T) {
	srcVault, dstVault, pub, priv := setupCopyVaults(t)
	writeTestVault(t, srcVault, pub, "KEY_A=alpha\nKEY_B=beta\nKEY_C=gamma\n")

	opts := vault.CopyOptions{Keys: []string{"KEY_A", "KEY_C"}, Overwrite: true}
	if err := vault.CopyVault(srcVault, dstVault, priv, pub, opts); err != nil {
		t.Fatalf("CopyVault: %v", err)
	}

	entries := readTestVault(t, dstVault, priv)
	assertEntry(t, entries, "KEY_A", "alpha")
	assertEntry(t, entries, "KEY_C", "gamma")
	for _, e := range entries {
		if e.Key == "KEY_B" {
			t.Error("KEY_B should have been filtered out")
		}
	}
}

func TestCopyVaultNoOverwrite(t *testing.T) {
	srcVault, dstVault, pub, priv := setupCopyVaults(t)
	writeTestVault(t, srcVault, pub, "KEY_A=from_src\n")
	writeTestVault(t, dstVault, pub, "KEY_A=from_dst\n")

	opts := vault.CopyOptions{Overwrite: false}
	if err := vault.CopyVault(srcVault, dstVault, priv, pub, opts); err != nil {
		t.Fatalf("CopyVault: %v", err)
	}

	entries := readTestVault(t, dstVault, priv)
	assertEntry(t, entries, "KEY_A", "from_dst")
}

func TestCopyVaultMissingSource(t *testing.T) {
	_, dstVault, pub, priv := setupCopyVaults(t)
	opts := vault.CopyOptions{}
	err := vault.CopyVault("/nonexistent/src.env.age", dstVault, priv, pub, opts)
	if err == nil {
		t.Fatal("expected error for missing source vault")
	}
}
