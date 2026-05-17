package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func setupRenameTest(t *testing.T) (dir string, pubKey string, privKey string, vaultPath string) {
	t.Helper()
	dir = t.TempDir()
	pubKey = filepath.Join(dir, "age.pub")
	privKey = filepath.Join(dir, "age.key")
	vaultPath = filepath.Join(dir, ".env.age")

	require.NoError(t, runInit(pubKey, privKey, false))

	src := filepath.Join(dir, ".env")
	require.NoError(t, os.WriteFile(src, []byte("OLD_KEY=hello\nOTHER=world\n"), 0600))
	require.NoError(t, runEncrypt(src, vaultPath, pubKey))
	return
}

func TestRunRenameSuccess(t *testing.T) {
	dir, pubKey, privKey, vaultPath := setupRenameTest(t)
	_ = dir

	err := runRename(vaultPath, "OLD_KEY", "NEW_KEY", pubKey, privKey)
	require.NoError(t, err)

	out := filepath.Join(dir, "out.env")
	require.NoError(t, runDecrypt(vaultPath, out, privKey))

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	content := string(data)
	require.Contains(t, content, "NEW_KEY=")
	require.NotContains(t, content, "OLD_KEY=")
	require.Contains(t, content, "OTHER=")
}

func TestRunRenameMissingArgs(t *testing.T) {
	err := runRename("", "OLD", "NEW", "", "")
	require.Error(t, err)
}

func TestRunRenameKeyNotFound(t *testing.T) {
	_, pubKey, privKey, vaultPath := setupRenameTest(t)

	err := runRename(vaultPath, "NONEXISTENT", "NEW_KEY", pubKey, privKey)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func TestRunRenameAlreadyExists(t *testing.T) {
	_, pubKey, privKey, vaultPath := setupRenameTest(t)

	err := runRename(vaultPath, "OLD_KEY", "OTHER", pubKey, privKey)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}
