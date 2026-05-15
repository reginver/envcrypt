package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yourusername/envcrypt/internal/vault"
)

func setupInjectTest(t *testing.T) (dir string, pubPath string, privPath string) {
	t.Helper()
	dir = t.TempDir()
	pubPath = filepath.Join(dir, "key.pub")
	privPath = filepath.Join(dir, "key")

	err := vault.InitKeys(pubPath, privPath, false)
	require.NoError(t, err)
	return dir, pubPath, privPath
}

func TestRunInjectAll(t *testing.T) {
	dir, pubPath, privPath := setupInjectTest(t)
	vaultPath := filepath.Join(dir, ".env.vault")

	// Create a vault with known entries
	err := vault.EncryptVault(".env", vaultPath, pubPath, vault.NoopAuditHook)
	if err != nil {
		// Write a plaintext .env and encrypt it
		envPath := filepath.Join(dir, ".env")
		err = os.WriteFile(envPath, []byte("INJECT_KEY=hello\nINJECT_OTHER=world\n"), 0600)
		require.NoError(t, err)
		err = vault.EncryptVault(envPath, vaultPath, pubPath, vault.NoopAuditHook)
		require.NoError(t, err)
	}

	// Unset env vars before test
	os.Unsetenv("INJECT_KEY")
	os.Unsetenv("INJECT_OTHER")

	err = runInject([]string{vaultPath, privPath}, nil, false)
	require.NoError(t, err)

	assert.Equal(t, "hello", os.Getenv("INJECT_KEY"))
	assert.Equal(t, "world", os.Getenv("INJECT_OTHER"))
}

func TestRunInjectNoOverwrite(t *testing.T) {
	dir, pubPath, privPath := setupInjectTest(t)
	vaultPath := filepath.Join(dir, ".env.vault")
	envPath := filepath.Join(dir, ".env")

	err := os.WriteFile(envPath, []byte("NOOVERWRITE=original\n"), 0600)
	require.NoError(t, err)
	err = vault.EncryptVault(envPath, vaultPath, pubPath, vault.NoopAuditHook)
	require.NoError(t, err)

	// Pre-set the env var
	os.Setenv("NOOVERWRITE", "existing")
	t.Cleanup(func() { os.Unsetenv("NOOVERWRITE") })

	err = runInject([]string{vaultPath, privPath}, nil, true)
	require.NoError(t, err)

	// Should not have been overwritten
	assert.Equal(t, "existing", os.Getenv("NOOVERWRITE"))
}

func TestRunInjectFilterKeys(t *testing.T) {
	dir, pubPath, privPath := setupInjectTest(t)
	vaultPath := filepath.Join(dir, ".env.vault")
	envPath := filepath.Join(dir, ".env")

	err := os.WriteFile(envPath, []byte("FILTER_A=aaa\nFILTER_B=bbb\n"), 0600)
	require.NoError(t, err)
	err = vault.EncryptVault(envPath, vaultPath, pubPath, vault.NoopAuditHook)
	require.NoError(t, err)

	os.Unsetenv("FILTER_A")
	os.Unsetenv("FILTER_B")
	t.Cleanup(func() {
		os.Unsetenv("FILTER_A")
		os.Unsetenv("FILTER_B")
	})

	err = runInject([]string{vaultPath, privPath}, []string{"FILTER_A"}, false)
	require.NoError(t, err)

	assert.Equal(t, "aaa", os.Getenv("FILTER_A"))
	assert.Empty(t, os.Getenv("FILTER_B"))
}

func TestRunInjectMissingVault(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "key")
	vaultPath := filepath.Join(dir, "nonexistent.vault")

	err := runInject([]string{vaultPath, privPath}, nil, false)
	assert.Error(t, err)
}

func TestRunInjectMissingArgs(t *testing.T) {
	err := runInject([]string{}, nil, false)
	assert.Error(t, err)

	err = runInject([]string{"only-one"}, nil, false)
	assert.Error(t, err)
}
