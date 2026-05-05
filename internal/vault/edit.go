package vault

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/user/envcrypt/internal/crypto"
	"github.com/user/envcrypt/internal/env"
)

// EditVault decrypts the vault to a temp file, opens it in an editor,
// then re-encrypts the modified contents back to the vault file.
func EditVault(vaultPath, editor string) error {
	pubKey, err := LoadPublicKey("")
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}

	privKey, err := LoadPrivateKey("")
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	v, err := New(pubKey, privKey)
	if err != nil {
		return fmt.Errorf("create vault: %w", err)
	}

	entries, err := v.DecryptFile(vaultPath)
	if err != nil {
		return fmt.Errorf("decrypt vault: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "envcrypt-edit-*.env")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(env.Serialize(entries)); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	tmpFile.Close()

	cmd := exec.Command(editor, tmpPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor exited with error: %w", err)
	}

	updated, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("read edited file: %w", err)
	}

	newEntries, err := env.Parse(string(updated))
	if err != nil {
		return fmt.Errorf("parse edited env: %w", err)
	}

	recipient, err := crypto.ParsePublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	ciphertext, err := crypto.Encrypt([]byte(env.Serialize(newEntries)), recipient)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	if err := os.WriteFile(vaultPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("write vault: %w", err)
	}

	return nil
}
