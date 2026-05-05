package main

import (
	"fmt"
	"os"

	"github.com/user/envcrypt/internal/vault"
)

// resolveEditor returns the editor to use, preferring the EDITOR env var,
// then the provided flag value, and finally falling back to "vi".
func resolveEditor(flagEditor string) string {
	if e := os.Getenv("EDITOR"); e != "" {
		return e
	}
	if flagEditor != "" {
		return flagEditor
	}
	return "vi"
}

func runEdit(vaultPath, editor string) error {
	if vaultPath == "" {
		vaultPath = ".env.age"
	}

	editorCmd := resolveEditor(editor)

	fmt.Printf("Opening %s in %s...\n", vaultPath, editorCmd)

	if err := vault.EditVault(vaultPath, editorCmd); err != nil {
		return fmt.Errorf("edit vault: %w", err)
	}

	fmt.Println("Vault updated successfully.")
	return nil
}
