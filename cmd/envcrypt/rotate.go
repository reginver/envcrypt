package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/user/envcrypt/internal/vault"
)

// runRotate handles the `envcrypt rotate` sub-command.
// It decrypts the existing vault with the current private key, generates a
// fresh key pair, and re-encrypts the vault with the new public key.
func runRotate(args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)

	paths := vault.DefaultKeyPaths()

	vaultFile := fs.String("vault", ".env.age", "path to the encrypted vault file")
	pubKey := fs.String("pub", paths.PublicKey, "path to write the new public key")
	privKey := fs.String("priv", paths.PrivateKey, "path to write the new private key")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if _, err := os.Stat(*vaultFile); os.IsNotExist(err) {
		return fmt.Errorf("vault file %q not found; run 'envcrypt encrypt' first", *vaultFile)
	}

	if err := vault.RotateKeys(*vaultFile, "", *pubKey, *privKey); err != nil {
		return fmt.Errorf("key rotation failed: %w", err)
	}

	fmt.Printf("Key rotation complete.\n")
	fmt.Printf("  New public key : %s\n", *pubKey)
	fmt.Printf("  New private key: %s\n", *privKey)
	fmt.Printf("  Vault re-encrypted: %s\n", *vaultFile)
	return nil
}
