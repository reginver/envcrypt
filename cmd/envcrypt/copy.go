package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/vault"
)

func runCopy(args []string) error {
	fs := flag.NewFlagSet("copy", flag.ContinueOnError)

	var (
		privKeyPath string
		pubKeyPath  string
		keys        string
		overwrite   bool
	)

	defaultPaths := vault.DefaultKeyPaths()

	fs.StringVar(&privKeyPath, "identity", defaultPaths.PrivateKey, "Path to age private key")
	fs.StringVar(&pubKeyPath, "recipient", defaultPaths.PublicKey, "Path to age public key")
	fs.StringVar(&keys, "keys", "", "Comma-separated list of keys to copy (default: all)")
	fs.BoolVar(&overwrite, "overwrite", false, "Overwrite destination vault if it exists")

	if err := fs.Parse(args); err != nil {
		return err
	}

	positional := fs.Args()
	if len(positional) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: envcrypt copy [flags] <source> <destination>")
		fs.PrintDefaults()
		return fmt.Errorf("source and destination vault paths are required")
	}

	src := positional[0]
	dst := positional[1]

	var filterKeys []string
	if keys != "" {
		filterKeys = splitCSV(keys)
	}

	opts := vault.CopyOptions{
		PrivateKeyPath: privKeyPath,
		PublicKeyPath:  pubKeyPath,
		FilterKeys:     filterKeys,
		Overwrite:      overwrite,
	}

	if err := vault.CopyVault(src, dst, opts); err != nil {
		return fmt.Errorf("copy failed: %w", err)
	}

	fmt.Printf("Vault copied: %s → %s\n", src, dst)
	return nil
}
