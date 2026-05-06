package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/vault"
)

func runDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	privKeyPath := fs.String("key", "", "path to private key (default: from DefaultKeyPaths)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 2 {
		return fmt.Errorf("usage: envcrypt diff [--key <path>] <vault-a> <vault-b>")
	}

	vaultA := fs.Arg(0)
	vaultB := fs.Arg(1)

	if *privKeyPath == "" {
		_, priv := vault.DefaultKeyPaths()
		*privKeyPath = priv
	}

	result, err := vault.DiffVaults(vaultA, vaultB, *privKeyPath)
	if err != nil {
		return fmt.Errorf("diff: %w", err)
	}

	vault.FormatDiff(os.Stdout, result)

	if result.HasChanges() {
		os.Exit(1)
	}
	return nil
}
