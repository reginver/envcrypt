package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/yourusername/envcrypt/internal/vault"
)

func runPromote(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: envcrypt promote <src-vault> <dst-vault> [--keys=K1,K2] [--overwrite] [--dry-run]")
		os.Exit(1)
	}

	srcPath := args[0]
	dstPath := args[1]
	rest := args[2:]

	paths := vault.DefaultKeyPaths()
	pubKey := paths.PublicKey
	privKey := paths.PrivateKey

	opts := vault.PromoteOptions{}

	for _, arg := range rest {
		switch {
		case strings.HasPrefix(arg, "--keys="):
			opts.Keys = splitCSV(strings.TrimPrefix(arg, "--keys="))
		case arg == "--overwrite":
			opts.Overwrite = true
		case arg == "--dry-run":
			opts.DryRun = true
		case strings.HasPrefix(arg, "--pub="):
			pubKey = strings.TrimPrefix(arg, "--pub=")
		case strings.HasPrefix(arg, "--priv="):
			privKey = strings.TrimPrefix(arg, "--priv=")
		}
	}

	res, err := vault.PromoteVault(srcPath, dstPath, privKey, pubKey, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "promote: %v\n", err)
		os.Exit(1)
	}

	if opts.DryRun {
		fmt.Println("[dry-run] no changes written")
	}

	for _, k := range res.Promoted {
		action := "promoted"
		if opts.DryRun {
			action = "would promote"
		}
		fmt.Printf("  %s: %s\n", action, k)
	}
	for _, k := range res.Skipped {
		fmt.Printf("  skipped (exists): %s\n", k)
	}

	if !opts.DryRun {
		fmt.Printf("promoted %d key(s) to %s\n", len(res.Promoted), dstPath)
	}
}
