package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

// runInject implements the `envcrypt inject` subcommand.
// It decrypts the vault and exports its variables into the current process,
// then exec-replaces the process with the provided command (if any).
func runInject(args []string) error {
	fs := flag.NewFlagSet("inject", flag.ContinueOnError)
	vaultPath := fs.String("vault", ".env.vault", "path to encrypted vault")
	privKeyPath := fs.String("priv", "", "path to age private key (default: ~/.config/envcrypt/key.age)")
	keys := fs.String("keys", "", "comma-separated list of keys to inject (default: all)")
	overwrite := fs.Bool("overwrite", false, "overwrite existing environment variables")
	printCount := fs.Bool("count", false, "print number of variables injected")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *privKeyPath == "" {
		_, priv := vault.DefaultKeyPaths()
		*privKeyPath = priv
	}

	opts := vault.InjectOptions{
		Overwrite: *overwrite,
	}
	if *keys != "" {
		for _, k := range strings.Split(*keys, ",") {
			if k = strings.TrimSpace(k); k != "" {
				opts.Keys = append(opts.Keys, k)
			}
		}
	}

	n, err := vault.InjectVault(*vaultPath, *privKeyPath, opts)
	if err != nil {
		return fmt.Errorf("inject: %w", err)
	}

	if *printCount {
		fmt.Fprintf(os.Stdout, "injected %d variable(s)\n", n)
	}

	// If extra arguments are supplied, exec the command with the enriched env.
	if rest := fs.Args(); len(rest) > 0 {
		return execCommand(rest[0], rest[1:])
	}
	return nil
}
