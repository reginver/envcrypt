package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/vault"
)

func runSearch(args []string) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	vaultFile := fs.String("vault", ".env.age", "path to encrypted vault file")
	privKeyFile := fs.String("key", "", "path to private key (default: ~/.config/envcrypt/key)")
	keysOnly := fs.Bool("keys", false, "search keys only")
	valuesOnly := fs.Bool("values", false, "search values only")
	caseSensitive := fs.Bool("case", false, "case-sensitive search")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: envcrypt search [flags] <query>")
	}
	query := fs.Arg(0)

	paths := vault.DefaultKeyPaths()
	if *privKeyFile == "" {
		*privKeyFile = paths.PrivateKey
	}

	opts := vault.SearchOptions{
		CaseSensitive: *caseSensitive,
		KeysOnly:      *keysOnly,
		ValuesOnly:    *valuesOnly,
	}

	results, err := vault.SearchVault(*vaultFile, *privKeyFile, query, opts)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "no matches found")
		return nil
	}

	for _, r := range results {
		fmt.Printf("%s=%s\n", r.Key, r.Value)
	}
	return nil
}
