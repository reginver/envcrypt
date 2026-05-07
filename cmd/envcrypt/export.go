package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/yourusername/envcrypt/internal/vault"
)

// runExport handles the `export` subcommand, decrypting the vault and printing
// its contents in the requested format (raw, export, or json).
//
// Formats:
//   - raw:    KEY=VALUE pairs, one per line (suitable for sourcing without `export`)
//   - export: export KEY=VALUE pairs, one per line (suitable for `eval $(envcrypt export)`)
//   - json:   JSON object mapping keys to values
func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)

	vaultFile := fs.String("vault", ".env.age", "Path to the encrypted vault file")
	privKeyFile := fs.String("key", "", "Path to the age private key (default: ~/.config/envcrypt/key.age)")
	format := fs.String("format", "raw", "Output format: raw, export, or json")
	keys := fs.String("keys", "", "Comma-separated list of keys to include (empty = all)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Resolve private key path
	privPath := *privKeyFile
	if privPath == "" {
		_, privPath = vault.DefaultKeyPaths()
	}

	// Parse optional key filter
	filterKeys := parseKeyFilter(*keys)

	// Validate format
	switch *format {
	case "raw", "export", "json":
		// valid
	default:
		return fmt.Errorf("unknown format %q: must be raw, export, or json", *format)
	}

	opts := vault.ExportOptions{
		VaultFile:   *vaultFile,
		PrivKeyFile: privPath,
		Format:      *format,
		FilterKeys:  filterKeys,
	}

	output, err := vault.ExportVault(opts)
	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	fmt.Fprint(os.Stdout, output)
	return nil
}

// parseKeyFilter splits a comma-separated list of key names into a slice,
// trimming whitespace and ignoring empty entries. Returns nil if s is empty.
func parseKeyFilter(s string) []string {
	if s == "" {
		return nil
	}
	var keys []string
	for _, k := range strings.Split(s, ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			keys = append(keys, k)
		}
	}
	return keys
}
