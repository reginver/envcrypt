package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/vault"
)

func runImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)

	var (
		srcFile    string
		vaultFile  string
		pubKeyFile string
		keys       string
		overwrite  bool
	)

	fs.StringVar(&srcFile, "src", ".env", "Source .env file to import from")
	fs.StringVar(&vaultFile, "vault", ".env.age", "Destination vault file")
	fs.StringVar(&pubKeyFile, "pubkey", "", "Path to public key (default: auto-detect)")
	fs.StringVar(&keys, "keys", "", "Comma-separated list of keys to import (empty = all)")
	fs.BoolVar(&overwrite, "overwrite", false, "Overwrite existing keys in vault")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if pubKeyFile == "" {
		paths := vault.DefaultKeyPaths()
		pubKeyFile = paths.PublicKey
	}

	pubKey, err := vault.LoadPublicKey(pubKeyFile)
	if err != nil {
		return fmt.Errorf("loading public key: %w", err)
	}

	privKeyFile := ""
	var filterKeys []string
	if keys != "" {
		filterKeys = splitCSV(keys)
	}

	opts := vault.ImportOptions{
		SourceFile:     srcFile,
		VaultFile:      vaultFile,
		PublicKey:      pubKey,
		PrivateKeyFile: privKeyFile,
		FilterKeys:     filterKeys,
		Overwrite:      overwrite,
	}

	if err := vault.ImportVault(opts); err != nil {
		return fmt.Errorf("import failed: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Imported %s → %s\n", srcFile, vaultFile)
	return nil
}

func splitCSV(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			if tok := s[start:i]; tok != "" {
				result = append(result, tok)
			}
			start = i + 1
		}
	}
	if tok := s[start:]; tok != "" {
		result = append(result, tok)
	}
	return result
}
