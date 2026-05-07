package main

import (
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/vault"
)

// runLint decrypts the vault and checks for common issues such as empty values,
// lowercase keys, and placeholder values. It prints a summary of findings and
// exits with a non-zero status code if any issues are found.
func runLint(args []string) {
	fs := newFlagSet("lint")

	var (
		vaultFile  string
		privKeyFile string
		strict     bool
	)

	fs.StringVar(&vaultFile, "vault", ".env.age", "Path to the encrypted vault file")
	fs.StringVar(&privKeyFile, "key", "", "Path to the age private key (default: ~/.config/envcrypt/key.age)")
	fs.BoolVar(&strict, "strict", false, "Exit with non-zero status if any issues are found")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if privKeyFile == "" {
		paths := vault.DefaultKeyPaths()
		privKeyFile = paths.PrivateKey
	}

	identity, err := vault.LoadPrivateKey(privKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading private key: %v\n", err)
		os.Exit(1)
	}

	issues, err := vault.LintVault(vaultFile, identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error linting vault: %v\n", err)
		os.Exit(1)
	}

	if len(issues) == 0 {
		fmt.Println("✓ No issues found.")
		return
	}

	fmt.Printf("Found %d issue(s) in %s:\n\n", len(issues), vaultFile)
	for _, issue := range issues {
		fmt.Printf("  [%s] %s: %s\n", issue.Severity, issue.Key, issue.Message)
	}

	if strict {
		os.Exit(1)
	}
}
