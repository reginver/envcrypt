package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/vault"
)

// runValidate decrypts a vault file and runs configurable validation rules
// against its entries, reporting any issues found.
func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)

	var (
		vaultPath   string
		privKeyPath string
		strict      bool
		jsonOut     bool
		noEmpty     bool
		noLowercase bool
		noPlaceholder bool
		noDuplicate bool
	)

	fs.StringVar(&vaultPath, "vault", ".env.age", "Path to the encrypted vault file")
	fs.StringVar(&privKeyPath, "key", "", "Path to the age private key (default: ~/.config/envcrypt/key.txt)")
	fs.BoolVar(&strict, "strict", false, "Exit with non-zero status if any issues are found")
	fs.BoolVar(&jsonOut, "json", false, "Output results as JSON")
	fs.BoolVar(&noEmpty, "no-empty", false, "Flag entries with empty values")
	fs.BoolVar(&noLowercase, "no-lowercase", false, "Flag keys that are not uppercase")
	fs.BoolVar(&noPlaceholder, "no-placeholder", false, "Flag entries with placeholder values (e.g. CHANGEME, TODO)")
	fs.BoolVar(&noDuplicate, "no-duplicate", false, "Flag duplicate keys")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Resolve private key path
	if privKeyPath == "" {
		_, privKeyPath = vault.DefaultKeyPaths()
	}

	// Build rule set from flags; if no specific rules are requested, use defaults
	rules := buildValidationRules(noEmpty, noLowercase, noPlaceholder, noDuplicate)

	results, err := vault.ValidateVault(vaultPath, privKeyPath, rules)
	if err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	output := vault.FormatValidation(results, jsonOut)
	fmt.Print(output)

	if strict && len(results) > 0 {
		os.Exit(1)
	}

	return nil
}

// buildValidationRules constructs a slice of rule names based on CLI flags.
// When no specific flags are set, an empty slice is returned so ValidateVault
// falls back to its built-in default rule set.
func buildValidationRules(noEmpty, noLowercase, noPlaceholder, noDuplicate bool) []string {
	if !noEmpty && !noLowercase && !noPlaceholder && !noDuplicate {
		// Use default rules defined in the vault package
		return nil
	}

	var rules []string
	if noEmpty {
		rules = append(rules, "empty_value")
	}
	if noLowercase {
		rules = append(rules, "lowercase_key")
	}
	if noPlaceholder {
		rules = append(rules, "placeholder_value")
	}
	if noDuplicate {
		rules = append(rules, "duplicate_key")
	}
	return rules
}
