package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func runTruncate(args []string) {
	var vaultFile string
	var keys []string
	var force bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--vault", "-v":
			i++
			if i < len(args) {
				vaultFile = args[i]
			}
		case "--keys", "-k":
			i++
			if i < len(args) {
				keys = splitCSV(args[i])
			}
		case "--force", "-f":
			force = true
		}
	}

	if vaultFile == "" {
		vaultFile = ".env.age"
	}

	pubPath, privPath := DefaultKeyPaths()

	if !force && len(keys) == 0 {
		fmt.Printf("This will remove ALL keys from %s. Use --force to confirm.\n", vaultFile)
		os.Exit(1)
	}

	count, err := vault.TruncateVault(vaultFile, pubPath, privPath, keys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(keys) > 0 {
		fmt.Printf("Removed %d key(s) from %s: %s\n", count, vaultFile, strings.Join(keys, ", "))
	} else {
		fmt.Printf("Truncated %s — removed %d key(s).\n", vaultFile, count)
	}
}
