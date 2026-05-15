package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func runCompare(args []string) {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	privKey := fs.String("priv", vault.DefaultKeyPaths().Private, "path to private key")
	fs.Parse(args)

	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "usage: envcrypt compare <vault-a> <vault-b>")
		os.Exit(1)
	}

	vaultA := fs.Arg(0)
	vaultB := fs.Arg(1)

	res, err := vault.CompareVaults(vaultA, vaultB, *privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(res.OnlyInA) == 0 && len(res.OnlyInB) == 0 && len(res.Different) == 0 {
		fmt.Println("Vaults are identical.")
		return
	}

	if len(res.OnlyInA) > 0 {
		fmt.Printf("Only in %s:\n", vaultA)
		for _, k := range res.OnlyInA {
			fmt.Printf("  - %s\n", k)
		}
	}

	if len(res.OnlyInB) > 0 {
		fmt.Printf("Only in %s:\n", vaultB)
		for _, k := range res.OnlyInB {
			fmt.Printf("  + %s\n", k)
		}
	}

	if len(res.Different) > 0 {
		fmt.Println("Different values:")
		for _, k := range res.Different {
			fmt.Printf("  ~ %s\n", k)
		}
	}

	if len(res.Identical) > 0 {
		fmt.Printf("Identical keys: %d\n", len(res.Identical))
	}
}
