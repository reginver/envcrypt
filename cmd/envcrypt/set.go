package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func runSet(args []string) {
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	vaultFile := fs.String("vault", ".env.age", "Path to the encrypted vault file")
	pubKey := fs.String("pub", "", "Path to public key (default: ~/.envcrypt/key.pub)")
	privKey := fs.String("priv", "", "Path to private key (default: ~/.envcrypt/key)")
	deleteFlag := fs.Bool("delete", false, "Delete the specified key from the vault")
	_ = fs.Parse(args)

	paths := vault.DefaultKeyPaths()
	if *pubKey == "" {
		*pubKey = paths[0]
	}
	if *privKey == "" {
		*privKey = paths[1]
	}

	if *deleteFlag {
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "usage: envcrypt set --delete KEY")
			os.Exit(1)
		}
		key := fs.Arg(0)
		if err := vault.DeleteKey(*vaultFile, *pubKey, *privKey, key); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Deleted key %q from vault.\n", key)
		return
	}

	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "usage: envcrypt set KEY VALUE")
		os.Exit(1)
	}

	key := fs.Arg(0)
	value := fs.Arg(1)

	if err := vault.SetKey(*vaultFile, *pubKey, *privKey, key, value); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Set %q in vault.\n", key)
}
