package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nicholasgasior/envcrypt/internal/vault"
)

func runRename(args []string) {
	fs := flag.NewFlagSet("rename", flag.ExitOnError)
	vaultFile := fs.String("vault", ".env.age", "Path to the encrypted vault file")
	pubKey := fs.String("pub", "", "Path to public key (default: from DefaultKeyPaths)")
	privKey := fs.String("priv", "", "Path to private key (default: from DefaultKeyPaths)")

	_ = fs.Parse(args)

	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "usage: envcrypt rename [flags] <OLD_KEY> <NEW_KEY>")
		fs.Usage()
		os.Exit(1)
	}

	oldKey := fs.Arg(0)
	newKey := fs.Arg(1)

	paths := vault.DefaultKeyPaths()
	if *pubKey == "" {
		*pubKey = paths.PublicKey
	}
	if *privKey == "" {
		*privKey = paths.PrivateKey
	}

	if err := vault.RenameKey(*vaultFile, *privKey, *pubKey, oldKey, newKey); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Renamed key %q → %q in %s\n", oldKey, newKey, *vaultFile)
}
