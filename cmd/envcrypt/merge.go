package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/vault"
)

func runMerge(args []string) {
	fs := flag.NewFlagSet("merge", flag.ExitOnError)
	theirs := fs.Bool("theirs", false, "overwrite destination values with source values on conflict")
	pubKey := fs.String("pub", "", "path to public key (default: ~/.envcrypt/age.pub)")
	privKey := fs.String("priv", "", "path to private key (default: ~/.envcrypt/age.key)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: envcrypt merge [flags] <source> <destination>")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 2 {
		fs.Usage()
		os.Exit(1)
	}

	src := fs.Arg(0)
	dst := fs.Arg(1)

	paths := vault.DefaultKeyPaths()
	if *pubKey == "" {
		*pubKey = paths.PublicKey
	}
	if *privKey == "" {
		*privKey = paths.PrivateKey
	}

	strategy := vault.MergeStrategyOurs
	if *theirs {
		strategy = vault.MergeStrategyTheirs
	}

	n, err := vault.MergeVault(src, dst, *pubKey, *privKey, strategy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	strategyName := "ours"
	if *theirs {
		strategyName = "theirs"
	}
	fmt.Printf("merged %d key(s) from %s into %s [strategy: %s]\n", n, src, dst, strategyName)
}
