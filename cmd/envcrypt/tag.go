package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/yourusername/envcrypt/internal/vault"
)

func runTag(args []string) error {
	fs := flag.NewFlagSet("tag", flag.ContinueOnError)
	vaultFile := fs.String("vault", ".env.age", "path to vault file")
	pubKey := fs.String("pub", "", "public key path")
	privKey := fs.String("priv", "", "private key path")
	untag := fs.Bool("remove", false, "remove tags instead of adding")
	list := fs.Bool("list", false, "list all tags")
	filterTag := fs.String("filter", "", "list keys with this tag")

	if err := fs.Parse(args); err != nil {
		return err
	}

	pub, priv := resolvePubPrivKeys(*pubKey, *privKey)

	if *list {
		entries, err := vault.ListTags(*vaultFile)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			fmt.Println("(no tags)")
			return nil
		}
		for _, e := range entries {
			fmt.Printf("%-30s %s\n", e.Key, strings.Join(e.Tags, ", "))
		}
		return nil
	}

	if *filterTag != "" {
		keys, err := vault.FilterByTag(*vaultFile, *filterTag)
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			fmt.Printf("(no keys tagged %q)\n", *filterTag)
			return nil
		}
		for _, k := range keys {
			fmt.Println(k)
		}
		return nil
	}

	remaining := fs.Args()
	if len(remaining) < 2 {
		return fmt.Errorf("usage: envcrypt tag [flags] <KEY> <tag1,tag2,...>")
	}
	key := remaining[0]
	tags := splitCSV(remaining[1])

	if *untag {
		return vault.UntagVault(*vaultFile, priv, key, tags)
	}
	return vault.TagVault(*vaultFile, priv, pub, key, tags)
}

func resolvePubPrivKeys(pub, priv string) (string, string) {
	paths := vault.DefaultKeyPaths()
	if pub == "" {
		pub = paths.PublicKey
	}
	if priv == "" {
		priv = paths.PrivateKey
	}
	return pub, priv
}

func init() {
	_ = os.Stderr // ensure os imported
}
