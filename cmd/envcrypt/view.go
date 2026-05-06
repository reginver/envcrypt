package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/user/envcrypt/internal/vault"
)

func runView(args []string) error {
	fs := flag.NewFlagSet("view", flag.ContinueOnError)

	var (
		vaultPath   = fs.String("vault", ".env.age", "path to encrypted vault file")
		privKeyPath = fs.String("key", "", "path to age private key (default: ~/.config/envcrypt/key.age)")
		keysFlag    = fs.String("keys", "", "comma-separated list of keys to display")
		maskAll     = fs.Bool("mask", false, "mask all values with ***")
		maskKeys    = fs.String("mask-keys", "", "comma-separated list of keys whose values should be masked")
	)

	if err := fs.Parse(args); err != nil {
		return err
	}

	_, privDefault := vault.DefaultKeyPaths()
	if *privKeyPath == "" {
		*privKeyPath = privDefault
	}

	var filterKeys []string
	if *keysFlag != "" {
		for _, k := range strings.Split(*keysFlag, ",") {
			if k = strings.TrimSpace(k); k != "" {
				filterKeys = append(filterKeys, k)
			}
		}
	}

	var maskedKeys []string
	if *maskKeys != "" {
		for _, k := range strings.Split(*maskKeys, ",") {
			if k = strings.TrimSpace(k); k != "" {
				maskedKeys = append(maskedKeys, k)
			}
		}
	}

	opts := vault.ViewOptions{
		Keys:     filterKeys,
		MaskAll:  *maskAll,
		MaskKeys: maskedKeys,
	}

	if err := vault.ViewVault(*vaultPath, *privKeyPath, opts); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return err
	}
	return nil
}
