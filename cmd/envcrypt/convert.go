package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/yourusername/envcrypt/internal/vault"
)

func runConvert(args []string) {
	fs := flag.NewFlagSet("convert", flag.ExitOnError)
	privKey := fs.String("priv", "", "path to private key (default: ~/.envcrypt/key.age)")
	output := fs.String("out", "-", "output file path (default: stdout)")
	format := fs.String("format", "dotenv", "output format: dotenv, json, export")
	keys := fs.String("keys", "", "comma-separated list of keys to include")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: envcrypt convert [flags] <vault>")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	vaultPath := fs.Arg(0)

	paths := vault.DefaultKeyPaths()
	if *privKey == "" {
		*privKey = paths.PrivateKey
	}

	var keyList []string
	if *keys != "" {
		keyList = splitCSV(*keys)
	}

	fmt := vault.ConvertFormat(strings.ToLower(*format))
	switch fmt {
	case vault.FormatDotenv, vault.FormatJSON, vault.FormatExport:
	default:
		fmt.Fprintln(os.Stderr, "unknown format:", *format)
		os.Exit(1)
	}

	if err := vault.ConvertVault(vault.ConvertOptions{
		VaultPath:   vaultPath,
		PrivKeyPath: *privKey,
		OutputPath:  *output,
		Format:      fmt,
		Keys:        keyList,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
