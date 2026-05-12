package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/vault"
)

func runTemplate(args []string) {
	fs := flag.NewFlagSet("template", flag.ExitOnError)
	vaultPath := fs.String("vault", ".env.age", "path to encrypted vault file")
	privKeyPath := fs.String("priv", "", "path to private key (default: ~/.config/envcrypt/key)")
	outPath := fs.String("out", "", "write rendered output to file instead of stdout")
	strict := fs.Bool("strict", false, "fail on unresolved placeholders")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: envcrypt template [flags] <template-file>")
		fs.PrintDefaults()
		os.Exit(1)
	}

	tmplPath := fs.Arg(0)

	_, priv := DefaultKeyPaths()
	if *privKeyPath != "" {
		priv = *privKeyPath
	}

	result, err := vault.RenderTemplate(tmplPath, *vaultPath, priv, *strict)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *outPath != "" {
		if err := os.WriteFile(*outPath, []byte(result), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "write output: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stdout, "rendered template written to %s\n", *outPath)
	} else {
		fmt.Print(result)
	}
}
