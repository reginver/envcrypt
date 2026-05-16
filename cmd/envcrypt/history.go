package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/vault"
)

func runHistory(args []string) {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	vaultFile := fs.String("vault", ".env.age", "path to encrypted vault file")
	keyFilter := fs.String("key", "", "filter history by key name")
	clear := fs.Bool("clear", false, "clear history for the vault")
	_ = fs.Parse(args)

	if *clear {
		if err := vault.ClearHistory(*vaultFile); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("history cleared")
		return
	}

	entries, err := vault.LoadHistory(*vaultFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading history: %v\n", err)
		os.Exit(1)
	}

	if *keyFilter != "" {
		entries = vault.FilterHistoryByKey(entries, *keyFilter)
	}

	fmt.Print(vault.FormatHistory(entries))
}
