package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/vault"
)

func runPin(args []string) {
	fs := flag.NewFlagSet("pin", flag.ExitOnError)
	vaultFile := fs.String("vault", ".env.age", "Path to the vault file")
	note := fs.String("note", "", "Optional note for the pinned key")
	remove := fs.Bool("remove", false, "Unpin the key instead of pinning")
	list := fs.Bool("list", false, "List all pinned keys")
	_ = fs.Parse(args)

	if *list {
		pins, err := vault.ListPins(*vaultFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if len(pins) == 0 {
			fmt.Println("No pinned keys.")
			return
		}
		fmt.Printf("%-30s %-25s %s\n", "KEY", "PINNED AT", "NOTE")
		for _, p := range pins {
			fmt.Printf("%-30s %-25s %s\n", p.Key, p.PinnedAt.Format("2006-01-02 15:04:05"), p.Note)
		}
		return
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: envcrypt pin [--remove] [--note=...] <KEY>")
		os.Exit(1)
	}
	key := fs.Arg(0)

	if *remove {
		if err := vault.UnpinKey(*vaultFile, key); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Unpinned key: %s\n", key)
		return
	}

	if err := vault.PinKey(*vaultFile, key, *note); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Pinned key: %s\n", key)
}
