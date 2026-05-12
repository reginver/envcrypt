package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yourusername/envcrypt/internal/vault"
)

func runWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	vaultPath := fs.String("vault", ".env.age", "path to encrypted vault file")
	interval := fs.Duration("interval", 2*time.Second, "polling interval (e.g. 1s, 500ms)")
	fs.Parse(args)

	if *vaultPath == "" {
		fmt.Fprintln(os.Stderr, "error: --vault is required")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "Watching %s every %s (Ctrl+C to stop)...\n", *vaultPath, *interval)

	initialHash, err := vault.HashVaultFile(*vaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "Initial hash: %s\n", initialHash)

	done := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		close(done)
	}()

	events, err := vault.WatchVault(*vaultPath, *interval, done)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error starting watch: %v\n", err)
		os.Exit(1)
	}

	for ev := range events {
		fmt.Fprintf(os.Stdout, "[%s] vault changed\n  old: %s\n  new: %s\n",
			ev.DetectedAt.Format(time.RFC3339), ev.OldHash, ev.NewHash)
	}
	fmt.Fprintln(os.Stdout, "Watch stopped.")
}
