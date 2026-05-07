package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/vault"
)

const defaultAuditLog = ".envcrypt-audit.json"

func runAuditLog(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	logPath := fs.String("log", defaultAuditLog, "Path to audit log file")
	clear := fs.Bool("clear", false, "Clear the audit log")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *clear {
		if err := os.Remove(*logPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clear audit log: %w", err)
		}
		fmt.Println("Audit log cleared.")
		return nil
	}

	log, err := vault.LoadAuditLog(*logPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No audit log found.")
			return nil
		}
		return fmt.Errorf("load audit log: %w", err)
	}

	fmt.Print(vault.FormatAuditLog(log))
	return nil
}
