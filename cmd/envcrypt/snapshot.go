package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/user/envcrypt/internal/vault"
)

func runSnapshot(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: envcrypt snapshot <subcommand> [args]\nsubcommands: create, list, restore")
	}

	_, privPath := vault.DefaultKeyPaths()

	switch args[0] {
	case "create":
		vaultPath := ".env.vault"
		if len(args) >= 2 {
			vaultPath = args[1]
		}
		snapshotFile, err := vault.SnapshotVault(vaultPath)
		if err != nil {
			return fmt.Errorf("snapshot failed: %w", err)
		}
		fmt.Printf("Snapshot created: %s\n", snapshotFile)
		return nil

	case "list":
		vaultPath := ".env.vault"
		if len(args) >= 2 {
			vaultPath = args[1]
		}
		dir := filepath.Dir(vaultPath)
		snapshots, err := vault.ListSnapshots(dir)
		if err != nil {
			return fmt.Errorf("list snapshots failed: %w", err)
		}
		if len(snapshots) == 0 {
			fmt.Println("No snapshots found.")
			return nil
		}
		fmt.Println("Snapshots:")
		for _, s := range snapshots {
			fmt.Printf("  %s\n", s)
		}
		return nil

	case "restore":
		if len(args) < 2 {
			return fmt.Errorf("usage: envcrypt snapshot restore <snapshot-file> [dest-vault]")
		}
		snapshotFile := args[1]
		destVault := ".env.vault"
		if len(args) >= 3 {
			destVault = args[2]
		}
		pubPath, _ := vault.DefaultKeyPaths()
		err := vault.RestoreSnapshot(snapshotFile, destVault, pubPath, privPath)
		if err != nil {
			return fmt.Errorf("restore failed: %w", err)
		}
		fmt.Printf("Restored snapshot %s -> %s\n", snapshotFile, destVault)
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func init() {
	_ = os.Stderr // ensure os imported
}
