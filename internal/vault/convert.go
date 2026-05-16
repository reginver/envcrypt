package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/yourusername/envcrypt/internal/crypto"
	"github.com/yourusername/envcrypt/internal/env"
)

// ConvertFormat represents supported output formats for vault conversion.
type ConvertFormat string

const (
	FormatDotenv ConvertFormat = "dotenv"
	FormatJSON   ConvertFormat = "json"
	FormatExport ConvertFormat = "export"
)

// ConvertOptions controls how a vault is converted.
type ConvertOptions struct {
	VaultPath  string
	PrivKeyPath string
	OutputPath  string
	Format      ConvertFormat
	Keys        []string
}

// ConvertVault decrypts a vault and writes its contents in the specified format.
func ConvertVault(opts ConvertOptions) error {
	privKey, err := LoadPrivateKey(opts.PrivKeyPath)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	data, err := os.ReadFile(opts.VaultPath)
	if err != nil {
		return fmt.Errorf("read vault: %w", err)
	}

	plain, err := crypto.Decrypt(data, privKey)
	if err != nil {
		return fmt.Errorf("decrypt vault: %w", err)
	}

	entries, err := env.Parse(string(plain))
	if err != nil {
		return fmt.Errorf("parse vault: %w", err)
	}

	if len(opts.Keys) > 0 {
		entries = env.FilterKeys(entries, opts.Keys)
	}

	var output string
	switch opts.Format {
	case FormatJSON:
		m := env.ToMap(entries)
		b, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal json: %w", err)
		}
		output = string(b) + "\n"
	case FormatExport:
		var sb strings.Builder
		for _, e := range entries {
			fmt.Fprintf(&sb, "export %s=%q\n", e.Key, e.Value)
		}
		output = sb.String()
	default: // dotenv
		output = env.Serialize(entries)
	}

	if opts.OutputPath == "" || opts.OutputPath == "-" {
		fmt.Print(output)
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(opts.OutputPath), 0o700); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	return os.WriteFile(opts.OutputPath, []byte(output), 0o600)
}
