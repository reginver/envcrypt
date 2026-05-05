package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/nicholasgasior/envcrypt/internal/crypto"
	"github.com/nicholasgasior/envcrypt/internal/env"
)

// ExportFormat represents the output format for exported variables.
type ExportFormat int

const (
	FormatRaw   ExportFormat = iota // KEY=VALUE
	FormatExport                    // export KEY=VALUE
	FormatJSON                      // {"KEY": "VALUE"}
)

// ExportOptions controls how the vault is exported.
type ExportOptions struct {
	Format ExportFormat
	Keys   []string // if non-empty, only export these keys
}

// ExportVault decrypts the vault file and writes its contents to the given
// writer in the requested format. If opts.Keys is non-empty only matching
// entries are included.
func ExportVault(vaultPath, privateKeyPath string, opts ExportOptions) (string, error) {
	privKey, err := LoadPrivateKey(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("load private key: %w", err)
	}

	ciphertext, err := os.ReadFile(vaultPath)
	if err != nil {
		return "", fmt.Errorf("read vault: %w", err)
	}

	plaintext, err := crypto.Decrypt(ciphertext, privKey)
	if err != nil {
		return "", fmt.Errorf("decrypt vault: %w", err)
	}

	entries, err := env.Parse(string(plaintext))
	if err != nil {
		return "", fmt.Errorf("parse env: %w", err)
	}

	if len(opts.Keys) > 0 {
		entries = env.FilterKeys(entries, opts.Keys)
	}

	switch opts.Format {
	case FormatExport:
		return formatExport(entries), nil
	case FormatJSON:
		return formatJSON(entries), nil
	default:
		return env.Serialize(entries), nil
	}
}

func formatExport(entries []env.Entry) string {
	var sb strings.Builder
	for _, e := range entries {
		if e.Comment || e.Blank {
			continue
		}
		fmt.Fprintf(&sb, "export %s=%s\n", e.Key, e.Value)
	}
	return sb.String()
}

func formatJSON(entries []env.Entry) string {
	m := env.ToMap(entries)
	var sb strings.Builder
	sb.WriteString("{\n")
	i := 0
	for k, v := range m {
		comma := ","
		if i == len(m)-1 {
			comma = ""
		}
		fmt.Fprintf(&sb, "  %q: %q%s\n", k, v, comma)
		i++
	}
	sb.WriteString("}\n")
	return sb.String()
}
