package vault

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/user/envcrypt/internal/env"
)

// ViewOptions controls how the vault contents are displayed.
type ViewOptions struct {
	Keys    []string // if non-empty, only show these keys
	MaskAll bool     // mask all values with ***
	MaskKeys []string // mask only these keys
}

// ViewVault decrypts the vault and prints its contents to stdout in a
// human-readable table format.
func ViewVault(vaultPath, privateKeyPath string, opts ViewOptions) error {
	privKey, err := LoadPrivateKey(privateKeyPath)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	data, err := os.ReadFile(vaultPath)
	if err != nil {
		return fmt.Errorf("read vault: %w", err)
	}

	v := New(nil, privKey)
	plaintext, err := v.Decrypt(data)
	if err != nil {
		return fmt.Errorf("decrypt vault: %w", err)
	}

	entries, err := env.Parse(string(plaintext))
	if err != nil {
		return fmt.Errorf("parse env: %w", err)
	}

	if len(opts.Keys) > 0 {
		entries = env.FilterKeys(entries, opts.Keys)
	}

	maskSet := make(map[string]bool, len(opts.MaskKeys))
	for _, k := range opts.MaskKeys {
		maskSet[k] = true
	}

	// Determine column width for keys.
	maxLen := 3
	for _, e := range entries {
		if len(e.Key) > maxLen {
			maxLen = len(e.Key)
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Key < entries[j].Key
	})

	fmt.Printf("%-*s  %s\n", maxLen, "KEY", "VALUE")
	fmt.Println(strings.Repeat("-", maxLen+2+40))
	for _, e := range entries {
		val := e.Value
		if opts.MaskAll || maskSet[e.Key] {
			val = "***"
		}
		fmt.Printf("%-*s  %s\n", maxLen, e.Key, val)
	}
	return nil
}
