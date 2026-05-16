package vault

import (
	"fmt"
	"sort"

	"github.com/nicholasgasior/envcrypt/internal/crypto"
	"github.com/nicholasgasior/envcrypt/internal/env"
)

// VaultStats holds summary statistics about a vault file.
type VaultStats struct {
	TotalKeys    int
	EmptyValues  int
	UniqueValues int
	LongestKey   string
	ShortestKey  string
	KeyLengthAvg float64
}

// StatsVault decrypts the vault at path using privKeyPath and returns
// summary statistics about its contents.
func StatsVault(path, privKeyPath string) (*VaultStats, error) {
	identity, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}

	entries, err := decryptVaultEntries(path, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault: %w", err)
	}

	if len(entries) == 0 {
		return &VaultStats{}, nil
	}

	m := env.ToMap(entries)
	seen := make(map[string]int)
	for _, v := range m {
		seen[v]++
	}

	unique := 0
	for _, count := range seen {
		if count == 1 {
			unique++
		}
	}

	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, e.Key)
	}
	sort.Strings(keys)

	empty := 0
	totalLen := 0
	for _, e := range entries {
		if e.Value == "" {
			empty++
		}
		totalLen += len(e.Key)
	}

	longest := keys[0]
	shortest := keys[0]
	for _, k := range keys[1:] {
		if len(k) > len(longest) {
			longest = k
		}
		if len(k) < len(shortest) {
			shortest = k
		}
	}

	return &VaultStats{
		TotalKeys:    len(entries),
		EmptyValues:  empty,
		UniqueValues: unique,
		LongestKey:   longest,
		ShortestKey:  shortest,
		KeyLengthAvg: float64(totalLen) / float64(len(entries)),
	}, nil
}

// ensure crypto import used via shared helpers
var _ = crypto.Decrypt
