package vault

import (
	"strings"

	"github.com/yourusername/envcrypt/internal/crypto"
	"github.com/yourusername/envcrypt/internal/env"
)

// SearchResult holds a matched key-value pair and optional context.
type SearchResult struct {
	Key   string
	Value string
}

// SearchOptions controls how the vault search is performed.
type SearchOptions struct {
	CaseSensitive bool
	KeysOnly      bool
	ValuesOnly    bool
}

// SearchVault decrypts the vault at vaultPath and returns entries whose
// keys or values contain the given query string.
func SearchVault(vaultPath, privKeyPath, query string, opts SearchOptions) ([]SearchResult, error) {
	privKey, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return nil, err
	}

	entries, err := decryptVaultEntries(vaultPath, privKey)
	if err != nil {
		return nil, err
	}

	needle := query
	if !opts.CaseSensitive {
		needle = strings.ToLower(query)
	}

	var results []SearchResult
	for _, e := range entries {
		key := e.Key
		val := e.Value
		cmpKey := key
		cmpVal := val
		if !opts.CaseSensitive {
			cmpKey = strings.ToLower(key)
			cmpVal = strings.ToLower(val)
		}

		keyMatch := !opts.ValuesOnly && strings.Contains(cmpKey, needle)
		valMatch := !opts.KeysOnly && strings.Contains(cmpVal, needle)

		if keyMatch || valMatch {
			results = append(results, SearchResult{Key: key, Value: val})
		}
	}
	return results, nil
}

// decryptVaultEntries is a shared helper that decrypts a vault file and
// returns parsed env entries.
func decryptVaultEntries(vaultPath string, privKey interface{ Unwrap([]byte) ([]byte, error) }) ([]env.Entry, error) {
	v, err := New(vaultPath, nil)
	if err != nil {
		return nil, err
	}
	plaintext, err := v.Decrypt([]crypto.Identity{privKey})
	if err != nil {
		return nil, err
	}
	return env.Parse(strings.NewReader(string(plaintext)))
}
