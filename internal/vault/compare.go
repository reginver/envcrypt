package vault

import (
	"fmt"
	"sort"
)

// CompareResult holds the result of comparing two vault files.
type CompareResult struct {
	OnlyInA    []string
	OnlyInB    []string
	Different  []string
	Identical  []string
}

// CompareVaults decrypts two vault files and compares their key-value pairs.
// It returns a CompareResult summarizing which keys are unique to each vault,
// which differ in value, and which are identical.
func CompareVaults(vaultA, vaultB, privKeyPath string) (*CompareResult, error) {
	identA, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}

	entriesA, err := decryptVaultEntries(vaultA, identA)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault A %q: %w", vaultA, err)
	}

	entriesB, err := decryptVaultEntries(vaultB, identA)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault B %q: %w", vaultB, err)
	}

	mapA := toStringMap(entriesA)
	mapB := toStringMap(entriesB)

	result := &CompareResult{}

	for k, va := range mapA {
		vb, ok := mapB[k]
		if !ok {
			result.OnlyInA = append(result.OnlyInA, k)
		} else if va == vb {
			result.Identical = append(result.Identical, k)
		} else {
			result.Different = append(result.Different, k)
		}
	}

	for k := range mapB {
		if _, ok := mapA[k]; !ok {
			result.OnlyInB = append(result.OnlyInB, k)
		}
	}

	sort.Strings(result.OnlyInA)
	sort.Strings(result.OnlyInB)
	sort.Strings(result.Different)
	sort.Strings(result.Identical)

	return result, nil
}

func toStringMap(entries []Entry) map[string]string {
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		m[e.Key] = e.Value
	}
	return m
}
