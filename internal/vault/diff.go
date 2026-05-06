package vault

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// DiffResult holds the result of comparing two vaults.
type DiffResult struct {
	Added   []string
	Removed []string
	Changed []string
	Unchanged []string
}

// HasChanges returns true if there are any differences.
func (d *DiffResult) HasChanges() bool {
	return len(d.Added) > 0 || len(d.Removed) > 0 || len(d.Changed) > 0
}

// DiffVaults decrypts two vault files and compares their key/value pairs.
func DiffVaults(vaultA, vaultB string, privKeyPath string) (*DiffResult, error) {
	identity, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}

	v := New("")

	mapA, err := v.decryptToMap(vaultA, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault A: %w", err)
	}

	mapB, err := v.decryptToMap(vaultB, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault B: %w", err)
	}

	return computeDiff(mapA, mapB), nil
}

func computeDiff(a, b map[string]string) *DiffResult {
	result := &DiffResult{}

	keys := make(map[string]struct{})
	for k := range a {
		keys[k] = struct{}{}
	}
	for k := range b {
		keys[k] = struct{}{}
	}

	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	for _, k := range sorted {
		valA, inA := a[k]
		valB, inB := b[k]
		switch {
		case inA && !inB:
			result.Removed = append(result.Removed, k)
		case !inA && inB:
			result.Added = append(result.Added, k)
		case valA != valB:
			result.Changed = append(result.Changed, k)
		default:
			result.Unchanged = append(result.Unchanged, k)
		}
	}
	return result
}

// FormatDiff writes a human-readable diff to w.
func FormatDiff(w io.Writer, d *DiffResult) {
	for _, k := range d.Added {
		fmt.Fprintf(w, "+ %s\n", k)
	}
	for _, k := range d.Removed {
		fmt.Fprintf(w, "- %s\n", k)
	}
	for _, k := range d.Changed {
		fmt.Fprintf(w, "~ %s\n", k)
	}
	if !d.HasChanges() {
		fmt.Fprintln(w, strings.TrimSpace("no differences found"))
	}
}
