package vault

import (
	"fmt"
	"sort"

	"github.com/yourusername/envcrypt/internal/env"
)

// TagEntry represents a key-tag association stored alongside the vault.
type TagEntry struct {
	Key  string
	Tags []string
}

// TagVault adds one or more tags to a key in the vault.
// It decrypts the vault to verify the key exists, then persists tag metadata.
func TagVault(vaultPath, privKeyPath, pubKeyPath, key string, tags []string) error {
	entries, err := decryptVault(vaultPath, privKeyPath)
	if err != nil {
		return fmt.Errorf("tag: decrypt vault: %w", err)
	}

	m := env.ToMap(entries)
	if _, ok := m[key]; !ok {
		return fmt.Errorf("tag: key %q not found in vault", key)
	}

	tagMap, err := loadTagMap(vaultPath)
	if err != nil {
		tagMap = map[string][]string{}
	}

	existing := tagMap[key]
	merged := mergeTags(existing, tags)
	tagMap[key] = merged

	return saveTagMap(vaultPath, tagMap)
}

// UntagVault removes one or more tags from a key.
func UntagVault(vaultPath, privKeyPath, key string, tags []string) error {
	tagMap, err := loadTagMap(vaultPath)
	if err != nil {
		return fmt.Errorf("untag: load tags: %w", err)
	}

	existing := tagMap[key]
	tagMap[key] = removeTags(existing, tags)
	if len(tagMap[key]) == 0 {
		delete(tagMap, key)
	}

	return saveTagMap(vaultPath, tagMap)
}

// ListTags returns all tag entries for a vault, sorted by key.
func ListTags(vaultPath string) ([]TagEntry, error) {
	tagMap, err := loadTagMap(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("list tags: %w", err)
	}

	keys := make([]string, 0, len(tagMap))
	for k := range tagMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]TagEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, TagEntry{Key: k, Tags: tagMap[k]})
	}
	return out, nil
}

// FilterByTag returns keys that have the given tag.
func FilterByTag(vaultPath, tag string) ([]string, error) {
	entries, err := ListTags(vaultPath)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, e := range entries {
		for _, t := range e.Tags {
			if t == tag {
				keys = append(keys, e.Key)
				break
			}
		}
	}
	return keys, nil
}

func mergeTags(existing, newTags []string) []string {
	seen := map[string]struct{}{}
	for _, t := range existing {
		seen[t] = struct{}{}
	}
	for _, t := range newTags {
		seen[t] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func removeTags(existing, toRemove []string) []string {
	remove := map[string]struct{}{}
	for _, t := range toRemove {
		remove[t] = struct{}{}
	}
	var out []string
	for _, t := range existing {
		if _, skip := remove[t]; !skip {
			out = append(out, t)
		}
	}
	return out
}
