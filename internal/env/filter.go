package env

// ToMap converts a slice of entries into a key-value map.
// Comment-only entries are skipped.
func ToMap(entries []Entry) map[string]string {
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		if e.Key != "" {
			m[e.Key] = e.Value
		}
	}
	return m
}

// FromMap creates a flat list of entries from a map.
// Order is not guaranteed.
func FromMap(m map[string]string) []Entry {
	entries := make([]Entry, 0, len(m))
	for k, v := range m {
		entries = append(entries, Entry{Key: k, Value: v})
	}
	return entries
}

// FilterKeys returns only entries whose keys are in the provided set.
// Comment entries are preserved.
func FilterKeys(entries []Entry, keys []string) []Entry {
	set := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		set[k] = struct{}{}
	}

	var result []Entry
	for _, e := range entries {
		if e.Key == "" {
			result = append(result, e)
			continue
		}
		if _, ok := set[e.Key]; ok {
			result = append(result, e)
		}
	}
	return result
}

// MergeEntries merges override entries into base, updating existing keys
// and appending new ones. Comment entries from base are preserved.
func MergeEntries(base, overrides []Entry) []Entry {
	overrideMap := ToMap(overrides)
	result := make([]Entry, 0, len(base))

	for _, e := range base {
		if e.Key == "" {
			result = append(result, e)
			continue
		}
		if v, ok := overrideMap[e.Key]; ok {
			result = append(result, Entry{Key: e.Key, Value: v})
			delete(overrideMap, e.Key)
		} else {
			result = append(result, e)
		}
	}

	for _, e := range overrides {
		if e.Key == "" {
			continue
		}
		if _, ok := overrideMap[e.Key]; ok {
			result = append(result, e)
		}
	}

	return result
}
