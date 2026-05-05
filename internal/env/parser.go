package env

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Entry represents a single key-value pair from a .env file.
type Entry struct {
	Key     string
	Value   string
	Comment string
}

// Parse reads .env formatted content and returns a slice of entries.
// It preserves comments and blank lines as empty entries with only Comment set.
func Parse(r io.Reader) ([]Entry, error) {
	var entries []Entry
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			entries = append(entries, Entry{Comment: line})
			continue
		}

		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid line: %q", line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = stripQuotes(value)

		entries = append(entries, Entry{Key: key, Value: value})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning env file: %w", err)
	}

	return entries, nil
}

// Serialize writes entries back to .env format.
func Serialize(entries []Entry, w io.Writer) error {
	for _, e := range entries {
		var line string
		if e.Key == "" {
			line = e.Comment
		} else {
			line = fmt.Sprintf("%s=%s", e.Key, e.Value)
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return fmt.Errorf("writing entry: %w", err)
		}
	}
	return nil
}

func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
