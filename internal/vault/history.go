package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// HistoryEntry represents a single change record for a vault key.
type HistoryEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Key       string    `json:"key"`
	OldValue  string    `json:"old_value"`
	NewValue  string    `json:"new_value"`
	Action    string    `json:"action"` // set, delete, rename
}

func historyFilePath(vaultPath string) string {
	return vaultPath + ".history.json"
}

// AppendHistory records a change event for the given vault.
func AppendHistory(vaultPath, key, oldValue, newValue, action string) error {
	entries, _ := LoadHistory(vaultPath)
	entries = append(entries, HistoryEntry{
		Timestamp: time.Now().UTC(),
		Key:       key,
		OldValue:  oldValue,
		NewValue:  newValue,
		Action:    action,
	})
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal history: %w", err)
	}
	return os.WriteFile(historyFilePath(vaultPath), data, 0600)
}

// LoadHistory reads all history entries for the given vault file.
func LoadHistory(vaultPath string) ([]HistoryEntry, error) {
	data, err := os.ReadFile(historyFilePath(vaultPath))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read history: %w", err)
	}
	var entries []HistoryEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse history: %w", err)
	}
	return entries, nil
}

// FormatHistory returns a human-readable string of history entries.
func FormatHistory(entries []HistoryEntry) string {
	if len(entries) == 0 {
		return "no history found\n"
	}
	out := ""
	for _, e := range entries {
		out += fmt.Sprintf("[%s] %s key=%s",
			e.Timestamp.Format(time.RFC3339), e.Action, e.Key)
		if e.OldValue != "" {
			out += fmt.Sprintf(" old=%s", e.OldValue)
		}
		if e.NewValue != "" {
			out += fmt.Sprintf(" new=%s", e.NewValue)
		}
		out += "\n"
	}
	return out
}

// ClearHistory removes the history file for the given vault.
func ClearHistory(vaultPath string) error {
	p := historyFilePath(vaultPath)
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear history: %w", err)
	}
	return nil
}

// FilterHistoryByKey returns entries matching the given key.
func FilterHistoryByKey(entries []HistoryEntry, key string) []HistoryEntry {
	var out []HistoryEntry
	for _, e := range entries {
		if e.Key == key {
			out = append(out, e)
		}
	}
	return out
}

// HistoryFilePath exposes the path for testing purposes.
func HistoryFilePath(vaultPath string) string {
	return filepath.Clean(historyFilePath(vaultPath))
}
