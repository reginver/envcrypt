package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupHistoryVault(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "test.env.age")
}

func TestAppendAndLoadHistory(t *testing.T) {
	vaultPath := setupHistoryVault(t)

	if err := AppendHistory(vaultPath, "DB_PASS", "", "secret", "set"); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}
	if err := AppendHistory(vaultPath, "DB_PASS", "secret", "newsecret", "set"); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	entries, err := LoadHistory(vaultPath)
	if err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Key != "DB_PASS" || entries[0].Action != "set" {
		t.Errorf("unexpected entry: %+v", entries[0])
	}
	if entries[1].OldValue != "secret" || entries[1].NewValue != "newsecret" {
		t.Errorf("unexpected values in entry[1]: %+v", entries[1])
	}
}

func TestLoadHistoryMissing(t *testing.T) {
	vaultPath := setupHistoryVault(t)
	entries, err := LoadHistory(vaultPath)
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if entries != nil {
		t.Errorf("expected nil entries, got %v", entries)
	}
}

func TestFormatHistory(t *testing.T) {
	entries := []HistoryEntry{
		{Timestamp: time.Now().UTC(), Key: "API_KEY", NewValue: "abc", Action: "set"},
	}
	out := FormatHistory(entries)
	if !strings.Contains(out, "API_KEY") || !strings.Contains(out, "set") {
		t.Errorf("unexpected format output: %s", out)
	}
}

func TestFormatHistoryEmpty(t *testing.T) {
	out := FormatHistory(nil)
	if !strings.Contains(out, "no history") {
		t.Errorf("expected 'no history' message, got: %s", out)
	}
}

func TestClearHistory(t *testing.T) {
	vaultPath := setupHistoryVault(t)
	_ = AppendHistory(vaultPath, "X", "", "1", "set")

	if err := ClearHistory(vaultPath); err != nil {
		t.Fatalf("ClearHistory: %v", err)
	}
	if _, err := os.Stat(HistoryFilePath(vaultPath)); !os.IsNotExist(err) {
		t.Errorf("expected history file to be removed")
	}
	// idempotent
	if err := ClearHistory(vaultPath); err != nil {
		t.Errorf("ClearHistory on missing file should not error: %v", err)
	}
}

func TestFilterHistoryByKey(t *testing.T) {
	vaultPath := setupHistoryVault(t)
	_ = AppendHistory(vaultPath, "KEY_A", "", "1", "set")
	_ = AppendHistory(vaultPath, "KEY_B", "", "2", "set")
	_ = AppendHistory(vaultPath, "KEY_A", "1", "", "delete")

	all, _ := LoadHistory(vaultPath)
	filtered := FilterHistoryByKey(all, "KEY_A")
	if len(filtered) != 2 {
		t.Errorf("expected 2 entries for KEY_A, got %d", len(filtered))
	}
	for _, e := range filtered {
		if e.Key != "KEY_A" {
			t.Errorf("unexpected key in filtered result: %s", e.Key)
		}
	}
}
