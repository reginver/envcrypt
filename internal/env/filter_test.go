package env

import (
	"testing"
)

func TestToMap(t *testing.T) {
	entries := []Entry{
		{Key: "A", Value: "1"},
		{Key: "B", Value: "2"},
		{Comment: "# ignored"},
	}
	m := ToMap(entries)
	if len(m) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(m))
	}
	if m["A"] != "1" || m["B"] != "2" {
		t.Errorf("unexpected map: %v", m)
	}
}

func TestFilterKeys(t *testing.T) {
	entries := []Entry{
		{Comment: "# comment"},
		{Key: "KEEP", Value: "yes"},
		{Key: "DROP", Value: "no"},
	}
	result := FilterKeys(entries, []string{"KEEP"})
	if len(result) != 2 {
		t.Fatalf("expected 2 entries (comment + KEEP), got %d", len(result))
	}
	if result[1].Key != "KEEP" {
		t.Errorf("expected KEEP, got %q", result[1].Key)
	}
}

func TestMergeEntries(t *testing.T) {
	base := []Entry{
		{Key: "A", Value: "old"},
		{Key: "B", Value: "keep"},
	}
	overrides := []Entry{
		{Key: "A", Value: "new"},
		{Key: "C", Value: "added"},
	}

	result := MergeEntries(base, overrides)
	m := ToMap(result)

	if m["A"] != "new" {
		t.Errorf("expected A=new, got %q", m["A"])
	}
	if m["B"] != "keep" {
		t.Errorf("expected B=keep, got %q", m["B"])
	}
	if m["C"] != "added" {
		t.Errorf("expected C=added, got %q", m["C"])
	}
}

func TestFromMap(t *testing.T) {
	m := map[string]string{"X": "1", "Y": "2"}
	entries := FromMap(m)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	back := ToMap(entries)
	if back["X"] != "1" || back["Y"] != "2" {
		t.Errorf("unexpected map: %v", back)
	}
}
