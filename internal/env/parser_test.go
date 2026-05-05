package env

import (
	"strings"
	"testing"
)

func TestParseBasic(t *testing.T) {
	input := `KEY=value
FOO=bar
BAZ=hello world`

	entries, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Key != "KEY" || entries[0].Value != "value" {
		t.Errorf("unexpected entry: %+v", entries[0])
	}
}

func TestParseQuotedValues(t *testing.T) {
	input := `SINGLE='hello'
DOUBLE="world"`

	entries, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entries[0].Value != "hello" {
		t.Errorf("expected hello, got %q", entries[0].Value)
	}
	if entries[1].Value != "world" {
		t.Errorf("expected world, got %q", entries[1].Value)
	}
}

func TestParseComments(t *testing.T) {
	input := `# This is a comment
KEY=value

# Another comment`

	entries, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}
	if entries[0].Key != "" || entries[0].Comment == "" {
		t.Errorf("expected comment entry, got %+v", entries[0])
	}
}

func TestSerializeRoundtrip(t *testing.T) {
	input := "# comment\nKEY=value\nFOO=bar\n"
	entries, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	var sb strings.Builder
	if err := Serialize(entries, &sb); err != nil {
		t.Fatalf("serialize error: %v", err)
	}

	if sb.String() != input {
		t.Errorf("roundtrip mismatch:\ngot:  %q\nwant: %q", sb.String(), input)
	}
}

func TestParseInvalidLine(t *testing.T) {
	input := "NOTVALID"
	_, err := Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for invalid line")
	}
}
