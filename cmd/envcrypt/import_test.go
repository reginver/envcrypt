package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func TestRunImportCreatesVault(t *testing.T) {
	dir := t.TempDir()

	pubKeyFile := filepath.Join(dir, "age.pub")
	privKeyFile := filepath.Join(dir, "age.key")
	if err := vault.InitKeys(pubKeyFile, privKeyFile, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	srcFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(srcFile, []byte("FOO=bar\nBAZ=qux\n"), 0600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	vaultFile := filepath.Join(dir, ".env.age")

	err := runImport([]string{
		"-src", srcFile,
		"-vault", vaultFile,
		"-pubkey", pubKeyFile,
	})
	if err != nil {
		t.Fatalf("runImport: %v", err)
	}

	if _, err := os.Stat(vaultFile); os.IsNotExist(err) {
		t.Error("vault file was not created")
	}
}

func TestRunImportMissingSource(t *testing.T) {
	dir := t.TempDir()

	pubKeyFile := filepath.Join(dir, "age.pub")
	privKeyFile := filepath.Join(dir, "age.key")
	if err := vault.InitKeys(pubKeyFile, privKeyFile, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	err := runImport([]string{
		"-src", filepath.Join(dir, "nonexistent.env"),
		"-vault", filepath.Join(dir, ".env.age"),
		"-pubkey", pubKeyFile,
	})
	if err == nil {
		t.Error("expected error for missing source file, got nil")
	}
}

func TestSplitCSV(t *testing.T) {
	cases := []struct {
		input    string
		expected []string
	}{
		{"FOO,BAR,BAZ", []string{"FOO", "BAR", "BAZ"}},
		{"SINGLE", []string{"SINGLE"}},
		{"", []string(nil)},
		{"A,,B", []string{"A", "B"}},
	}

	for _, tc := range cases {
		got := splitCSV(tc.input)
		if len(got) != len(tc.expected) {
			t.Errorf("splitCSV(%q) = %v, want %v", tc.input, got, tc.expected)
			continue
		}
		for i := range got {
			if got[i] != tc.expected[i] {
				t.Errorf("splitCSV(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.expected[i])
			}
		}
	}
}
