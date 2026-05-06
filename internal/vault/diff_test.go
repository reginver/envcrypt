package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupDiffVaults(t *testing.T, contentA, contentB string) (string, string, string) {
	t.Helper()
	dir := t.TempDir()

	pubPath := filepath.Join(dir, "pub.age")
	privPath := filepath.Join(dir, "priv.age")
	if err := InitKeys(pubPath, privPath, false); err != nil {
		t.Fatalf("InitKeys: %v", err)
	}

	v := New(pubPath)

	vaultA := filepath.Join(dir, "a.env.age")
	plainA := filepath.Join(dir, "a.env")
	if err := os.WriteFile(plainA, []byte(contentA), 0600); err != nil {
		t.Fatalf("write plainA: %v", err)
	}
	if err := v.Encrypt(plainA, vaultA); err != nil {
		t.Fatalf("encrypt A: %v", err)
	}

	vaultB := filepath.Join(dir, "b.env.age")
	plainB := filepath.Join(dir, "b.env")
	if err := os.WriteFile(plainB, []byte(contentB), 0600); err != nil {
		t.Fatalf("write plainB: %v", err)
	}
	if err := v.Encrypt(plainB, vaultB); err != nil {
		t.Fatalf("encrypt B: %v", err)
	}

	return vaultA, vaultB, privPath
}

func TestDiffVaultsNoChanges(t *testing.T) {
	content := "FOO=bar\nBAZ=qux\n"
	a, b, priv := setupDiffVaults(t, content, content)

	result, err := DiffVaults(a, b, priv)
	if err != nil {
		t.Fatalf("DiffVaults: %v", err)
	}
	if result.HasChanges() {
		t.Error("expected no changes")
	}
	if len(result.Unchanged) != 2 {
		t.Errorf("expected 2 unchanged, got %d", len(result.Unchanged))
	}
}

func TestDiffVaultsWithChanges(t *testing.T) {
	contentA := "FOO=bar\nOLD=remove\n"
	contentB := "FOO=changed\nNEW=add\n"
	a, b, priv := setupDiffVaults(t, contentA, contentB)

	result, err := DiffVaults(a, b, priv)
	if err != nil {
		t.Fatalf("DiffVaults: %v", err)
	}
	if !result.HasChanges() {
		t.Fatal("expected changes")
	}
	if len(result.Added) != 1 || result.Added[0] != "NEW" {
		t.Errorf("expected NEW added, got %v", result.Added)
	}
	if len(result.Removed) != 1 || result.Removed[0] != "OLD" {
		t.Errorf("expected OLD removed, got %v", result.Removed)
	}
	if len(result.Changed) != 1 || result.Changed[0] != "FOO" {
		t.Errorf("expected FOO changed, got %v", result.Changed)
	}
}

func TestFormatDiff(t *testing.T) {
	d := &DiffResult{
		Added:   []string{"NEW"},
		Removed: []string{"OLD"},
		Changed: []string{"FOO"},
	}
	var buf bytes.Buffer
	FormatDiff(&buf, d)
	out := buf.String()
	if !strings.Contains(out, "+ NEW") {
		t.Error("missing added key")
	}
	if !strings.Contains(out, "- OLD") {
		t.Error("missing removed key")
	}
	if !strings.Contains(out, "~ FOO") {
		t.Error("missing changed key")
	}
}

func TestFormatDiffNoChanges(t *testing.T) {
	d := &DiffResult{Unchanged: []string{"FOO"}}
	var buf bytes.Buffer
	FormatDiff(&buf, d)
	if !strings.Contains(buf.String(), "no differences found") {
		t.Error("expected no-differences message")
	}
}
