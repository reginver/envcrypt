package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func captureAuditOutput(t *testing.T, args []string) string {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = old }()

	_ = runAuditLog(args)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestRunAuditLogEmpty(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.json")

	out := captureAuditOutput(t, []string{"-log", logPath})
	if out != "No audit log found.\n" {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestRunAuditLogWithEvents(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.json")

	_ = vault.AppendAuditEvent(logPath, "encrypt", ".env.age", "")
	_ = vault.AppendAuditEvent(logPath, "decrypt", ".env.age", "")

	out := captureAuditOutput(t, []string{"-log", logPath})
	if out == "" {
		t.Fatal("expected non-empty output")
	}
	if len(out) < 20 {
		t.Errorf("output suspiciously short: %q", out)
	}
}

func TestRunAuditLogClear(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.json")

	_ = vault.AppendAuditEvent(logPath, "encrypt", ".env.age", "")

	err := runAuditLog([]string{"-log", logPath, "-clear"})
	if err != nil {
		t.Fatalf("runAuditLog clear: %v", err)
	}

	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Error("expected audit log to be removed")
	}
}

func TestRunAuditLogClearMissing(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.json")

	err := runAuditLog([]string{"-log", logPath, "-clear"})
	if err != nil {
		t.Fatalf("clear missing log should not error: %v", err)
	}
}
