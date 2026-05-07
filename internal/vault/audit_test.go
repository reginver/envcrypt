package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendAndLoadAuditLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.json")

	err := AppendAuditEvent(logPath, "encrypt", ".env.age", "")
	if err != nil {
		t.Fatalf("AppendAuditEvent: %v", err)
	}

	err = AppendAuditEvent(logPath, "decrypt", ".env.age", "output: .env")
	if err != nil {
		t.Fatalf("AppendAuditEvent second: %v", err)
	}

	log, err := LoadAuditLog(logPath)
	if err != nil {
		t.Fatalf("LoadAuditLog: %v", err)
	}

	if len(log.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(log.Events))
	}

	if log.Events[0].Operation != "encrypt" {
		t.Errorf("expected operation 'encrypt', got %q", log.Events[0].Operation)
	}
	if log.Events[1].Details != "output: .env" {
		t.Errorf("expected details 'output: .env', got %q", log.Events[1].Details)
	}
}

func TestLoadAuditLogMissing(t *testing.T) {
	_, err := LoadAuditLog("/nonexistent/audit.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFormatAuditLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.json")

	_ = AppendAuditEvent(logPath, "rotate", "secrets.age", "")

	log, _ := LoadAuditLog(logPath)
	out := FormatAuditLog(log)

	if out == "" {
		t.Fatal("expected non-empty formatted output")
	}
	if len(out) < 10 {
		t.Errorf("output too short: %q", out)
	}
}

func TestFormatAuditLogEmpty(t *testing.T) {
	log := &AuditLog{}
	out := FormatAuditLog(log)
	if out != "No audit events recorded.\n" {
		t.Errorf("unexpected output for empty log: %q", out)
	}
}

func TestAuditLogPermissions(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.json")

	_ = AppendAuditEvent(logPath, "init", ".env.age", "")

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %v", info.Mode().Perm())
	}
}
