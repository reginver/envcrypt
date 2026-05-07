package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// AuditEvent represents a single recorded vault operation.
type AuditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Operation string    `json:"operation"`
	VaultPath string    `json:"vault_path"`
	Details   string    `json:"details,omitempty"`
}

// AuditLog holds a list of audit events.
type AuditLog struct {
	Events []AuditEvent `json:"events"`
}

// AppendAuditEvent appends an event to the audit log file.
func AppendAuditEvent(logPath, operation, vaultPath, details string) error {
	log, err := LoadAuditLog(logPath)
	if err != nil {
		log = &AuditLog{}
	}

	log.Events = append(log.Events, AuditEvent{
		Timestamp: time.Now().UTC(),
		Operation: operation,
		VaultPath: vaultPath,
		Details:   details,
	})

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal audit log: %w", err)
	}

	return os.WriteFile(logPath, data, 0600)
}

// LoadAuditLog reads and parses an audit log from disk.
func LoadAuditLog(logPath string) (*AuditLog, error) {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}

	var log AuditLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("parse audit log: %w", err)
	}

	return &log, nil
}

// FormatAuditLog returns a human-readable string of all audit events.
func FormatAuditLog(log *AuditLog) string {
	if len(log.Events) == 0 {
		return "No audit events recorded.\n"
	}

	var out string
	for _, e := range log.Events {
		line := fmt.Sprintf("[%s] %-10s %s", e.Timestamp.Format(time.RFC3339), e.Operation, e.VaultPath)
		if e.Details != "" {
			line += " (" + e.Details + ")"
		}
		out += line + "\n"
	}
	return out
}
