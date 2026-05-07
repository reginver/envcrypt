package vault

// AuditHook is a function called after a vault operation to record an audit event.
// logPath is empty string to disable auditing.
type AuditHook func(logPath, operation, vaultPath, details string)

// DefaultAuditHook records an event using AppendAuditEvent, ignoring errors
// and skipping when logPath is empty.
func DefaultAuditHook(logPath, operation, vaultPath, details string) {
	if logPath == "" {
		return
	}
	// Best-effort: audit failures should not break the primary operation.
	_ = AppendAuditEvent(logPath, operation, vaultPath, details)
}

// NoopAuditHook is an AuditHook that does nothing, useful in tests.
func NoopAuditHook(_, _, _, _ string) {}
