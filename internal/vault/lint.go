package vault

import (
	"fmt"
	"strings"
)

// LintIssue represents a single linting warning or error found in a vault.
type LintIssue struct {
	Key     string
	Message string
	Severity string // "warn" or "error"
}

func (l LintIssue) String() string {
	return fmt.Sprintf("[%s] %s: %s", strings.ToUpper(l.Severity), l.Key, l.Message)
}

// LintVault decrypts the vault at the given path and checks for common issues.
// It returns a list of issues found.
func LintVault(vaultPath, privateKeyPath string) ([]LintIssue, error) {
	v, err := New(vaultPath, "")
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}

	privKey, err := LoadPrivateKey(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}

	entries, err := v.Decrypt(privKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault: %w", err)
	}

	var issues []LintIssue

	for _, entry := range entries {
		k := entry.Key
		v := entry.Value

		// Warn on empty values
		if strings.TrimSpace(v) == "" {
			issues = append(issues, LintIssue{Key: k, Message: "value is empty", Severity: "warn"})
		}

		// Warn on keys that are not uppercase
		if k != strings.ToUpper(k) {
			issues = append(issues, LintIssue{Key: k, Message: "key is not uppercase", Severity: "warn"})
		}

		// Warn on keys with spaces
		if strings.Contains(k, " ") {
			issues = append(issues, LintIssue{Key: k, Message: "key contains spaces", Severity: "error"})
		}

		// Warn on values that look like unresolved placeholders
		if strings.Contains(v, "<CHANGE_ME>") || strings.Contains(v, "TODO") {
			issues = append(issues, LintIssue{Key: k, Message: "value appears to be a placeholder", Severity: "warn"})
		}
	}

	return issues, nil
}
