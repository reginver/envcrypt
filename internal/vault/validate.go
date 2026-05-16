package vault

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/yourusername/envcrypt/internal/env"
)

// ValidationRule defines a rule applied to vault entries during validation.
type ValidationRule struct {
	Name    string
	Message string
	Check   func(key, value string) bool
}

// ValidationIssue represents a single validation failure.
type ValidationIssue struct {
	Key     string
	Rule    string
	Message string
}

// ValidationResult holds the outcome of a vault validation run.
type ValidationResult struct {
	Issues []ValidationIssue
	Valid  bool
}

var (
	reValidKey    = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	reURL         = regexp.MustCompile(`^https?://`)
	placeholders  = []string{"TODO", "FIXME", "CHANGEME", "YOUR_", "<", ">"}
)

// defaultRules returns the built-in set of validation rules.
func defaultRules() []ValidationRule {
	return []ValidationRule{
		{
			Name:    "non-empty-value",
			Message: "value is empty",
			Check:   func(_, v string) bool { return strings.TrimSpace(v) != "" },
		},
		{
			Name:    "uppercase-key",
			Message: "key should be UPPER_SNAKE_CASE",
			Check:   func(k, _ string) bool { return reValidKey.MatchString(k) },
		},
		{
			Name:    "no-placeholder",
			Message: "value appears to be a placeholder",
			Check: func(_, v string) bool {
				upper := strings.ToUpper(v)
				for _, p := range placeholders {
					if strings.Contains(upper, strings.ToUpper(p)) {
						return false
					}
				}
				return true
			},
		},
		{
			Name:    "no-localhost-url",
			Message: "value contains a localhost URL (not suitable for production)",
			Check: func(_, v string) bool {
				if reURL.MatchString(v) {
					return !strings.Contains(v, "localhost") && !strings.Contains(v, "127.0.0.1")
				}
				return true
			},
		},
	}
}

// ValidateVault decrypts the vault at vaultPath using privKeyPath and runs
// all built-in validation rules against each entry. Additional custom rules
// may be supplied via extraRules. Returns a ValidationResult summarising any
// issues found.
func ValidateVault(vaultPath, privKeyPath string, extraRules []ValidationRule) (*ValidationResult, error) {
	entries, err := decryptVaultEntries(vaultPath, privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("validate: decrypt vault: %w", err)
	}

	rules := append(defaultRules(), extraRules...)
	result := &ValidationResult{Valid: true}

	for _, entry := range entries {
		if entry.Comment || strings.TrimSpace(entry.Key) == "" {
			continue
		}
		for _, rule := range rules {
			if !rule.Check(entry.Key, entry.Value) {
				result.Issues = append(result.Issues, ValidationIssue{
					Key:     entry.Key,
					Rule:    rule.Name,
					Message: rule.Message,
				})
				result.Valid = false
			}
		}
	}

	return result, nil
}

// FormatValidation returns a human-readable summary of a ValidationResult.
func FormatValidation(result *ValidationResult) string {
	if result.Valid {
		return "vault is valid — no issues found"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d issue(s) found:\n", len(result.Issues)))
	for _, issue := range result.Issues {
		sb.WriteString(fmt.Sprintf("  [%s] %s: %s\n", issue.Rule, issue.Key, issue.Message))
	}
	return strings.TrimRight(sb.String(), "\n")
}

// ensure env import is used for the Comment field reference
var _ = env.Entry{}
