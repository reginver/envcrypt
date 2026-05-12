package vault

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/yourusername/envcrypt/internal/crypto"
	"github.com/yourusername/envcrypt/internal/env"
)

// templateVarRe matches {{VAR_NAME}} placeholders in templates.
var templateVarRe = regexp.MustCompile(`\{\{([A-Z0-9_]+)\}\}`)

// RenderTemplate reads a template file, decrypts the given vault, and replaces
// all {{KEY}} placeholders with their corresponding vault values.
// Unknown placeholders are left unchanged unless strict is true, in which case
// an error is returned.
func RenderTemplate(templatePath, vaultPath, privKeyPath string, strict bool) (string, error) {
	tmplBytes, err := os.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("read template: %w", err)
	}

	identity, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return "", fmt.Errorf("load private key: %w", err)
	}

	ciphertext, err := os.ReadFile(vaultPath)
	if err != nil {
		return "", fmt.Errorf("read vault: %w", err)
	}

	plaintext, err := crypto.Decrypt(ciphertext, []interface{ Unwrap([]string) ([]byte, error) }{identity})
	if err != nil {
		return "", fmt.Errorf("decrypt vault: %w", err)
	}

	entries, err := env.Parse(strings.NewReader(string(plaintext)))
	if err != nil {
		return "", fmt.Errorf("parse vault: %w", err)
	}

	kvMap := env.ToMap(entries)

	var missing []string
	result := templateVarRe.ReplaceAllStringFunc(string(tmplBytes), func(match string) string {
		key := templateVarRe.FindStringSubmatch(match)[1]
		val, ok := kvMap[key]
		if !ok {
			missing = append(missing, key)
			return match
		}
		return val
	})

	if strict && len(missing) > 0 {
		return "", fmt.Errorf("template has unresolved placeholders: %s", strings.Join(missing, ", "))
	}

	return result, nil
}
