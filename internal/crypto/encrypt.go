package crypto

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
)

// Encrypt encrypts plaintext data using the provided age recipients.
// Returns the encrypted ciphertext as a byte slice.
func Encrypt(plaintext []byte, recipients []age.Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("failed to create age encryptor: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("failed to write plaintext: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize encryption: %w", err)
	}

	return buf.Bytes(), nil
}

// Decrypt decrypts ciphertext data using the provided age identities.
// Returns the decrypted plaintext as a byte slice.
func Decrypt(ciphertext []byte, identities []age.Identity) ([]byte, error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("at least one identity is required")
	}

	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext must not be empty")
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return nil, fmt.Errorf("failed to create age decryptor: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return plaintext, nil
}
