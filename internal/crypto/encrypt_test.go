package crypto_test

import (
	"testing"

	"filippo.io/age"
	"github.com/yourusername/envcrypt/internal/crypto"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	plaintext := []byte("DB_HOST=localhost\nDB_PORT=5432\nSECRET_KEY=supersecret")

	ciphertext, err := crypto.Encrypt(plaintext, []age.Recipient{kp.Recipient})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("Encrypt() returned empty ciphertext")
	}

	decrypted, err := crypto.Decrypt(ciphertext, []age.Identity{kp.Identity})
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptNoRecipients(t *testing.T) {
	_, err := crypto.Encrypt([]byte("data"), nil)
	if err == nil {
		t.Error("Encrypt() expected error with no recipients, got nil")
	}
}

func TestDecryptNoIdentities(t *testing.T) {
	_, err := crypto.Decrypt([]byte("data"), nil)
	if err == nil {
		t.Error("Decrypt() expected error with no identities, got nil")
	}
}

func TestParseKeyRoundtrip(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	parsedPub, err := crypto.ParsePublicKey(kp.PublicKeyString())
	if err != nil {
		t.Fatalf("ParsePublicKey() error = %v", err)
	}
	if parsedPub.String() != kp.PublicKeyString() {
		t.Errorf("ParsePublicKey() = %q, want %q", parsedPub.String(), kp.PublicKeyString())
	}

	parsedPriv, err := crypto.ParsePrivateKey(kp.PrivateKeyString())
	if err != nil {
		t.Fatalf("ParsePrivateKey() error = %v", err)
	}
	if parsedPriv.String() != kp.PrivateKeyString() {
		t.Errorf("ParsePrivateKey() = %q, want %q", parsedPriv.String(), kp.PrivateKeyString())
	}
}
