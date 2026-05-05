package crypto_test

import (
	"strings"
	"testing"

	"github.com/yourusername/envcrypt/internal/crypto"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	if kp.Identity == nil {
		t.Error("GenerateKeyPair() Identity is nil")
	}
	if kp.Recipient == nil {
		t.Error("GenerateKeyPair() Recipient is nil")
	}
}

func TestKeyPairStrings(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	privKey := kp.PrivateKeyString()
	if !strings.HasPrefix(privKey, "AGE-SECRET-KEY-") {
		t.Errorf("PrivateKeyString() = %q, expected prefix AGE-SECRET-KEY-", privKey)
	}

	pubKey := kp.PublicKeyString()
	if !strings.HasPrefix(pubKey, "age1") {
		t.Errorf("PublicKeyString() = %q, expected prefix age1", pubKey)
	}
}

func TestParsePublicKeyInvalid(t *testing.T) {
	_, err := crypto.ParsePublicKey("not-a-valid-key")
	if err == nil {
		t.Error("ParsePublicKey() expected error for invalid key, got nil")
	}
}

func TestParsePrivateKeyInvalid(t *testing.T) {
	_, err := crypto.ParsePrivateKey("not-a-valid-key")
	if err == nil {
		t.Error("ParsePrivateKey() expected error for invalid key, got nil")
	}
}

func TestGenerateKeyPairUniqueness(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()

	if kp1.PublicKeyString() == kp2.PublicKeyString() {
		t.Error("GenerateKeyPair() produced duplicate public keys")
	}
}
