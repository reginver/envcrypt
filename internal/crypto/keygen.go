package crypto

import (
	"fmt"
	"strings"

	"filippo.io/age"
)

// KeyPair holds an age X25519 identity (private key) and its corresponding recipient (public key).
type KeyPair struct {
	Identity  *age.X25519Identity
	Recipient *age.X25519Recipient
}

// GenerateKeyPair generates a new age X25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("failed to generate age identity: %w", err)
	}

	return &KeyPair{
		Identity:  identity,
		Recipient: identity.Recipient(),
	}, nil
}

// PrivateKeyString returns the private key as an age-encoded string.
func (kp *KeyPair) PrivateKeyString() string {
	return kp.Identity.String()
}

// PublicKeyString returns the public key as an age-encoded string.
func (kp *KeyPair) PublicKeyString() string {
	return kp.Recipient.String()
}

// ParsePublicKey parses an age X25519 public key string into a Recipient.
func ParsePublicKey(pubKey string) (*age.X25519Recipient, error) {
	recipient, err := age.ParseX25519Recipient(strings.TrimSpace(pubKey))
	if err != nil {
		return nil, fmt.Errorf("invalid public key %q: %w", pubKey, err)
	}
	return recipient, nil
}

// ParsePrivateKey parses an age X25519 private key string into an Identity.
func ParsePrivateKey(privKey string) (*age.X25519Identity, error) {
	identity, err := age.ParseX25519Identity(strings.TrimSpace(privKey))
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	return identity, nil
}
