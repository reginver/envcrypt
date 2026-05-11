package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yourusername/envcrypt/internal/vault"
)

func setupPinVault(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "test.env.age")
}

func TestPinKeyAddsPin(t *testing.T) {
	vaultFile := setupPinVault(t)
	if err := vault.PinKey(vaultFile, "DB_PASSWORD", "critical secret"); err != nil {
		t.Fatalf("PinKey failed: %v", err)
	}
	pins, err := vault.ListPins(vaultFile)
	if err != nil {
		t.Fatalf("ListPins failed: %v", err)
	}
	if len(pins) != 1 {
		t.Fatalf("expected 1 pin, got %d", len(pins))
	}
	if pins[0].Key != "DB_PASSWORD" {
		t.Errorf("expected key DB_PASSWORD, got %s", pins[0].Key)
	}
	if pins[0].Note != "critical secret" {
		t.Errorf("unexpected note: %s", pins[0].Note)
	}
}

func TestPinKeyDuplicate(t *testing.T) {
	vaultFile := setupPinVault(t)
	if err := vault.PinKey(vaultFile, "API_KEY", ""); err != nil {
		t.Fatalf("first PinKey failed: %v", err)
	}
	if err := vault.PinKey(vaultFile, "API_KEY", ""); err == nil {
		t.Error("expected error for duplicate pin, got nil")
	}
}

func TestUnpinKey(t *testing.T) {
	vaultFile := setupPinVault(t)
	_ = vault.PinKey(vaultFile, "SECRET", "")
	if err := vault.UnpinKey(vaultFile, "SECRET"); err != nil {
		t.Fatalf("UnpinKey failed: %v", err)
	}
	pins, _ := vault.ListPins(vaultFile)
	if len(pins) != 0 {
		t.Errorf("expected 0 pins after unpin, got %d", len(pins))
	}
}

func TestUnpinKeyNotFound(t *testing.T) {
	vaultFile := setupPinVault(t)
	if err := vault.UnpinKey(vaultFile, "MISSING_KEY"); err == nil {
		t.Error("expected error for unpinning non-existent key")
	}
}

func TestListPinsEmpty(t *testing.T) {
	vaultFile := setupPinVault(t)
	pins, err := vault.ListPins(vaultFile)
	if err != nil {
		t.Fatalf("ListPins failed: %v", err)
	}
	if len(pins) != 0 {
		t.Errorf("expected empty pin list, got %d", len(pins))
	}
}

func TestPinFilePermissions(t *testing.T) {
	vaultFile := setupPinVault(t)
	_ = vault.PinKey(vaultFile, "TOKEN", "")
	dir := filepath.Dir(vaultFile)
	base := filepath.Base(vaultFile)
	pinFile := filepath.Join(dir, "."+base+".pins.json")
	info, err := os.Stat(pinFile)
	if err != nil {
		t.Fatalf("pin file not found: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %v", info.Mode().Perm())
	}
}
