package vault

import (
	"fmt"

	"github.com/yourusername/envcrypt/internal/env"
)

// MergeStrategy controls how conflicting keys are resolved during merge.
type MergeStrategy int

const (
	// MergeStrategyOurs keeps the destination value on conflict.
	MergeStrategyOurs MergeStrategy = iota
	// MergeStrategyTheirs overwrites with the source value on conflict.
	MergeStrategyTheirs
)

// MergeVault merges entries from srcPath into dstPath using the given strategy.
// Both vaults are decrypted with their respective key pairs before merging.
func MergeVault(srcPath, dstPath, pubKeyPath, privKeyPath string, strategy MergeStrategy) (int, error) {
	pub, err := LoadPublicKey(pubKeyPath)
	if err != nil {
		return 0, fmt.Errorf("load public key: %w", err)
	}
	priv, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return 0, fmt.Errorf("load private key: %w", err)
	}

	v := New(pub, priv)

	srcEntries, err := v.Decrypt(srcPath)
	if err != nil {
		return 0, fmt.Errorf("decrypt source vault: %w", err)
	}

	dstEntries, err := v.Decrypt(dstPath)
	if err != nil {
		return 0, fmt.Errorf("decrypt destination vault: %w", err)
	}

	srcMap := env.ToMap(srcEntries)
	dstMap := env.ToMap(dstEntries)

	added := 0
	for k, srcVal := range srcMap {
		if _, exists := dstMap[k]; !exists {
			dstMap[k] = srcVal
			added++
		} else if strategy == MergeStrategyTheirs {
			dstMap[k] = srcVal
			added++
		}
	}

	merged := env.FromMap(dstMap, dstEntries)
	if err := v.Encrypt(dstPath, merged); err != nil {
		return 0, fmt.Errorf("encrypt merged vault: %w", err)
	}

	return added, nil
}
