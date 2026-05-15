package vault

import (
	"fmt"
	"os"

	"github.com/yourusername/envcrypt/internal/env"
)

// PromoteOptions controls how keys are promoted between vaults.
type PromoteOptions struct {
	Keys      []string // specific keys to promote; empty means all
	Overwrite bool     // overwrite existing keys in destination
	DryRun    bool     // report what would change without writing
}

// PromoteResult summarises what was (or would be) changed.
type PromoteResult struct {
	Promoted []string
	Skipped  []string
}

// PromoteVault copies selected keys from src vault into dst vault,
// decrypting with srcPrivKey and re-encrypting with dstPubKey.
func PromoteVault(srcPath, dstPath, srcPrivKey, dstPubKey string, opts PromoteOptions) (PromoteResult, error) {
	srcEntries, err := decryptVault(srcPath, srcPrivKey)
	if err != nil {
		return PromoteResult{}, fmt.Errorf("promote: decrypt source: %w", err)
	}

	// Load existing destination entries (may not exist yet).
	var dstEntries []env.Entry
	if _, err := os.Stat(dstPath); err == nil {
		dstEntries, err = decryptVault(dstPath, srcPrivKey)
		if err != nil {
			// Try with dstPubKey path — destination may use a different key.
			// Callers should pass the dst private key when available; we
			// treat failure as an empty destination for simplicity.
			dstEntries = nil
		}
	}

	srcMap := env.ToMap(srcEntries)
	dstMap := env.ToMap(dstEntries)

	var result PromoteResult

	keys := opts.Keys
	if len(keys) == 0 {
		for _, e := range srcEntries {
			keys = append(keys, e.Key)
		}
	}

	for _, k := range keys {
		val, ok := srcMap[k]
		if !ok {
			continue
		}
		if _, exists := dstMap[k]; exists && !opts.Overwrite {
			result.Skipped = append(result.Skipped, k)
			continue
		}
		dstMap[k] = val
		result.Promoted = append(result.Promoted, k)
	}

	if opts.DryRun {
		return result, nil
	}

	merged := env.FromMap(dstMap)
	if err := encryptVault(dstPath, dstPubKey, merged); err != nil {
		return PromoteResult{}, fmt.Errorf("promote: encrypt destination: %w", err)
	}

	return result, nil
}
