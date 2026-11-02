package systembackupkekregistry

import (
	"bytes"
	"context"
	"encoding/json"
)

const bindingReadColumns = `identity_hash,registry_version,binding_sha256,core_sha256,core_json,row_version,generate_revocation_json,unwrap_revocation_json`

// ReadBindingTx reads current comparison facts in the caller's ORIGINAL
// transaction. The owner must already hold its earlier domain/authorization
// locks; this method takes the existing KEK fence FOR SHARE before the exact
// binding FOR SHARE, preserving the original fence-before-binding order.
//
// It does not create a fence, begin/commit a transaction, perform a write or
// grant authority. In particular it works with a caller-owned ReadOnlyTx and
// must not be replaced with Bind (which INSERTs). The consumer must compare
// SameSecurityBinding against its authenticated mapping and check the required
// purpose's current revocation; a returned row alone authorizes nothing.
func (s *SQLStore) ReadBindingTx(ctx context.Context, view SQLReadView, installation string, pin ReferencePin) (BindingFacts, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !present(view) || installation == "" || len(installation) > 128 ||
		!kekHash.MatchString(pin.IdentityHash) || pin.Version == "" || len(pin.Version) > 128 {
		return BindingFacts{}, ErrKEKFacts
	}
	var epoch uint64
	if err := view.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR SHARE`, installation).Scan(&epoch); err != nil {
		return BindingFacts{}, ErrKEKFacts
	}
	// A valid installation has a unique exact binding. LIMIT 2 also bounds a
	// malformed source and allows an explicit duplicate check rather than taking
	// an arbitrary first row. No installation-wide scan is needed.
	rows, err := view.QueryContext(ctx, `SELECT `+bindingReadColumns+` FROM system_backup_v2_kek_bindings WHERE installation_id=? AND identity_hash=? AND registry_version=? LIMIT 2 FOR SHARE`, installation, pin.IdentityHash, pin.Version)
	if err != nil {
		return BindingFacts{}, ErrKEKFacts
	}
	defer rows.Close()
	if !rows.Next() {
		return BindingFacts{}, ErrKEKFacts
	}
	facts, err := scanBindingRow(rows, installation)
	if err != nil || facts.Binding.ConfigRef != pin || rows.Next() || rows.Err() != nil {
		return BindingFacts{}, ErrKEKFacts
	}
	return facts, nil
}

// scanBindingRow is shared with the original snapshot/Bind reader. Keep one
// implementation of its canonical core, semantic hash, key fingerprint and
// independent purpose revocation parsing; this extraction changes no checks.
func scanBindingRow(row interface{ Scan(...any) error }, installation string) (BindingFacts, error) {
	var key, version, bindingHash, coreHash string
	var raw []byte
	var rowVersion uint64
	var generate, unwrap []byte
	if row.Scan(&key, &version, &bindingHash, &coreHash, &raw, &rowVersion, &generate, &unwrap) != nil || !kekHash.MatchString(key) || rowVersion == 0 || len(raw) == 0 {
		return BindingFacts{}, ErrKEKFacts
	}
	var binding Binding
	if json.Unmarshal(raw, &binding) != nil || binding.InstallationID != installation || binding.Key.IdentityHash != key || binding.Key.RegistryVersion != version || binding.ConfigRef != (ReferencePin{key, version}) {
		return BindingFacts{}, ErrKEKFacts
	}
	canonical, _, err := hashJSON(binding)
	semanticDigest, semanticErr := semanticCoreHash(binding)
	fingerprint, fpErr := BindingFingerprint(binding)
	if err != nil || semanticErr != nil || fpErr != nil || semanticDigest != coreHash || !bytes.Equal(canonical, raw) || fingerprint != bindingHash {
		return BindingFacts{}, ErrKEKFacts
	}
	facts := BindingFacts{Binding: binding, BindingSHA256: bindingHash, RowVersion: rowVersion}
	if len(generate) != 0 {
		var rev Revocation
		if json.Unmarshal(generate, &rev) != nil || rev.Purpose != GenerateRevocation {
			return BindingFacts{}, ErrKEKFacts
		}
		facts.GenerateRevoked = &rev
	}
	if len(unwrap) != 0 {
		var rev Revocation
		if json.Unmarshal(unwrap, &rev) != nil || rev.Purpose != UnwrapRevocation {
			return BindingFacts{}, ErrKEKFacts
		}
		facts.UnwrapRevoked = &rev
	}
	return facts, nil
}
