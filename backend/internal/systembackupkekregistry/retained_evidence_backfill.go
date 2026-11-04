package systembackupkekregistry

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sort"
	"strconv"
)

const RetainedEvidencePurpose = "c1_retained_evidence.v1"
const RetainedEvidenceProvider = "vault-transit-evidence"

func validRetainedEvidenceBinding(b Binding) bool {
	r := b.Retention
	if r == nil || r.Purpose != RetainedEvidencePurpose || r.Source.SourceID == "" || r.Source.RecordID == "" || r.Source.RecordVersion == "" || !kekHash.MatchString(r.Source.ContentSHA256) || !kekHash.MatchString(r.KeyContextSHA256) || b.InstallationID == "" || b.Key.Provider != RetainedEvidenceProvider || !kekHash.MatchString(b.Key.IdentityHash) || b.Key.RegistryVersion == "" || b.Key.ProviderKeyID == "" || b.Provider.KeyName != b.Key.ProviderKeyID || b.ConfigRef != (ReferencePin{b.Key.IdentityHash, b.Key.RegistryVersion}) || b.Provider.Endpoint == "" || !kekHash.MatchString(b.Provider.ProviderIdentityHash) || b.Provider.ScopeHash != r.KeyContextSHA256 || !kekHash.MatchString(b.Provider.CAPEMSHA256) || b.Provider.CASource.SourceID == "" || b.Provider.CASource.RecordID == "" || b.Provider.CASource.RecordVersion == "" || !kekHash.MatchString(b.Provider.CASource.ContentSHA256) {
		return false
	}
	v, e := strconv.ParseUint(b.Key.ProviderVersion, 10, 32)
	return e == nil && v > 0 && strconv.FormatUint(v, 10) == b.Key.ProviderVersion && len(b.GenerateRef.RawJSON) == 0 && b.GenerateRef.SHA256 == "" && len(b.UnwrapRef.RawJSON) == 0 && b.UnwrapRef.SHA256 == ""
}

func (b *Bound) retentionOnly(identity, version string) bool {
	if b == nil {
		return false
	}
	for _, fact := range b.original.Bindings {
		if fact.Binding.Key.IdentityHash == identity && fact.Binding.Key.RegistryVersion == version {
			return fact.Binding.Retention != nil
		}
	}
	return false
}

// StageInitialRetainedEvidence runs ONLY inside D's original FIRST adoption
// transaction, after original B/C/source prefix locks and KEK fence, BEFORE
// original17 Stage/Bind/authentication/AdoptCoverage. It does not advance the
// fence: this private staging and adoption's one epoch change commit atomically.
// Any error requires rollback of that original transaction. This method has no
// Commit/Begin, native IO, permission minting, replacement or release path.
func (b *Bound) StageInitialRetainedEvidence(ctx context.Context, p PreparedRetainedEvidenceBackfill) error {
	if b == nil || b.tx == nil || !present(p) || ctx == nil || ctx.Err() != nil || b.epoch != b.original.Epoch || len(b.original.Coverage) != 0 || !SameSnapshotFacts(p.ExpectedSnapshot(), b.original) {
		return ErrKEKCoverage
	}
	bindings, refs := p.Bindings(), p.References()
	until := p.ValidUntil()
	if len(bindings) == 0 || len(bindings) > 20 || refs == nil || len(refs) == 0 || len(refs) > 4096 {
		return ErrKEKFacts
	}
	// Detach before any trusted owner callback or SQL wait.
	next := cloneSnapshot(Snapshot{Database: b.original.Database, InstallationID: b.installationID, Bindings: make([]BindingFacts, len(bindings)), References: refs})
	for n, binding := range bindings {
		next.Bindings[n].Binding = binding
	}
	next = cloneSnapshot(next)
	bindings = make([]Binding, len(next.Bindings))
	for n := range next.Bindings {
		bindings[n] = next.Bindings[n].Binding
	}
	known := map[ReferencePin]Binding{}
	for _, binding := range bindings {
		if binding.InstallationID != b.installationID || !validRetainedEvidenceBinding(binding) {
			return ErrKEKFacts
		}
		if _, exists := known[binding.ConfigRef]; exists {
			return ErrKEKFacts
		}
		known[binding.ConfigRef] = binding
	}
	refs = next.References
	seen := map[string]bool{}
	for _, r := range refs {
		binding, ok := known[ReferencePin{r.Key.IdentityHash, r.Key.RegistryVersion}]
		fingerprint, e := BindingFingerprint(binding)
		key := string(r.Partition) + "\x00" + r.SourceRecordID + "\x00" + r.SourceRecordVersion
		if !ok || e != nil || r.Key != binding.Key || r.BindingSHA256 != fingerprint || r.State != ReferenceRetained || (r.Partition != RetainedArtifacts && r.Partition != HoldsAndCatalog) || r.SourceRecordID == "" || len(r.SourceRecordID) > 256 || r.SourceRecordVersion == "" || len(r.SourceRecordVersion) > 128 || seen[key] || r.MappingSource != binding.Retention.Source || r.ExpectedRequestSource.SourceID == "" || !kekHash.MatchString(r.ExpectedRequestSource.ContentSHA256) || r.LifecycleSource.SourceID == "" || !kekHash.MatchString(r.LifecycleSource.ContentSHA256) {
			return ErrKEKFacts
		}
		seen[key] = true
	}
	now, e := b.sqlNow(ctx)
	if e != nil || !now.Before(until) || p.RecheckOriginalRetained(ctx, b.tx, b.Snapshot(), now) != nil || !p.ValidUntil().Equal(until) || !SameSnapshotFacts(p.ExpectedSnapshot(), b.original) {
		return ErrKEKCoverage
	}
	sort.Slice(bindings, func(i, j int) bool {
		if bindings[i].Key.IdentityHash != bindings[j].Key.IdentityHash {
			return bindings[i].Key.IdentityHash < bindings[j].Key.IdentityHash
		}
		return bindings[i].Key.RegistryVersion < bindings[j].Key.RegistryVersion
	})
	for _, binding := range bindings {
		raw, _, e := hashJSON(binding)
		core, ce := semanticCoreHash(binding)
		fingerprint, fe := BindingFingerprint(binding)
		if e != nil || ce != nil || fe != nil || len(raw) > 1<<20 {
			return ErrKEKFacts
		}
		var oldRaw []byte
		var oldHash string
		e = b.tx.QueryRowContext(ctx, `SELECT binding_sha256,core_json FROM system_backup_v2_kek_bindings WHERE installation_id=? AND identity_hash=? AND registry_version=? FOR UPDATE`, b.installationID, binding.Key.IdentityHash, binding.Key.RegistryVersion).Scan(&oldHash, &oldRaw)
		if !errors.Is(e, sql.ErrNoRows) {
			return ErrKEKFacts
		} // No conversion/replacement/idempotent reissue.
		result, e := b.tx.ExecContext(ctx, `INSERT INTO system_backup_v2_kek_bindings(installation_id,identity_hash,registry_version,binding_sha256,core_sha256,core_json) VALUES (?,?,?,?,?,?)`, b.installationID, binding.Key.IdentityHash, binding.Key.RegistryVersion, fingerprint, core, raw)
		if e != nil {
			return e
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return ErrKEKFacts
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		a, c := refs[i], refs[j]
		if a.Partition != c.Partition {
			return a.Partition < c.Partition
		}
		if a.SourceRecordID != c.SourceRecordID {
			return a.SourceRecordID < c.SourceRecordID
		}
		return a.SourceRecordVersion < c.SourceRecordVersion
	})
	for _, r := range refs {
		raw, digest, e := hashJSON(r)
		if e != nil || len(raw) > 1<<20 {
			return ErrKEKFacts
		}
		var old []byte
		e = b.tx.QueryRowContext(ctx, `SELECT reference_json FROM system_backup_v2_kek_references WHERE installation_id=? AND partition_name=? AND source_record_id=? AND source_record_version=? FOR UPDATE`, b.installationID, r.Partition, r.SourceRecordID, r.SourceRecordVersion).Scan(&old)
		if !errors.Is(e, sql.ErrNoRows) {
			return ErrKEKFacts
		}
		result, e := b.tx.ExecContext(ctx, `INSERT INTO system_backup_v2_kek_references(installation_id,partition_name,source_record_id,source_record_version,identity_hash,registry_version,reference_state,reference_sha256,reference_json) VALUES (?,?,?,?,?,?,?,?,?)`, b.installationID, r.Partition, r.SourceRecordID, r.SourceRecordVersion, r.Key.IdentityHash, r.Key.RegistryVersion, r.State, digest, raw)
		if e != nil {
			return e
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return ErrKEKFacts
		}
	}
	actual := cloneSnapshot(b.original)
	actual.Bindings = []BindingFacts{}
	actual.References = []Reference{}
	if readBindings(ctx, b.tx, &actual, true) != nil || readReferences(ctx, b.tx, &actual, true) != nil {
		return ErrKEKFacts
	}
	wantBindings := append(append([]BindingFacts(nil), b.original.Bindings...), next.Bindings...)
	if len(actual.Bindings) != len(wantBindings) || len(actual.References) != len(b.original.References)+len(refs) {
		return ErrKEKFacts
	}
	for _, old := range b.original.Bindings {
		matched := false
		for _, fact := range actual.Bindings {
			if reflect.DeepEqual(old, fact) {
				matched = true
			}
		}
		if !matched {
			return ErrKEKFacts
		}
	}
	for _, binding := range bindings {
		matched := false
		for _, fact := range actual.Bindings {
			if reflect.DeepEqual(fact.Binding, binding) && fact.RowVersion == 1 && fact.GenerateRevoked == nil && fact.UnwrapRevoked == nil {
				matched = true
			}
		}
		if !matched {
			return ErrKEKFacts
		}
	}
	wantRefs := append(append([]Reference(nil), b.original.References...), refs...)
	for _, r := range wantRefs {
		matched := false
		want, _, _ := hashJSON(r)
		for _, got := range actual.References {
			raw, _, _ := hashJSON(got)
			if bytes.Equal(want, raw) {
				matched = true
			}
		}
		if !matched {
			return ErrKEKFacts
		}
	}
	now, e = b.sqlNow(ctx)
	if e != nil || !now.Before(until) || !p.ValidUntil().Equal(until) {
		return ErrKEKCoverage
	}
	b.original = actual
	return nil
}
