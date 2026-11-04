package systembackupkekregistry

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"reflect"
)

// StageAdmission appends the exact independently prepared mapping to the
// caller's original config/operation transaction. The operation and config
// rows are read back together after commit before any production use.
func (b *Bound) StageAdmission(ctx context.Context, operationID string, configVersion uint64, prepared PreparedAdmission) error {
	if b == nil || b.tx == nil || operationID == "" || len(operationID) > 128 || configVersion == 0 || !present(prepared) || !present(prepared.OriginalMapping()) {
		return ErrKEKFacts
	}
	binding := prepared.Binding()
	if binding.Retention != nil {
		return ErrKEKFacts
	}
	observation := prepared.Observation()
	mapping := prepared.OriginalMapping()
	if binding.InstallationID != b.installationID || observation.InstallationID != b.installationID || binding.ConfigRef.IdentityHash != binding.Key.IdentityHash || binding.ConfigRef.Version != binding.Key.RegistryVersion || !kekHash.MatchString(binding.Key.IdentityHash) || !kekHash.MatchString(observation.ConfigSHA256) ||
		mapping.Source() != observation.MappingSource || mapping.SourceRevision() != observation.SourceRevision || !reflect.DeepEqual(mapping.Binding(), binding) || !SameSnapshotFacts(prepared.ExpectedSnapshot(), b.original) || len(b.original.Coverage) != 4 || b.epoch != b.original.Epoch {
		return ErrKEKCoverage
	}
	if err := b.Recheck(ctx, prepared); err != nil {
		return err
	}
	core, _, err := hashJSON(binding)
	if err != nil || len(core) > 1<<20 {
		return ErrKEKFacts
	}
	coreHash, err := semanticCoreHash(binding)
	if err != nil {
		return err
	}
	bindingHash, err := BindingFingerprint(binding)
	if err != nil {
		return err
	}
	var oldCoreHash, oldBindingHash string
	var oldCore []byte
	err = b.tx.QueryRowContext(ctx, `SELECT core_sha256,binding_sha256,core_json FROM system_backup_v2_kek_bindings WHERE installation_id=? AND identity_hash=? AND registry_version=? FOR SHARE`, b.installationID, binding.Key.IdentityHash, binding.Key.RegistryVersion).Scan(&oldCoreHash, &oldBindingHash, &oldCore)
	changed := false
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = b.tx.ExecContext(ctx, `INSERT INTO system_backup_v2_kek_bindings(installation_id,identity_hash,registry_version,binding_sha256,core_sha256,core_json) VALUES (?,?,?,?,?,?)`, b.installationID, binding.Key.IdentityHash, binding.Key.RegistryVersion, bindingHash, coreHash, core)
		if err != nil {
			return err
		}
		changed = true
	case err != nil:
		return err
	case oldCoreHash != coreHash || oldBindingHash != bindingHash || len(oldCore) == 0:
		return ErrKEKFacts
	}
	// Store the exact refs and their SHA per admission. The first binding row
	// remains unchanged when a later config changes redacted descriptions.
	obsRaw, obsHash, err := hashJSON(struct {
		Observation AdmissionObservation
		GenerateRef TypedReference
		UnwrapRef   TypedReference
	}{observation, binding.GenerateRef, binding.UnwrapRef})
	if err != nil || len(obsRaw) > 65535 {
		return ErrKEKFacts
	}
	var oldConfig, oldIdentity, oldVersion, oldObsHash string
	var oldConfigVersion uint64
	var oldObs []byte
	err = b.tx.QueryRowContext(ctx, `SELECT config_sha256,config_version,identity_hash,registry_version,observation_sha256,observation_json FROM system_backup_v2_kek_admissions WHERE installation_id=? AND operation_id=? FOR SHARE`, b.installationID, operationID).Scan(&oldConfig, &oldConfigVersion, &oldIdentity, &oldVersion, &oldObsHash, &oldObs)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = b.tx.ExecContext(ctx, `INSERT INTO system_backup_v2_kek_admissions(installation_id,operation_id,config_sha256,config_version,identity_hash,registry_version,observation_sha256,observation_json) VALUES (?,?,?,?,?,?,?,?)`, b.installationID, operationID, observation.ConfigSHA256, configVersion, binding.Key.IdentityHash, binding.Key.RegistryVersion, obsHash, obsRaw)
		if err != nil {
			return err
		}
		changed = true
	case err != nil:
		return err
	case oldConfig != observation.ConfigSHA256 || oldConfigVersion != configVersion || oldIdentity != binding.Key.IdentityHash || oldVersion != binding.Key.RegistryVersion || oldObsHash != obsHash || !bytes.Equal(oldObs, obsRaw):
		return ErrKEKFacts
	}
	if changed {
		return b.advance(ctx)
	}
	return nil
}

// RetainPlanned is invoked before the original owner commits a provider-use
// reserve/send intent. A duplicate exact member is idempotent; conflicting
// source identity or unknown external outcome cannot be replaced.
func (b *Bound) RetainPlanned(ctx context.Context, prepared PreparedReferenceChange) error {
	if ctx == nil || ctx.Err() != nil || b == nil || b.tx == nil || !present(prepared) || prepared.ExpectedEpoch() != b.epoch || b.epoch != b.original.Epoch {
		return ErrKEKFacts
	}
	r := prepared.Reference()
	if b.retentionOnly(r.Key.IdentityHash, r.Key.RegistryVersion) {
		return ErrKEKFacts
	}
	if r.State != ReferencePlanned || !validPartition(r.Partition) || r.SourceRecordID == "" || len(r.SourceRecordID) > 256 || r.SourceRecordVersion == "" || len(r.SourceRecordVersion) > 128 || !kekHash.MatchString(r.BindingSHA256) || prepared.Source().RecordID != r.SourceRecordID || prepared.Source().RecordVersion != r.SourceRecordVersion {
		return ErrKEKFacts
	}
	var bindingHash string
	var revoked []byte
	if err := b.tx.QueryRowContext(ctx, `SELECT binding_sha256,generate_revocation_json FROM system_backup_v2_kek_bindings WHERE installation_id=? AND identity_hash=? AND registry_version=? FOR SHARE`, b.installationID, r.Key.IdentityHash, r.Key.RegistryVersion).Scan(&bindingHash, &revoked); err != nil || bindingHash != r.BindingSHA256 || len(revoked) != 0 {
		return ErrKEKFacts
	}
	now, err := b.sqlNow(ctx)
	if err != nil || !now.Before(prepared.ValidUntil()) || prepared.Recheck(ctx, b.tx, b.Snapshot(), now) != nil {
		return ErrKEKFacts
	}
	raw, digest, err := hashJSON(r)
	if err != nil || len(raw) > 1<<20 {
		return ErrKEKFacts
	}
	var oldDigest string
	var oldRaw []byte
	err = b.tx.QueryRowContext(ctx, `SELECT reference_sha256,reference_json FROM system_backup_v2_kek_references WHERE installation_id=? AND partition_name=? AND source_record_id=? AND source_record_version=? FOR SHARE`, b.installationID, r.Partition, r.SourceRecordID, r.SourceRecordVersion).Scan(&oldDigest, &oldRaw)
	if err == nil {
		if oldDigest != digest || !bytes.Equal(oldRaw, raw) {
			return ErrKEKFacts
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err = b.tx.ExecContext(ctx, `INSERT INTO system_backup_v2_kek_references(installation_id,partition_name,source_record_id,source_record_version,identity_hash,registry_version,reference_state,reference_sha256,reference_json) VALUES (?,?,?,?,?,?,?,?,?)`, b.installationID, r.Partition, r.SourceRecordID, r.SourceRecordVersion, r.Key.IdentityHash, r.Key.RegistryVersion, r.State, digest, raw); err != nil {
		return err
	}
	return b.advance(ctx)
}
