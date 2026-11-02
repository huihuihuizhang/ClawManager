package systembackupkekregistry

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
)

type admissionRecord struct {
	Observation AdmissionObservation
	GenerateRef TypedReference
	UnwrapRef   TypedReference
}

// ReadCommitted resolves historical mapping bytes only after the original
// config and succeeded operation can be read back together. It grants neither
// Generate nor Unwrap; each use still needs current independent authority.
func (SQLStore) ReadCommitted(ctx context.Context, db *sql.DB, installationID, operationID string) (Binding, AdmissionObservation, error) {
	if ctx == nil || ctx.Err() != nil || db == nil || installationID == "" || operationID == "" {
		return Binding{}, AdmissionObservation{}, ErrKEKFacts
	}
	return (SQLStore{}).ReadCommittedInView(ctx, db, installationID, operationID)
}

// ReadCommittedInView compares the immutable prior admission/config/succeeded
// operation inside the original caller's read capability. It deliberately adds
// no FOR UPDATE/SHARE locks after a historical branch and does not consult live
// provider material, refresh an observation, open a DB or grant any key use.
func (SQLStore) ReadCommittedInView(ctx context.Context, view SQLReadView, installationID, operationID string) (Binding, AdmissionObservation, error) {
	if ctx == nil || ctx.Err() != nil || !present(view) || installationID == "" || operationID == "" {
		return Binding{}, AdmissionObservation{}, ErrKEKFacts
	}
	var coreRaw, obsRaw []byte
	var coreHash, bindingHash, obsHash, identity, version, configHash string
	err := view.QueryRowContext(ctx, `SELECT b.core_json,b.core_sha256,b.binding_sha256,a.observation_json,a.observation_sha256,a.identity_hash,a.registry_version,a.config_sha256
		FROM system_backup_v2_kek_admissions a
		JOIN system_backup_v2_kek_bindings b ON b.installation_id=a.installation_id AND b.identity_hash=a.identity_hash AND b.registry_version=a.registry_version
		JOIN system_backup_v2_configs c ON c.origin_installation_id=a.installation_id AND c.version=a.config_version AND c.config_sha256=a.config_sha256 AND c.kek_identity_hash=a.identity_hash AND c.kek_ref_version=a.registry_version
		JOIN system_backup_v2_operations o ON o.origin_installation_id=a.installation_id AND o.public_id=a.operation_id AND o.operation_type='config_update' AND o.status='succeeded' AND o.result_config_version=a.config_version
		WHERE a.installation_id=? AND a.operation_id=?`, installationID, operationID).Scan(&coreRaw, &coreHash, &bindingHash, &obsRaw, &obsHash, &identity, &version, &configHash)
	if err != nil {
		return Binding{}, AdmissionObservation{}, ErrKEKFacts
	}
	var binding Binding
	var observation admissionRecord
	if json.Unmarshal(coreRaw, &binding) != nil || json.Unmarshal(obsRaw, &observation) != nil || binding.InstallationID != installationID || observation.Observation.InstallationID != installationID || observation.Observation.ConfigSHA256 != configHash || binding.Key.IdentityHash != identity || binding.Key.RegistryVersion != version {
		return Binding{}, AdmissionObservation{}, ErrKEKFacts
	}
	core, _, err := hashJSON(binding)
	semantic, semanticErr := semanticCoreHash(binding)
	obs, observedHash, obsErr := hashJSON(observation)
	fingerprint, fpErr := BindingFingerprint(binding)
	if err != nil || semanticErr != nil || obsErr != nil || fpErr != nil || semantic != coreHash || observedHash != obsHash || fingerprint != bindingHash || !bytes.Equal(core, coreRaw) || !bytes.Equal(obs, obsRaw) {
		return Binding{}, AdmissionObservation{}, ErrKEKFacts
	}
	binding.GenerateRef = observation.GenerateRef
	binding.UnwrapRef = observation.UnwrapRef
	if current, err := semanticCoreHash(binding); err != nil || current != coreHash {
		return Binding{}, AdmissionObservation{}, ErrKEKFacts
	}
	return cloneBinding(binding), observation.Observation, nil
}
