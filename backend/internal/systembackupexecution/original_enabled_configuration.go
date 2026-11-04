package systembackupexecution

import (
	"bytes"
	"context"

	d "clawreef/internal/systembackupdispatch"
	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
)

// Read-only consumption of A's actual closed SQL lineage, never a local JSON
// inference or an edited material hash. The supplied old SHA is independently
// pinned by the original Forward or signed owner policy; current bytes belong
// to the caller's actual active/task SQL view. Every new view reads its proof.
func readOriginalEnabledConfiguration(ctx context.Context, view reg.SQLReadView, installation, originalSHA string, currentVersion uint64, currentSHA string, currentRaw []byte) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || !formalCandidateDigest(originalSHA) || !formalCandidateDigest(currentSHA) || currentVersion == 0 || len(currentRaw) < 2 || len(currentRaw) > 262144 || hash(currentRaw) != currentSHA {
		return nil, d.ErrNotReady
	}
	if originalSHA == currentSHA {
		return bytes.Clone(currentRaw), nil
	}
	proof, err := sec.ReadOriginalEnabledOnlyLineage(ctx, view, installation, originalSHA, currentVersion, currentSHA)
	if err != nil || !proof.Matches(installation, originalSHA, currentVersion, currentSHA) {
		return nil, d.ErrNotReady
	}
	// A authenticated canonical bytes, every denormalized cell, the actual
	// enable operation/response/MFA and committed KEK mapping in THIS view.
	// Read that same immutable v1 for original policy evidence verification;
	// keep the effective v2 task and its original authority unchanged.
	var raw []byte
	var sum string
	var size int64
	if view.QueryRowContext(ctx, "SELECT canonical_config_json,config_sha256,config_size_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=1", installation).Scan(&raw, &sum, &size) != nil || len(raw) < 2 || len(raw) > 262144 || size != int64(len(raw)) || sum != originalSHA || hash(raw) != originalSHA {
		return nil, d.ErrNotReady
	}
	values, err := sec.DecodeConfigValues(raw)
	if err != nil || values.SHA256() != originalSHA || !bytes.Equal(values.CanonicalJSON(), raw) || ctx.Err() != nil {
		return nil, d.ErrNotReady
	}
	authorizedSHA, err := proof.AuthorizationConfigSHA256(ctx, view)
	if err != nil || authorizedSHA != originalSHA {
		return nil, d.ErrNotReady
	}
	return bytes.Clone(raw), nil
}
