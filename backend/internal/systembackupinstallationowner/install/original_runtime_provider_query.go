package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"time"

	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	kms "clawreef/internal/systembackupkms"
)

type OriginalRuntimeProviderQueryResult struct {
	Version, State               string
	MaterialState                string
	SQLMetadataReceipt           BootstrapSourceFilePin
	OriginalUntil, CheckedAt     time.Time
	OriginalAuthorizationExpired bool
	RetryAllowed                 bool
	PendingProviderResult        BootstrapSourceFilePin
	ProviderResult               *OriginalRuntimeProviderIssueReceipt `json:",omitempty"`
}

// Across-process original SQL commit READBACK only. No hold reconstruction,
// re-signing, deadline extension, config, task or recovery operation occurs.
// A staged file alone never proves COMMIT. Missing/drifted/GC'd rows remain
// unconfirmed; this API never concludes "safe to retry" from their absence.
func (i *Installer) QueryOriginalRuntimeProviderInstallation(ctx context.Context, password []byte, enrollment EnrollmentPin, pin, pending BootstrapSourceFilePin) (OriginalRuntimeProviderQueryResult, error) {
	result := OriginalRuntimeProviderQueryResult{Version: "original-runtime-provider-query.v1", MaterialState: "not_verified", State: "commit_unknown_original_rows_not_confirmed", SQLMetadataReceipt: pin, PendingProviderResult: pending, RetryAllowed: false}
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil {
		return result, ErrInstall
	}
	raw, e := readBootstrapSourcePin(pin, originalRuntimeMetadataLimit)
	var signed signedOriginalRuntimeSQLMetadataReceipt
	var receipt originalRuntimeSQLMetadataReceipt
	if e != nil || decodeOriginalRuntimeMetadata(raw, &signed) != nil || decodeOriginalRuntimeMetadata(signed.Record, &receipt) != nil || receipt.Version != "original-runtime-installed-sql-metadata.v1" || receipt.PlanSHA256 != i.planHash || receipt.Target != i.plan.Target || receipt.Enrollment != enrollment {
		return result, ErrInstall
	}
	material, e := i.readOriginalRuntimeIssuerMaterial(receipt.Issuers, enrollment)
	if e != nil {
		return result, ErrInstall
	}
	mappingPublic, e := readBootstrapSourcePin(material.Issuers["installation_mapping"].PublicKey, 32)
	if e != nil || !ed25519.Verify(mappingPublic, append([]byte(originalRuntimeSQLMetadataReceiptDomain), signed.Record...), signed.Signature) {
		return result, ErrInstall
	}
	want := receipt.Snapshot
	database := want.Database
	if database.ServerUUID != i.plan.Target.ServerUUID || database.Database != i.plan.Target.Database || want.InstallationID != i.plan.Target.InstallationID || want.FenceBefore == ^uint64(0) || want.FenceAfter != want.FenceBefore+1 || receipt.Until.IsZero() || len(want.Rows) != 3 || len(want.Capabilities) != 3 {
		return result, ErrInstall
	}
	var mapping a.OriginalRecord
	if json.Unmarshal(want.MappingRecord, &mapping) != nil || a.InspectOriginalKEKMaterial(want.MappingRecord, want.MappingSignature, mappingPublic, hash(want.MappingRecord), want.InstallationID, mapping.Revision, mapping.Binding.ConfigRef, want.ObservedAt) != nil || receipt.Until.After(mapping.Until) {
		return result, ErrInstall
	}
	permissionPublic, e := readBootstrapSourcePin(material.Issuers["provider_permission"].PublicKey, 32)
	if e != nil {
		return result, ErrInstall
	}
	generate, unwrap := 0, 0
	for _, cap := range want.Capabilities {
		if !bytes.Equal(cap.Pin.Issuer, permissionPublic) {
			return result, ErrInstall
		}
		record, e := a.InspectProviderCapabilityMaterial(cap.Raw, cap.Pin, mapping.Binding, cap.Operation, receipt.Until, want.ObservedAt)
		if e != nil || receipt.Until.After(record.Until) {
			return result, ErrInstall
		}
		switch cap.Operation {
		case kms.Generate:
			generate++
		case kms.Unwrap:
			unwrap++
		default:
			return result, ErrInstall
		}
	}
	if generate != 1 || unwrap != 2 {
		return result, ErrInstall
	}
	actualUntil, untilErr := a.RuntimeInstalledSnapshotUntil(want)
	if untilErr != nil {
		return result, ErrInstall
	}
	result.OriginalUntil = receipt.Until
	var originalPending OriginalRuntimeProviderIssueReceipt
	pendingRaw, pendingErr := readBootstrapSourcePin(pending, 262144)
	if pendingErr != nil || decodeExact(pendingRaw, &originalPending) != nil || originalPending.State != "material_issued_sql_install_pending" {
		return result, ErrInstall
	}

	// All source files and native enrollment dependencies precede SQL locks.
	if s.authority(ctx, enrollment) != nil {
		return result, ErrInstall
	}
	again, e := readBootstrapSourcePin(pin, originalRuntimeMetadataLimit)
	if e != nil || !bytes.Equal(again, raw) {
		return result, ErrInstall
	}
	tx, e := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return result, ErrInstall
	}
	defer tx.Rollback()
	var gate string
	e = tx.QueryRowContext(ctx, `SELECT gate_state FROM system_backup_v2_maintenance_locks WHERE origin_installation_id=? AND scope=? FOR SHARE`, want.InstallationID, c.CaptureGateScope).Scan(&gate)
	if e != nil && e != sql.ErrNoRows {
		return result, ErrInstall
	}
	now, e := s.lockAdmin(ctx, tx)
	if e != nil {
		return result, ErrInstall
	}
	result.OriginalAuthorizationExpired = !now.Before(receipt.Until) || !now.Before(actualUntil)
	var epoch uint64
	var actual a.RuntimeInstalledSQLSnapshot
	readErr := a.ErrAuthorityWrite
	if want.C1 != nil {
		// The actual mixed reader locks C1 protocol tables FIRST. Never take
		// the later KEK fence before this prefix (install/consume use C1->KEK).
		actual, readErr = a.QueryMixedRuntimeInstalledSQLSnapshotTx(ctx, tx, database, want.InstallationID, want.MappingRecord, want.MappingSignature, want.Capabilities, want.C1)
		if readErr == nil {
			e = tx.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR SHARE`, want.InstallationID).Scan(&epoch)
			if e != nil || actual.FenceAfter != epoch {
				readErr = a.ErrAuthorityWrite
			}
		}
	} else {
		e = tx.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR SHARE`, want.InstallationID).Scan(&epoch)
		missingFence := e == sql.ErrNoRows
		if e != nil && !missingFence {
			return result, ErrInstall
		}
		if !missingFence {
			actual, readErr = a.QueryRuntimeInstalledSQLSnapshotTx(ctx, tx, database, want.InstallationID, want.MappingRecord, want.MappingSignature, want.Capabilities)
		}
	}
	tail, e := s.lockAdmin(ctx, tx)
	if e != nil || tail.Before(now) || !s.live(ctx) {
		return result, ErrInstall
	}
	result.CheckedAt = tail
	result.OriginalAuthorizationExpired = untilErr != nil || !tail.Before(receipt.Until) || !tail.Before(actualUntil)
	if readErr == nil && actual.FenceAfter >= want.FenceAfter && a.SameRuntimeInstalledSQLRows(want, actual) {
		result.State = "committed_original_rows_verified"
	}
	if tx.Rollback() != nil {
		return result, ErrInstall
	}
	if result.State == "committed_original_rows_verified" {
		if result.OriginalAuthorizationExpired {
			result.MaterialState = "original_authorization_expired"
		} else {
			result.MaterialState = "original_materials_missing_or_changed"
		}
	}
	if result.State == "committed_original_rows_verified" && !result.OriginalAuthorizationExpired {
		recovered, recoverErr := i.readOriginalRuntimeProviderResult(ctx, enrollment, pending, pin, receipt)
		if recoverErr == nil {
			currentReceipt, e := readBootstrapSourcePin(pin, originalRuntimeMetadataLimit)
			if e != nil || !bytes.Equal(currentReceipt, raw) {
				return result, ErrInstall
			}
			if s.authority(ctx, enrollment) != nil {
				return result, ErrInstall
			}
			finalTx, e := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if e != nil {
				return result, ErrInstall
			}
			defer finalTx.Rollback()
			finished, e := s.lockAdmin(ctx, finalTx)
			if e != nil || finished.Before(result.CheckedAt) || !s.live(ctx) {
				return result, ErrInstall
			}
			if finalTx.Rollback() != nil {
				return result, ErrInstall
			}
			result.CheckedAt = finished
			result.OriginalAuthorizationExpired = !finished.Before(receipt.Until) || !finished.Before(actualUntil)
			if !result.OriginalAuthorizationExpired {
				result.ProviderResult = &recovered
				result.MaterialState = "original_result_sources_verified"
			} else {
				result.MaterialState = "original_authorization_expired"
			}
		}
	}
	return result, nil
}
