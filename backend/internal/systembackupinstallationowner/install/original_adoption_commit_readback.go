package install

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"

	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
)

// Readback is exact original-operation comparison, never new admission or
// source proof. Unknown/mixed derived rows retain the physical recovery hold.
func readbackOriginalAdoptionCommit(ctx context.Context, db *sql.DB, expected originalAdoptionCommitExpected) error {
	if ctx == nil || db == nil || expected.Version != "original-adoption-commit-expectation.v1" || expected.Operation == "" || expected.NewEpoch != expected.OldEpoch+1 || len(expected.ControlRows) != 17 || len(expected.Sources) != 4 || expected.References == nil || expected.Bindings == nil {
		return ErrCommitUnknown
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrCommitUnknown
	}
	defer tx.Rollback()
	// Waiting for this exact original maintenance row settles any in-flight
	// final transaction, which retained its shared gate lock through COMMIT.
	gate, err := (c.SQLCoordinationTransaction{Tx: tx}).LockGate(ctx, c.GateKey{InstallationID: expected.InstallationID, Scope: c.CaptureGateScope})
	if err != nil || gate.Owner != "adoption:"+expected.Operation || gate.State != c.GateHeld {
		return ErrCommitUnknown
	}
	var epoch uint64
	err = tx.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR UPDATE`, expected.InstallationID).Scan(&epoch)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ErrCommitUnknown
	}
	snapshot, err := (reg.SQLStore{}).ReadOriginalAdoptionSnapshotTx(ctx, tx, expected.InstallationID)
	if err != nil || snapshot.InstallationID != expected.InstallationID || snapshot.Database != (reg.DatabaseIdentity{ServerUUID: expected.ServerUUID, Database: expected.Database}) || snapshot.Epoch != expected.NewEpoch || !reflect.DeepEqual(snapshot.References, expected.References) || !reflect.DeepEqual(snapshot.Bindings, expected.Bindings) || len(snapshot.Coverage) != 4 {
		return ErrCommitUnknown
	}
	byPart := map[reg.Partition]reg.CoverageSource{}
	for _, s := range expected.Sources {
		if _, exists := byPart[s.Partition]; exists {
			return ErrCommitUnknown
		}
		byPart[s.Partition] = s
	}
	for _, s := range snapshot.Coverage {
		if byPart[s.Partition] != s {
			return ErrCommitUnknown
		}
	}
	for id, want := range expected.ControlRows {
		var payload []byte
		var checksum, owner, kind, state string
		if tx.QueryRowContext(ctx, `SELECT inline_payload,content_checksum,owner_target_public_id,evidence_type,storage_state FROM system_backup_v2_evidence WHERE public_id=? AND owner_target_type='system' FOR SHARE`, id).Scan(&payload, &checksum, &owner, &kind, &state) != nil || owner != expected.InstallationID || kind != "catalog_scan_receipt" || state != "inline" || hash(payload) != want || checksum != want {
			return ErrCommitUnknown
		}
		var signed a.SignedCoverageOwnerRecord
		if json.Unmarshal(payload, &signed) != nil {
			return ErrCommitUnknown
		}
		encoded, err := json.Marshal(signed)
		if err != nil || !bytes.Equal(encoded, payload) {
			return ErrCommitUnknown
		}
	}
	if tx.Rollback() != nil {
		return ErrCommitUnknown
	}
	return nil
}
