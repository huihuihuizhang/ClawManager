package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"time"

	a "clawreef/internal/systembackupkekadapter"
)

// Private authenticated source data for nonempty history. A stopped/retired
// original C1 Pod need not remain Running: historical provenance is the actual
// purpose-signed original installer receipt and complete current SQL rows, not
// a borrowed execution token or caller receipt/Passed/hash.
type originalC1HistoryReceipt struct {
	origin       *originalC1HistoryReceipt
	prep         *PreparedOriginalAdoptionSQLCut
	hold         *OriginalWriterHold
	pin          BootstrapSourceFilePin
	raw          []byte
	receipt      originalRuntimeSQLMetadataReceipt
	until, floor time.Time
}

func readOriginalC1HistoryReceipt(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, pin BootstrapSourceFilePin) (*originalC1HistoryReceipt, error) {
	if !originalEmptyHistoryOwner(ctx, p, h, false) || h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil {
		return nil, ErrInstall
	}
	raw, e := readBootstrapSourcePin(pin, originalRuntimeMetadataLimit)
	var signed signedOriginalRuntimeSQLMetadataReceipt
	var receipt originalRuntimeSQLMetadataReceipt
	if e != nil || decodeOriginalRuntimeMetadata(raw, &signed) != nil || decodeOriginalRuntimeMetadata(signed.Record, &receipt) != nil || receipt.Version != "original-runtime-installed-sql-metadata.v1" || receipt.PlanSHA256 != p.operator.installer.planHash || receipt.Enrollment != p.enrollment || receipt.Target != p.operator.installer.plan.Target || receipt.Snapshot.C1 == nil {
		return nil, ErrInstall
	}
	material, e := p.operator.installer.readOriginalRuntimeIssuerMaterial(receipt.Issuers, p.enrollment)
	if e != nil {
		return nil, ErrInstall
	}
	public, e := readBootstrapSourcePin(material.Issuers["installation_mapping"].PublicKey, 32)
	if e != nil || !ed25519.Verify(public, append([]byte(originalRuntimeSQLMetadataReceiptDomain), signed.Record...), signed.Signature) {
		return nil, ErrInstall
	}
	want := receipt.Snapshot
	if want.Database != p.observed.Facts().Database || want.InstallationID != p.reservation.InstallationID || want.FenceBefore == ^uint64(0) || want.FenceAfter != want.FenceBefore+1 || len(want.Rows) != 3 || len(want.Capabilities) != 3 || len(want.C1.Sources) == 0 || len(want.C1.Sources) > 20 || want.ObservedAt.IsZero() || want.ObservedAt.After(p.observed.Facts().ObservedAt) {
		return nil, ErrInstall
	}
	actualUntil, e := a.RuntimeInstalledSnapshotUntil(want)
	if e != nil {
		return nil, ErrInstall
	}
	r := &originalC1HistoryReceipt{prep: p, hold: h, pin: pin, raw: bytes.Clone(raw), receipt: receipt, until: minTime(p.until, minTime(receipt.Until, actualUntil)), floor: p.observed.Facts().ObservedAt}
	r.origin = r
	if r.recheckBeforeSQL(ctx) != nil {
		return nil, ErrInstall
	}
	return r, nil
}

func (r *originalC1HistoryReceipt) recheckBeforeSQL(ctx context.Context) error {
	if r == nil || r.origin != r || !originalEmptyHistoryOwner(ctx, r.prep, r.hold, false) || !time.Now().Before(r.until) || r.hold.recheckBeforeSQL(ctx) != nil || r.prep.operator.authority(ctx, r.prep.enrollment) != nil {
		return ErrInstall
	}
	raw, e := readBootstrapSourcePin(r.pin, originalRuntimeMetadataLimit)
	if e != nil || !bytes.Equal(raw, r.raw) {
		return ErrInstall
	}
	if _, e := r.prep.operator.installer.readOriginalRuntimeIssuerMaterial(r.receipt.Issuers, r.prep.enrollment); e != nil {
		return ErrInstall
	}
	tx, e := r.prep.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	if r.recheckLocked(ctx, tx, r.receipt.Snapshot.FenceAfter) != nil {
		return ErrInstall
	}
	return tx.Rollback()
}

// SQL-only reread, after original C1/evidence/source prefix ranges are held.
// It authenticates DATA lineage and current bytes, never calls external
// provider APIs, samples new capacity or mints a key/execution capability.
func (r *originalC1HistoryReceipt) recheckLocked(ctx context.Context, tx *sql.Tx, epoch uint64, controls ...*a.OriginalAdoptionControlCut) error {
	if r == nil || r.origin != r || tx == nil || !consumerSameContext(ctx, r.prep.ctx) || ctx.Err() != nil || !time.Now().Before(r.until) {
		return ErrInstall
	}
	want := r.receipt.Snapshot
	actual, e := a.ReadMixedRuntimeInstalledSQLSnapshotTx(ctx, tx, want.Database, want.InstallationID, want.MappingRecord, want.MappingSignature, want.Capabilities, true, want.C1, controls...)
	if e != nil || actual.FenceAfter != epoch || actual.ObservedAt.Before(r.floor) || !actual.ObservedAt.Before(r.until) || !a.SameRuntimeInstalledSQLRows(want, actual) {
		return ErrInstall
	}
	r.floor = actual.ObservedAt
	return nil
}
