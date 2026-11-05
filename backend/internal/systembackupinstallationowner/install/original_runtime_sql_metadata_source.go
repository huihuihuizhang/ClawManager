package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	a "clawreef/internal/systembackupkekadapter"
	kms "clawreef/internal/systembackupkms"
)

const originalRuntimeSQLMetadataReceiptDomain = "system-backup-original-runtime-sql-metadata-installation.v1\x00"

type originalRuntimeSQLMetadataReceipt struct {
	Version, PlanSHA256 string
	Enrollment          EnrollmentPin
	Target              owner.Target
	Issuers             BootstrapSourceFilePin
	Snapshot            a.RuntimeInstalledSQLSnapshot
	Until               time.Time
}
type signedOriginalRuntimeSQLMetadataReceipt struct{ Record, Signature []byte }

// Only authenticated installation plus exact actual rows creates this sealed
// classification. The signed installation receipt alone proves no COMMIT.
type originalRuntimeInstalledSQLMetadata struct {
	origin       *originalRuntimeInstalledSQLMetadata
	prep         *PreparedOriginalAdoptionSQLCut
	pin          BootstrapSourceFilePin
	raw          []byte
	receipt      originalRuntimeSQLMetadataReceipt
	floor, until time.Time
}

func (*originalRuntimeInstalledSQLMetadata) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

func (p *PreparedOriginalAdoptionSQLCut) AttachOriginalRuntimeInstalledSQLMetadata(ctx context.Context, pin BootstrapSourceFilePin) error {
	if p == nil {
		return ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.used || p.runtimeMetadata != nil || !consumerSameContext(ctx, p.ctx) || !p.operator.live(ctx) || p.operator.authority(ctx, p.enrollment) != nil {
		return ErrInstall
	}
	raw, e := readBootstrapSourcePin(pin, originalRuntimeMetadataLimit)
	var signed signedOriginalRuntimeSQLMetadataReceipt
	var receipt originalRuntimeSQLMetadataReceipt
	if e != nil || decodeOriginalRuntimeMetadata(raw, &signed) != nil || decodeOriginalRuntimeMetadata(signed.Record, &receipt) != nil || receipt.Version != "original-runtime-installed-sql-metadata.v1" || receipt.PlanSHA256 != p.operator.installer.planHash || receipt.Target != p.operator.installer.plan.Target || receipt.Enrollment != p.enrollment {
		return ErrInstall
	}
	material, e := p.operator.installer.readOriginalRuntimeIssuerMaterial(receipt.Issuers, p.enrollment)
	if e != nil {
		return ErrInstall
	}
	public, e := readBootstrapSourcePin(material.Issuers["installation_mapping"].PublicKey, 32)
	if e != nil || !ed25519.Verify(public, append([]byte(originalRuntimeSQLMetadataReceiptDomain), signed.Record...), signed.Signature) {
		return ErrInstall
	}
	snapshot := receipt.Snapshot
	facts := p.observed.Facts()
	if snapshot.Database != facts.Database || snapshot.InstallationID != facts.InstallationID || snapshot.FenceBefore == ^uint64(0) || snapshot.FenceAfter != snapshot.FenceBefore+1 || len(snapshot.Rows) != 3 || snapshot.ObservedAt.IsZero() || snapshot.ObservedAt.After(facts.ObservedAt) || receipt.Until.IsZero() {
		return ErrInstall
	}
	if snapshot.C1 == nil {
		if snapshot.Evidence.Rows != 3 || snapshot.Chunks.Rows != 0 || snapshot.Chunks.Bytes != 0 {
			return ErrInstall
		}
	} else if snapshot.C1.Database != facts.Database || snapshot.C1.InstallationID != facts.InstallationID || len(snapshot.C1.Sources) == 0 || len(snapshot.C1.Sources) > 20 || len(snapshot.C1.Tables) != 8 || snapshot.Evidence.Rows != uint64(3+len(snapshot.C1.EvidenceRows)) || snapshot.Chunks.Rows != uint64(len(snapshot.C1.ChunkRows)) {
		return ErrInstall
	}
	var mapping a.OriginalRecord
	if json.Unmarshal(snapshot.MappingRecord, &mapping) != nil || mapping.Binding.InstallationID != facts.InstallationID || a.InspectOriginalKEKMaterial(snapshot.MappingRecord, snapshot.MappingSignature, public, hash(snapshot.MappingRecord), facts.InstallationID, mapping.Revision, mapping.Binding.ConfigRef, facts.ObservedAt) != nil {
		return ErrInstall
	}
	permissionPublic, e := readBootstrapSourcePin(material.Issuers["provider_permission"].PublicKey, 32)
	if e != nil {
		return ErrInstall
	}
	generate, unwrap := 0, 0
	for _, c := range snapshot.Capabilities {
		if !bytes.Equal(c.Pin.Issuer, permissionPublic) {
			return ErrInstall
		}
		record, e := a.InspectProviderCapabilityMaterial(c.Raw, c.Pin, mapping.Binding, c.Operation, receipt.Until, facts.ObservedAt)
		if e != nil || receipt.Until.After(record.Until) {
			return ErrInstall
		}
		switch c.Operation {
		case kms.Generate:
			generate++
		case kms.Unwrap:
			unwrap++
		default:
			return ErrInstall
		}
	}
	if generate != 1 || unwrap != 2 || receipt.Until.After(mapping.Until) {
		return ErrInstall
	}
	actualUntil, e := a.RuntimeInstalledSnapshotUntil(snapshot)
	if e != nil {
		return ErrInstall
	}
	r := &originalRuntimeInstalledSQLMetadata{prep: p, pin: pin, raw: bytes.Clone(raw), receipt: receipt, until: minTime(actualUntil, minTime(p.until, receipt.Until)), floor: facts.ObservedAt}
	r.origin = r
	if !r.classifiesTables(facts) || r.recheck(ctx, nil, 0) != nil {
		return ErrInstall
	}
	p.runtimeMetadata = r
	return nil
}

func (r *originalRuntimeInstalledSQLMetadata) local(ctx context.Context) bool {
	return r != nil && r.origin == r && r.prep != nil && r.prep.origin == r.prep && consumerSameContext(ctx, r.prep.ctx) && r.prep.operator.live(ctx) && time.Now().Before(r.until)
}

// Every other original table retains the original singleton/empty rule. This
// accepts neither a type/prefix exemption nor caller-provided row counts.
func (r *originalRuntimeInstalledSQLMetadata) classifiesTables(f a.SQLCoverageCensusFacts) bool {
	if r == nil || r.origin != r || f.Database != r.receipt.Snapshot.Database || f.InstallationID != r.receipt.Snapshot.InstallationID {
		return false
	}
	copy := f
	copy.Tables = append([]a.SQLCoverageTable(nil), f.Tables...)
	found := 0
	c1Tables := map[string]a.SQLCoverageTable{}
	if r.receipt.Snapshot.C1 != nil {
		allowed := map[string]bool{}
		for _, suffix := range []string{"domains", "grants", "runs", "evidence_bindings", "targets", "result_receipts", "command_receipts", "evidence_refs"} {
			allowed["system_backup_producer_"+suffix] = true
		}
		for _, table := range r.receipt.Snapshot.C1.Tables {
			if !allowed[table.Table] {
				return false
			}
			if _, duplicate := c1Tables[table.Table]; duplicate {
				return false
			}
			c1Tables[table.Table] = table
		}
		if len(c1Tables) != 8 {
			return false
		}
	}
	for n, table := range copy.Tables {
		if expected, ok := c1Tables[table.Table]; ok {
			if table != expected {
				return false
			}
			copy.Tables[n].Rows, copy.Tables[n].Bytes = 0, 0
			delete(c1Tables, table.Table)
			continue
		}
		switch table.Table {
		case "system_backup_v2_evidence":
			if table != r.receipt.Snapshot.Evidence {
				return false
			}
			copy.Tables[n].Rows, copy.Tables[n].Bytes = 0, 0
			found++
		case "system_backup_v2_evidence_chunks":
			if table != r.receipt.Snapshot.Chunks {
				return false
			}
			copy.Tables[n].Rows, copy.Tables[n].Bytes = 0, 0
			found++
		}
	}
	return found == 2 && len(c1Tables) == 0 && originalHistorySingletonOnly(copy)
}

// Before SQL: reauthenticate selected bytes/issuer source, then actual full
// rows/EOF. Locked: ONLY revisit ranges already held by the genuine original
// coverage transaction, with its authenticated epoch; no file/network reads.
func (r *originalRuntimeInstalledSQLMetadata) recheck(ctx context.Context, lockedTx *sql.Tx, expectedEpoch uint64, controls ...*a.OriginalAdoptionControlCut) error {
	if !r.local(ctx) {
		return ErrInstall
	}
	p := r.prep
	i := p.operator.installer
	if lockedTx == nil {
		if p.operator.authority(ctx, p.enrollment) != nil {
			return ErrInstall
		}
		raw, e := readBootstrapSourcePin(r.pin, originalRuntimeMetadataLimit)
		if e != nil || !bytes.Equal(raw, r.raw) {
			return ErrInstall
		}
		if _, e := i.readOriginalRuntimeIssuerMaterial(r.receipt.Issuers, p.enrollment); e != nil {
			return ErrInstall
		}
	}
	tx := lockedTx
	if tx == nil {
		var e error
		tx, e = i.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: r.receipt.Snapshot.C1 == nil, Isolation: sql.LevelRepeatableRead})
		if e != nil {
			return ErrInstall
		}
		defer tx.Rollback()
	}
	want := r.receipt.Snapshot
	var actual a.RuntimeInstalledSQLSnapshot
	var e error
	if want.C1 == nil {
		actual, e = a.ReadRuntimeInstalledSQLSnapshotTx(ctx, tx, want.Database, want.InstallationID, want.MappingRecord, want.MappingSignature, want.Capabilities, lockedTx != nil, controls...)
	} else {
		actual, e = a.ReadMixedRuntimeInstalledSQLSnapshotTx(ctx, tx, want.Database, want.InstallationID, want.MappingRecord, want.MappingSignature, want.Capabilities, lockedTx != nil, want.C1, controls...)
	}
	epoch := want.FenceAfter
	if lockedTx != nil {
		epoch = expectedEpoch
	}
	if e != nil || actual.FenceAfter != epoch || actual.ObservedAt.Before(r.floor) || !actual.ObservedAt.Before(r.until) || !a.SameRuntimeInstalledSQLRows(want, actual) {
		return ErrInstall
	}
	stamp, e := i.database(ctx, tx, r.until)
	if e != nil || stamp.Before(actual.ObservedAt) || stamp.Before(r.floor) || !r.local(ctx) {
		return ErrInstall
	}
	if lockedTx == nil && tx.Rollback() != nil {
		return ErrInstall
	}
	r.floor = stamp
	return nil
}
