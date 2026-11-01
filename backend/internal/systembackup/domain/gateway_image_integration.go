package domain

import (
	"context"

	"clawreef/internal/systembackup/staging"
)

// HasGatewayImageData is a data presence check, never an authorization result.
func HasGatewayImageData(s Snapshot) bool {
	for _, table := range s.Tables {
		if isGatewayImageTable(table.Name) && len(table.Rows) > 0 {
			return true
		}
	}
	return false
}
func validateRestoreTableAdapter(a TableAdapter, t Table) error {
	if a.Normalizer != GatewayImage074Normalizer {
		return a.validate(t)
	}
	if validateGatewayImageAdapter(a, t) != nil || SchemaDigest(t) != a.SchemaSHA256 || len(a.Columns) != len(t.Columns) {
		return ErrSchema
	}
	return nil
}
func validateGatewayImageRestore(ctx context.Context, source Snapshot, target []Table, adapters map[string]TableAdapter, r *GatewayImageReceipt) (bool, error) {
	selected := HasGatewayImageData(source)
	for _, t := range source.Tables {
		selected = selected || isGatewayImageTable(t.Name) && adapters[t.Name].Normalizer == GatewayImage074Normalizer
	}
	if !selected {
		return false, nil
	}
	src, dst := gatewayImageTables(source), gatewayImageTables(Snapshot{Tables: target})
	frozen := ""
	for name := range gatewayImageColumns {
		a := adapters[name]
		if a.Normalizer != GatewayImage074Normalizer || validateRestoreTableAdapter(a, src[name]) != nil || validateRestoreTableAdapter(a, dst[name]) != nil {
			return false, ErrSchema
		}
		if frozen != "" && frozen != a.InterruptedAt {
			return false, ErrNormalization
		}
		frozen = a.InterruptedAt
	}
	if validateImageRows(ctx, source, false) != nil {
		return false, ErrData
	}
	if HasGatewayImageData(source) {
		for name := range gatewayBudgetColumns {
			a := adapters[name]
			if a.Normalizer != GatewayBudget055Normalizer || a.InterruptedAt != frozen {
				return false, ErrNormalization
			}
		}
		if r.sourceMatches(source, frozen) != nil {
			return false, ErrNormalization
		}
	}
	return true, nil
}
func (r *GatewayImageReceipt) sourceMatches(s Snapshot, frozen string) error {
	if r == nil || r.data.InterruptedAt != frozen || !imageTLSClient(r.reader) {
		return ErrNormalization
	}
	digest, e := Digest(s)
	if e != nil || digest != r.data.SourceSQLSHA256 {
		return ErrData
	}
	projection, e := imageProjection(s, frozen)
	if e != nil || projection != r.data.ImageSQLSHA256 {
		return ErrData
	}
	return nil
}
func (r *GatewayImageReceipt) quarantineMatches(ctx context.Context, s Snapshot) error {
	if !HasGatewayImageData(s) {
		return nil
	}
	if r == nil || validateImageRows(ctx, s, true) != nil {
		return ErrNormalization
	}
	projection, e := imageProjection(s, r.data.InterruptedAt)
	if e != nil || projection != r.data.ImageSQLSHA256 {
		return ErrData
	}
	return nil
}

// CheckGatewayImageSourceBinding compares the independently authenticated local
// artifacts' original capture context. Different part/path/envelopes are legal;
// this does not manufacture a formal fullC source authorization.
func CheckGatewayImageSourceBinding(r *GatewayImageReceipt, b staging.Binding) error {
	if r == nil || r.data.SourceImageBinding.BackupID != b.BackupID || r.data.SourceImageBinding.Attempt != b.Attempt || r.data.SourceImageBinding.CaptureContextHash != b.CaptureContextHash {
		return ErrData
	}
	return nil
}
func verifyGatewayImageExpected(ctx context.Context, s Snapshot, r *GatewayImageReceipt, database, uuid string) error {
	if !HasGatewayImageData(s) {
		return nil
	}
	if r == nil || !imageValidHash(r.data.ExpectedSQLSHA256) || r.quarantineMatches(ctx, s) != nil {
		return ErrNormalization
	}
	digest, e := Digest(s)
	if e != nil || digest != r.data.ExpectedSQLSHA256 {
		return ErrData
	}
	return r.verify(ctx, s, true, database, uuid)
}
