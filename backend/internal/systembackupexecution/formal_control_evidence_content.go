package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
)

// Each original candidate must match its exact frozen locator. The proofs
// stream independently reconstructs and verifies the full sidecar without SQL.
// Publication still verifies BOTH original decrypted streams together.
func inspectControlEvidencePart(ctx context.Context, reader io.Reader, part string, locator ce.CaptureLocator) error {
	if ctx == nil || ctx.Err() != nil || reader == nil || locator.Validate() != nil || part != ce.Part && part != ce.ProofPart {
		return d.ErrNotReady
	}
	limit, expected := int64(ce.MaxBytes), locator.SidecarSHA256
	if part == ce.ProofPart {
		limit, expected = ce.MaxProofBytes, locator.ProofsSHA256
	}
	raw, err := io.ReadAll(io.LimitReader(reader, limit+1))
	defer clear(raw)
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit || ce.SHA256(raw) != expected || ctx.Err() != nil {
		return d.ErrNotReady
	}
	decode := func(out any) error {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
			return d.ErrNotReady
		}
		canonical, err := ce.CanonicalProofs(out)
		defer clear(canonical)
		if err != nil || !bytes.Equal(canonical, raw) {
			return d.ErrNotReady
		}
		return nil
	}
	if part == ce.ProofPart {
		var bundle ce.ProofBundle
		if decode(&bundle) != nil || bundle.Version != "system-backup-control-evidence-proofs.v1" || bundle.Scope != locator.Expected.Scope {
			return d.ErrNotReady
		}
		prepared, err := ce.Rebuild(ctx, locator, bundle.Entries)
		defer clear(prepared.SidecarJSON)
		defer clear(prepared.ProofsJSON)
		if err != nil {
			return d.ErrNotReady
		}
		return nil
	}
	var sidecar ce.Sidecar
	if decode(&sidecar) != nil || sidecar.Version != ce.Version || sidecar.Contract != "system-backup-plan.v12" || sidecar.Scope != locator.Expected.Scope || !sidecar.Generated.Equal(locator.Generated) || !sidecar.Start.Equal(locator.Start) || !sidecar.End.Equal(locator.End) || sidecar.Exclusion.Version != locator.Expected.SchemaRegistry.Version || sidecar.Exclusion.SHA256 != locator.Expected.SchemaRegistry.SHA256 || sidecar.Redaction.Version != locator.Expected.RedactionRegistry.Version || sidecar.Redaction.SHA256 != locator.Expected.RedactionRegistry.SHA256 {
		return d.ErrNotReady
	}
	return nil
}
