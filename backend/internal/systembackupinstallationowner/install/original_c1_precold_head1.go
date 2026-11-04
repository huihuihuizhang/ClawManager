package install

import (
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
)

// Explicit ORIGINAL capture-owner action after current20, BEFORE B freezes
// the complete source roster/SQL scan. It is not a current-health refresh and
// does not adopt history, enable config or bypass candidate observation expiry.
type OriginalC1Head1Receipt struct {
	Version, State           string
	Selection, Draft, Bundle BootstrapSourceFilePin
	Authority                AuthorityReceipt
}

func (p *OriginalC1SigningProduction) ImportOriginalPreColdHead1(ctx context.Context, password, issuerPrivate []byte, directory string) (OriginalC1Head1Receipt, error) {
	var zero OriginalC1Head1Receipt
	if p == nil || p.run == nil || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	if _, err := p.CompleteOriginalSources(ctx); err != nil {
		return zero, err
	}
	origin := p.run.parent
	i := origin.operator.installer
	authenticated, err := i.authenticate(ctx, password)
	if err != nil || authenticated.authority(ctx, origin.enrollment) != nil {
		return zero, ErrInstall
	}
	current, _, err := snapshot(ctx, authenticated)
	if err != nil || current.cas != (HeadCAS{}) {
		return zero, ErrInstall
	}
	grant := origin.request.grant
	var fields map[string]json.RawMessage
	grantRaw, err := json.Marshal(grant)
	if err != nil || json.Unmarshal(origin.request.config.CanonicalJSON(), &fields) != nil || origin.request.recheck(i) != nil {
		return zero, ErrInstall
	}
	selected := pd.BootstrapConsumptionRequest{Scope: origin.domain.Scope, OfflineGrantHash: pd.Hash(hash(grantRaw)), ConfigHash: pd.Hash(origin.request.config.SHA256()), RegistrySetHash: pd.Hash(hash(fields["registries"])), RefSetHash: pd.Hash(hash(fields["references"])), ActorID: c1counter(uint64(grant.UserID)), Username: grant.Username, MatrixKey: grant.MatrixKey, Endpoint: sec.BootstrapConfigEndpoint, IdempotencyKey: grant.IdempotencyKey}
	// Actual original committed sources are read together in one independent RR
	// transaction. The selection cannot be supplied by a shell/JSON approval.
	tx, err := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, ErrInstall
	}
	defer tx.Rollback()
	for _, batch := range append([]*OriginalC1SigningProduction{p}, p.children...) {
		facts, err := batch.run.source.ReadCommitted(ctx, tx)
		if err != nil || !reflect.DeepEqual(facts.Receipt.Request, batch.run.result) {
			return zero, ErrInstall
		}
		selected.Candidates = append(selected.Candidates, batch.selections...)
	}
	if err = tx.Rollback(); err != nil {
		return zero, ErrInstall
	}
	sort.Slice(selected.Candidates, func(a, b int) bool { return selected.Candidates[a].Purpose < selected.Candidates[b].Purpose })
	if _, err = originalFirstCaptureSelection(origin.request, selected); err != nil {
		return zero, err
	}
	raw, err := canonical(selected)
	if err != nil || writeNewFiles(directory, map[string][]byte{"current20.selection.json": raw}) != nil {
		return zero, ErrInstall
	}
	selection := BootstrapSourceFilePin{File: filepath.Join(directory, "current20.selection.json"), SHA256: hash(raw)}
	draft, err := i.PrepareOriginalFirstCaptureDraft(ctx, password, origin.enrollment, OriginalFirstCaptureDraftInputs{Request: origin.input.Request, SigningMaterial: p.run.native.source, Selection: selection, ControllerDeployment: p.run.native.deployment, ControllerPodName: p.run.native.actor.PodName, OutputDirectory: directory, Until: origin.request.end})
	if err != nil {
		return zero, err
	}
	raw, err = readBootstrapSourcePin(draft.Draft, 262144)
	if err != nil {
		return zero, ErrInstall
	}
	bundle, err := i.IssueCapture(ctx, password, origin.enrollment, raw, draft.Draft.SHA256, issuerPrivate, origin.input.Request)
	if err != nil {
		return zero, err
	}
	if err = SaveFrozenBundle(directory, bundle); err != nil {
		return zero, err
	}
	bundlePin := BootstrapSourceFilePin{File: filepath.Join(directory, "authority.bundle.json"), SHA256: hash(bundle)}
	receipt, err := i.ImportCapture(ctx, password, origin.enrollment, bundle, bundlePin.SHA256, origin.input.Request)
	if errors.Is(err, ErrCommitUnknown) {
		receipt, err = i.Resolve(ctx, password, origin.enrollment, bundle, bundlePin.SHA256)
	}
	if err != nil {
		return zero, err
	}
	// Read back even a known commit. Unknown never reissues or repeats import.
	again, err := i.Resolve(ctx, password, origin.enrollment, bundle, bundlePin.SHA256)
	if err != nil || again.HeadRevision != 1 || again.State != "active" || again.RecordSHA256 != receipt.RecordSHA256 || again.HeadSHA256 != receipt.HeadSHA256 {
		return zero, ErrInstall
	}
	result := OriginalC1Head1Receipt{Version: "original-c1-precold-head1-result.v1", State: "original-head1-committed-readback-verified-not-adoption-not-config", Selection: selection, Draft: draft.Draft, Bundle: bundlePin, Authority: again}
	encoded, err := canonical(result)
	if err != nil || writeNewFiles(directory, map[string][]byte{"head1.result.json": encoded}) != nil {
		return zero, ErrInstall
	}
	return result, nil
}
