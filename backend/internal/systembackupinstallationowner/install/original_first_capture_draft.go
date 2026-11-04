package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// Selection is the COMPLETE original comparison request, not an approval or a
// replacement for D's independent candidate/mapping and original SQL checks.
// No caller Record, Binding, Passed, selection hash or grant ID is accepted.
type OriginalFirstCaptureDraftInputs struct {
	Request                                                  RequestFiles
	SigningMaterial, Selection                               BootstrapSourceFilePin
	ControllerDeployment, ControllerPodName, OutputDirectory string
	Until                                                    time.Time
}

type OriginalFirstCaptureDraftReceipt struct {
	Version, State             string
	Draft, Sources             BootstrapSourceFilePin
	Request                    RequestFiles
	SigningMaterial, Selection BootstrapSourceFilePin
	Until                      time.Time
}

// This action writes only an unsigned draft and its source coordinates. The
// unchanged IssueCapture performs native observation and original signing;
// ImportCapture alone owns the original head/grant CAS transaction. Neither
// this receipt nor matching hashes establishes adoption or candidate authority.
func (i *Installer) PrepareOriginalFirstCaptureDraft(ctx context.Context, password []byte, enrollment EnrollmentPin, in OriginalFirstCaptureDraftInputs) (OriginalFirstCaptureDraftReceipt, error) {
	var zero OriginalFirstCaptureDraftReceipt
	s, e := i.authenticate(ctx, password)
	if e != nil || privateDirectory(in.OutputDirectory) != nil || in.Until.IsZero() {
		return zero, ErrInstall
	}
	before, now, e := originalRuntimeAuthoritySnapshot(ctx, s, enrollment)
	if e != nil || before.cas != (HeadCAS{}) {
		return zero, ErrInstall // First head only; never renew or replace a head.
	}
	request, e := readRequest(i, in.Request)
	if e != nil {
		return zero, ErrInstall
	}
	defer request.observer.Close()
	selectionRaw, e := readBootstrapSourcePin(in.Selection, 262144)
	var selection pd.BootstrapConsumptionRequest
	if e != nil || decodeExact(selectionRaw, &selection) != nil {
		return zero, ErrInstall
	}
	digests, e := originalFirstCaptureSelection(request, selection)
	if e != nil || request.grant.UserID != s.userID || request.grant.Username != i.plan.LocalAdminUsername || request.grant.InstallationID != i.plan.Target.InstallationID || request.grant.ServerUUID != i.plan.Target.ServerUUID || request.grant.Database != i.plan.Target.Database {
		return zero, ErrInstall
	}
	material, signing, actor, binding, e := i.originalFirstCaptureSigning(ctx, enrollment, in, request)
	if e != nil {
		return zero, ErrInstall
	}
	until := minTime(in.Until, minTime(request.end, signing.Until))
	if now.Before(request.start) || now.Before(signing.NotBefore) || !now.Before(until) || until.Sub(now) > 24*time.Hour {
		return zero, ErrInstall
	}
	entropy := make([]byte, 48)
	if _, e := rand.Read(entropy); e != nil {
		return zero, ErrInstall
	}
	r := owner.Record{SchemaVersion: owner.RecordVersion, EnrollmentID: i.plan.EnrollmentID, IssuerID: i.plan.IssuerID, GrantID: "capture-" + hex.EncodeToString(entropy[:16]), EnrollmentRevision: i.plan.EnrollmentRevision, Revision: 1, NotBefore: now, Until: until, Target: i.plan.Target, Actor: owner.Actor{UserID: s.userID, Username: i.plan.LocalAdminUsername, OwnerSubject: i.plan.OwnerUsername}, Endpoint: sec.BootstrapConfigEndpoint, IdempotencyKey: request.grant.IdempotencyKey, MatrixKey: request.grant.MatrixKey, GrantSHA256: digests.grant, ConfigSHA256: request.config.SHA256(), RegistrySetSHA256: digests.registries, ReferenceSetSHA256: digests.references, SelectionSHA256: digests.selection, CanonicalProfile: "system-backup-config-values.v1", Binding: binding, Histories: material.Histories, Probe: owner.Probe{Challenge: hex.EncodeToString(entropy[16:]), Until: until}}
	for _, ref := range request.config.References() {
		if ref.Purpose == "capture_signing" {
			r.Reference = ref
		}
	}
	draft, e := owner.EncodeRecord(r)
	if e != nil || !s.matchesRecord(r) || !request.matchesDraft(r) || owner.CheckInstallationDraft(draft, s.pinFor(r, hash(draft), 1)) != nil {
		return zero, ErrInstall
	}
	floor := now
	recheck := func() error {
		if request.recheck(i) != nil {
			return ErrInstall
		}
		raw, e := readBootstrapSourcePin(in.Selection, 262144)
		if e != nil || !bytes.Equal(raw, selectionRaw) {
			return ErrInstall
		}
		m, sr, a, b, e := i.originalFirstCaptureSigning(ctx, enrollment, in, request)
		mRaw, me := canonical(m)
		originalRaw, oe := canonical(material)
		srRaw, se := canonical(sr)
		originalSigning, ose := canonical(signing)
		if e != nil || me != nil || oe != nil || se != nil || ose != nil || !bytes.Equal(mRaw, originalRaw) || !bytes.Equal(srRaw, originalSigning) || a != actor || b != binding {
			return ErrInstall
		}
		current, t, e := originalRuntimeAuthoritySnapshot(ctx, s, enrollment)
		if e != nil || current.cas != before.cas || t.Before(floor) || !t.Before(until) || !s.live(ctx) {
			return ErrInstall
		}
		floor = t
		return nil
	}
	result := OriginalFirstCaptureDraftReceipt{Version: "original-first-capture-draft-result.v1", State: "unsigned_draft_requires_original_issue_and_import", Draft: BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "capture-owner.draft.json"), SHA256: hash(draft)}, Request: in.Request, SigningMaterial: in.SigningMaterial, Selection: in.Selection, Until: until}
	sources, e := canonical(result)
	if e != nil || recheck() != nil || writeNewFiles(in.OutputDirectory, map[string][]byte{"capture-owner.draft.json": draft, "capture-owner.draft-sources.json": sources}) != nil {
		return zero, ErrInstall
	}
	for _, pin := range []BootstrapSourceFilePin{result.Draft, {File: filepath.Join(in.OutputDirectory, "capture-owner.draft-sources.json"), SHA256: hash(sources)}} {
		if _, e := readBootstrapSourcePin(pin, 262144); e != nil {
			return zero, ErrInstall
		}
	}
	if recheck() != nil {
		return zero, ErrInstall // Existing inert files never authorize or retry SQL.
	}
	result.Sources = BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "capture-owner.draft-sources.json"), SHA256: hash(sources)}
	return result, nil
}

type originalFirstCaptureDigests struct{ grant, registries, references, selection string }

func originalFirstCaptureSelection(r *originalRequest, selected pd.BootstrapConsumptionRequest) (originalFirstCaptureDigests, error) {
	var zero originalFirstCaptureDigests
	if r == nil {
		return zero, ErrInstall
	}
	selection, e := pd.BootstrapConsumptionHash(selected)
	grant, ge := json.Marshal(r.grant) // Original struct-order grant wire.
	var fields map[string]json.RawMessage
	if e != nil || ge != nil || json.Unmarshal(r.config.CanonicalJSON(), &fields) != nil {
		return zero, ErrInstall
	}
	g := r.grant
	d := originalFirstCaptureDigests{hash(grant), hash(fields["registries"]), hash(fields["references"]), string(selection)}
	if selected.Scope != (pd.Scope{ServerUUID: pd.ServerUUID(g.ServerUUID), Database: pd.Database(g.Database), Installation: pd.Installation(g.InstallationID)}) || string(selected.ActorID) != strconv.FormatInt(g.UserID, 10) || selected.Username != g.Username || selected.MatrixKey != g.MatrixKey || selected.Endpoint != sec.BootstrapConfigEndpoint || selected.IdempotencyKey != g.IdempotencyKey || string(selected.OfflineGrantHash) != d.grant || string(selected.ConfigHash) != r.config.SHA256() || g.ConfigSHA256 != r.config.SHA256() || string(selected.RegistrySetHash) != d.registries || string(selected.RefSetHash) != d.references {
		return zero, ErrInstall
	}
	refs := r.config.References()
	if len(selected.Candidates) != len(refs) || len(refs) != 20 {
		return zero, ErrInstall
	}
	byPurpose := make(map[string]sec.BootstrapSecretRef, len(refs))
	for _, ref := range refs {
		byPurpose[ref.Purpose] = ref
	}
	for _, c := range selected.Candidates {
		ref, found := byPurpose[c.Purpose]
		if !found || string(c.ReferenceIdentityHash) != ref.IdentityHash || string(c.ReferenceVersion) != ref.Version {
			return zero, ErrInstall
		}
		delete(byPurpose, c.Purpose)
	}
	if len(byPurpose) != 0 {
		return zero, ErrInstall
	}
	return d, nil
}
