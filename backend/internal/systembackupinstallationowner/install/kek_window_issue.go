package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"

	kek "clawreef/internal/systembackupkekadapter"
	pd "clawreef/internal/systembackupproducer"
)

// Separate original action. It authenticates the actual original administrator,
// enrollment and capture selection, then reads the EXISTING concrete KEK
// admission source once with all SQL locks released. It does not turn capture
// signing permission into Generate/Unwrap or manufacture coverage/witnesses.
func (i *Installer) IssueBootstrapKEKWindow(ctx context.Context, password []byte, enrollment EnrollmentPin, bundleRaw []byte, bundleSHA string, selection pd.BootstrapConsumptionRequest, files RequestFiles, preparation *kek.SQLBootstrapKEKPreparation, issuerPrivate []byte) (SignedBootstrapOriginalMapping, error) {
	var zero SignedBootstrapOriginalMapping
	bundleRaw = bytes.Clone(bundleRaw)
	selectionRaw, err := json.Marshal(selection)
	var frozen pd.BootstrapConsumptionRequest
	if err != nil || len(selectionRaw) > 262144 || json.Unmarshal(selectionRaw, &frozen) != nil {
		return zero, ErrInstall
	}
	selection = frozen
	s, err := i.authenticate(ctx, password)
	if err != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	b, capture, _, err := s.decodeBundle(bundleRaw, bundleSHA, enrollment)
	if err != nil || b.SchemaVersion != AuthorityBundleVersion || !functionalSelectionMatches(capture, selection) {
		return zero, ErrInstall
	}
	cfg, sourceSHA, err := kekWindowPreparation(preparation)
	if err != nil || cfg.Database.ServerUUID != capture.Target.ServerUUID || cfg.Database.Database != capture.Target.Database || cfg.InstallationID != capture.Target.InstallationID {
		return zero, ErrInstall
	}
	request, err := readConsumerCaptureRequest(i, files)
	if err != nil {
		return zero, ErrInstall
	}
	defer request.observer.Close()
	ref, err := kekWindowReference(request.config)
	if err != nil || !request.matchesDraft(capture) || ref.IdentityHash != cfg.Mapping.IdentityHash || ref.Version != cfg.Mapping.Version {
		return zero, ErrInstall
	}
	before, now, err := snapshot(ctx, s)
	if err != nil || !exactCommitted(before, b) || now.Before(capture.NotBefore) || !now.Before(capture.Until) {
		return zero, ErrInstall
	}
	// snapshot has released its admin/head/grant locks. This actual concrete
	// call authenticates mapping + both purpose capabilities + adoption + all
	// sixteen original witness sources; it is NOT a direct Generate/Unwrap call.
	actual, err := preparation.PrepareBootstrapKEK(ctx, i.db, request.grant, request.config)
	if err != nil || consumerNil(actual) {
		return zero, ErrInstall
	}
	original, ok := actual.(kek.BootstrapOriginalEvidenceAdmission)
	if !ok || consumerNil(original.OriginalCoverage()) || len(original.OriginalEvidenceIDs()) != 17 {
		return zero, ErrInstall
	}
	observation := actual.Observation()
	bindingSHA, err := kekWindowBindingSHA(actual.Binding())
	if err != nil {
		return zero, ErrInstall
	}
	snapshotSHA, err := kekWindowSnapshotSHA(actual.ExpectedSnapshot())
	if err != nil || observation.InstallationID != capture.Target.InstallationID || observation.ConfigSHA256 != capture.ConfigSHA256 || observation.GenerateCapabilitySource != cfg.Generate.Source || observation.UnwrapCapabilitySource != cfg.Unwrap.Source {
		return zero, ErrInstall
	}
	r := BootstrapKEKWindowRecord{SchemaVersion: BootstrapKEKWindowVersion, PlanSHA256: i.planHash, CaptureRecordSHA256: hash(b.Record), PreparationSHA256: sourceSHA, Target: capture.Target, Actor: capture.Actor, Enrollment: enrollment, NotBefore: capture.NotBefore, Until: capture.Until, Selection: selection, Reference: ref, MappingSource: observation.MappingSource, SourceRevision: observation.SourceRevision, BindingSHA256: bindingSHA, SnapshotFactsSHA256: snapshotSHA}
	r.SnapshotFactsProfile = BootstrapKEKWindowSnapshotProfile
	if validateKEKWindow(r) != nil {
		return zero, ErrInstall
	}
	encoded, err := canonical(r)
	if err != nil || len(encoded) > 262144 {
		return zero, ErrInstall
	}
	key, err := s.privateKey(issuerPrivate)
	if err != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	signature := ed25519.Sign(key, append([]byte(BootstrapKEKWindowDomain), encoded...))
	for _, pin := range []consumerPinnedFile{{files.ConfigFile, files.ConfigFileSHA256, 262144}, {files.GrantFile, files.GrantFileSHA256, 16384}, {files.ObserverFile, files.ObserverFileSHA256, 262144}} {
		raw, err := ReadPrivateFile(pin.path, pin.limit)
		if err != nil || hash(raw) != pin.sha {
			return zero, ErrInstall
		}
	}
	if s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	after, now, err := snapshot(ctx, s)
	if err != nil || after.cas != before.cas || !exactCommitted(after, b) || now.Before(r.NotBefore) || !now.Before(r.Until) || !now.Before(actual.ValidUntil()) || !s.live(ctx) {
		return zero, ErrInstall
	}
	return SignedBootstrapOriginalMapping{Record: encoded, Signature: signature}, nil
}

func SaveFrozenBootstrapKEKWindow(directory string, signed SignedBootstrapOriginalMapping) error {
	var r BootstrapKEKWindowRecord
	if len(signed.Record) == 0 || len(signed.Record) > 262144 || len(signed.Signature) != 64 || decodeExact(signed.Record, &r) != nil || validateKEKWindow(r) != nil {
		return ErrInstall
	}
	return writeNewFiles(directory, map[string][]byte{"bootstrap-kek-window.record.json": bytes.Clone(signed.Record), "bootstrap-kek-window.signature": bytes.Clone(signed.Signature), "bootstrap-kek-window.sha256": []byte(hash(signed.Record))})
}
