package install

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	ma "clawreef/internal/systembackupminioauthority"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OriginalMinIORecoveryDescriptorInputs struct {
	Version                         string
	SQLTrustPin, PermissionSource   BootstrapSourceFilePin
	OutputDirectory, ProjectionFile string
}
type OriginalMinIORecoveryDescriptorReceipt struct {
	Version, State string
	Descriptor     BootstrapSourceFilePin
	ProjectionFile string
}

// Original installed SQL declaration supplies Actor/definition/profile/target;
// the operator selects actual producer file locations, never authorization JSON.
func (i *Installer) PrepareOriginalMinIORecoveryDescriptor(ctx context.Context, password []byte, enrollment EnrollmentPin, in OriginalMinIORecoveryDescriptorInputs) (OriginalMinIORecoveryDescriptorReceipt, error) {
	var zero OriginalMinIORecoveryDescriptorReceipt
	if in.ProjectionFile == "" {
		in.ProjectionFile = filepath.Join(in.OutputDirectory, "original-minio-recovery.projection.json")
	}
	if i == nil || ctx == nil || in.Version != "original-minio-recovery-descriptor-inputs.v1" || in.ProjectionFile == filepath.Join(in.OutputDirectory, "original-minio-recovery.descriptor.json") || privateDirectory(in.OutputDirectory) != nil || !filepath.IsAbs(in.ProjectionFile) || filepath.Clean(in.ProjectionFile) != in.ProjectionFile || privateDirectory(filepath.Dir(in.ProjectionFile)) != nil {
		return zero, ErrInstall
	}
	if _, e := os.Lstat(in.ProjectionFile); !os.IsNotExist(e) {
		return zero, ErrCommitUnknown
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(in.SQLTrustPin, 65536)
	var pin ma.SQLTrustPin
	if e != nil || decodeExact(raw, &pin) != nil || op.minioSQLPin(ctx, enrollment, pin) != nil {
		return zero, ErrInstall
	}
	current, e := readOriginalMinIORecoverySQL(ctx, op, pin)
	if e != nil {
		return zero, ErrInstall
	}
	g, _, _, e := current.Declarations()
	_, now, ce := current.Comparison()
	if e != nil || ce != nil || current.RequireCurrent(now) != nil || !minioSQLActor(op, g) {
		return zero, ErrInstall
	}
	source, e := readBootstrapSourcePin(in.PermissionSource, 262144)
	clear(source)
	if e != nil {
		return zero, ErrInstall
	}
	d := ma.MinIORecoveryDescriptor{Version: ma.MinIORecoveryDescriptorVersion, ProjectionFile: in.ProjectionFile, Pin: pin, Actor: g.Actor, DefinitionSHA256: g.Observation.DefinitionSHA256, PermissionSourceFile: in.PermissionSource.File, PermissionSourceSHA256: ma.Digest(in.PermissionSource.SHA256), PermissionProfile: g.PermissionSource.Profile}
	raw, e = ma.EncodeMinIORecoveryDescriptor(d)
	if e != nil {
		return zero, ErrInstall
	}
	if _, e = ma.DecodeMinIORecoveryDescriptor(raw); e != nil {
		return zero, ErrInstall
	}
	if op.authority(ctx, enrollment) != nil || writeNewFiles(in.OutputDirectory, map[string][]byte{"original-minio-recovery.descriptor.json": raw}) != nil {
		return zero, ErrInstall
	}
	name := filepath.Join(in.OutputDirectory, "original-minio-recovery.descriptor.json")
	again, e := ReadPrivateFile(name, 65536)
	if e != nil || !bytes.Equal(raw, again) {
		return zero, ErrCommitUnknown
	}
	return OriginalMinIORecoveryDescriptorReceipt{Version: ma.MinIORecoveryDescriptorVersion, State: "actual_original_sql_actor_pinned_future_projection_not_issued", Descriptor: BootstrapSourceFilePin{File: name, SHA256: hash(raw)}, ProjectionFile: d.ProjectionFile}, nil
}

type originalMinIORecoveryBaseline struct {
	descriptor  BootstrapSourceFilePin
	declaration ma.MinIORecoveryDescriptor
	expected    ma.SQLExpected
	provider    ma.Provider
	target      ma.Target
	resources   ma.MinIORecoveryResources
	originalCID string
}
type originalMinIORecoverySigning struct {
	ctx              context.Context
	password, issuer []byte
	authorization    *OriginalWriterRecoveryAuthorization
	attempted        bool
	receipt          *OriginalMinIORecoveryProjectionReceipt
}

func (s *originalMinIORecoverySigning) close() {
	if s != nil {
		clear(s.password)
		clear(s.issuer)
	}
}

// Baseline is actual BEFORE-cold API data; neither after-recovery observations
// nor a caller-filled Resources object can construct this private record.
func (s *PreparedOriginalWriterSet) PrepareOriginalMinIORecoverySource(ctx context.Context, descriptor BootstrapSourceFilePin) error {
	if s == nil {
		return ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.minioHistory
	if s.origin != s || s.used || r == nil || r.recoveryBaseline != nil || r.check(ctx) != nil {
		return ErrInstall
	}
	i := s.owner.operator.installer
	raw, e := readBootstrapSourcePin(descriptor, 65536)
	if e != nil {
		return ErrInstall
	}
	d, e := ma.DecodeMinIORecoveryDescriptor(raw)
	if e != nil || s.owner.operator.minioSQLPin(ctx, s.owner.enrollment, d.Pin) != nil {
		return ErrInstall
	}
	if privateDirectory(filepath.Dir(d.ProjectionFile)) != nil {
		return ErrInstall
	}
	if len(s.nodes) > 0 && !originalMinIOProjectionOutsideSources(s, d.ProjectionFile) {
		return ErrInstall
	}
	current, e := readOriginalMinIORecoverySQL(ctx, s.owner.operator, d.Pin)
	if e != nil {
		return ErrInstall
	}
	g, _, _, e := current.Declarations()
	expected, now, ce := current.Comparison()
	if e != nil || ce != nil || current.RequireCurrent(now) != nil || !minioSQLActor(s.owner.operator, g) || g.Actor != d.Actor || g.Observation.DefinitionSHA256 != d.DefinitionSHA256 {
		return ErrInstall
	}
	var material struct {
		Native struct{ Pod, PodUID, Container, ImageID string }
	}
	raw, e = readBootstrapSourcePin(r.material, 262144)
	if e != nil || json.Unmarshal(raw, &material) != nil || g.Provider.Pod.Name != material.Native.Pod || g.Provider.Pod.UID != material.Native.PodUID || g.Provider.Container != material.Native.Container || g.Provider.ImageID != material.Native.ImageID {
		return ErrInstall
	}
	pod, e := i.kube.CoreV1().Pods(g.Target.Namespace).Get(ctx, g.Provider.Pod.Name, metav1.GetOptions{})
	if e != nil || string(pod.UID) != g.Provider.Pod.UID {
		return ErrInstall
	}
	cid := ""
	for _, st := range pod.Status.ContainerStatuses {
		if st.Name == g.Provider.Container && st.ImageID == g.Provider.ImageID && st.Ready && st.State.Running != nil {
			if cid != "" {
				return ErrInstall
			}
			cid = st.ContainerID
		}
	}
	if cid == "" {
		return ErrInstall
	}
	resources, e := ma.CollectMinIORecoveryResources(ctx, i.kube, g.Target, g.Provider, g.Provider.Pod, cid)
	if e != nil {
		return ErrInstall
	}
	again, e := ma.CollectMinIORecoveryResources(ctx, i.kube, g.Target, g.Provider, g.Provider.Pod, cid)
	if e != nil || !reflect.DeepEqual(resources, again) || r.check(ctx) != nil {
		return ErrInstall
	}
	r.recoveryBaseline = &originalMinIORecoveryBaseline{descriptor, d, expected, g.Provider, g.Target, resources, cid}
	return nil
}
func originalMinIOProjectionOutsideSources(s *PreparedOriginalWriterSet, file string) bool {
	if s == nil || len(s.nodes) == 0 || !filepath.IsAbs(file) || filepath.Clean(file) != file || privateDirectory(filepath.Dir(file)) != nil {
		return false
	}
	resolved, e := filepath.EvalSymlinks(filepath.Dir(file))
	if e != nil || resolved != filepath.Dir(file) {
		return false
	}
	roots := 0
	for _, node := range s.nodes {
		if node == nil {
			return false
		}
		for _, root := range node.request.SourcePaths {
			roots++
			if custodyWithin(root, file) {
				return false
			}
		}
	}
	return roots > 0
}

var ErrOriginalRecoveryProjectionPending = errors.New("original physical sources recovered: signed succession unverified; retain admission and query original material only")

func (r *originalMinIOHistoryLifecycle) configureOriginalRecoverySigning(ctx context.Context, password, issuer []byte, authorization *OriginalWriterRecoveryAuthorization) error {
	if r == nil || r.recoveryBaseline == nil || r.signing != nil || authorization == nil || authorization.origin != authorization || authorization.set != r.set || r.set.recoveryAuthorization != authorization || !authorization.providersStopped || consumerSameContext(ctx, r.ctx) || len(password) == 0 || len(issuer) == 0 {
		return ErrInstall
	}
	r.signing = &originalMinIORecoverySigning{ctx: ctx, password: bytes.Clone(password), issuer: bytes.Clone(issuer), authorization: authorization}
	return nil
}

// Exact independent query only: legal after the source mutation barrier too.
// No source callback, permission mutation or signature send occurs here.
func (r *originalMinIOHistoryLifecycle) queryOriginalRecoveryProjection(ctx context.Context) error {
	if r == nil || !r.adoptionCommitted || r.signing == nil || r.recoveryBaseline == nil || !consumerSameContext(ctx, r.signing.ctx) || r.signing.authorization != r.set.recoveryAuthorization {
		return ErrInstall
	}
	s := r.signing
	s.attempted = true
	receipt, e := r.set.owner.operator.installer.QueryOriginalMinIORecoveryProjection(ctx, s.password, r.set.owner.enrollment, r.recoveryBaseline.descriptor)
	if e != nil {
		return e
	}
	s.receipt = &receipt
	return r.set.journal.append(ctx, r.writer.ID(), "minio_recovery_projection_exact_readback", nil, receipt)
}

// Called by the real lifecycle AFTER native permission recovery/readback and
// BEFORE its source-mutation barrier. Native restore and file send are separate
// phases: a partial retry still queries/finishes the original file operation.
func (r *originalMinIOHistoryLifecycle) issueOriginalRecoveryProjection(ctx context.Context) error {
	if r == nil || !r.adoptionCommitted {
		return nil
	} // failed/uncommitted adoption grants no succession
	if r.signing == nil || r.recoveryBaseline == nil || !consumerSameContext(ctx, r.signing.ctx) || r.recoveryObservation == nil {
		return ErrInstall
	}
	s := r.signing
	i := r.set.owner.operator.installer
	var receipt OriginalMinIORecoveryProjectionReceipt
	var e error
	if s.attempted || s.receipt != nil || r.set.journal.originalSourceMutationsClosed() {
		return r.queryOriginalRecoveryProjection(ctx)
	} else {
		if r.set.journal.append(ctx, r.writer.ID(), "minio_recovery_projection_send_intent", nil, r.recoveryBaseline.descriptor) != nil {
			return ErrInstall
		}
		receipt, e = i.IssueOriginalMinIORecoveryProjection(ctx, s.password, r.set.owner.enrollment, r.recoveryBaseline.descriptor, r, s.issuer)
		if errors.Is(e, ErrCommitUnknown) {
			s.attempted = true
			receipt, e = i.QueryOriginalMinIORecoveryProjection(ctx, s.password, r.set.owner.enrollment, r.recoveryBaseline.descriptor)
		}
	}
	if e != nil {
		return e
	}
	s.attempted = true
	s.receipt = &receipt
	return r.set.journal.append(ctx, r.writer.ID(), "minio_recovery_projection_exact_readback", nil, receipt)
}

var _ OriginalMinIORecoverySource = (*originalMinIOHistoryLifecycle)(nil)

func (r *originalMinIOHistoryLifecycle) originalMinIORecoveryTransition(ctx context.Context, i *Installer, enrollment EnrollmentPin, d ma.MinIORecoveryDescriptor, current *ma.SQLCurrentSnapshot) (ma.MinIORecoveryTransition, error) {
	var zero ma.MinIORecoveryTransition
	if r == nil || r.set == nil || r.set.minioHistory != r || r.recoveryBaseline == nil || r.signing == nil || !consumerSameContext(ctx, r.signing.ctx) || r.signing.authorization != r.set.recoveryAuthorization || r.set.owner.operator.installer != i || r.set.owner.enrollment != enrollment || !r.adoptionCommitted || r.archiveSource == nil || r.archiveSource.origin != r.archiveSource || r.recoveryObservation == nil || r.recoveryObservation.origin != r.recoveryObservation || r.recoveryObservation.lifecycle != r || r.recoveryObservation.fence != r.fence || r.recoveryPod.UID == "" || r.recoveryCID == r.recoveryBaseline.originalCID || current == nil {
		return zero, ErrInstall
	}
	baseline := r.recoveryBaseline
	expected, now, e := current.Comparison()
	if e != nil || current.RequireCurrent(now) != nil || !reflect.DeepEqual(expected, baseline.expected) || !reflect.DeepEqual(d, baseline.declaration) || r.recovered == nil || r.recovered.Recheck(ctx, r.set.owner.operation, r.set.inventorySHA, "recovered", now) != nil || r.check(ctx) != nil {
		return zero, ErrInstall
	}
	if r.checkOriginalCommittedAdoptionReadback(ctx) != nil {
		return zero, ErrInstall
	}
	response := r.recoveryObservation.native.Response()
	raw, e := json.Marshal(response)
	if e != nil || response.Binding.OperationID != r.set.owner.operation || response.Binding.InventorySHA256 != r.set.inventorySHA || response.Binding.ReservationID != r.archiveSource.archive.provider.reservation.ReservationID {
		return zero, ErrInstall
	}
	var format struct {
		SHA string `json:"format_sha256"`
	}
	if json.Unmarshal(r.archiveSource.cold.Format, &format) != nil {
		return zero, ErrInstall
	}
	recovered := r.recovered.Data()
	until := minTime(response.ValidUntil, minTime(recovered.ValidUntil, r.fence.operator.until))
	if end, ok := ctx.Deadline(); !ok {
		return zero, ErrInstall
	} else {
		until = minTime(until, end)
	}
	transition := ma.MinIORecoveryTransition{OperationID: r.set.owner.operation, ReservationID: response.Binding.ReservationID, InventorySHA256: ma.Digest(r.set.inventorySHA), NativeRequestSHA256: ma.Digest(response.RequestSHA256), NativeResponseSHA256: ma.Digest(hash(raw)), OriginalNativeSHA256: ma.Digest(r.gate.OriginalDigest()), ColdTreeSHA256: ma.Digest(r.archiveSource.cold.TreeSHA256), ArchiveReadbackSHA256: ma.Digest(originalObjectSHA(r.archiveSource.archive.retained.data.Readback)), FormatSHA256: ma.Digest(format.SHA), OriginalContainerID: baseline.originalCID, NewPod: r.recoveryPod, NewContainerID: r.recoveryCID, OriginalResources: retainedC1Copy(baseline.resources), RecoveredAt: recovered.StartedAt, OriginalProofUntil: until}
	if ma.ValidateMinIORecoveryTransition(transition) != nil {
		return zero, ErrInstall
	}
	r.signingTransition = &transition
	if r.recheckOriginalMinIORecoveryTransition(ctx, transition) != nil {
		return zero, ErrInstall
	}
	return transition, nil
}
func (r *originalMinIOHistoryLifecycle) recheckOriginalMinIORecoveryTransition(ctx context.Context, t ma.MinIORecoveryTransition) error {
	if r == nil || r.signing == nil || !consumerSameContext(ctx, r.signing.ctx) || r.signingTransition == nil || !reflect.DeepEqual(*r.signingTransition, t) || r.fence == nil || r.recovered == nil || r.recoveryObservation == nil || r.recoveryObservation.origin != r.recoveryObservation || r.set.journal.originalSourceMutationsClosed() || r.check(ctx) != nil || r.set.recheckVolumePins(ctx) != nil || !time.Now().Before(t.OriginalProofUntil) || r.recovered.Recheck(ctx, r.set.owner.operation, r.set.inventorySHA, "recovered", time.Now()) != nil {
		return ErrInstall
	}
	proof := r.recoveryObservation
	for _, node := range r.set.nodes {
		if node.request.Binding.Node == proof.request.Binding.Node {
			if proof.native.RecheckOriginalRecoveryScope(ctx, proof.request, nil, node.boot, time.Now()) != nil {
				return ErrInstall
			}
			return r.checkOriginalCommittedAdoptionReadback(ctx)
		}
	}
	return ErrInstall
}

// The actual real commit caller sets its private latch ONLY after independent
// readback/reconciliation. Verify the exact durable17/F/index again, without
// trying the old held-gate readback after recovery has entered releasing.
func (r *originalMinIOHistoryLifecycle) checkOriginalCommittedAdoptionReadback(ctx context.Context) error {
	if r == nil || !r.adoptionCommitted || r.adoption.ExpectedSHA256 == "" || r.fence == nil || r.fence.authorization == nil || r.fence.authorization != r.set.recoveryAuthorization {
		return ErrInstall
	}
	journal, e := r.fence.authorization.inspectOriginal(ctx)
	if e != nil {
		return ErrInstall
	}
	var expected originalAdoptionCommitExpected
	found := false
	for _, record := range journal.Records {
		if record.Action == "adoption_commit_readback" || record.Action == "adoption_commit_reconciled_committed_readback" {
			var current originalAdoptionCommitExpected
			if json.Unmarshal(record.Data, &current) != nil || found && originalObjectSHA(current) != originalObjectSHA(expected) {
				return ErrInstall
			}
			expected = current
			found = true
		}
	}
	if !found || originalObjectSHA(expected) != r.adoption.ExpectedSHA256 || expected.Operation != r.set.owner.operation || expected.InventorySHA256 != r.set.inventorySHA || expected.NewEpoch != r.adoption.ExpectedEpoch || len(expected.ControlRows) != 17 || len(expected.Sources) != 4 {
		return ErrInstall
	}
	tx, e := r.set.owner.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	snapshot, e := (reg.SQLStore{}).ReadExistingSnapshotInView(ctx, tx, expected.InstallationID)
	if e != nil || snapshot.Epoch != expected.NewEpoch || snapshot.Database.ServerUUID != expected.ServerUUID || snapshot.Database.Database != expected.Database || !reflect.DeepEqual(snapshot.Bindings, expected.Bindings) || !reflect.DeepEqual(snapshot.References, expected.References) || len(snapshot.Coverage) != 4 {
		return ErrInstall
	}
	parts := map[reg.Partition]reg.CoverageSource{}
	for _, source := range expected.Sources {
		if _, dup := parts[source.Partition]; dup {
			return ErrInstall
		}
		parts[source.Partition] = source
	}
	for _, source := range snapshot.Coverage {
		if parts[source.Partition] != source {
			return ErrInstall
		}
	}
	for id, want := range expected.ControlRows {
		var raw []byte
		var checksum, owner, kind, state string
		if tx.QueryRowContext(ctx, `SELECT inline_payload,content_checksum,owner_target_public_id,evidence_type,storage_state FROM system_backup_v2_evidence WHERE public_id=? AND owner_target_type='system'`, id).Scan(&raw, &checksum, &owner, &kind, &state) != nil || hash(raw) != want || checksum != want || owner != expected.InstallationID || kind != "catalog_scan_receipt" || state != "inline" {
			return ErrInstall
		}
	}
	return tx.Rollback()
}

func (r *originalMinIOHistoryLifecycle) recheckOriginalResourcesBeforeCold(ctx context.Context) error {
	if r == nil || r.recoveryBaseline == nil || r.check(ctx) != nil {
		return ErrInstall
	}
	b := r.recoveryBaseline
	actual, e := ma.CollectMinIORecoveryResources(ctx, r.set.owner.operator.installer.kube, b.target, b.provider, b.provider.Pod, b.originalCID)
	if e != nil || !reflect.DeepEqual(actual, b.resources) {
		return ErrInstall
	}
	return nil
}
