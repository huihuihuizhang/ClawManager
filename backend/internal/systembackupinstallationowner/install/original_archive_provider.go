package install

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	controller "clawreef/internal/systembackupcontroller"
	ev "clawreef/internal/systembackupevidence"
	archive "clawreef/internal/systembackuphostpatharchive"
	adapter "clawreef/internal/systembackupkekadapter"
)

const OriginalArchiveProviderVersion = "original-adoption-evidence-archive-provider.v1"

// Trusted original Installer input, independently file+SHA selected like Plan;
// never page request data. Selecting it does not grant provider operations.
// PrepareOriginalAdoptionArchiveProvider authenticates the DISTINCT original
// maintenance action, enrollment, live SQL gate and actual native permissions.
// No task, OfflineBootstrapGrant, key/role/token creation or SQL writes exist.
type OriginalArchiveProviderDefinition struct {
	Version, PlanSHA256, OperationIdentitySHA256 string
	MinIODefinitionFile, MinIODefinitionSHA256   string
	Vault                                        adapter.EvidenceVaultObserverConfig
	WrapJWT, UnwrapJWT                           OriginalArchiveJWTSource
	CustodyRoot                                  string
	PVCName, PVCUID, PVName, PVUID               string
	NativePythonFile, NativePythonSHA256         string
	NativeScriptFile, NativeScriptSHA256         string
	MaximumFiles, MaximumSeconds                 int
	MaximumBytes                                 int64
}

type OriginalArchiveJWTSource struct {
	File, SHA256, PodName, PodUID, DeploymentName, DeploymentUID string
}

// This opaque object is only original evidence-provider/copy authority.
// It is NOT B's physical holder, an immutable snapshot/history witness, or
// PreparedCoverage. Its actual SQL check cannot prove all writers stopped.
type OriginalAdoptionArchiveProvider struct {
	origin         *OriginalAdoptionArchiveProvider
	ctx            context.Context
	outer          context.Context
	cancel         context.CancelFunc
	done           chan struct{}
	operator       *authenticatedOperator
	enrollment     EnrollmentPin
	reservation    controller.OriginalAdoptionReservation
	database       controller.OriginalAdoptionDatabasePin
	definition     OriginalArchiveProviderDefinition
	sourceFile     string
	sourceSHA      string
	minio          MinIOPermissionDefinition
	initial        HeadCAS
	permissionSHA  string
	sourceIdentity string
	until          time.Time
	client         *http.Client
	keys           *ev.TransitKeys
	local          *archive.LocalArchive
	nativePlanSHA  string
	used, active   atomic.Bool
	failed         atomic.Bool
	wrapCalls      atomic.Uint32
	unwrapCalls    atomic.Uint32
}

func (*OriginalAdoptionArchiveProvider) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

// Fresh explicit Installer action; an existing six-reference record is NOT
// repurposed into write permission. Only actual original admin/enrollment,
// operation gate and pre-existing independent evidence provider roles permit
// this one call. D must journal the original archive intent before invoking it.
func (i *Installer) PrepareOriginalAdoptionArchiveProvider(ctx context.Context, password []byte,
	enrollment EnrollmentPin, reservation controller.OriginalAdoptionReservation,
	sourceFile, sourceSHA string) (*OriginalAdoptionArchiveProvider, error) {
	s, err := i.authenticate(ctx, password)
	if err != nil || s.authority(ctx, enrollment) != nil || reservation.Phase != controller.GateHeld ||
		reservation.InstallationID != i.plan.Target.InstallationID ||
		reservation.ServerUUID != i.plan.Target.ServerUUID || reservation.Database != i.plan.Target.Database {
		return nil, ErrInstall
	}
	raw, err := ReadPrivateFile(sourceFile, 1<<20)
	var d OriginalArchiveProviderDefinition
	identity, identityErr := controller.OriginalAdoptionReservationIdentitySHA256(reservation)
	if err != nil || hash(raw) != sourceSHA || decodeExact(raw, &d) != nil || identityErr != nil ||
		d.Version != OriginalArchiveProviderVersion || d.PlanSHA256 != i.planHash ||
		d.OperationIdentitySHA256 != identity || adapter.ValidateEvidenceVaultObserver(d.Vault) != nil ||
		d.Vault.Transit.Installation != i.plan.Target.InstallationID ||
		d.Vault.Wrap.Namespace != i.plan.Target.Namespace || d.Vault.Unwrap.Namespace != i.plan.Target.Namespace ||
		d.WrapJWT.PodUID == "" || d.UnwrapJWT.PodUID == "" ||
		d.Vault.Wrap.Audience == d.Vault.Unwrap.Audience || d.WrapJWT.File == d.UnwrapJWT.File ||
		d.WrapJWT.SHA256 == d.UnwrapJWT.SHA256 || d.CustodyRoot == "" ||
		d.PVCName == "" || d.PVCUID == "" || d.PVName == "" || d.PVUID == "" ||
		d.NativePythonFile == "" || d.NativeScriptFile == "" ||
		!digestPattern.MatchString(d.NativePythonSHA256) || !digestPattern.MatchString(d.NativeScriptSHA256) ||
		d.MaximumFiles <= 0 || d.MaximumBytes <= 0 || d.MaximumSeconds <= 0 || d.MaximumSeconds > 600 {
		return nil, ErrInstall
	}
	minioRaw, err := ReadSourceMaterialFile(d.MinIODefinitionFile)
	m, decodeErr := DecodeMinIOPermissionDefinition(minioRaw, d.MinIODefinitionSHA256)
	if err != nil || decodeErr != nil || m.Grant.Profile != "minio-2025-09-07-builtin-flat.v1" ||
		m.Grant.Installation != i.plan.Target.InstallationID ||
		m.Grant.Namespace != i.plan.Target.Namespace || m.Grant.NamespaceUID != i.plan.Target.NamespaceUID {
		return nil, ErrInstall
	}
	p := &OriginalAdoptionArchiveProvider{ctx: ctx, outer: ctx, done: make(chan struct{}), operator: s, enrollment: enrollment,
		reservation: reservation, database: controller.OriginalAdoptionDatabasePin{
			ServerUUID: i.plan.Target.ServerUUID, Database: i.plan.Target.Database, Account: i.plan.InstallerDatabaseAccount},
		definition: d, sourceFile: sourceFile, sourceSHA: sourceSHA, minio: m, until: s.until}
	p.origin = p
	if _, err = p.currentSQL(true); err != nil {
		return nil, ErrInstall
	}
	// Transfer this private authenticated IO session to a strictly SHORTER
	// child deadline after the real gate read. No SQL locks survive this point;
	// this child context is never D's final evidence/adoption tx context.
	p.ctx, p.cancel = context.WithDeadline(ctx, p.until)
	s.ctx = p.ctx
	prepared := false
	defer func() {
		if !prepared {
			p.Close()
		}
	}()
	observation, err := adapter.ObserveEvidenceVault(p.ctx, d.Vault)
	if err != nil {
		return nil, ErrInstall
	}
	p.permissionSHA = observation.IdentitySHA256()
	if p.permissionSHA == "" {
		return nil, ErrInstall
	}
	p.sourceIdentity, err = p.observeSource()
	if err != nil || p.checkJWT(d.WrapJWT, d.Vault.Wrap) != nil || p.checkJWT(d.UnwrapJWT, d.Vault.Unwrap) != nil {
		return nil, ErrInstall
	}
	p.client, err = originalArchiveTLSClient(d.Vault.Transit)
	if err != nil {
		return nil, ErrInstall
	}
	p.keys, err = ev.NewTransitKeys(d.Vault.Transit, originalArchiveCredentials{p})
	if err != nil || p.current() != nil {
		p.Close()
		return nil, ErrInstall
	}
	prepared = true
	return p, nil
}

func (p *OriginalAdoptionArchiveProvider) fail() error {
	if p != nil {
		p.failed.Store(true)
		if p.cancel != nil {
			p.cancel()
		}
	}
	return ErrInstall
}

// Real short original RR read: gate -> actual admin/head/grant. It ALWAYS
// releases SQL locks before Kubernetes/Vault/node IO. No detached new tx can
// stand in for D's final SAME original evidence/adoption transaction.
func (p *OriginalAdoptionArchiveProvider) currentSQL(initial bool) (time.Time, error) {
	if p == nil || p.origin != p || p.operator == nil || p.failed.Load() || !p.operator.live(p.ctx) || !time.Now().Before(p.until) {
		return time.Time{}, p.fail()
	}
	s, i := p.operator, p.operator.installer
	tx, err := i.db.BeginTx(p.ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return time.Time{}, p.fail()
	}
	defer tx.Rollback()
	gate, err := controller.LockOriginalAdoptionReservation(p.ctx, tx, p.database, p.reservation)
	if err != nil {
		return time.Time{}, p.fail()
	}
	now, err := s.lockAdmin(p.ctx, tx)
	if err != nil {
		return time.Time{}, p.fail()
	}
	current, err := s.current(p.ctx, tx, false)
	if err != nil || current.cas.HeadRevision != 0 && (current.cas.State != "active" ||
		now.Before(current.head.NotBefore) || !now.Before(current.head.Until)) || !initial && current.cas != p.initial {
		return time.Time{}, p.fail()
	}
	if initial {
		p.initial = current.cas
		if gate.ValidUntil().Before(p.until) {
			p.until = gate.ValidUntil()
		}
	}
	stamp, err := i.database(p.ctx, tx, p.until)
	if err != nil || gate.Recheck(p.ctx, tx, stamp) != nil || tx.Rollback() != nil {
		return time.Time{}, p.fail()
	}
	return stamp, nil
}

func (p *OriginalAdoptionArchiveProvider) current() error {
	if p == nil || p.origin != p || p.operator == nil || p.failed.Load() || !p.operator.live(p.ctx) || !time.Now().Before(p.until) ||
		p.operator.authority(p.ctx, p.enrollment) != nil {
		return p.fail()
	}
	raw, err := ReadPrivateFile(p.sourceFile, 1<<20)
	if err != nil || hash(raw) != p.sourceSHA {
		return p.fail()
	}
	minioRaw, err := ReadSourceMaterialFile(p.definition.MinIODefinitionFile)
	if err != nil || hash(minioRaw) != p.definition.MinIODefinitionSHA256 {
		return p.fail()
	}
	if _, err = p.currentSQL(false); err != nil {
		return p.fail()
	}
	identity, err := p.observeSource()
	if err != nil || identity != p.sourceIdentity {
		return p.fail()
	}
	observed, err := adapter.ObserveEvidenceVault(p.ctx, p.definition.Vault)
	if err != nil || observed.IdentitySHA256() != p.permissionSHA ||
		p.checkJWT(p.definition.WrapJWT, p.definition.Vault.Wrap) != nil ||
		p.checkJWT(p.definition.UnwrapJWT, p.definition.Vault.Unwrap) != nil {
		return p.fail()
	}
	_, err = p.currentSQL(false)
	return err
}

// One-shot encrypted RAW copy, not a cold/immutable/history/adoption receipt.
// B/D must add their actual physical holder and independently managed archive
// custody/retention before using it for the page's first-adoption dependency.
// Source and sink selection are authenticated by this original Installer
// action and native discovery; caller cannot supply a Binding/Keys/Passed flag.
func (p *OriginalAdoptionArchiveProvider) CreateUnadmittedEncryptedCopy(ctx context.Context,
	name string, native archive.NativeStream) (*archive.LocalArchive, error) {
	if p == nil || !consumerSameContext(ctx, p.outer) || !p.used.CompareAndSwap(false, true) {
		return nil, p.fail()
	}
	defer close(p.done)
	if p.current() != nil {
		return nil, p.fail()
	}
	if native.PythonFile != p.definition.NativePythonFile || native.PythonSHA256 != p.definition.NativePythonSHA256 ||
		native.ScriptFile != p.definition.NativeScriptFile || native.ScriptSHA256 != p.definition.NativeScriptSHA256 ||
		native.MaxFiles > p.definition.MaximumFiles || native.MaxBytes > p.definition.MaximumBytes ||
		native.MaxSeconds > p.definition.MaximumSeconds {
		return nil, p.fail()
	}
	planRaw, err := ReadPrivateFile(native.PlanFile, 1<<20)
	var plan struct {
		Root          string `json:"root"`
		PodUID        string `json:"pod_uid"`
		ContainerName string `json:"container_name"`
		Node          struct {
			BootID    string `json:"boot_id"`
			MachineID string `json:"machine_id"`
		} `json:"node"`
		Format struct {
			DeploymentID string `json:"deployment_id"`
		} `json:"format"`
	}
	if err != nil || hash(planRaw) != native.PlanSHA256 || json.Unmarshal(planRaw, &plan) != nil ||
		plan.PodUID != p.minio.Grant.Provider.Pod.UID || plan.ContainerName != p.minio.Grant.Provider.Container ||
		plan.Format.DeploymentID != p.minio.Grant.Provider.DeploymentID {
		return nil, p.fail()
	}
	hostPath, nodeBoot, nodeMachine, err := p.sourcePath()
	if err != nil || hostPath != plan.Root || plan.Node.BootID != nodeBoot || plan.Node.MachineID != nodeMachine {
		return nil, p.fail()
	}
	custody, err := os.OpenRoot(p.definition.CustodyRoot)
	if err != nil {
		return nil, p.fail()
	}
	defer custody.Close()
	info, err := custody.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, p.fail()
	}
	canonicalPath, err := filepath.EvalSymlinks(p.definition.CustodyRoot)
	if err != nil || canonicalPath != p.definition.CustodyRoot ||
		strings.HasPrefix(canonicalPath+string(os.PathSeparator), hostPath+string(os.PathSeparator)) {
		return nil, p.fail()
	}
	identity, _ := controller.OriginalAdoptionReservationIdentitySHA256(p.reservation)
	binding := archive.Binding{Installation: p.reservation.InstallationID, ServerUUID: p.reservation.ServerUUID,
		Database: p.reservation.Database, MaintenanceID: p.reservation.OperationID, Generation: p.reservation.GateGeneration,
		WriterCensusSHA256: p.reservation.SourceWritersSHA256, HoldRevision: identity,
		SourceIdentitySHA256: p.sourceIdentity, EvidenceProviderSHA256: p.permissionSHA,
		CustodyIdentitySHA256: p.custodyIdentity(), SourceHostPath: hostPath,
		SourcePVUID: p.definition.PVUID, SourceClaimUID: p.definition.PVCUID, SourceNodeUID: p.minio.Grant.Provider.NodeUID}
	p.active.Store(true)
	defer p.active.Store(false)
	local, err := archive.CreateEncryptedLocal(p.ctx, custody, name, binding, native, p.keys, p.definition.Vault.Transit.Key)
	if err != nil || p.current() != nil {
		if local != nil {
			local.Close()
		}
		return nil, p.fail()
	}
	p.local, p.nativePlanSHA = local, native.PlanSHA256
	return local, nil
}

// RecheckOriginalCopy is the concrete NEXT consumer boundary: D calls it
// BEFORE opening its final original evidence/adoption transaction. It verifies
// the actual same producer object, pinned ciphertext and current original
// operation/enrollment/source/provider. It does not attest B physical quiesce,
// immutable independent custody, normalized history or adopted coverage.
func (p *OriginalAdoptionArchiveProvider) RecheckOriginalCopy(ctx context.Context, local *archive.LocalArchive) error {
	if p == nil || !consumerSameContext(ctx, p.outer) || local == nil || p.local != local ||
		local.Receipt().SHA256 == "" || p.current() != nil || local.CopyCiphertext(p.ctx, io.Discard) != nil {
		return p.fail()
	}
	_, err := p.currentSQL(false)
	return err
}

// These are actual producer association DATA for D's original journal, not a
// new grant/evidence kind. A caller-supplied copy must never replace this opaque
// producer in RecheckOriginalCopy or authorize D's final SQL source binding.
type OriginalArchiveCopyObservation struct {
	Version, State, DefinitionSHA256, NativePlanSHA256                  string
	Reservation                                                         controller.OriginalAdoptionReservation
	NativePermissionSHA256, SourceIdentitySHA256, CustodyIdentitySHA256 string
	CiphertextSHA256, AssociationSHA256, Name                           string
	CiphertextBytes                                                     int64
	EvidenceKey                                                         ev.KeyRef
	Until                                                               time.Time
}

func (p *OriginalAdoptionArchiveProvider) ObserveOriginalCopy(ctx context.Context, local *archive.LocalArchive) (OriginalArchiveCopyObservation, error) {
	if p.RecheckOriginalCopy(ctx, local) != nil {
		return OriginalArchiveCopyObservation{}, ErrInstall
	}
	receipt := local.Receipt()
	return OriginalArchiveCopyObservation{Version: OriginalArchiveProviderVersion, State: "encrypted_raw_copy_only_not_admitted",
		DefinitionSHA256: p.sourceSHA, NativePlanSHA256: p.nativePlanSHA, Reservation: p.reservation,
		NativePermissionSHA256: p.permissionSHA, SourceIdentitySHA256: p.sourceIdentity,
		CustodyIdentitySHA256: p.custodyIdentity(), CiphertextSHA256: receipt.SHA256,
		AssociationSHA256: hash(local.AssociationHeader()), Name: receipt.Name, CiphertextBytes: receipt.Size,
		EvidenceKey: p.definition.Vault.Transit.Key, Until: p.until}, nil
}

func (p *OriginalAdoptionArchiveProvider) Close() {
	if p != nil {
		p.failed.Store(true)
		if p.cancel != nil {
			p.cancel()
		}
		if p.client != nil {
			p.client.CloseIdleConnections()
		}
		if p.keys != nil {
			p.keys.Close()
		}
	}
}

// Stop cancels the original bounded native copy and waits for its actual
// process/encryption call to return. A timeout is NOT a stopped ACK. D must
// keep the original recovery fence and must not resume writers on this error.
func (p *OriginalAdoptionArchiveProvider) Stop(ctx context.Context) error {
	if p == nil || p.origin != p || ctx == nil {
		return ErrInstall
	}
	p.Close()
	if !p.used.Load() {
		return nil
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ErrInstall
	}
}
