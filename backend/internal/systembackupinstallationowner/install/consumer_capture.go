package install

import (
	"bytes"
	"context"
	"database/sql"
	"sync/atomic"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const CaptureConsumerVersion = "system-backup-bootstrap-capture-consumer.v1"

// CaptureConsumerFiles only locates independently installed original public
// pins and exact request inputs. Neither this document nor its self-declared
// hashes establishes issuer trust: sourcePinFile is an independently deployed
// exact SHA256 pin, and the exported enrollment/public/consumer pins are kept
// separate from the signed record. No password, DSN or issuer private key fits
// this closed document. Current source authority is still checked at SQL L2.
type CaptureConsumerFiles struct {
	SchemaVersion                          string
	PlanFile, PlanSHA256                   string
	IssuerPublicFile, IssuerPublicSHA256   string
	TrustPinFile, TrustPinSHA256           string
	EnrollmentPinFile, EnrollmentPinSHA256 string
	KubeconfigFile, KubeconfigSHA256       string
	RecordFile, SignatureFile              string
	Request                                RequestFiles
}

type CaptureSigningConsumer struct{ sourceFile, sourcePinFile string }

// NewCaptureSigningConsumer performs no reads, credential opens, SQL or
// network work. D may link this concrete adapter in requirements mode; actual
// Prepare still refuses absent/untrusted inputs and remaining owners stay
// mandatory. Both fixed paths belong to trusted offline deployment composition.
func NewCaptureSigningConsumer(sourceFile, sourcePinFile string) *CaptureSigningConsumer {
	return &CaptureSigningConsumer{sourceFile: sourceFile, sourcePinFile: sourcePinFile}
}
func (*CaptureSigningConsumer) String() string               { return "EnrolledCaptureSigningConsumer" }
func (*CaptureSigningConsumer) GoString() string             { return "EnrolledCaptureSigningConsumer" }
func (*CaptureSigningConsumer) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

// Owners links only this concrete source and preserves the remaining mandatory
// requirements. Candidate composition must separately wrap the same Original.
func (s *CaptureSigningConsumer) Owners(base sec.BootstrapOwnerAdapters) (sec.BootstrapOwnerAdapters, error) {
	if s == nil || base.Candidates != nil {
		return sec.BootstrapOwnerAdapters{}, ErrInstall
	}
	if _, exists := base.References["capture_signing"]; exists {
		return sec.BootstrapOwnerAdapters{}, ErrInstall
	}
	out := sec.BootstrapOwnerAdapters{Registries: make(map[string]sec.BootstrapResourceValidator), References: make(map[string]sec.BootstrapResourceValidator), CrossResources: base.CrossResources, KEK: base.KEK}
	for k, v := range base.Registries {
		out.Registries[k] = v
	}
	for k, v := range base.References {
		out.References[k] = v
	}
	out.References["capture_signing"] = s
	return out, nil
}

type consumerPinnedFile struct {
	path, sha string
	limit     int64
}
type consumerCaptureState struct {
	ctx       context.Context
	files     []consumerPinnedFile
	request   *originalRequest
	validator *owner.CaptureSigningValidator
	failed    atomic.Bool
}

func (s *consumerCaptureState) current(ctx context.Context) error {
	if s == nil {
		return ErrInstall
	}
	if s.failed.Load() || !consumerSameContext(ctx, s.ctx) || ctx.Err() != nil {
		return s.finish(ErrInstall)
	}
	for _, pin := range s.files {
		raw, e := ReadPrivateFile(pin.path, pin.limit)
		if e != nil || hash(raw) != pin.sha {
			s.failed.Store(true)
			return ErrInstall
		}
	}
	if s.request == nil {
		s.failed.Store(true)
		return ErrInstall
	}
	for _, pin := range []consumerPinnedFile{{s.request.files.ConfigFile, s.request.files.ConfigFileSHA256, 262144}, {s.request.files.GrantFile, s.request.files.GrantFileSHA256, 16384}, {s.request.files.ObserverFile, s.request.files.ObserverFileSHA256, 262144}} {
		raw, e := ReadPrivateFile(pin.path, pin.limit)
		if e != nil || hash(raw) != pin.sha {
			return s.finish(ErrInstall)
		}
	}
	return nil
}
func (s *consumerCaptureState) finish(e error) error {
	if e != nil && s != nil {
		s.failed.Store(true)
	}
	return e
}

func (s *CaptureSigningConsumer) load(ctx context.Context) (*consumerCaptureState, error) {
	if s == nil || consumerNil(ctx) || ctx.Err() != nil {
		return nil, ErrInstall
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, ErrInstall
	}
	independent, e := ReadPrivateFile(s.sourcePinFile, 64)
	if e != nil || !digestPattern.Match(independent) {
		return nil, ErrInstall
	}
	raw, e := ReadPrivateFile(s.sourceFile, 262144)
	var files CaptureConsumerFiles
	if e != nil || hash(raw) != string(independent) || decodeExact(raw, &files) != nil || files.SchemaVersion != CaptureConsumerVersion {
		return nil, ErrInstall
	}
	state := &consumerCaptureState{ctx: ctx, files: []consumerPinnedFile{{s.sourcePinFile, hash(independent), 64}, {s.sourceFile, string(independent), 262144}}}
	read := func(path, sha string, limit int64) ([]byte, error) {
		raw, e := ReadPrivateFile(path, limit)
		if e != nil || !digestPattern.MatchString(sha) || hash(raw) != sha {
			return nil, ErrInstall
		}
		state.files = append(state.files, consumerPinnedFile{path, sha, limit})
		return raw, nil
	}
	planRaw, e := read(files.PlanFile, files.PlanSHA256, 262144)
	if e != nil {
		return nil, e
	}
	plan, e := DecodePlan(planRaw, files.PlanSHA256)
	if e != nil || plan.InstallerDatabaseAccount == plan.Target.DatabaseAccount {
		return nil, ErrInstall
	}
	public, e := read(files.IssuerPublicFile, files.IssuerPublicSHA256, 32)
	if e != nil || len(public) != 32 || files.IssuerPublicSHA256 != plan.IssuerPublicKeySHA256 {
		return nil, ErrInstall
	}
	pinRaw, e := read(files.TrustPinFile, files.TrustPinSHA256, 262144)
	var pin owner.TrustPin
	if e != nil || decodeExact(pinRaw, &pin) != nil {
		return nil, ErrInstall
	}
	enrollmentRaw, e := read(files.EnrollmentPinFile, files.EnrollmentPinSHA256, 262144)
	if e != nil {
		return nil, e
	}
	enrollment, e := DecodeEnrollmentPin(enrollmentRaw, files.EnrollmentPinSHA256)
	if e != nil {
		return nil, e
	}
	record, e := read(files.RecordFile, pin.RecordSHA256, 262144)
	if e != nil {
		return nil, e
	}
	signature, e := ReadPrivateFile(files.SignatureFile, 64)
	if e != nil {
		return nil, e
	}
	state.files = append(state.files, consumerPinnedFile{files.SignatureFile, hash(signature), 64})
	var r owner.Record
	if decodeExact(record, &r) != nil || r.Target != plan.Target || r.EnrollmentID != plan.EnrollmentID || r.EnrollmentRevision != plan.EnrollmentRevision || r.IssuerID != plan.IssuerID || r.Actor.Username != plan.LocalAdminUsername || r.Actor.OwnerSubject != plan.OwnerUsername || r.Actor.UserID < 1 {
		return nil, ErrInstall
	}
	expected := owner.TrustPin{InstallationID: plan.Target.InstallationID, EnrollmentID: plan.EnrollmentID, IssuerID: plan.IssuerID, EnrollmentRevision: plan.EnrollmentRevision, MinimumHeadRevision: pin.MinimumHeadRevision, Issuer: public, ClusterID: plan.Target.ClusterID, NamespaceUID: plan.Target.NamespaceUID, OwnerSubject: plan.OwnerUsername, ServerUUID: plan.Target.ServerUUID, Database: plan.Target.Database, DatabaseAccount: plan.Target.DatabaseAccount, GrantID: r.GrantID, GrantRevision: r.Revision, RecordSHA256: hash(record)}
	if !samePin(pin, expected) {
		return nil, ErrInstall
	}
	if _, e := owner.VerifyRecord(record, signature, expected); e != nil {
		return nil, ErrInstall
	}
	kube, e := openCaptureConsumerKubernetes(plan, files.KubeconfigFile, files.KubeconfigSHA256)
	if e != nil {
		return nil, e
	}
	state.files = append(state.files, consumerPinnedFile{files.KubeconfigFile, files.KubeconfigSHA256, 262144})
	// Actual immutable API registration is compared with the independently
	// retained UID/document pin. The signed record never supplies its own issuer.
	expectedEnrollment, e := canonical(enrollmentDocument{SchemaVersion: EnrollmentVersion, Plan: plan, AdminUserID: r.Actor.UserID, Issuer: public})
	if e != nil || hash(expectedEnrollment) != enrollment.DocumentSHA256 {
		return nil, ErrInstall
	}
	cm, e := kube.CoreV1().ConfigMaps(plan.Target.Namespace).Get(ctx, plan.EnrollmentName, metav1.GetOptions{})
	if e != nil || cm == nil || cm.Name != plan.EnrollmentName || cm.Namespace != plan.Target.Namespace || string(cm.UID) != enrollment.ConfigMapUID || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 1 || len(cm.BinaryData) != 0 || !bytes.Equal([]byte(cm.Data["enrollment.json"]), expectedEnrollment) {
		return nil, ErrInstall
	}
	request, e := readConsumerCaptureRequest(&Installer{plan: plan, kube: kube}, files.Request)
	if e != nil {
		return nil, e
	}
	state.request = request
	if owner.VerifyInstallationRequest(record, signature, pin, request.grant, request.config) != nil || r.NotBefore.Before(request.start) || r.Until.After(request.end) {
		request.observer.Close()
		return nil, ErrInstall
	}
	recordFiles := owner.RecordFiles{RecordFile: files.RecordFile, SignatureFile: files.SignatureFile}
	if request.observer == nil {
		state.validator, e = owner.NewCaptureSigningIdentityOnlyValidator(pin, recordFiles)
	} else {
		state.validator, e = owner.NewCaptureSigningValidator(pin, recordFiles, request.observer)
	}
	if e != nil || state.current(ctx) != nil {
		request.observer.Close()
		return nil, ErrInstall
	}
	return state, nil
}

type captureConsumerCheck struct {
	state    *consumerCaptureState
	original *owner.PreparedCaptureSigning
}

func (*captureConsumerCheck) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*captureConsumerCheck) String() string               { return "EnrolledCaptureSigningCheck" }
func (*captureConsumerCheck) GoString() string             { return "EnrolledCaptureSigningCheck" }
func (s *CaptureSigningConsumer) Prepare(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	state, e := s.load(ctx)
	if e != nil {
		return nil, e
	}
	defer state.request.observer.Close()
	if grant != state.request.grant || config.SHA256() != state.request.config.SHA256() {
		return nil, ErrInstall
	}
	check, e := state.validator.Prepare(ctx, grant, config)
	if e != nil || state.current(ctx) != nil {
		return nil, ErrInstall
	}
	prepared, ok := check.(*owner.PreparedCaptureSigning)
	if !ok {
		return nil, ErrInstall
	}
	return &captureConsumerCheck{state: state, original: prepared}, nil
}
func (c *captureConsumerCheck) AuthorizeBootstrapOriginal(ctx context.Context, tx *sql.Tx, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig, now time.Time) error {
	if c == nil || c.state == nil || c.original == nil || c.state.current(ctx) != nil {
		return ErrInstall
	}
	return c.state.finish(c.original.AuthorizeBootstrapOriginal(ctx, tx, grant, config, now))
}
func (c *captureConsumerCheck) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if c == nil || c.state == nil || c.original == nil || c.state.physical(ctx) != nil {
		return ErrInstall
	}
	return c.state.finish(c.original.Recheck(ctx, tx, now))
}

var _ sec.BootstrapResourceValidator = (*CaptureSigningConsumer)(nil)
var _ sec.BootstrapOriginalResourceAuthority = (*captureConsumerCheck)(nil)
