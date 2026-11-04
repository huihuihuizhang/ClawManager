package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"

	c "clawreef/internal/systembackupcontroller"
	api "clawreef/internal/systembackupdeployment"
	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
)

// Offline original-owner action parameters, not an authenticated scope DTO.
// Forward is reauthenticated through its original runtime SQL peer; source
// material's issuer is fixed by the independently enrolled original Plan.
type OriginalPublicationAuthorizationInputs struct {
	Request                                                  RequestFiles
	Forward                                                  *c.PinnedExecutionIdentity
	DeploymentCore, Config, Profile, SigningMaterial         BootstrapSourceFilePin
	ControllerDeployment, ControllerPodName, OutputDirectory string
}
type OriginalPublicationRuntimeOwnerInputs struct {
	Version, PlanSHA256, EnrollmentDocumentSHA256 string
	SigningRecord                                 sec.FileSigningRecordReader
	SigningPin                                    sec.InstallationSigningPin
	SigningMounts                                 []sec.PublicationSigningMount
	PublisherGrant                                sec.PublisherCaptureGrantMount
}
type OriginalPublicationAuthorizationReceipt struct {
	Version                            string
	RuntimeOwnerInputs, SigningPinFile BootstrapSourceFilePin
	SigningRecord                      sec.FileSigningRecordReader
	SigningPin                         sec.InstallationSigningPin
	PublisherGrant                     sec.PublisherCaptureGrantMount
}

// This EXPLICIT separate original installation-owner action creates the
// SQL-signing and publisher-verification business authorizations. Neither is
// inferred from capture, metadata/login, a resource consumer or a provider ACL.
// It uses the original enrolled issuer, exact original SQL/deployment scope,
// live admin/enrollment/head and actual independent purpose-specific probes.
// First-install scope is the exact signed disabled bootstrap request and fixed
// version one, not an assertion that an active config row already exists.
func (i *Installer) IssueOriginalPublicationAuthorization(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, in OriginalPublicationAuthorizationInputs, issuerPrivate []byte) (OriginalPublicationAuthorizationReceipt, error) {
	return i.issueOriginalPublicationAuthorization(ctx, runtimeDB, password, enrollment, in, issuerPrivate, nil)
}
func (i *Installer) IssueEnabledPublicationAuthorization(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, in OriginalPublicationAuthorizationInputs, issuerPrivate []byte, enabled *OriginalEnabledPublication) (OriginalPublicationAuthorizationReceipt, error) {
	if enabled == nil || enabled.operator == nil || enabled.operator.installer != i || enabled.enrollment != enrollment || enabled.request.files != in.Request || enabled.Recheck(ctx) != nil {
		return OriginalPublicationAuthorizationReceipt{}, ErrInstall
	}
	return i.issueOriginalPublicationAuthorization(ctx, runtimeDB, password, enrollment, in, issuerPrivate, enabled)
}
func (i *Installer) issueOriginalPublicationAuthorization(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, in OriginalPublicationAuthorizationInputs, issuerPrivate []byte, enabled *OriginalEnabledPublication) (OriginalPublicationAuthorizationReceipt, error) {
	var zero OriginalPublicationAuthorizationReceipt
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil || runtimeDB == nil || in.Forward == nil || privateDirectory(in.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	before, now, e := originalAdoptionAuthoritySnapshot(ctx, op)
	if e != nil || before.cas.State != "active" || before.cas.HeadRevision == 0 || now.Before(before.head.NotBefore) || !now.Before(before.head.Until) {
		return zero, ErrInstall
	}
	expectedVersion := uint64(1)
	revision := uint64(2)
	if enabled != nil {
		expectedVersion = 2
		revision = 3
		if enabled.operator.userID != op.userID || before.cas != enabled.initial || enabled.Recheck(ctx) != nil {
			return zero, ErrInstall
		}
	}
	binding := func(r owner.Record, request *originalRequest) error {
		if enabled == nil {
			return originalPublicationBootstrapBinding(i.plan.Target, in.Forward.DeploymentBinding(), r, in.Config, request)
		}
		if enabled.Recheck(ctx) != nil || r.Target != i.plan.Target || !request.matchesDraft(r) || in.Config.SHA256 != enabled.configSHA || in.Forward.DeploymentBinding().ConfigSHA256 != enabled.configSHA {
			return ErrInstall
		}
		raw, e := readBootstrapSourcePin(in.Config, 262144)
		if e != nil || !bytes.Equal(raw, enabled.current) {
			return ErrInstall
		}
		return nil
	}
	g := in.Forward.DeploymentBinding()
	if g.InstallationID != i.plan.Target.InstallationID || g.Database != i.plan.Target.Database || g.ServerUUID != i.plan.Target.ServerUUID || g.ConfigVersion != expectedVersion || g.ConfigSHA256 != in.Config.SHA256 || g.DeploymentConfigSHA256 != in.DeploymentCore.SHA256 || g.ProfileSHA256 != in.Profile.SHA256 || in.Forward.CheckDeployment(ctx, runtimeDB) != nil {
		return zero, ErrInstall
	}
	if _, e := i.checkOriginalRuntimeSQLPeer(ctx, runtimeDB, g.DatabaseAccount); e != nil {
		return zero, ErrInstall
	}
	request, e := readRequest(i, in.Request)
	if e != nil {
		return zero, ErrInstall
	}
	defer request.observer.Close()
	if binding(before.record, request) != nil || !requestWindow(before.record, request, now) {
		return zero, ErrInstall
	}
	for _, p := range []BootstrapSourceFilePin{in.DeploymentCore, in.Config} {
		if _, e := readBootstrapSourcePin(p, 262144); e != nil {
			return zero, e
		}
	}
	profile, e := api.LoadExecutionProfile(in.Profile.File)
	if e != nil {
		return zero, e
	}
	_, profileSHA, e := profile.CanonicalIdentity()
	if e != nil || profileSHA != in.Profile.SHA256 || profile.InstallationID != i.plan.Target.InstallationID || profile.TargetClass != "same-cluster-copy" {
		return zero, ErrInstall
	}
	material, e := readOriginalPublicationSigningFiles(ctx, i.public, in.SigningMaterial)
	if e != nil || material.Version != "original-publication-signing-material.v1" || material.PlanSHA256 != i.planHash || material.EnrollmentDocumentSHA256 != enrollment.DocumentSHA256 || !bytes.Equal(material.Pin.Issuer, i.public) || material.Pin.InstallationID != i.plan.Target.InstallationID || len(material.Bindings) != 3 || len(material.Histories) != 3 || len(material.JWTFiles) != 3 {
		return zero, ErrInstall
	}
	if _, e = sec.LoadInstallationSigningHistory(ctx, material.Record, material.Pin); e != nil {
		return zero, e
	}
	recordRaw, signature, e := material.Record.ReadSigningRecord(ctx)
	var original sec.InstallationSigningRecord
	if e != nil || !ed25519.Verify(i.public, append([]byte(sec.InstallationSigningDomain), recordRaw...), signature) || decodeExact(recordRaw, &original) != nil || len(original.Permissions) != 3 || len(original.Keys) != 3 || original.Revision != 1 || material.Pin.Revision != 1 || hash(recordRaw) != material.Pin.RecordSHA256 || original.InstallationID != i.plan.Target.InstallationID {
		return zero, ErrInstall
	}
	actor, e := i.originalPublicationActor(ctx, in.ControllerDeployment, in.ControllerPodName)
	if e != nil {
		return zero, e
	}
	until := minTime(g.ExpiresAt, minTime(original.Until, minTime(before.head.Until, minTime(before.record.Until, request.end))))
	if now.Before(g.NotBefore) || now.Before(original.NotBefore) || !now.Before(until) || until.Sub(now) > 24*time.Hour {
		return zero, ErrInstall
	}
	// Original issuer can delegate this distinct purpose only within all retained
	// original windows. No automatic renewal or extension is performed here.
	key, e := op.privateKey(issuerPrivate)
	if e != nil {
		return zero, e
	}
	defer clear(key)
	ca, e := readBootstrapSourcePin(material.CA, 65536)
	if e != nil {
		return zero, e
	}
	docRaw, e := readBootstrapSourcePin(material.ResourceObserver, 262144)
	var doc observerDocument
	if e != nil || decodeExact(docRaw, &doc) != nil || doc.CASHA256 != material.CA.SHA256 || doc.CAFile != material.CA.File || !reflect.DeepEqual(doc.Trust, material.Trust) {
		return zero, ErrInstall
	}
	vault, e := newOriginalPublicationVault(doc.Endpoint, ca, doc.CASHA256)
	if e != nil {
		return zero, e
	}
	defer vault.close()
	observerRaw, e := ReadPrivateFile(doc.ObserverTokenFile, 16384)
	if e != nil || hash(observerRaw) != doc.ObserverTokenSHA256 {
		return zero, ErrInstall
	}
	defer clear(observerRaw)
	token, e := originalPublicationToken(observerRaw)
	if e != nil {
		return zero, e
	}
	defer clear(token)
	lookup, e := vault.data(ctx, "/v1/auth/token/lookup-self", token)
	var tokenInfo struct {
		Policies         []string
		IdentityPolicies []string `json:"identity_policies"`
		TTL              int64
	}
	if e != nil || json.Unmarshal(lookup, &tokenInfo) != nil || !reflect.DeepEqual(tokenInfo.Policies, []string{doc.ObserverPolicy}) || len(tokenInfo.IdentityPolicies) != 0 || tokenInfo.TTL < 1 || tokenInfo.TTL > 600 {
		return zero, ErrInstall
	}
	wantedACL, e := owner.SigningResourceObserverACL(owner.SigningResourceGrant{Target: i.plan.Target, Bindings: material.Bindings, Histories: material.Histories}, doc.ObserverPolicy)
	if e != nil {
		return zero, e
	}
	observerACL, e := vault.data(ctx, "/v1/sys/policies/acl/"+doc.ObserverPolicy, token)
	var policy struct{ Name, Policy string }
	if e != nil || json.Unmarshal(observerACL, &policy) != nil || policy.Name != doc.ObserverPolicy || policy.Policy != wantedACL {
		return zero, ErrInstall
	}
	record := sec.InstallationSigningRecord{InstallationID: g.InstallationID, Revision: revision, NotBefore: now, Until: until}
	result := OriginalPublicationRuntimeOwnerInputs{Version: "original-publication-runtime-owner-inputs.v1", PlanSHA256: i.planHash, EnrollmentDocumentSHA256: enrollment.DocumentSHA256}
	probeUntil := until
	for n, b := range material.Bindings {
		if b.Purpose != []string{"acceptance_record", "capture_certificate", "catalog_record"}[n] || b.InstallationID != actor.InstallationID || b.Namespace != actor.Namespace || b.NamespaceUID != actor.NamespaceUID || b.PodName != actor.PodName || b.PodUID != actor.PodUID || b.ServiceAccountName != actor.ServiceAccountName || b.ServiceAccountUID != actor.ServiceAccountUID || b.Endpoint != doc.Endpoint || b.CASHA256 != doc.CASHA256 || material.Histories[n].Purpose != b.Purpose {
			return zero, ErrInstall
		}
		p := original.Permissions[n]
		if p.SQLOwner != nil || p.Binding != (sec.TransitSigningBinding{InstallationID: b.InstallationID, Purpose: b.Purpose, KeyID: b.KeyID, KeyVersion: b.KeyVersion, Endpoint: b.Endpoint, KeyName: b.KeyName, ProviderVersion: b.ProviderVersion}) || p.AuthMount != b.AuthMount || p.Role != b.Role || p.Policy != b.Policy || p.CASHA256 != b.CASHA256 {
			return zero, ErrInstall
		}
		k := original.Keys[n]
		if k.InstallationID != b.InstallationID || k.Purpose != b.Purpose || k.KeyID != b.KeyID || k.KeyVersion != b.KeyVersion || k.Revoked || now.Before(k.NotBefore) || until.After(k.NotAfter) {
			return zero, ErrInstall
		}
		if vault.health(ctx, b.ProviderClusterID) != nil || originalPublicationCheckMetadata(ctx, vault, b, material.Histories[n], token) != nil {
			return zero, ErrInstall
		}
		jwt, e := readBootstrapSourcePin(material.JWTFiles[b.Purpose], 16384)
		if e != nil {
			return zero, e
		}
		end, e := i.originalPublicationProbe(ctx, vault, b, k.PublicKey, jwt)
		clear(jwt)
		if e != nil {
			return zero, e
		}
		if end.Before(probeUntil) {
			probeUntil = end
		}
		p.SQLOwner = &sec.SQLSigningOwnerGrant{ServerUUID: g.ServerUUID, Database: g.Database, DatabaseAccount: g.DatabaseAccount, ControllerOwner: "public:" + actor.PodUID, ConfigVersion: g.ConfigVersion, ConfigSHA256: g.ConfigSHA256, Workload: sec.SigningWorkloadIdentity{Namespace: actor.Namespace, PodUID: actor.PodUID, ServiceAccountUID: actor.ServiceAccountUID}}
		record.Permissions = append(record.Permissions, p)
		record.Keys = append(record.Keys, k)
		result.SigningMounts = append(result.SigningMounts, sec.PublicationSigningMount{Binding: p.Binding, AuthMount: p.AuthMount, Role: p.Role, Policy: p.Policy, CASHA256: p.CASHA256, CAFile: material.CA.File, JWTFile: material.JWTFiles[b.Purpose].File})
	}
	deployment := sec.PublisherCaptureDeployment{InstallationID: g.InstallationID, ServerUUID: g.ServerUUID, Database: g.Database, DatabaseAccount: g.DatabaseAccount, ControllerOwner: g.ControllerOwner, ConfigVersion: g.ConfigVersion, ConfigSHA256: g.ConfigSHA256, ProfileSHA256: g.ProfileSHA256, DeploymentConfigSHA256: g.DeploymentConfigSHA256, CaptureGrantSHA256: in.Forward.GrantSHA256(), NotBefore: g.NotBefore, Until: g.ExpiresAt}
	workload := sec.PublisherCaptureWorkload{Namespace: actor.Namespace, NamespaceUID: actor.NamespaceUID, PodName: actor.PodName, PodUID: actor.PodUID, ServiceAccountName: actor.ServiceAccountName, ServiceAccountUID: actor.ServiceAccountUID, PublisherOwner: "public:" + actor.PodUID}
	if workload.PublisherOwner == deployment.ControllerOwner {
		return zero, ErrInstall
	}
	grant := sec.PublisherCaptureGrant{Version: sec.PublisherCaptureGrantVersion, Deployment: deployment, Workload: workload, NotBefore: now, Until: until}
	recordBytes, e := canonical(record)
	if e != nil {
		return zero, e
	}
	grantBytes, e := canonical(grant)
	if e != nil {
		return zero, e
	}
	signedGrant, e := canonical(sec.SignedPublisherCaptureGrant{Record: grantBytes, Signature: ed25519.Sign(key, append([]byte(sec.PublisherCaptureGrantDomain), grantBytes...))})
	if e != nil {
		return zero, e
	}
	recordSig := ed25519.Sign(key, append([]byte(sec.InstallationSigningDomain), recordBytes...))
	result.SigningRecord = sec.FileSigningRecordReader{RecordFile: filepath.Join(in.OutputDirectory, "runtime-signing.record.json"), SignatureFile: filepath.Join(in.OutputDirectory, "runtime-signing.signature")}
	result.SigningPin = sec.InstallationSigningPin{InstallationID: g.InstallationID, Revision: record.Revision, RecordSHA256: hash(recordBytes), Issuer: bytes.Clone(i.public)}
	result.PublisherGrant = sec.PublisherCaptureGrantMount{File: filepath.Join(in.OutputDirectory, "publisher-capture.grant.json"), SHA256: hash(signedGrant), Issuer: bytes.Clone(i.public)}
	pinBytes, e := canonical(result.SigningPin)
	if e != nil {
		return zero, e
	}
	resultBytes, e := canonical(result)
	if e != nil {
		return zero, e
	}
	floor := now
	recheck := func() error {
		if request.recheck(i) != nil || op.authority(ctx, enrollment) != nil || in.Forward.CheckDeployment(ctx, runtimeDB) != nil {
			return ErrInstall
		}
		current, t, e := originalAdoptionAuthoritySnapshot(ctx, op)
		if e != nil || current.cas != before.cas || t.Before(floor) || binding(current.record, request) != nil || !requestWindow(current.record, request, t) || !t.Before(until) || !t.Before(probeUntil) || !time.Now().Before(probeUntil) {
			return ErrInstall
		}
		actual, e := i.originalPublicationActor(ctx, in.ControllerDeployment, in.ControllerPodName)
		if e != nil || actual != actor {
			return ErrInstall
		}
		for _, p := range []BootstrapSourceFilePin{in.SigningMaterial, in.Config, in.DeploymentCore, material.ResourceObserver, material.CA} {
			if _, e := readBootstrapSourcePin(p, 262144); e != nil {
				return ErrInstall
			}
		}
		profile, profileErr := api.LoadExecutionProfile(in.Profile.File)
		if profileErr != nil {
			return ErrInstall
		}
		_, profileSHA, profileErr := profile.CanonicalIdentity()
		if profileErr != nil || profileSHA != in.Profile.SHA256 || profileSHA != g.ProfileSHA256 {
			return ErrInstall
		}
		checked, manifestErr := readOriginalPublicationSigningFiles(ctx, i.public, in.SigningMaterial)
		if manifestErr != nil || !reflect.DeepEqual(checked, material) {
			return ErrInstall
		}
		r, s, e := material.Record.ReadSigningRecord(ctx)
		if e != nil || !bytes.Equal(r, recordRaw) || !bytes.Equal(s, signature) {
			return ErrInstall
		}
		for _, p := range material.JWTFiles {
			if _, e := readBootstrapSourcePin(p, 16384); e != nil {
				return ErrInstall
			}
		}
		fresh, e := ReadPrivateFile(doc.ObserverTokenFile, 16384)
		defer clear(fresh)
		if e != nil || !bytes.Equal(fresh, observerRaw) {
			return ErrInstall
		}
		if _, e := i.checkOriginalRuntimeSQLPeer(ctx, runtimeDB, g.DatabaseAccount); e != nil {
			return ErrInstall
		}
		// Final SQL sample follows every slow actor/file read; its original CAS,
		// source request and monotonic floor remain mandatory through output.
		tail, after, e := originalAdoptionAuthoritySnapshot(ctx, op)
		if e != nil || tail.cas != before.cas || after.Before(t) || after.Before(floor) || binding(tail.record, request) != nil || !requestWindow(tail.record, request, after) || !after.Before(until) || !after.Before(probeUntil) || !time.Now().Before(probeUntil) {
			return ErrInstall
		}
		floor = after
		return nil
	}
	if recheck() != nil {
		return zero, ErrInstall
	}
	files := map[string][]byte{"runtime-signing.record.json": recordBytes, "runtime-signing.signature": recordSig, "runtime-signing.pin.json": pinBytes, "publisher-capture.grant.json": signedGrant, "runtime-owner-inputs.json": resultBytes}
	if writeNewFiles(in.OutputDirectory, files) != nil {
		return zero, ErrInstall
	}
	for name, want := range files {
		got, e := ReadPrivateFile(filepath.Join(in.OutputDirectory, name), 262144)
		if e != nil || !bytes.Equal(got, want) {
			return zero, ErrInstall
		}
	}
	if _, e = sec.LoadInstallationSigningHistory(ctx, result.SigningRecord, result.SigningPin); e != nil || recheck() != nil {
		return zero, ErrInstall
	}
	if sec.CheckPublisherCaptureDeploymentWorkload(ctx, sec.PublisherCaptureAuthorityConfig{DB: runtimeDB, Kubernetes: i.kube, Deployment: deployment, Workload: sec.PublisherCaptureWorkload{Namespace: workload.Namespace, NamespaceUID: workload.NamespaceUID, PodName: workload.PodName, PodUID: workload.PodUID, ServiceAccountName: workload.ServiceAccountName, ServiceAccountUID: workload.ServiceAccountUID, PublisherOwner: workload.PublisherOwner, GrantSHA256: result.PublisherGrant.SHA256}, GrantMount: result.PublisherGrant}) != nil || recheck() != nil {
		return zero, ErrInstall
	}
	return OriginalPublicationAuthorizationReceipt{Version: "original-publication-runtime-authorization-result.v1", RuntimeOwnerInputs: BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "runtime-owner-inputs.json"), SHA256: hash(resultBytes)}, SigningPinFile: BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "runtime-signing.pin.json"), SHA256: hash(pinBytes)}, SigningRecord: result.SigningRecord, SigningPin: result.SigningPin, PublisherGrant: result.PublisherGrant}, nil
}

// Comparison only, after current() authenticated the exact original head and
// record and readRequest loaded the complete original disabled config/grant.
// A record revision is NOT a SQL configuration version. Bootstrap installs
// version ONE; later enabled/reconfigured versions require their own reviewed
// actual-current-config authorization path, never this first-install branch.
func originalPublicationBootstrapBinding(target owner.Target, g c.ExecutionGrant, r owner.Record, selected BootstrapSourceFilePin, request *originalRequest) error {
	if request == nil || g.ConfigVersion != 1 || r.Target != target || g.InstallationID != target.InstallationID || g.ServerUUID != target.ServerUUID || g.Database != target.Database || r.ConfigSHA256 != g.ConfigSHA256 || selected.File != request.files.ConfigFile || selected.SHA256 != request.files.ConfigFileSHA256 || selected.SHA256 != request.config.SHA256() || selected.SHA256 != g.ConfigSHA256 || !request.matchesDraft(r) {
		return ErrInstall
	}
	return nil
}

// Returns authenticated SOURCE DATA only, never a task/claim/readiness handle.
// Signature trust is always the actual enrolled Plan issuer, not a key in JSON.
func (i *Installer) ReadOriginalPublicationRuntimeOwnerInputs(ctx context.Context, password []byte, enrollment EnrollmentPin, pin BootstrapSourceFilePin, runtimeDB ...*sql.DB) (OriginalPublicationRuntimeOwnerInputs, error) {
	return i.readOriginalPublicationRuntimeOwnerInputs(ctx, password, enrollment, pin, nil, runtimeDB...)
}
func (i *Installer) ReadEnabledPublicationRuntimeOwnerInputs(ctx context.Context, password []byte, enrollment EnrollmentPin, pin BootstrapSourceFilePin, enabled *OriginalEnabledPublication, runtimeDB ...*sql.DB) (OriginalPublicationRuntimeOwnerInputs, error) {
	if enabled == nil || enabled.operator == nil || enabled.operator.installer != i || enabled.enrollment != enrollment || enabled.Recheck(ctx) != nil {
		return OriginalPublicationRuntimeOwnerInputs{}, ErrInstall
	}
	return i.readOriginalPublicationRuntimeOwnerInputs(ctx, password, enrollment, pin, enabled, runtimeDB...)
}
func (i *Installer) readOriginalPublicationRuntimeOwnerInputs(ctx context.Context, password []byte, enrollment EnrollmentPin, pin BootstrapSourceFilePin, enabled *OriginalEnabledPublication, runtimeDB ...*sql.DB) (OriginalPublicationRuntimeOwnerInputs, error) {
	var zero OriginalPublicationRuntimeOwnerInputs
	if len(runtimeDB) != 1 || runtimeDB[0] == nil {
		return zero, ErrInstall
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	before, now, e := originalAdoptionAuthoritySnapshot(ctx, op)
	if e != nil || before.cas.State != "active" || before.record.Target != i.plan.Target || now.Before(before.head.NotBefore) || !now.Before(before.head.Until) {
		return zero, ErrInstall
	}
	expectedVersion := uint64(1)
	expectedRevision := uint64(2)
	expectedSHA := before.record.ConfigSHA256
	if enabled != nil {
		if enabled.operator.userID != op.userID || before.cas != enabled.initial || enabled.Recheck(ctx) != nil {
			return zero, ErrInstall
		}
		expectedVersion = 2
		expectedRevision = 3
		expectedSHA = enabled.configSHA
	}
	raw, e := readBootstrapSourcePin(pin, 262144)
	var in OriginalPublicationRuntimeOwnerInputs
	if e != nil || decodeExact(raw, &in) != nil || in.Version != "original-publication-runtime-owner-inputs.v1" || in.PlanSHA256 != i.planHash || in.EnrollmentDocumentSHA256 != enrollment.DocumentSHA256 || in.SigningPin.InstallationID != i.plan.Target.InstallationID || in.SigningPin.Revision != expectedRevision || !bytes.Equal(in.SigningPin.Issuer, i.public) || !bytes.Equal(in.PublisherGrant.Issuer, i.public) || len(in.SigningMounts) != 3 {
		return zero, ErrInstall
	}
	recordRaw, signature, e := in.SigningRecord.ReadSigningRecord(ctx)
	var record sec.InstallationSigningRecord
	if e != nil || hash(recordRaw) != in.SigningPin.RecordSHA256 || !ed25519.Verify(i.public, append([]byte(sec.InstallationSigningDomain), recordRaw...), signature) || decodeExact(recordRaw, &record) != nil || record.InstallationID != i.plan.Target.InstallationID || record.Revision != expectedRevision || now.Before(record.NotBefore) || !now.Before(record.Until) {
		return zero, ErrInstall
	}
	if _, e = sec.LoadInstallationSigningHistory(ctx, in.SigningRecord, in.SigningPin); e != nil {
		return zero, e
	}
	grantRaw, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: in.PublisherGrant.File, SHA256: in.PublisherGrant.SHA256}, 65536)
	var signed sec.SignedPublisherCaptureGrant
	var grant sec.PublisherCaptureGrant
	if e != nil || decodeExact(grantRaw, &signed) != nil || !ed25519.Verify(i.public, append([]byte(sec.PublisherCaptureGrantDomain), signed.Record...), signed.Signature) || decodeExact(signed.Record, &grant) != nil || grant.Version != sec.PublisherCaptureGrantVersion || grant.Deployment.InstallationID != i.plan.Target.InstallationID || grant.Revoked || now.Before(grant.NotBefore) || !now.Before(grant.Until) {
		return zero, ErrInstall
	}
	if grant.Deployment.ConfigVersion != expectedVersion || grant.Deployment.ConfigSHA256 != expectedSHA || grant.Deployment.ServerUUID != i.plan.Target.ServerUUID || grant.Deployment.Database != i.plan.Target.Database || grant.Workload.Namespace != i.plan.Target.Namespace || grant.Workload.NamespaceUID != i.plan.Target.NamespaceUID || grant.Workload.PublisherOwner != "public:"+grant.Workload.PodUID || len(record.Permissions) != 3 {
		return zero, ErrInstall
	}
	if _, e := i.checkOriginalRuntimeSQLPeer(ctx, runtimeDB[0], grant.Deployment.DatabaseAccount); e != nil {
		return zero, ErrInstall
	}
	for n, p := range record.Permissions {
		m := in.SigningMounts[n]
		g := p.SQLOwner
		if g == nil || g.ConfigVersion != expectedVersion || g.ConfigSHA256 != grant.Deployment.ConfigSHA256 || g.ServerUUID != grant.Deployment.ServerUUID || g.Database != grant.Deployment.Database || g.DatabaseAccount != grant.Deployment.DatabaseAccount || g.ControllerOwner != grant.Workload.PublisherOwner || g.Workload != (sec.SigningWorkloadIdentity{Namespace: grant.Workload.Namespace, PodUID: grant.Workload.PodUID, ServiceAccountUID: grant.Workload.ServiceAccountUID}) || m.Binding != p.Binding || m.AuthMount != p.AuthMount || m.Role != p.Role || m.Policy != p.Policy || m.CASHA256 != p.CASHA256 {
			return zero, ErrInstall
		}
	}
	if op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	again, tail, e := originalAdoptionAuthoritySnapshot(ctx, op)
	if e != nil || again.cas != before.cas || tail.Before(now) || !tail.Before(record.Until) || !tail.Before(grant.Until) {
		return zero, ErrInstall
	}
	check, e := readBootstrapSourcePin(pin, 262144)
	if e != nil || !bytes.Equal(check, raw) {
		return zero, ErrInstall
	}
	r, s, e := in.SigningRecord.ReadSigningRecord(ctx)
	if e != nil || !bytes.Equal(r, recordRaw) || !bytes.Equal(s, signature) {
		return zero, ErrInstall
	}
	g, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: in.PublisherGrant.File, SHA256: in.PublisherGrant.SHA256}, 65536)
	if e != nil || !bytes.Equal(g, grantRaw) {
		return zero, ErrInstall
	}
	if enabled != nil && enabled.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	if _, e := i.checkOriginalRuntimeSQLPeer(ctx, runtimeDB[0], grant.Deployment.DatabaseAccount); e != nil {
		return zero, ErrInstall
	}
	// All selected manifest/record/signature/grant reads precede this actual
	// final enrollment/head/SQL sample; they cannot outlive this auth session.
	if op.authority(ctx, enrollment) != nil || !op.live(ctx) {
		return zero, ErrInstall
	}
	final, finished, e := originalAdoptionAuthoritySnapshot(ctx, op)
	if e != nil || final.cas != before.cas || finished.Before(tail) || finished.Before(now) || finished.Before(final.head.NotBefore) || !finished.Before(final.head.Until) || finished.Before(final.record.NotBefore) || !finished.Before(final.record.Until) || finished.Before(record.NotBefore) || !finished.Before(record.Until) || finished.Before(grant.NotBefore) || !finished.Before(grant.Until) || ctx.Err() != nil || !op.live(ctx) {
		return zero, ErrInstall
	}
	return in, nil
}
