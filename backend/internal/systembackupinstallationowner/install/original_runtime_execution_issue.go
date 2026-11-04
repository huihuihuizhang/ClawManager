package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"strings"
	"time"

	"clawreef/internal/mysqltls"
	c "clawreef/internal/systembackupcontroller"
	api "clawreef/internal/systembackupdeployment"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OriginalRuntimeExecutionIssueInputs struct {
	Issuers, Core, Profile, RecordExport, RecordKey, CaptureKey BootstrapSourceFilePin
	Request                                                     RequestFiles
	ControllerDeployment, ControllerPodName, OutputDirectory    string
	Until                                                       time.Time
}
type OriginalRuntimeExecutionIssueReceipt struct {
	Version                        string
	Grant, PublicKey               BootstrapSourceFilePin
	ConfigVersion                  uint64
	ConfigSHA256, ControllerPodUID string
}

// Only the core fields relevant to execution scope are decoded here; the
// unchanged full deployment decoder still validates the complete core later.
type originalRuntimeCoreScope struct {
	InstallationID    string             `json:"installation_id"`
	Namespace         string             `json:"namespace"`
	NamespaceUID      string             `json:"namespace_uid"`
	ControllerOwner   string             `json:"controller_owner"`
	ProfileFile       string             `json:"profile_file"`
	KeyDirectory      string             `json:"key_directory"`
	SourceUser        string             `json:"source_user"`
	SourceDSNFile     string             `json:"source_dsn_file"`
	SourceTLS         *mysqltls.Material `json:"source_tls,omitempty"`
	SourceDatabase    string             `json:"source_database"`
	SourceServerUUID  string             `json:"source_server_uuid"`
	IssuerCertificate string             `json:"issuer_certificate"`
	IssuerSHA256      string             `json:"issuer_certificate_sha256"`
	Forward           struct {
		Path      string `json:"path"`
		PublicKey string `json:"public_key_base64"`
	} `json:"forward_grant"`
	Security struct{ ServiceAccountName, ServiceAccountUID string } `json:"worker_security"`
}

// Actual FIRST execution-purpose issuance: authenticated original enrollment,
// Plan-signed purpose manifest, native SQL peer, real Pod chain/worker SA,
// actual full disabled config and original worker CA. No caller grant DTO.
func (i *Installer) IssueOriginalRuntimeExecution(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, in OriginalRuntimeExecutionIssueInputs) (OriginalRuntimeExecutionIssueReceipt, error) {
	var zero OriginalRuntimeExecutionIssueReceipt
	s, e := i.authenticate(ctx, password)
	if e != nil || runtimeDB == nil || privateDirectory(in.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	before, now, e := originalRuntimeAuthoritySnapshot(ctx, s, enrollment)
	if e != nil {
		return zero, ErrInstall
	}
	material, e := i.readOriginalRuntimeIssuerMaterial(in.Issuers, enrollment)
	if e != nil {
		return zero, ErrInstall
	}
	exported, e := i.readOriginalRuntimeRecordExport(enrollment, in.Issuers, in.RecordExport)
	if e != nil {
		return zero, ErrInstall
	}
	if in.RecordKey != (BootstrapSourceFilePin{}) && in.RecordKey != exported.RecordKey || in.CaptureKey != (BootstrapSourceFilePin{}) && in.CaptureKey != exported.CaptureKey {
		return zero, ErrInstall
	}
	recordKey, captureKey := exported.RecordKey, exported.CaptureKey
	key, e := readBootstrapSourcePin(material.Issuers["forward_execution"].PrivateKey, ed25519.PrivateKeySize)
	if e != nil || len(key) != ed25519.PrivateKeySize {
		clear(key)
		return zero, ErrInstall
	}
	defer clear(key)
	keys := map[string]ed25519.PrivateKey{"forward_execution": ed25519.PrivateKey(key)}
	for _, pin := range []BootstrapSourceFilePin{recordKey, captureKey} {
		raw, e := readBootstrapSourcePin(pin, 32)
		valid := e == nil && len(raw) == 32
		clear(raw)
		if !valid {
			return zero, ErrInstall
		}
	}
	if recordKey.SHA256 != material.RecordKey.SHA256 || captureKey.SHA256 != material.CaptureKey.SHA256 || recordKey.SHA256 == captureKey.SHA256 {
		return zero, ErrInstall
	}
	request, e := readRequest(i, in.Request)
	if e != nil {
		return zero, ErrInstall
	}
	defer request.observer.Close()
	if request.grant.InstallationID != i.plan.Target.InstallationID || request.grant.ServerUUID != i.plan.Target.ServerUUID || request.grant.Database != i.plan.Target.Database || request.grant.UserID != s.userID || request.grant.Username != i.plan.LocalAdminUsername {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(in.Core, 262144)
	var core originalRuntimeCoreScope
	if e != nil {
		return zero, ErrInstall
	}
	if _, e = jsoncanonicalizer.Transform(raw); e != nil || json.Unmarshal(raw, &core) != nil {
		return zero, ErrInstall
	}
	target := i.plan.Target
	runtimeAccount, e := i.checkOriginalRuntimeSQLPeer(ctx, runtimeDB, "")
	if e != nil {
		return zero, ErrInstall
	}
	if core.InstallationID != target.InstallationID || core.Namespace != target.Namespace || core.NamespaceUID != target.NamespaceUID || core.SourceDatabase != target.Database || core.SourceServerUUID != target.ServerUUID || (core.SourceUser == "" || strings.EqualFold(core.SourceUser, "root")) || core.ProfileFile != in.Profile.File || core.KeyDirectory != filepath.Dir(recordKey.File) || core.KeyDirectory != filepath.Dir(captureKey.File) || core.Forward.PublicKey != base64.StdEncoding.EncodeToString(keys["forward_execution"].Public().(ed25519.PublicKey)) || filepath.Dir(core.Forward.Path) != in.OutputDirectory || !filepath.IsAbs(core.Forward.Path) || filepath.Clean(core.Forward.Path) != core.Forward.Path {
		return zero, ErrInstall
	}
	if core.SourceTLS == nil || !core.SourceTLS.Selected() {
		return zero, ErrInstall
	}
	sourceDSN, e := ReadPrivateFile(core.SourceDSNFile, 16384)
	if e != nil {
		return zero, ErrInstall
	}
	sourceDSNPin := BootstrapSourceFilePin{File: core.SourceDSNFile, SHA256: hash(sourceDSN)}
	clear(sourceDSN)
	sourceCAPin := BootstrapSourceFilePin{File: core.SourceTLS.CAFile, SHA256: core.SourceTLS.CASHA256}
	sourceDB, sourceIdentity, e := openOriginalEnrollmentDatabase(ctx, sourceDSNPin, sourceCAPin, core.SourceTLS.ServerName)
	if e != nil {
		return zero, ErrInstall
	}
	defer sourceDB.Close()
	if strings.Split(sourceIdentity.Account, "@")[0] != core.SourceUser || sourceIdentity.ServerUUID != core.SourceServerUUID || sourceIdentity.Database != core.SourceDatabase {
		return zero, ErrInstall
	}
	profile, e := api.LoadExecutionProfile(in.Profile.File)
	if e != nil {
		return zero, ErrInstall
	}
	_, profileSHA, e := profile.CanonicalIdentity()
	if e != nil || profileSHA != in.Profile.SHA256 || profile.InstallationID != target.InstallationID || profile.TargetClass != "same-cluster-copy" {
		return zero, ErrInstall
	}
	actor, e := i.originalPublicationActor(ctx, in.ControllerDeployment, in.ControllerPodName)
	if e != nil {
		return zero, ErrInstall
	}
	worker, e := i.kube.CoreV1().ServiceAccounts(target.Namespace).Get(ctx, core.Security.ServiceAccountName, metav1.GetOptions{})
	if e != nil || string(worker.UID) != core.Security.ServiceAccountUID || worker.UID == "" || worker.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	certificate, e := ReadPrivateFile(core.IssuerCertificate, 65536)
	if e != nil {
		return zero, ErrInstall
	}
	block, _ := pem.Decode(certificate)
	if block == nil {
		return zero, ErrInstall
	}
	ca, e := x509.ParseCertificate(block.Bytes)
	if e != nil || !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 || hash(ca.Raw) != core.IssuerSHA256 || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return zero, ErrInstall
	}
	until := minTime(in.Until, minTime(request.end, ca.NotAfter))
	if before.cas.HeadRevision > 0 {
		if !request.matchesDraft(before.record) {
			return zero, ErrInstall
		}
		until = minTime(until, minTime(before.head.Until, before.record.Until))
	}
	if !now.Before(until) || until.Sub(now) > 24*time.Hour || now.Before(request.start) {
		return zero, ErrInstall
	}
	grant := c.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: target.InstallationID, ControllerOwner: core.ControllerOwner, DatabaseAccount: runtimeAccount, ServerUUID: target.ServerUUID, Database: target.Database, ConfigVersion: 1, ConfigSHA256: request.config.SHA256(), ProfileSHA256: profileSHA, DeploymentConfigSHA256: in.Core.SHA256, WorkerIssuerSHA256: hash(ca.Raw), NotBefore: now, ExpiresAt: until, Actions: []string{"prepare", "capture", "issue_worker"}, RecordKeys: []c.ExecutionRecordKey{{Ref: filepath.Base(recordKey.File), SHA256: recordKey.SHA256}}, CaptureKeys: []c.ExecutionRecordKey{{Ref: filepath.Base(captureKey.File), SHA256: captureKey.SHA256}}}
	payload, e := canonical(grant)
	if e != nil {
		return zero, ErrInstall
	}
	envelope, e := canonical(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(payload), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(keys["forward_execution"], payload))})
	if e != nil {
		return zero, ErrInstall
	}
	floor := now
	recheck := func() error {
		if request.recheck(i) != nil {
			return ErrInstall
		}
		actual, e := i.originalPublicationActor(ctx, in.ControllerDeployment, in.ControllerPodName)
		if e != nil || actual != actor {
			return ErrInstall
		}
		workerNow, e := i.kube.CoreV1().ServiceAccounts(target.Namespace).Get(ctx, worker.Name, metav1.GetOptions{})
		if e != nil || workerNow.UID != worker.UID || workerNow.DeletionTimestamp != nil {
			return ErrInstall
		}
		coreNow, e := readBootstrapSourcePin(in.Core, 262144)
		if e != nil || !bytes.Equal(coreNow, raw) {
			return ErrInstall
		}
		p, e := api.LoadExecutionProfile(in.Profile.File)
		if e != nil {
			return ErrInstall
		}
		_, sum, e := p.CanonicalIdentity()
		if e != nil || sum != profileSHA {
			return ErrInstall
		}
		certNow, e := ReadPrivateFile(core.IssuerCertificate, 65536)
		if e != nil || !bytes.Equal(certNow, certificate) {
			return ErrInstall
		}
		_, e = i.readOriginalRuntimeIssuerMaterial(in.Issuers, enrollment)
		if e != nil {
			return ErrInstall
		}
		freshExport, e := i.readOriginalRuntimeRecordExport(enrollment, in.Issuers, in.RecordExport)
		if e != nil || freshExport != exported {
			return ErrInstall
		}
		for _, pin := range []BootstrapSourceFilePin{sourceDSNPin, sourceCAPin} {
			raw, e := readBootstrapSourcePin(pin, 65536)
			clear(raw)
			if e != nil {
				return ErrInstall
			}
		}
		var sourceAccount, sourceServer, sourceDatabase string
		if sourceDB.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE()").Scan(&sourceAccount, &sourceServer, &sourceDatabase) != nil || sourceAccount != sourceIdentity.Account || sourceServer != sourceIdentity.ServerUUID || sourceDatabase != sourceIdentity.Database {
			return ErrInstall
		}
		authenticated, authTime, e := originalRuntimeAuthoritySnapshot(ctx, s, enrollment)
		if e != nil || authenticated.cas != before.cas || authTime.Before(floor) || !authTime.Before(until) {
			return ErrInstall
		}
		if _, e := i.checkOriginalRuntimeSQLPeer(ctx, runtimeDB, runtimeAccount); e != nil {
			return ErrInstall
		}
		var sqlNow time.Time
		var account, server, database string
		if runtimeDB.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6),CURRENT_USER(),@@server_uuid,DATABASE()").Scan(&sqlNow, &account, &server, &database) != nil || sqlNow.Before(floor) || !sqlNow.Before(until) || account != runtimeAccount || server != target.ServerUUID || database != target.Database {
			return ErrInstall
		}
		final, t, e := originalAdoptionAuthoritySnapshot(ctx, s)
		if e != nil || final.cas != before.cas || t.Before(sqlNow) || t.Before(floor) || !t.Before(until) || !s.live(ctx) {
			return ErrInstall
		}
		floor = t
		return nil
	}
	if recheck() != nil || writeNewFiles(in.OutputDirectory, map[string][]byte{filepath.Base(core.Forward.Path): envelope}) != nil {
		return zero, ErrInstall
	}
	forward, e := c.NewPinnedExecutionIdentity(core.Forward.Path, hash(envelope), core.KeyDirectory, keys["forward_execution"].Public().(ed25519.PublicKey))
	if e != nil || forward.CheckDeployment(ctx, runtimeDB) != nil || recheck() != nil {
		return zero, ErrInstall
	}
	return OriginalRuntimeExecutionIssueReceipt{Version: "original-runtime-execution-result.v1", Grant: BootstrapSourceFilePin{File: core.Forward.Path, SHA256: hash(envelope)}, PublicKey: material.Issuers["forward_execution"].PublicKey, ConfigVersion: 1, ConfigSHA256: grant.ConfigSHA256, ControllerPodUID: actor.PodUID}, nil
}

func originalRuntimeAuthoritySnapshot(ctx context.Context, s *authenticatedOperator, enrollment EnrollmentPin) (currentAuthority, time.Time, error) {
	if s == nil || s.kubernetes(ctx, "get") != nil || s.authority(ctx, enrollment) != nil {
		return currentAuthority{}, time.Time{}, ErrInstall
	}
	current, now, e := originalAdoptionAuthoritySnapshot(ctx, s)
	if e != nil || current.cas.HeadRevision > 0 && (current.cas.State != "active" || now.Before(current.head.NotBefore) || !now.Before(current.head.Until) || now.Before(current.record.NotBefore) || !now.Before(current.record.Until)) {
		return currentAuthority{}, time.Time{}, ErrInstall
	}
	return current, now, nil
}
