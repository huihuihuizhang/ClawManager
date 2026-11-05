package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// Source locations and explicit offline installation policy, never an actor,
// claimed UserID, approval, signature, live observation, or grant document.
type OriginalInitialRequestAuthorInputs struct {
	Config, SigningMaterial BootstrapSourceFilePin
	MatrixKey, ChangeReason string
	Until                   time.Time
	OutputDirectory         string
}

type OriginalInitialRequestAuthorReceipt struct {
	Version                                            string
	Config, Grant, RequestFiles                        BootstrapSourceFilePin
	Request                                            RequestFiles
	ConfigurationMutated, GrantsInstalled, BackupReady bool
}

// ProduceOriginalInitialRequestInputs authors the real first offline request
// using the existing password/enrollment/RBAC/ledger owner. It does not sign a
// future capture or grant bootstrap admission. Every downstream consumer still
// checks the original complete config, files, observer, and current authority.
func (i *Installer) ProduceOriginalInitialRequestInputs(ctx context.Context, password []byte, enrollment EnrollmentPin, in OriginalInitialRequestAuthorInputs) (OriginalInitialRequestAuthorReceipt, error) {
	var zero OriginalInitialRequestAuthorReceipt
	if i == nil || ctx == nil || ctx.Err() != nil || privateDirectory(in.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	s, err := i.authenticate(ctx, password)
	if err != nil {
		return zero, ErrInstall
	}
	before, now, err := originalRuntimeAuthoritySnapshot(ctx, s, enrollment)
	if err != nil || before.cas != (HeadCAS{}) || !now.Before(in.Until) || in.Until.Sub(now) > 24*time.Hour {
		return zero, ErrInstall
	}
	raw, err := readBootstrapSourcePin(in.Config, 262144)
	if err != nil {
		return zero, ErrInstall
	}
	config, err := sec.DecodeBootstrapConfig(raw)
	if err != nil || !bytes.Equal(raw, config.CanonicalJSON()) {
		return zero, ErrInstall
	}
	material, err := readOriginalPublicationSigningFiles(ctx, i.public, in.SigningMaterial)
	if err != nil || material.PlanSHA256 != i.planHash || material.EnrollmentDocumentSHA256 != enrollment.DocumentSHA256 {
		return zero, ErrInstall
	}
	if _, err = readBootstrapSourcePin(material.CaptureObserver, 262144); err != nil {
		return zero, ErrInstall
	}
	entropy := make([]byte, 24)
	if _, err = rand.Read(entropy); err != nil {
		return zero, ErrInstall
	}
	grant := sec.OfflineBootstrapGrant{InstallationID: i.plan.Target.InstallationID, ServerUUID: i.plan.Target.ServerUUID,
		Database: i.plan.Target.Database, Username: i.plan.LocalAdminUsername, UserID: s.userID,
		MatrixKey: in.MatrixKey, ConfigSHA256: config.SHA256(), IdempotencyKey: "original-" + hex.EncodeToString(entropy), ChangeReason: in.ChangeReason}
	if !sec.ValidOfflineBootstrapGrant(grant) {
		return zero, ErrInstall
	}
	grantRaw, err := canonical(sec.BootstrapGrantFile{SchemaVersion: "system-backup-offline-bootstrap-grant.v1", NotBefore: now, ExpiresAt: in.Until, Grant: grant})
	if err != nil {
		return zero, ErrInstall
	}
	configPin := in.Config
	grantPin := BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "bootstrap-grant.json"), SHA256: hash(grantRaw)}
	request := RequestFiles{ConfigFile: configPin.File, ConfigFileSHA256: configPin.SHA256, GrantFile: grantPin.File, GrantFileSHA256: grantPin.SHA256,
		ObserverFile: material.CaptureObserver.File, ObserverFileSHA256: material.CaptureObserver.SHA256}
	requestRaw, err := canonical(request)
	if err != nil {
		return zero, ErrInstall
	}
	recheck := func() error {
		current, clock, e := originalRuntimeAuthoritySnapshot(ctx, s, enrollment)
		if e != nil || current.cas != before.cas || clock.Before(now) || !clock.Before(in.Until) {
			return ErrInstall
		}
		actual, e := readBootstrapSourcePin(in.Config, 262144)
		if e != nil || !bytes.Equal(actual, raw) {
			return ErrInstall
		}
		fresh, e := readOriginalPublicationSigningFiles(ctx, i.public, in.SigningMaterial)
		if e != nil || fresh.PlanSHA256 != material.PlanSHA256 || fresh.EnrollmentDocumentSHA256 != material.EnrollmentDocumentSHA256 || fresh.CaptureObserver != material.CaptureObserver {
			return ErrInstall
		}
		return nil
	}
	if recheck() != nil || writeNewFiles(in.OutputDirectory, map[string][]byte{"bootstrap-grant.json": grantRaw, "request-files.json": requestRaw}) != nil {
		return zero, ErrInstall
	}
	// Retain any written files on failure. Never renew/reissue after unknown
	// output; the operator journal owns one dispatch and requires readback.
	actual, err := readRequest(i, request)
	if err != nil {
		return zero, ErrInstall
	}
	defer actual.observer.Close()
	if actual.grant != grant || recheck() != nil {
		return zero, ErrInstall
	}
	return OriginalInitialRequestAuthorReceipt{Version: "original-initial-request-authored.v1", Config: configPin, Grant: grantPin,
		RequestFiles: BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "request-files.json"), SHA256: hash(requestRaw)}, Request: request}, nil
}
