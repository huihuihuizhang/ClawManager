package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"reflect"

	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
)

func (i *Installer) originalFirstCaptureSigning(ctx context.Context, enrollment EnrollmentPin, in OriginalFirstCaptureDraftInputs, request *originalRequest) (OriginalPublicationSigningFiles, sec.InstallationSigningRecord, owner.Binding, owner.Binding, error) {
	var empty OriginalPublicationSigningFiles
	var zero sec.InstallationSigningRecord
	var noBinding owner.Binding
	fail := func() (OriginalPublicationSigningFiles, sec.InstallationSigningRecord, owner.Binding, owner.Binding, error) {
		return empty, zero, noBinding, noBinding, ErrInstall
	}
	m, e := readOriginalPublicationSigningFiles(ctx, i.public, in.SigningMaterial)
	if e != nil || request == nil || m.Version != "original-publication-signing-material.v1" || m.PlanSHA256 != i.planHash || m.EnrollmentDocumentSHA256 != enrollment.DocumentSHA256 || !bytes.Equal(m.Pin.Issuer, i.public) || m.Pin.InstallationID != i.plan.Target.InstallationID || m.Pin.Revision != 1 || len(m.Bindings) != 3 || len(m.Histories) != 3 || len(m.JWTFiles) != 3 || m.CaptureObserver != (BootstrapSourceFilePin{File: request.files.ObserverFile, SHA256: request.files.ObserverFileSHA256}) {
		return fail()
	}
	if _, e := sec.LoadInstallationSigningHistory(ctx, m.Record, m.Pin); e != nil {
		return fail()
	}
	raw, signature, e := m.Record.ReadSigningRecord(ctx)
	var signed sec.InstallationSigningRecord
	if e != nil || !ed25519.Verify(i.public, append([]byte(sec.InstallationSigningDomain), raw...), signature) || hash(raw) != m.Pin.RecordSHA256 || decodeExact(raw, &signed) != nil || signed.InstallationID != i.plan.Target.InstallationID || signed.Revision != 1 || len(signed.Keys) != 3 || len(signed.Permissions) != 3 {
		return fail()
	}
	actor, e := i.originalPublicationActor(ctx, in.ControllerDeployment, in.ControllerPodName)
	if e != nil {
		return fail()
	}
	var capture owner.Binding
	purposes := []string{"acceptance_record", "capture_certificate", "catalog_record"}
	for n, purpose := range purposes {
		b, h, k, p := m.Bindings[n], m.Histories[n], signed.Keys[n], signed.Permissions[n]
		if k.Revoked {
			return fail()
		}
		if b.Purpose != purpose || b.InstallationID != actor.InstallationID || b.Namespace != actor.Namespace || b.NamespaceUID != actor.NamespaceUID || b.PodName != actor.PodName || b.PodUID != actor.PodUID || b.ServiceAccountName != actor.ServiceAccountName || b.ServiceAccountUID != actor.ServiceAccountUID || b.KeyVersion != "1" || b.ProviderVersion != "1" || b.CASHA256 != m.CA.SHA256 || h.Purpose != purpose || h.KeyName != b.KeyName || len(h.Keys) != 1 || h.Keys[0].Version != b.ProviderVersion || !h.Keys[0].ProtectedUntil.Equal(signed.Until) || h.Keys[0].PublicKey != base64.StdEncoding.EncodeToString(k.PublicKey) || k.InstallationID != b.InstallationID || k.Purpose != purpose || k.KeyID != b.KeyID || k.KeyVersion != b.KeyVersion || !k.NotBefore.Equal(signed.NotBefore) || !k.NotAfter.Equal(signed.Until) || p.SQLOwner != nil || p.Binding != (sec.TransitSigningBinding{InstallationID: b.InstallationID, Purpose: purpose, KeyID: b.KeyID, KeyVersion: b.KeyVersion, Endpoint: b.Endpoint, KeyName: b.KeyName, ProviderVersion: b.ProviderVersion}) || p.AuthMount != b.AuthMount || p.Role != b.Role || p.Policy != b.Policy || p.CASHA256 != b.CASHA256 {
			return fail()
		}
		jwt, e := readBootstrapSourcePin(m.JWTFiles[purpose], 16384)
		if e != nil || len(jwt) == 0 {
			clear(jwt)
			return fail()
		}
		clear(jwt)
		if purpose == "capture_certificate" {
			capture = b
		}
	}
	docRaw, e := readBootstrapSourcePin(m.CaptureObserver, 262144)
	var doc observerDocument
	if e != nil || decodeExact(docRaw, &doc) != nil || doc.Endpoint != capture.Endpoint || doc.CAFile != m.CA.File || doc.CASHA256 != m.CA.SHA256 || doc.RuntimeJWTFile != m.JWTFiles["capture_certificate"].File || !reflect.DeepEqual(doc.Trust, m.Trust) {
		return fail()
	}
	if _, e := readBootstrapSourcePin(m.CA, 65536); e != nil {
		return fail()
	}
	identity, e := owner.ReferenceIdentity(capture)
	if e != nil {
		return fail()
	}
	found := 0
	for _, ref := range request.config.References() {
		if ref.Purpose == "capture_signing" {
			if ref.IdentityHash != identity || ref.Version != capture.KeyVersion {
				return fail()
			}
			found++
		}
	}
	if found != 1 {
		return fail()
	}
	return m, signed, actor, capture, nil
}
