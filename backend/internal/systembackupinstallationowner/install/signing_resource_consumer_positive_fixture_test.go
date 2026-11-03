package install

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	a "clawreef/internal/systembackupkekadapter"
	sec "clawreef/internal/systembackupsecurity"
)

type signerConsumerDeliveryFixture struct {
	capture *captureConsumerFixture
	model   *signerSQLModel
	inputs  []SigningResourceSQLInput
	assets  []SigningResourceConsumerAsset
}

// Explicit component issuer declarations, not production Issue.../Vault proof.
// New signed public installation material has its ACTUAL byte SHA, complete
// three-purpose history and windows. No placeholder material digest or old
// signed resource grant is transplanted/re-signed into this fixture.
func newSignerConsumerDeliveryFixture(t *testing.T, ctx context.Context) *signerConsumerDeliveryFixture {
	t.Helper()
	c := newCaptureConsumerFixture(t, ctx)
	f, plan := c.f, c.f.i.plan
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private component delivery source")
	}
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("private component delivery file")
		}
		return path
	}
	oldRaw, err := ReadPrivateFile(f.files.ObserverFile, 262144)
	var originalObserver observerDocument
	if err != nil || decodeExact(oldRaw, &originalObserver) != nil {
		t.Fatal("actual controlled observer source")
	}
	jwt, err := ReadPrivateFile(originalObserver.RuntimeJWTFile, 16384)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(jwt)
	var bindings []owner.Binding
	material := sec.InstallationSigningRecord{InstallationID: plan.Target.InstallationID, Revision: 1, NotBefore: f.record.NotBefore, Until: f.record.Until.Add(time.Hour)}
	for _, history := range f.record.Histories {
		b := f.record.Binding
		b.Purpose, b.KeyID, b.KeyName = history.Purpose, history.KeyName, history.KeyName
		b.AuthMount, b.Role, b.Policy = "jwt-"+b.Purpose, "role-"+b.Purpose, "policy-"+b.Purpose
		role, err := a.VaultJWTAuthRole(a.VaultPermissionRole{AuthMount: b.AuthMount, Role: b.Role, Policy: b.Policy, Audience: b.Audience, Namespace: b.Namespace, ServiceAccountName: b.ServiceAccountName, ServiceAccountUID: b.ServiceAccountUID, PodUID: b.PodUID})
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if json.Unmarshal(role, &value) != nil {
			t.Fatal("role projection")
		}
		roleCanonical, err := canonical(value)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := owner.CaptureSigningACL(b)
		if err != nil {
			t.Fatal(err)
		}
		b.RoleSHA256, b.PolicySHA256 = hash(roleCanonical), hash([]byte(policy))
		bindings = append(bindings, b)
		for _, key := range history.Keys {
			public, err := base64.StdEncoding.Strict().DecodeString(key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			material.Keys = append(material.Keys, sec.ArtifactSigningPublicKey{InstallationID: b.InstallationID, Purpose: b.Purpose, KeyID: b.KeyID, KeyVersion: b.KeyVersion, PublicKey: public, NotBefore: f.record.NotBefore, NotAfter: key.ProtectedUntil})
		}
		material.Permissions = append(material.Permissions, sec.InstallationSigningPermission{Binding: sec.TransitSigningBinding{InstallationID: b.InstallationID, Purpose: b.Purpose, KeyID: b.KeyID, KeyVersion: b.KeyVersion, Endpoint: b.Endpoint, KeyName: b.KeyName, ProviderVersion: b.ProviderVersion}, AuthMount: b.AuthMount, Role: b.Role, Policy: b.Policy, CASHA256: b.CASHA256})
	}
	materialRaw, err := canonical(material)
	if err != nil {
		t.Fatal(err)
	}
	materialSource := owner.SigningResourceMaterial{Files: owner.RecordFiles{RecordFile: write("installed-public.json", materialRaw), SignatureFile: write("installed-public.signature", ed25519.Sign(f.key, append([]byte(sec.InstallationSigningDomain), materialRaw...)))}, Pin: sec.InstallationSigningPin{InstallationID: plan.Target.InstallationID, Revision: 1, RecordSHA256: hash(materialRaw), Issuer: f.i.public}}
	// Explicit new disabled config/offline DATA match these declared references.
	// Existing capture authority is not rewritten; full admission is not tested.
	var configFields map[string]any
	if json.Unmarshal(f.config.CanonicalJSON(), &configFields) != nil {
		t.Fatal("disabled config source")
	}
	refs := map[string]sec.BootstrapSecretRef{}
	for _, b := range bindings {
		if purpose := owner.SigningResourceBootstrapPurpose(b.Purpose); purpose != "" {
			identity, err := owner.SigningResourceReferenceIdentity(b)
			if err != nil {
				t.Fatal(err)
			}
			refs[purpose] = sec.BootstrapSecretRef{Purpose: purpose, IdentityHash: identity, Version: b.KeyVersion}
		}
	}
	for _, value := range configFields["references"].([]any) {
		ref := value.(map[string]any)
		if selected, ok := refs[ref["purpose"].(string)]; ok {
			ref["identity_hash"], ref["version"] = selected.IdentityHash, selected.Version
		}
	}
	configRaw, err := canonical(configFields)
	if err != nil {
		t.Fatal(err)
	}
	config, err := sec.DecodeBootstrapConfig(configRaw)
	if err != nil {
		t.Fatal(err)
	}
	offline := f.grant
	offline.ConfigSHA256 = config.SHA256()
	offlineRaw, err := json.Marshal(offline)
	if err != nil {
		t.Fatal(err)
	}
	write("declared-disabled-config.json", config.CanonicalJSON())
	write("declared-offline-grant-data.json", offlineRaw)
	model := &signerSQLModel{base: f.s, data: signerSQLData{heads: map[string][]driver.Value{}, grants: map[string][]driver.Value{}}}
	db := sql.OpenDB(signerSQLConnector{model: model})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	f.i.db = db
	result := &signerConsumerDeliveryFixture{capture: c, model: model}
	for _, purpose := range owner.SigningResourcePurposes() {
		var binding owner.Binding
		for _, b := range bindings {
			if b.Purpose == purpose {
				binding = b
			}
		}
		g := owner.SigningResourceGrant{SchemaVersion: owner.SigningResourceGrantVersion, AuthorityID: "component-delivery", GrantID: "component-" + purpose, PlanSHA256: f.i.planHash, EnrollmentID: plan.EnrollmentID, IssuerID: plan.IssuerID, EnrollmentDocumentSHA256: f.enrollment.DocumentSHA256, EnrollmentRevision: plan.EnrollmentRevision, RecordRevision: 1, PermissionEpoch: 1, Target: plan.Target, Actor: f.record.Actor, BootstrapGrantSHA256: hash(offlineRaw), ConfigSHA256: config.SHA256(), SigningMaterialSHA256: hash(materialRaw), SigningMaterialRevision: 1, Reference: refs[owner.SigningResourceBootstrapPurpose(purpose)], Binding: binding, Bindings: bindings, Histories: f.record.Histories, NotBefore: f.record.NotBefore, Until: f.record.Until}
		if owner.CheckSigningResourceMaterial(ctx, materialSource, g) != nil {
			t.Fatal("actual signed public material/history must match declaration")
		}
		raw, err := owner.EncodeSigningResourceGrant(g)
		if err != nil {
			t.Fatal(err)
		}
		pin := owner.SigningResourceTrustPin{Target: plan.Target, Actor: g.Actor, EnrollmentID: plan.EnrollmentID, IssuerID: plan.IssuerID, EnrollmentDocumentSHA256: f.enrollment.DocumentSHA256, OwnerSubject: plan.OwnerUsername, EnrollmentRevision: plan.EnrollmentRevision, Issuer: f.i.public, AuthorityID: g.AuthorityID, Purpose: purpose, GrantID: g.GrantID, GrantSHA256: hash(raw), GrantRevision: 1, MinimumHeadRevision: 1, MinimumPermissionEpoch: 1}
		head, err := owner.EncodeSigningResourceHead(owner.SigningResourceHead{SchemaVersion: owner.SigningResourceHeadVersion, AuthorityID: g.AuthorityID, Purpose: purpose, EnrollmentID: plan.EnrollmentID, IssuerID: plan.IssuerID, EnrollmentRevision: plan.EnrollmentRevision, HeadRevision: 1, PermissionEpoch: 1, Target: plan.Target, OwnerSubject: plan.OwnerUsername, CurrentGrantID: g.GrantID, CurrentGrantRevision: 1, GrantSHA256: pin.GrantSHA256, State: "active", NotBefore: g.NotBefore, Until: g.Until})
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := canonical(SigningResourceBundle{Version: SigningResourceBundleVersion, Action: "install", PlanSHA256: f.i.planHash, EnrollmentDocumentSHA256: f.enrollment.DocumentSHA256, Grant: raw, GrantSignature: ed25519.Sign(f.key, append([]byte(owner.SigningResourceGrantDomain), raw...)), Head: head, HeadSignature: ed25519.Sign(f.key, append([]byte(owner.SigningResourceHeadDomain), head...))})
		if err != nil {
			t.Fatal(err)
		}
		doc := originalObserver
		doc.RuntimeJWTFile = write(purpose+".runtime.jwt", jwt)
		docRaw, err := canonical(doc)
		if err != nil {
			t.Fatal(err)
		}
		result.inputs = append(result.inputs, SigningResourceSQLInput{Pin: pin, Bundle: bundle, SHA256: hash(bundle)})
		result.assets = append(result.assets, SigningResourceConsumerAsset{Purpose: purpose, Material: materialSource, ObserverFile: write(purpose+".observer.json", docRaw), ObserverSHA256: hash(docRaw)})
	}
	if _, err := f.i.ImportSigningResourceSQLAuthority(ctx, f.password, f.enrollment, result.inputs); err != nil {
		t.Fatal("actual authenticated original importer with component SQL transport", err)
	}
	return result
}
