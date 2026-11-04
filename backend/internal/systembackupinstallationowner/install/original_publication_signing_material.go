package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	a "clawreef/internal/systembackupkekadapter"
	sec "clawreef/internal/systembackupsecurity"
	authn "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Exact existing native source names only. No caller public key, Binding,
// SQLOwner, workload UID, Passed, permission hash or signed grant is accepted.
type OriginalPublicationSigningOptions struct {
	Endpoint, ProviderClusterID, JWTMount   string
	CaptureKey, AcceptanceKey, CatalogKey   string
	ControllerDeployment, ControllerPodName string
	CA, VaultOwnerMaterial                  BootstrapSourceFilePin
	VaultOwnerMaterialIsInitJSON            bool
	Until                                   time.Time
	OutputDirectory                         string
}
type OriginalPublicationSigningFiles struct {
	Version, PlanSHA256, EnrollmentDocumentSHA256 string
	Record                                        sec.FileSigningRecordReader
	Pin                                           sec.InstallationSigningPin
	Bindings                                      []owner.Binding
	Histories                                     []owner.PurposeKeys
	ResourceObserver, CaptureObserver             BootstrapSourceFilePin
	ResourceObservers                             map[string]BootstrapSourceFilePin
	JWTFiles                                      map[string]BootstrapSourceFilePin
	CA                                            BootstrapSourceFilePin
	Trust                                         a.VaultJWTTrust
}

const originalPublicationSigningMaterialDomain = "system-backup-original-publication-signing-material.v1\x00"

type OriginalPublicationSigningReceipt struct {
	MaterialSignatureFile                                  string
	Version                                                string
	Material, RecordPin, ResourceObserver, CaptureObserver BootstrapSourceFilePin
	ResourceObservers                                      map[string]BootstrapSourceFilePin
	Record                                                 sec.FileSigningRecordReader
	Pin                                                    sec.InstallationSigningPin
}

func (i *Installer) originalPublicationActor(ctx context.Context, deploymentName, podName string) (owner.Binding, error) {
	var zero owner.Binding
	p := i.plan.Target
	dep, e := i.kube.AppsV1().Deployments(p.Namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if e != nil || dep.UID == "" || dep.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	pod, e := i.kube.CoreV1().Pods(p.Namespace).Get(ctx, podName, metav1.GetOptions{})
	if e != nil || pod.UID == "" || pod.DeletionTimestamp != nil || string(pod.Status.Phase) != "Running" || len(pod.OwnerReferences) != 1 || pod.Spec.ServiceAccountName != dep.Spec.Template.Spec.ServiceAccountName {
		return zero, ErrInstall
	}
	parent := pod.OwnerReferences[0]
	if parent.Kind != "ReplicaSet" || parent.APIVersion != "apps/v1" || parent.Controller == nil || !*parent.Controller {
		return zero, ErrInstall
	}
	rs, e := i.kube.AppsV1().ReplicaSets(p.Namespace).Get(ctx, parent.Name, metav1.GetOptions{})
	if e != nil || string(rs.UID) != string(parent.UID) || rs.DeletionTimestamp != nil || len(rs.OwnerReferences) != 1 {
		return zero, ErrInstall
	}
	d := rs.OwnerReferences[0]
	if d.Kind != "Deployment" || d.APIVersion != "apps/v1" || d.Controller == nil || !*d.Controller || d.Name != dep.Name || d.UID != dep.UID {
		return zero, ErrInstall
	}
	sa, e := i.kube.CoreV1().ServiceAccounts(p.Namespace).Get(ctx, pod.Spec.ServiceAccountName, metav1.GetOptions{})
	if e != nil || sa.UID == "" || sa.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	return owner.Binding{InstallationID: p.InstallationID, Namespace: p.Namespace, NamespaceUID: p.NamespaceUID, PodName: pod.Name, PodUID: string(pod.UID), ServiceAccountName: sa.Name, ServiceAccountUID: string(sa.UID)}, nil
}

// ProduceOriginalPublicationSigningMaterial is the explicit FIRST original
// signing-owner action. Original local admin + enrolled Kubernetes owner +
// existing provider owner authorize separate exact-purpose roles and a public
// installation record. No capture record/config/DB login is treated as signing
// authority. No key, issuer, deployment, service account or task is created.
func (i *Installer) ProduceOriginalPublicationSigningMaterial(ctx context.Context, password []byte, enrollment EnrollmentPin, o OriginalPublicationSigningOptions, issuerPrivate []byte) (OriginalPublicationSigningReceipt, error) {
	var zero OriginalPublicationSigningReceipt
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil || privateDirectory(o.OutputDirectory) != nil || !validEndpoint(o.Endpoint) || !originalPublicationName(o.JWTMount) || !text(o.ProviderClusterID) {
		return zero, ErrInstall
	}
	before, now, e := originalAdoptionAuthoritySnapshot(ctx, s)
	if e != nil || before.cas.State == "revoked" || o.Until.IsZero() || !now.Before(o.Until) || o.Until.Sub(now) > 24*time.Hour || before.cas.HeadRevision > 0 && o.Until.After(before.head.Until) {
		return zero, ErrInstall
	}
	actor, e := i.originalPublicationActor(ctx, o.ControllerDeployment, o.ControllerPodName)
	if e != nil {
		return zero, e
	}
	key, e := s.privateKey(issuerPrivate)
	if e != nil {
		return zero, e
	}
	defer clear(key)
	ca, e := readBootstrapSourcePin(o.CA, 65536)
	if e != nil {
		return zero, e
	}
	root, e := originalPublicationOwnerToken(o.VaultOwnerMaterial, o.VaultOwnerMaterialIsInitJSON)
	if e != nil {
		return zero, e
	}
	defer clear(root)
	vault, e := newOriginalPublicationVault(o.Endpoint, ca, o.CA.SHA256)
	if e != nil {
		return zero, e
	}
	defer vault.close()
	if vault.root(ctx, root) != nil || vault.health(ctx, o.ProviderClusterID) != nil {
		return zero, ErrInstall
	}
	trust, e := owner.ReadInstalledVaultKubernetesTrust(ctx, i.kube)
	if e != nil {
		return zero, e
	}
	wantedTrust, e := a.VaultJWTAuthConfig(trust)
	if e != nil {
		return zero, e
	}
	actualTrust, e := vault.data(ctx, "/v1/auth/"+o.JWTMount+"/config", root)
	if e != nil || !originalPublicationSubset(actualTrust, wantedTrust) {
		return zero, ErrInstall
	}
	actualTrust, e = originalPublicationObjectCanonical(actualTrust)
	if e != nil {
		return zero, e
	}
	auth := func() error {
		if s.authority(ctx, enrollment) != nil {
			return ErrInstall
		}
		current, t, e := originalAdoptionAuthoritySnapshot(ctx, s)
		if e != nil || current.cas != before.cas || t.Before(now) || !t.Before(o.Until) {
			return ErrInstall
		}
		actual, e := i.originalPublicationActor(ctx, o.ControllerDeployment, o.ControllerPodName)
		if e != nil || actual != actor {
			return ErrInstall
		}
		check, e := readBootstrapSourcePin(o.CA, 65536)
		clear(check)
		if e != nil {
			return ErrInstall
		}
		currentRoot, e := originalPublicationOwnerToken(o.VaultOwnerMaterial, o.VaultOwnerMaterialIsInitJSON)
		defer clear(currentRoot)
		if e != nil || !bytes.Equal(root, currentRoot) || vault.root(ctx, currentRoot) != nil {
			return ErrInstall
		}
		return nil
	}
	// Journal contains coordinates/public pins only, before ANY provider write.
	intent, e := canonical(struct {
		Version, PlanSHA256, EnrollmentSHA256 string
		Options                               OriginalPublicationSigningOptions
	}{"original-publication-signing-issue-intent.v1", i.planHash, enrollment.DocumentSHA256, o})
	if e != nil || writeNewFiles(o.OutputDirectory, map[string][]byte{"signing-issue.intent.json": intent}) != nil {
		return zero, ErrInstall
	}
	result := OriginalPublicationSigningFiles{Version: "original-publication-signing-material.v1", PlanSHA256: i.planHash, EnrollmentDocumentSHA256: enrollment.DocumentSHA256, CA: o.CA, Trust: trust, JWTFiles: map[string]BootstrapSourceFilePin{}, ResourceObservers: map[string]BootstrapSourceFilePin{}}
	record := sec.InstallationSigningRecord{InstallationID: i.plan.Target.InstallationID, Revision: 1, NotBefore: now, Until: o.Until}
	purposes := []string{"acceptance_record", "capture_certificate", "catalog_record"}
	names := []string{o.AcceptanceKey, o.CaptureKey, o.CatalogKey}
	distinct := map[string]bool{}
	prefix := "sbk-sign-" + hash([]byte(i.planHash + actor.PodUID))[:16]
	probeUntil := o.Until
	for n, purpose := range purposes {
		name := names[n]
		if !originalPublicationName(name) || distinct[name] {
			return zero, ErrInstall
		}
		distinct[name] = true
		pub, e := vault.key(ctx, "transit", name, root)
		if e != nil || bytes.Equal(pub, i.public) {
			return zero, ErrInstall
		}
		b := actor
		b.Purpose = purpose
		b.Endpoint = o.Endpoint
		b.ProviderClusterID = o.ProviderClusterID
		b.TransitMount = "transit"
		b.KeyName = name
		b.KeyID = name
		b.KeyVersion = "1"
		b.ProviderVersion = "1"
		b.AuthMount = o.JWTMount
		b.Role = prefix + "-" + purpose
		b.Policy = b.Role
		b.Audience = "system-backup-signing:" + i.plan.Target.InstallationID + ":" + purpose
		b.CASHA256 = o.CA.SHA256
		b.JWTConfigSHA256 = hash(actualTrust)
		acl, e := owner.CaptureSigningACL(b)
		if e != nil || vault.policy(ctx, b.Policy, acl, root, auth) != nil {
			return zero, ErrInstall
		}
		b.PolicySHA256 = hash([]byte(acl))
		wanted, e := originalPublicationRole(b)
		if e != nil {
			return zero, e
		}
		role, e := vault.role(ctx, b.AuthMount, b.Role, wanted, root, auth)
		if e != nil {
			return zero, e
		}
		b.RoleSHA256 = hash(role)
		if auth() != nil {
			return zero, ErrInstall
		}
		seconds := int64(600)
		token, e := i.kube.CoreV1().ServiceAccounts(b.Namespace).CreateToken(ctx, b.ServiceAccountName, &authn.TokenRequest{Spec: authn.TokenRequestSpec{Audiences: []string{b.Audience}, ExpirationSeconds: &seconds, BoundObjectRef: &authn.BoundObjectReference{Kind: "Pod", APIVersion: "v1", Name: b.PodName, UID: types.UID(actor.PodUID)}}}, metav1.CreateOptions{})
		if e != nil || token.Status.Token == "" || !time.Now().Before(token.Status.ExpirationTimestamp.Time) {
			return zero, ErrInstall
		}
		jwt, e := originalPublicationToken([]byte(token.Status.Token))
		if e != nil {
			return zero, e
		}
		filename := "signing-" + purpose + ".jwt"
		if writeNewFiles(o.OutputDirectory, map[string][]byte{filename: jwt}) != nil {
			clear(jwt)
			return zero, ErrInstall
		}
		clear(jwt)
		result.JWTFiles[purpose] = BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, filename), SHA256: hash([]byte(token.Status.Token))}
		result.Bindings = append(result.Bindings, b)
		result.Histories = append(result.Histories, owner.PurposeKeys{Purpose: purpose, KeyName: name, Keys: []owner.PublicKey{{Version: "1", PublicKey: base64.StdEncoding.EncodeToString(pub), ProtectedUntil: o.Until}}})
		record.Keys = append(record.Keys, sec.ArtifactSigningPublicKey{InstallationID: b.InstallationID, Purpose: purpose, KeyID: b.KeyID, KeyVersion: b.KeyVersion, PublicKey: pub, NotBefore: now, NotAfter: o.Until})
		record.Permissions = append(record.Permissions, sec.InstallationSigningPermission{Binding: sec.TransitSigningBinding{InstallationID: b.InstallationID, Purpose: purpose, KeyID: b.KeyID, KeyVersion: b.KeyVersion, Endpoint: b.Endpoint, KeyName: b.KeyName, ProviderVersion: b.ProviderVersion}, AuthMount: b.AuthMount, Role: b.Role, Policy: b.Policy, CASHA256: b.CASHA256})
	}
	if _, e = sec.NewArtifactSigningKeyHistory(record.InstallationID, record.Keys); e != nil {
		return zero, ErrInstall
	}
	// Distinct capture vs signing-resource observer ACLs. Neither can sign or
	// create tokens; original Vault owner creates the short read-only tokens.
	resourcePolicy := prefix + "-resource-observer"
	resourceACL, e := owner.SigningResourceObserverACL(owner.SigningResourceGrant{Target: i.plan.Target, Bindings: result.Bindings, Histories: result.Histories}, resourcePolicy)
	if e != nil {
		return zero, e
	}
	capturePolicy := prefix + "-capture-observer"
	captureACL, e := owner.CaptureSigningObserverACL(owner.Record{Binding: result.Bindings[1], Histories: result.Histories}, capturePolicy)
	if e != nil {
		return zero, e
	}
	files := map[string][]byte{}
	for _, entry := range []struct{ name, acl, file string }{{resourcePolicy, resourceACL, "resource-observer"}, {capturePolicy, captureACL, "capture-observer"}} {
		if vault.policy(ctx, entry.name, entry.acl, root, auth) != nil {
			return zero, ErrInstall
		}
		token, e := vault.observerToken(ctx, entry.name, root, auth)
		if e != nil {
			return zero, e
		}
		tokenFile := filepath.Join(o.OutputDirectory, entry.file+".token")
		doc := observerDocument{Endpoint: o.Endpoint, CASHA256: o.CA.SHA256, CAFile: o.CA.File, ObserverPolicy: entry.name, ObserverTokenFile: tokenFile, ObserverTokenSHA256: hash(token), RuntimeJWTFile: result.JWTFiles["capture_certificate"].File, Trust: trust}
		if entry.file == "resource-observer" {
			doc.RuntimeJWTFile = result.JWTFiles["acceptance_record"].File
		}
		docRaw, e := canonical(doc)
		if e != nil {
			clear(token)
			return zero, e
		}
		files[entry.file+".token"] = bytes.Clone(token)
		clear(token)
		files[entry.file+".json"] = docRaw
		if entry.file == "resource-observer" {
			for _, purpose := range purposes {
				specific := doc
				specific.RuntimeJWTFile = result.JWTFiles[purpose].File
				body, e := canonical(specific)
				if e != nil {
					return zero, e
				}
				name := "resource-observer-" + purpose + ".json"
				files[name] = body
				result.ResourceObservers[purpose] = BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, name), SHA256: hash(body)}
			}
		}

		pin := BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, entry.file+".json"), SHA256: hash(docRaw)}
		if entry.file == "resource-observer" {
			result.ResourceObserver = pin
		} else {
			result.CaptureObserver = pin
		}
	}
	if auth() != nil || vault.health(ctx, o.ProviderClusterID) != nil {
		return zero, ErrInstall
	}
	for n, b := range result.Bindings {
		if originalPublicationCheckMetadata(ctx, vault, b, result.Histories[n], root) != nil {
			return zero, ErrInstall
		}
		jwt, e := readBootstrapSourcePin(result.JWTFiles[b.Purpose], 16384)
		if e != nil {
			return zero, e
		}
		end, e := i.originalPublicationProbe(ctx, vault, b, record.Keys[n].PublicKey, jwt)
		clear(jwt)
		if e != nil {
			return zero, e
		}
		if end.Before(probeUntil) {
			probeUntil = end
		}
	}

	recordRaw, e := canonical(record)
	if e != nil {
		return zero, e
	}
	signature := ed25519.Sign(key, append([]byte(sec.InstallationSigningDomain), recordRaw...))
	result.Record = sec.FileSigningRecordReader{RecordFile: filepath.Join(o.OutputDirectory, "installation-signing.record.json"), SignatureFile: filepath.Join(o.OutputDirectory, "installation-signing.signature")}
	result.Pin = sec.InstallationSigningPin{InstallationID: record.InstallationID, Revision: record.Revision, RecordSHA256: hash(recordRaw), Issuer: bytes.Clone(i.public)}
	materialRaw, e := canonical(result)
	if e != nil {
		return zero, e
	}
	pinRaw, e := canonical(result.Pin)
	if e != nil {
		return zero, e
	}
	files["installation-signing.record.json"] = recordRaw
	files["installation-signing.signature"] = signature
	files["installation-signing.pin.json"] = pinRaw
	files["original-publication-signing.material.json"] = materialRaw
	files["original-publication-signing.material.signature"] = ed25519.Sign(key, append([]byte(originalPublicationSigningMaterialDomain), materialRaw...))
	if auth() != nil || !time.Now().Before(probeUntil) || writeNewFiles(o.OutputDirectory, files) != nil {
		return zero, ErrInstall
	}
	for name, expected := range files {
		raw, e := ReadPrivateFile(filepath.Join(o.OutputDirectory, name), 262144)
		if e != nil || !bytes.Equal(raw, expected) {
			return zero, ErrInstall
		}
	}
	if _, e = sec.LoadInstallationSigningHistory(ctx, result.Record, result.Pin); e != nil || auth() != nil || !time.Now().Before(probeUntil) {
		return zero, ErrInstall
	}
	return OriginalPublicationSigningReceipt{MaterialSignatureFile: filepath.Join(o.OutputDirectory, "original-publication-signing.material.signature"), Version: "original-publication-signing-material-result.v1", Material: BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, "original-publication-signing.material.json"), SHA256: hash(materialRaw)}, RecordPin: BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, "installation-signing.pin.json"), SHA256: hash(pinRaw)}, ResourceObserver: result.ResourceObserver, CaptureObserver: result.CaptureObserver, ResourceObservers: result.ResourceObservers, Record: result.Record, Pin: result.Pin}, nil
}

func readOriginalPublicationSigningFiles(ctx context.Context, issuer ed25519.PublicKey, pin BootstrapSourceFilePin) (OriginalPublicationSigningFiles, error) {
	var zero OriginalPublicationSigningFiles
	if ctx == nil || ctx.Err() != nil || len(issuer) != ed25519.PublicKeySize || filepath.Base(pin.File) != "original-publication-signing.material.json" {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(pin, 262144)
	if e != nil {
		return zero, e
	}
	signature, e := ReadPrivateFile(filepath.Join(filepath.Dir(pin.File), "original-publication-signing.material.signature"), 64)
	if e != nil || !ed25519.Verify(issuer, append([]byte(originalPublicationSigningMaterialDomain), raw...), signature) || decodeExact(raw, &zero) != nil {
		return OriginalPublicationSigningFiles{}, ErrInstall
	}
	return zero, nil
}
