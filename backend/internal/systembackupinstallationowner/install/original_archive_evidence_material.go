package install

import (
	"bytes"
	ev "clawreef/internal/systembackupevidence"
	owner "clawreef/internal/systembackupinstallationowner"
	a "clawreef/internal/systembackupkekadapter"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	authn "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const originalArchiveMaterialDomain = "original-enrolled-archive-evidence-material.v1\x00"

type OriginalArchiveEvidenceMaterialOptions struct {
	Version                                          string
	C1Material, C1Signature                          BootstrapSourceFilePin
	UnwrapDeployment, UnwrapPodName, OutputDirectory string
}
type OriginalArchiveEvidenceMaterialReceipt struct {
	Version, State      string
	Material, Signature BootstrapSourceFilePin
	C1                  OriginalC1EvidenceMaterialReceipt
	Vault               a.EvidenceVaultObserverConfig
	WrapJWT, UnwrapJWT  OriginalArchiveJWTSource
	Until               time.Time
}
type originalArchiveEvidenceMaterial struct {
	Version, PlanSHA256, EnrollmentSHA256                               string
	Source                                                              OriginalArchiveEvidenceMaterialOptions
	C1                                                                  OriginalC1EvidenceMaterialReceipt
	Vault                                                               a.EvidenceVaultObserverConfig
	WrapJWT, UnwrapJWT                                                  OriginalArchiveJWTSource
	UnwrapActor                                                         owner.Binding
	RoleSHA256, PolicySHA256, BeforeMetadataSHA256, AfterMetadataSHA256 string
	ObservedAt, Until                                                   time.Time
}

// Actual original owner creates only a dedicated decrypt role for the SAME
// already-issued C1 evidence key, a Pod-bound JWT and metadata-only observer.
// Existing C1 signed files and keys are never overwritten. Its updated C1
// material is independently signed in a new directory for downstream owners.
func (i *Installer) ProduceOriginalArchiveEvidenceMaterial(ctx context.Context, password []byte, enrollment EnrollmentPin, o OriginalArchiveEvidenceMaterialOptions, issuerPrivate []byte) (OriginalArchiveEvidenceMaterialReceipt, error) {
	var zero OriginalArchiveEvidenceMaterialReceipt
	if i == nil || ctx == nil || o.Version != "original-archive-evidence-material-inputs.v1" || privateDirectory(o.OutputDirectory) != nil || o.OutputDirectory == filepath.Dir(o.C1Material.File) {
		return zero, ErrInstall
	}
	original, e := i.QueryOriginalC1EvidenceMaterial(ctx, password, enrollment, filepath.Dir(o.C1Material.File))
	if e != nil || original.Material != o.C1Material || original.Signature != o.C1Signature {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(original.Material, 262144)
	var m OriginalC1EvidenceMaterial
	if e != nil || decodeExact(raw, &m) != nil {
		return zero, ErrInstall
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	state, now, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if e != nil || state.cas != (HeadCAS{}) || !now.Before(m.Until) {
		return zero, ErrInstall
	}
	issuer, e := op.privateKey(issuerPrivate)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(issuer)
	actor, e := i.originalPublicationActor(ctx, o.UnwrapDeployment, o.UnwrapPodName)
	if e != nil {
		return zero, ErrInstall
	}
	cfgRaw, e := readBootstrapSourcePin(m.InstalledObserver, 262144)
	var cfg owner.InstalledVaultDependencyConfig
	if e != nil || decodeExact(cfgRaw, &cfg) != nil || cfg.EvidenceWrap == nil || cfg.EvidenceWrap.ArchiveUnwrap != nil || !reflect.DeepEqual(cfg.EvidenceWrap.Transit, m.Transit.Transit) {
		return zero, ErrInstall
	}
	selectedRaw, e := readBootstrapSourcePin(m.WriterSelection, 262144)
	var selected OriginalWriterSetSelection
	if e != nil || decodeExact(selectedRaw, &selected) != nil || len(selected.PreAdoptionVaultDependencies) != 1 || selected.PreAdoptionVaultDependencies[0].InstalledObserver != m.InstalledObserver {
		return zero, ErrInstall
	}
	wrapDP, e := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).Get(ctx, m.Source.ControllerDeployment, metav1.GetOptions{})
	if e != nil || wrapDP.UID == "" {
		return zero, ErrInstall
	}
	readDP, e := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).Get(ctx, o.UnwrapDeployment, metav1.GetOptions{})
	if e != nil || readDP.UID == "" {
		return zero, ErrInstall
	}
	originalPins := []BootstrapSourceFilePin{o.C1Material, o.C1Signature, m.InstalledObserver, m.WriterSelection, m.RuntimeJWT}
	beforeObserver, e := owner.NewInstalledVaultDependencyObserver(cfg, i.kube, i.plan.Target.Namespace, i.plan.Target.NamespaceUID)
	if e != nil {
		return zero, ErrInstall
	}
	defer beforeObserver.Close()
	observed, e := beforeObserver.Observe(ctx)
	if e != nil {
		return zero, ErrInstall
	}
	before, _, e := observed.Data(ctx)
	if e != nil {
		return zero, ErrInstall
	}
	root, e := originalPublicationOwnerToken(m.Source.VaultOwnerMaterial, m.Source.VaultOwnerMaterialIsInitJSON)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(root)
	v, e := newOriginalPublicationVault(cfg.Endpoint, cfg.CAPEM, cfg.CASHA256)
	if e != nil {
		return zero, ErrInstall
	}
	defer v.close()
	if v.root(ctx, root) != nil || v.health(ctx, cfg.ClusterID) != nil {
		return zero, ErrInstall
	}
	roleName := "sbk-c1-read-" + hash([]byte(i.planHash + actor.PodUID))[:24]
	role := a.VaultPermissionRole{AuthMount: cfg.JWTMount, Role: roleName, Policy: roleName, Audience: "system-backup-c1-evidence-read:" + i.plan.Target.InstallationID, Namespace: actor.Namespace, ServiceAccountName: actor.ServiceAccountName, ServiceAccountUID: actor.ServiceAccountUID, PodUID: actor.PodUID}
	acl, e := a.EvidenceVaultRuntimeACL(m.Transit.Transit, ev.TransitUnwrap)
	if e != nil {
		return zero, ErrInstall
	}
	desired, e := a.VaultJWTAuthRole(role)
	if e != nil {
		return zero, ErrInstall
	}
	until := minTime(m.Until.Add(-6*time.Second), op.until)
	auth := func() error {
		if op.authority(ctx, enrollment) != nil || !time.Now().Before(until) {
			return ErrInstall
		}
		current, _, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
		if e != nil || current.cas != state.cas {
			return ErrInstall
		}
		actual, e := i.originalPublicationActor(ctx, o.UnwrapDeployment, o.UnwrapPodName)
		if e != nil || actual != actor {
			return ErrInstall
		}
		actual, e = i.originalPublicationActor(ctx, m.Source.ControllerDeployment, m.Source.ControllerPodName)
		if e != nil || actual != m.Binding {
			return ErrInstall
		}
		scope, e := ObserveInstalledVaultProviderScope(ctx, i.db, i.kube, i.plan.Target, selected.PreAdoptionVaultDependencies[0].Workload, cfg.Endpoint)
		if e != nil || !reflect.DeepEqual(scope, m.ProviderScope) {
			return ErrInstall
		}
		wd, e := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).Get(ctx, m.Source.ControllerDeployment, metav1.GetOptions{})
		if e != nil || wd.UID != wrapDP.UID {
			return ErrInstall
		}
		rd, e := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).Get(ctx, o.UnwrapDeployment, metav1.GetOptions{})
		if e != nil || rd.UID != readDP.UID {
			return ErrInstall
		}
		for _, pin := range originalPins {
			b, e := readBootstrapSourcePin(pin, 262144)
			clear(b)
			if e != nil {
				return ErrInstall
			}
		}
		r, e := originalPublicationOwnerToken(m.Source.VaultOwnerMaterial, m.Source.VaultOwnerMaterialIsInitJSON)
		defer clear(r)
		if e != nil || !bytes.Equal(r, root) || v.root(ctx, r) != nil {
			return ErrInstall
		}
		return nil
	}
	beforeMeta, e := originalC1VaultMetadata(ctx, v, root, cfg.JWTMount, before)
	if e != nil {
		return zero, ErrInstall
	}
	beforeRaw, e := canonical(beforeMeta)
	if e != nil {
		return zero, ErrInstall
	}
	intent, e := canonical(struct {
		Version, Plan, Enrollment string
		Source                    OriginalArchiveEvidenceMaterialOptions
		Role                      a.VaultPermissionRole
	}{"original-archive-evidence-material-intent.v1", i.planHash, enrollment.DocumentSHA256, o, role})
	if e != nil || auth() != nil || writeNewFiles(o.OutputDirectory, map[string][]byte{"archive-evidence.intent.json": intent, "archive-provider-metadata.before.json": beforeRaw}) != nil {
		return zero, ErrInstall
	}
	pending := OriginalArchiveEvidenceMaterialReceipt{Version: "original-archive-evidence-material-result.v1", State: "original_archive_native_write_unconfirmed_query_only_preserve_intent"}
	// Every mutation is covered by a create-only intent before dispatch. A lost
	// reply never causes this action to issue another token or repair a role.
	if writeNewFiles(o.OutputDirectory, map[string][]byte{"archive-native.sent.json": intent}) != nil {
		return pending, ErrInstall
	}
	if v.policy(ctx, role.Policy, acl, root, auth) != nil {
		return pending, ErrInstall
	}
	actualRole, e := v.role(ctx, role.AuthMount, role.Role, desired, root, auth)
	if e != nil {
		return pending, ErrInstall
	}
	if auth() != nil {
		return pending, ErrInstall
	}
	seconds := int64(600)
	token, e := i.kube.CoreV1().ServiceAccounts(actor.Namespace).CreateToken(ctx, actor.ServiceAccountName, &authn.TokenRequest{Spec: authn.TokenRequestSpec{Audiences: []string{role.Audience}, ExpirationSeconds: &seconds, BoundObjectRef: &authn.BoundObjectReference{Kind: "Pod", APIVersion: "v1", Name: actor.PodName, UID: types.UID(actor.PodUID)}}}, metav1.CreateOptions{})
	if e != nil || token.Status.Token == "" {
		return pending, ErrInstall
	}
	until = minTime(until, token.Status.ExpirationTimestamp.Time.Add(-6*time.Second))
	jwt, e := originalPublicationToken([]byte(token.Status.Token))
	if e != nil {
		return pending, ErrInstall
	}
	defer clear(jwt)
	jwtFile := filepath.Join(o.OutputDirectory, "archive-evidence-unwrap.jwt")
	observerPolicy := "sbk-c1-observe-" + hash([]byte(i.planHash + actor.PodUID + m.Binding.PodUID))[:24]
	observerACL, e := a.VaultObserverACL(m.Transit.Transit.KeyName, cfg.EvidenceWrap.Role, role, observerPolicy)
	if e != nil || v.policy(ctx, observerPolicy, observerACL, root, auth) != nil {
		return pending, ErrInstall
	}
	started := time.Now()
	observerToken, e := v.observerToken(ctx, observerPolicy, root, auth)
	if e != nil {
		return pending, ErrInstall
	}
	defer clear(observerToken)
	lookup, e := v.data(ctx, "/v1/auth/token/lookup-self", observerToken)
	defer clear(lookup)
	var lease struct {
		TTL              int64    `json:"ttl"`
		Policies         []string `json:"policies"`
		IdentityPolicies []string `json:"identity_policies"`
	}
	if e != nil || json.Unmarshal(lookup, &lease) != nil || lease.TTL < 1 || lease.TTL > 600 || !reflect.DeepEqual(lease.Policies, []string{observerPolicy}) || len(lease.IdentityPolicies) != 0 {
		return pending, ErrInstall
	}
	until = minTime(until, started.Add(time.Duration(lease.TTL)*time.Second))
	observerFile := filepath.Join(o.OutputDirectory, "archive-evidence-observer.token")
	if writeNewFiles(o.OutputDirectory, map[string][]byte{"archive-evidence-unwrap.jwt": jwt, "archive-evidence-observer.token": observerToken}) != nil {
		return pending, ErrInstall
	}
	transport := ev.TransitJWTConfig{Transit: m.Transit.Transit, Mount: role.AuthMount, Role: role.Role, Policy: role.Policy, Issuer: cfg.Trust.Issuer, Audience: role.Audience, Subject: "system:serviceaccount:" + actor.Namespace + ":" + actor.ServiceAccountName, TokenFile: jwtFile}
	wrapJWT, e := readBootstrapSourcePin(m.RuntimeJWT, 16384)
	if e != nil {
		return pending, ErrInstall
	}
	defer clear(wrapJWT)
	if auth() != nil || i.originalArchiveMaterialProbe(ctx, v, m.Binding, actor, m.Transit, transport, wrapJWT, jwt) != nil {
		return pending, ErrInstall
	}
	vault := a.EvidenceVaultObserverConfig{Transit: m.Transit.Transit, TokenFile: observerFile, TokenSHA256: hash(observerToken), ObserverPolicy: observerPolicy, Wrap: cfg.EvidenceWrap.Role, Unwrap: role, Trust: cfg.Trust}
	if _, e = a.ObserveEvidenceVault(ctx, vault); e != nil {
		return pending, ErrInstall
	}
	// Preserve exact native metadata for all other keys, roles and policies.
	updated := cfg
	profile := *cfg.EvidenceWrap
	profile.ArchiveUnwrap = &role
	updated.EvidenceWrap = &profile
	afterObserver, e := owner.NewInstalledVaultDependencyObserver(updated, i.kube, i.plan.Target.Namespace, i.plan.Target.NamespaceUID)
	if e != nil {
		return pending, ErrInstall
	}
	defer afterObserver.Close()
	afterObserved, e := afterObserver.Observe(ctx)
	if e != nil {
		return pending, ErrInstall
	}
	after, _, e := afterObserved.Data(ctx)
	if e != nil || !originalC1OnlyDedicatedMaterialChanged(before, after, m.Transit.Transit.KeyName, roleName) {
		return pending, ErrInstall
	}
	afterMeta, e := originalC1VaultMetadata(ctx, v, root, cfg.JWTMount, after)
	if e != nil || !originalC1OnlyOwnedMetadataChanged(beforeMeta, afterMeta, cfg.JWTMount, m.Transit.Transit.KeyName, roleName) {
		return pending, ErrInstall
	}
	keyPath := "/v1/transit/keys/" + m.Transit.Transit.KeyName
	metadata, e := v.data(ctx, keyPath, root)
	if e != nil || hash(metadata) != m.KeyMetadataSHA256 || beforeMeta[keyPath] != afterMeta[keyPath] {
		return pending, ErrInstall
	}
	finalRole, e := v.data(ctx, "/v1/auth/"+role.AuthMount+"/role/"+role.Role, root)
	if e != nil {
		return pending, ErrInstall
	}
	finalRole, e = originalPublicationObjectCanonical(finalRole)
	if e != nil || !bytes.Equal(finalRole, actualRole) || auth() != nil {
		return pending, ErrInstall
	}
	afterRaw, e := canonical(afterMeta)
	if e != nil {
		return pending, ErrInstall
	}
	updatedRaw, e := canonical(updated)
	if e != nil {
		return pending, ErrInstall
	}
	updatedPin := BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, "c1-installed-vault-observer.private.json"), SHA256: hash(updatedRaw)}
	selected.PreAdoptionVaultDependencies[0].InstalledObserver = updatedPin
	selectionRaw, e := canonical(selected)
	if e != nil {
		return pending, ErrInstall
	}
	selectionPin := BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, "c1-vault-writer-selection.json"), SHA256: hash(selectionRaw)}
	m.InstalledObserver, m.WriterSelection = updatedPin, selectionPin
	m.Source.OutputDirectory = o.OutputDirectory
	m.AfterMetadata = BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, "c1-provider-metadata.after.json"), SHA256: hash(afterRaw)}
	m.ObservedAt, m.Until = time.Now().UTC(), until
	c1Raw, e := canonical(m)
	if e != nil {
		return pending, ErrInstall
	}
	c1Sig := ed25519.Sign(issuer, append([]byte(originalC1EvidenceMaterialDomain), c1Raw...))
	if auth() != nil || writeNewFiles(o.OutputDirectory, map[string][]byte{"c1-installed-vault-observer.private.json": updatedRaw, "c1-vault-writer-selection.json": selectionRaw, "c1-provider-metadata.after.json": afterRaw, "c1-evidence.material.json": c1Raw, "c1-evidence.material.signature": c1Sig}) != nil {
		return pending, ErrInstall
	}
	c1, e := i.QueryOriginalC1EvidenceMaterial(ctx, password, enrollment, o.OutputDirectory)
	if e != nil {
		return pending, ErrInstall
	}
	wrapSource := OriginalArchiveJWTSource{File: m.RuntimeJWT.File, SHA256: m.RuntimeJWT.SHA256, PodName: m.Binding.PodName, PodUID: m.Binding.PodUID, DeploymentName: m.Source.ControllerDeployment, DeploymentUID: string(wrapDP.UID)}
	readSource := OriginalArchiveJWTSource{File: jwtFile, SHA256: hash(jwt), PodName: actor.PodName, PodUID: actor.PodUID, DeploymentName: o.UnwrapDeployment, DeploymentUID: string(readDP.UID)}
	material := originalArchiveEvidenceMaterial{Version: "original-archive-evidence-material.v1", PlanSHA256: i.planHash, EnrollmentSHA256: enrollment.DocumentSHA256, Source: o, C1: c1, Vault: vault, WrapJWT: wrapSource, UnwrapJWT: readSource, UnwrapActor: actor, RoleSHA256: hash(actualRole), PolicySHA256: hash([]byte(acl)), BeforeMetadataSHA256: hash(beforeRaw), AfterMetadataSHA256: hash(afterRaw), ObservedAt: time.Now().UTC(), Until: until}
	raw, e = canonical(material)
	if e != nil {
		return pending, ErrInstall
	}
	sig := ed25519.Sign(issuer, append([]byte(originalArchiveMaterialDomain), raw...))
	if auth() != nil || writeNewFiles(o.OutputDirectory, map[string][]byte{"archive-evidence.material.json": raw, "archive-evidence.material.signature": sig}) != nil {
		return pending, ErrInstall
	}
	return i.QueryOriginalArchiveEvidenceMaterial(ctx, password, enrollment, o.OutputDirectory)
}

// Original signed files and live metadata/Pod/TokenReview are checked only;
// query never creates credentials, changes policies, wraps or decrypts.
func (i *Installer) QueryOriginalArchiveEvidenceMaterial(ctx context.Context, password []byte, enrollment EnrollmentPin, directory string) (OriginalArchiveEvidenceMaterialReceipt, error) {
	pending := OriginalArchiveEvidenceMaterialReceipt{Version: "original-archive-evidence-material-result.v1", State: "original_archive_material_unconfirmed_query_only"}
	if i == nil || ctx == nil || privateDirectory(directory) != nil {
		return pending, ErrInstall
	}
	raw, e := ReadPrivateFile(filepath.Join(directory, "archive-evidence.material.json"), 262144)
	if e != nil {
		return pending, ErrInstall
	}
	sig, e := ReadPrivateFile(filepath.Join(directory, "archive-evidence.material.signature"), 64)
	var m originalArchiveEvidenceMaterial
	if e != nil || !ed25519.Verify(i.public, append([]byte(originalArchiveMaterialDomain), raw...), sig) || decodeExact(raw, &m) != nil || m.Version != "original-archive-evidence-material.v1" || m.PlanSHA256 != i.planHash || m.EnrollmentSHA256 != enrollment.DocumentSHA256 || m.Source.OutputDirectory != directory || !time.Now().Before(m.Until) || time.Now().Before(m.ObservedAt) {
		return pending, ErrInstall
	}
	c1, e := i.QueryOriginalC1EvidenceMaterial(ctx, password, enrollment, directory)
	if e != nil || !reflect.DeepEqual(c1, m.C1) {
		return pending, ErrInstall
	}
	c1raw, e := readBootstrapSourcePin(c1.Material, 262144)
	var c1material OriginalC1EvidenceMaterial
	if e != nil || decodeExact(c1raw, &c1material) != nil || m.Until.After(c1material.Until) {
		return pending, ErrInstall
	}
	cfgraw, e := readBootstrapSourcePin(c1.InstalledObserver, 262144)
	var cfg owner.InstalledVaultDependencyConfig
	if e != nil || decodeExact(cfgraw, &cfg) != nil || cfg.EvidenceWrap == nil || cfg.EvidenceWrap.ArchiveUnwrap == nil || !reflect.DeepEqual(*cfg.EvidenceWrap.ArchiveUnwrap, m.Vault.Unwrap) || !reflect.DeepEqual(cfg.EvidenceWrap.Role, m.Vault.Wrap) || !reflect.DeepEqual(cfg.EvidenceWrap.Transit, m.Vault.Transit) || !reflect.DeepEqual(cfg.Trust, m.Vault.Trust) {
		return pending, ErrInstall
	}
	if m.WrapJWT.File != c1material.RuntimeJWT.File || m.WrapJWT.SHA256 != c1material.RuntimeJWT.SHA256 || m.WrapJWT.PodUID != c1material.Binding.PodUID {
		return pending, ErrInstall
	}
	for _, source := range []OriginalArchiveJWTSource{m.WrapJWT, m.UnwrapJWT} {
		dep, e := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).Get(ctx, source.DeploymentName, metav1.GetOptions{})
		if e != nil || string(dep.UID) != source.DeploymentUID || dep.DeletionTimestamp != nil {
			return pending, ErrInstall
		}
	}
	actor, e := i.originalPublicationActor(ctx, m.Source.UnwrapDeployment, m.Source.UnwrapPodName)
	if e != nil || actor != m.UnwrapActor {
		return pending, ErrInstall
	}
	if _, e = a.ObserveEvidenceVault(ctx, m.Vault); e != nil {
		return pending, ErrInstall
	}
	jwt, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: m.UnwrapJWT.File, SHA256: m.UnwrapJWT.SHA256}, 16384)
	if e != nil {
		return pending, ErrInstall
	}
	defer clear(jwt)
	review, e := i.kube.AuthenticationV1().TokenReviews().Create(ctx, &authn.TokenReview{Spec: authn.TokenReviewSpec{Token: string(jwt), Audiences: []string{m.Vault.Unwrap.Audience}}}, metav1.CreateOptions{})
	if e != nil || !review.Status.Authenticated || review.Status.Error != "" || review.Status.User.UID != actor.ServiceAccountUID || review.Status.User.Username != "system:serviceaccount:"+actor.Namespace+":"+actor.ServiceAccountName || !reflect.DeepEqual(review.Status.Audiences, []string{m.Vault.Unwrap.Audience}) || !reflect.DeepEqual([]string(review.Status.User.Extra["authentication.kubernetes.io/pod-uid"]), []string{actor.PodUID}) {
		return pending, ErrInstall
	}
	for _, pin := range []BootstrapSourceFilePin{m.Source.C1Material, m.Source.C1Signature} {
		b, e := readBootstrapSourcePin(pin, 262144)
		clear(b)
		if e != nil {
			return pending, ErrInstall
		}
	}
	check, e := ReadPrivateFile(filepath.Join(directory, "archive-evidence.material.json"), 262144)
	if e != nil || !bytes.Equal(raw, check) || !time.Now().Before(m.Until) {
		return pending, ErrInstall
	}
	return OriginalArchiveEvidenceMaterialReceipt{Version: pending.Version, State: "original_archive_evidence_roles_jwts_native_verified_not_adopted", Material: BootstrapSourceFilePin{File: filepath.Join(directory, "archive-evidence.material.json"), SHA256: hash(raw)}, Signature: BootstrapSourceFilePin{File: filepath.Join(directory, "archive-evidence.material.signature"), SHA256: hash(sig)}, C1: c1, Vault: m.Vault, WrapJWT: m.WrapJWT, UnwrapJWT: m.UnwrapJWT, Until: m.Until}, nil
}

// Deadline DATA only; the actual archive provider still TokenReviews the exact
// pinned JWT and rechecks Pod/SA/deployment owner chain before authorization.
func originalArchiveMaterialJWTUntil(source OriginalArchiveJWTSource) (time.Time, error) {
	raw, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: source.File, SHA256: source.SHA256}, 16384)
	if e != nil {
		return time.Time{}, ErrInstall
	}
	defer clear(raw)
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 {
		return time.Time{}, ErrInstall
	}
	body, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil {
		return time.Time{}, ErrInstall
	}
	defer clear(body)
	if _, e = originalArchiveObject(body); e != nil {
		return time.Time{}, ErrInstall
	}
	var c struct {
		Expires int64 `json:"exp"`
	}
	if json.Unmarshal(body, &c) != nil || c.Expires <= 0 {
		return time.Time{}, ErrInstall
	}
	until := time.Unix(c.Expires, 0).Add(-6 * time.Second)
	if !time.Now().Before(until) {
		return time.Time{}, ErrInstall
	}
	return until, nil
}
