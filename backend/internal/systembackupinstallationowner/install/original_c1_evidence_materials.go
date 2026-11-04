package install

import (
	"bytes"
	ev "clawreef/internal/systembackupevidence"
	owner "clawreef/internal/systembackupinstallationowner"
	a "clawreef/internal/systembackupkekadapter"
	"context"
	"crypto/ed25519"
	"encoding/json"
	authn "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"path/filepath"
	"reflect"
	"time"
)

const originalC1EvidenceMaterialDomain = "original-enrolled-c1-evidence-material.v1\x00"

type OriginalC1EvidenceMaterialOptions struct {
	WriterSelection                                          BootstrapSourceFilePin
	VaultOwnerMaterial                                       BootstrapSourceFilePin
	VaultOwnerMaterialIsInitJSON                             bool
	ControllerDeployment, ControllerPodName, OutputDirectory string
	Until                                                    time.Time
}

type OriginalC1EvidenceMaterial struct {
	Version, PlanSHA256, EnrollmentSHA256                       string
	Source                                                      OriginalC1EvidenceMaterialOptions
	Binding                                                     owner.Binding
	ProviderScope                                               VaultProviderScopeData
	Transit                                                     ev.TransitJWTConfig
	RuntimeJWT                                                  BootstrapSourceFilePin
	InstalledObserver, WriterSelection                          BootstrapSourceFilePin
	KeyMetadataSHA256, PolicySHA256, RoleSHA256, JWTTrustSHA256 string
	ObservedAt, Until                                           time.Time
	BeforeMetadata, AfterMetadata                               BootstrapSourceFilePin
}

type OriginalC1EvidenceMaterialReceipt struct {
	Version, State                     string
	Material, Signature                BootstrapSourceFilePin
	InstalledObserver, WriterSelection BootstrapSourceFilePin
	Key                                ev.KeyRef
}

// Original owner installation only. Real source selection/native endpoint,
// provider cluster and current Pod/SA are read independently. A dedicated
// derived evidence key and encrypt-only batch role are issued; this creates
// neither a producer handle nor a KEK Generate/Unwrap authority or retention
// registry row. The real C1 pipeline still needs original SDK authorization.
func (i *Installer) ProduceOriginalC1EvidenceMaterial(ctx context.Context, password []byte, enrollment EnrollmentPin, o OriginalC1EvidenceMaterialOptions, issuerPrivate []byte) (OriginalC1EvidenceMaterialReceipt, error) {
	var zero OriginalC1EvidenceMaterialReceipt
	if i == nil || ctx == nil || ctx.Err() != nil || privateDirectory(o.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	s, err := i.authenticate(ctx, password)
	if err != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	before, now, err := originalRuntimeAuthoritySnapshot(ctx, s, enrollment)
	if err != nil || before.cas != (HeadCAS{}) || !now.Before(o.Until) || o.Until.Sub(now) > 10*time.Minute {
		return zero, ErrInstall
	}
	raw, err := readBootstrapSourcePin(o.WriterSelection, 262144)
	var selection OriginalWriterSetSelection
	if err != nil || decodeExact(raw, &selection) != nil || selection.Version != OriginalWriterSetSelectionVersion || len(selection.PreAdoptionVaultDependencies) != 1 || len(selection.VaultProviderDependencies) != 0 {
		return zero, ErrInstall
	}
	selected := selection.PreAdoptionVaultDependencies[0]
	raw, err = readBootstrapSourcePin(selected.InstalledObserver, 262144)
	var original owner.InstalledVaultDependencyConfig
	if err != nil || decodeExact(raw, &original) != nil || original.IdentityMode != "original-owner-readonly" || original.TransitMount != "transit" {
		return zero, ErrInstall
	}
	// Native full-roster check: never select an endpoint/Pod by caller flags.
	roster := map[string]string{}
	for _, d := range selection.Deployments {
		if d.Name == "" || d.UID == "" || roster[d.Name] != "" {
			return zero, ErrInstall
		}
		roster[d.Name] = d.UID
	}
	deployments, err := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil || len(deployments.Items) != len(roster) {
		return zero, ErrInstall
	}
	for _, d := range deployments.Items {
		if roster[d.Name] != string(d.UID) || d.DeletionTimestamp != nil {
			return zero, ErrInstall
		}
	}
	actor, err := i.originalPublicationActor(ctx, o.ControllerDeployment, o.ControllerPodName)
	if err != nil {
		return zero, ErrInstall
	}
	scope, err := ObserveInstalledVaultProviderScope(ctx, i.db, i.kube, i.plan.Target, selected.Workload, original.Endpoint)
	if err != nil {
		return zero, ErrInstall
	}
	trust, err := owner.ReadInstalledVaultKubernetesTrust(ctx, i.kube)
	if err != nil || !reflect.DeepEqual(trust, original.Trust) {
		return zero, ErrInstall
	}
	native, err := owner.NewInstalledVaultDependencyObserver(original, i.kube, i.plan.Target.Namespace, i.plan.Target.NamespaceUID)
	if err != nil {
		return zero, ErrInstall
	}
	defer native.Close()
	observation, err := native.Observe(ctx)
	if err != nil {
		return zero, ErrInstall
	}
	beforeNative, _, err := observation.Data(ctx)
	if err != nil {
		return zero, ErrInstall
	}
	ca := bytes.Clone(original.CAPEM)
	vault, err := newOriginalPublicationVault(original.Endpoint, ca, original.CASHA256)
	if err != nil {
		return zero, ErrInstall
	}
	defer vault.close()
	root, err := originalPublicationOwnerToken(o.VaultOwnerMaterial, o.VaultOwnerMaterialIsInitJSON)
	if err != nil {
		return zero, ErrInstall
	}
	defer clear(root)
	if vault.root(ctx, root) != nil || vault.health(ctx, original.ClusterID) != nil {
		return zero, ErrInstall
	}
	issuer, err := s.privateKey(issuerPrivate)
	if err != nil {
		return zero, ErrInstall
	}
	defer clear(issuer)
	auth := func() error {
		if s.authority(ctx, enrollment) != nil || !time.Now().Before(o.Until) {
			return ErrInstall
		}
		current, _, e := originalRuntimeAuthoritySnapshot(ctx, s, enrollment)
		if e != nil || current.cas != before.cas {
			return ErrInstall
		}
		for _, pin := range []BootstrapSourceFilePin{o.WriterSelection, selected.InstalledObserver} {
			b, e := readBootstrapSourcePin(pin, 262144)
			clear(b)
			if e != nil {
				return ErrInstall
			}
		}
		actual, e := ObserveInstalledVaultProviderScope(ctx, i.db, i.kube, i.plan.Target, selected.Workload, original.Endpoint)
		if e != nil || !reflect.DeepEqual(actual, scope) {
			return ErrInstall
		}
		binding, e := i.originalPublicationActor(ctx, o.ControllerDeployment, o.ControllerPodName)
		if e != nil || binding != actor {
			return ErrInstall
		}
		currentRoot, e := originalPublicationOwnerToken(o.VaultOwnerMaterial, o.VaultOwnerMaterialIsInitJSON)
		defer clear(currentRoot)
		if e != nil || !bytes.Equal(root, currentRoot) || vault.root(ctx, currentRoot) != nil {
			return ErrInstall
		}
		return nil
	}
	// Deterministic dedicated resource coordinates frozen BEFORE any mutation.
	keyName := "sbk-c1-evidence-" + hash([]byte(i.planHash + enrollment.DocumentSHA256))[:24]
	if keyName == original.PinnedKeyName {
		return zero, ErrInstall
	}
	identityRaw, err := canonical(struct{ Provider, Cluster, Installation, Key string }{"vault-transit-evidence", original.ClusterID, i.plan.Target.InstallationID, keyName})
	if err != nil {
		return zero, ErrInstall
	}
	key := ev.KeyRef{Identity: hash(identityRaw), Version: "1"}
	cfg := ev.TransitConfig{Endpoint: original.Endpoint, Installation: i.plan.Target.InstallationID, KeyName: keyName, Key: key, KeyVersion: 1, CAPEM: ca, CASHA256: original.CASHA256}
	roleName := "sbk-c1-wrap-" + hash([]byte(i.planHash + actor.PodUID))[:24]
	audience := "system-backup-c1-evidence-wrap:" + i.plan.Target.InstallationID
	role := a.VaultPermissionRole{AuthMount: original.JWTMount, Role: roleName, Policy: roleName, Audience: audience, Namespace: actor.Namespace, ServiceAccountName: actor.ServiceAccountName, ServiceAccountUID: actor.ServiceAccountUID, PodUID: actor.PodUID}
	acl, err := a.EvidenceVaultRuntimeACL(cfg, ev.TransitWrap)
	if err != nil {
		return zero, ErrInstall
	}
	desiredRole, err := a.VaultJWTAuthRole(role)
	if err != nil {
		return zero, ErrInstall
	}
	desiredTrust, err := a.VaultJWTAuthConfig(trust)
	if err != nil {
		return zero, ErrInstall
	}
	actualTrust, err := vault.data(ctx, "/v1/auth/"+original.JWTMount+"/config", root)
	if err != nil || !originalPublicationSubset(actualTrust, desiredTrust) {
		return zero, ErrInstall
	}
	actualTrust, err = originalPublicationObjectCanonical(actualTrust)
	if err != nil {
		return zero, ErrInstall
	}
	beforeMetadata, err := originalC1VaultMetadata(ctx, vault, root, original.JWTMount, beforeNative)
	if err != nil {
		return zero, ErrInstall
	}
	beforeRaw, err := canonical(beforeMetadata)
	if err != nil {
		return zero, ErrInstall
	}
	beforePin := BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, "c1-provider-metadata.before.json"), SHA256: hash(beforeRaw)}
	intent, err := canonical(struct {
		Version, Plan, Enrollment, Key, Role string
		Options                              OriginalC1EvidenceMaterialOptions
	}{"original-c1-evidence-material-intent.v1", i.planHash, enrollment.DocumentSHA256, keyName, roleName, o})
	if err != nil || auth() != nil || writeNewFiles(o.OutputDirectory, map[string][]byte{"c1-evidence-material.intent.json": intent, "c1-provider-metadata.before.json": beforeRaw}) != nil {
		return zero, ErrInstall
	}
	receipt := OriginalC1EvidenceMaterialReceipt{Version: "original-c1-evidence-material-result.v1", State: "original_provider_write_unconfirmed_no_retry", Key: key}
	keyPath := "/v1/transit/keys/" + keyName
	body, status, err := vault.call(ctx, "GET", keyPath, root, nil)
	clear(body)
	if err != nil {
		return receipt, ErrInstall
	}
	if status == 404 {
		if auth() != nil || writeNewFiles(o.OutputDirectory, map[string][]byte{"c1-key.sent.json": intent}) != nil {
			return receipt, ErrInstall
		}
		response, _, e := vault.call(ctx, "POST", keyPath, root, a.VaultTransitKeyPayload())
		clear(response)
		if e != nil {
			return receipt, ErrInstall
		}
	} else if status != 200 {
		return receipt, ErrInstall
	}
	metadata, err := vault.data(ctx, keyPath, root)
	if err != nil || !originalC1DedicatedKey(metadata, keyName) {
		return receipt, ErrInstall
	}
	if vault.policy(ctx, role.Policy, acl, root, auth) != nil {
		return receipt, ErrInstall
	}
	actualRole, err := vault.role(ctx, role.AuthMount, role.Role, desiredRole, root, auth)
	if err != nil {
		return receipt, ErrInstall
	}
	if auth() != nil {
		return receipt, ErrInstall
	}
	seconds := int64(600)
	token, err := i.kube.CoreV1().ServiceAccounts(actor.Namespace).CreateToken(ctx, actor.ServiceAccountName, &authn.TokenRequest{Spec: authn.TokenRequestSpec{Audiences: []string{audience}, ExpirationSeconds: &seconds, BoundObjectRef: &authn.BoundObjectReference{Kind: "Pod", APIVersion: "v1", Name: actor.PodName, UID: types.UID(actor.PodUID)}}}, metav1.CreateOptions{})
	if err != nil || token.Status.Token == "" || !token.Status.ExpirationTimestamp.After(now) {
		return receipt, ErrInstall
	}
	jwt, err := originalPublicationToken([]byte(token.Status.Token))
	if err != nil {
		return receipt, ErrInstall
	}
	defer clear(jwt)
	jwtFile := filepath.Join(o.OutputDirectory, "c1-evidence-wrap.jwt")
	if writeNewFiles(o.OutputDirectory, map[string][]byte{"c1-evidence-wrap.jwt": jwt}) != nil {
		return receipt, ErrInstall
	}
	until := o.Until
	if token.Status.ExpirationTimestamp.Time.Before(until) {
		until = token.Status.ExpirationTimestamp.Time
	}
	transport := ev.TransitJWTConfig{Transit: cfg, Mount: original.JWTMount, Role: role.Role, Policy: role.Policy, Issuer: trust.Issuer, Audience: audience, Subject: "system:serviceaccount:" + actor.Namespace + ":" + actor.ServiceAccountName, TokenFile: jwtFile}
	if auth() != nil || i.originalC1WrapProbe(ctx, vault, actor, transport, jwt) != nil {
		return receipt, ErrInstall
	}
	finalMetadata, err := vault.data(ctx, keyPath, root)
	if err != nil || !bytes.Equal(finalMetadata, metadata) || auth() != nil || !time.Now().Before(until) {
		return receipt, ErrInstall
	}
	updated := original
	updated.EvidenceWrap = &owner.InstalledVaultEvidenceWrapProfile{Transit: cfg, Role: role}
	updatedObserver, err := owner.NewInstalledVaultDependencyObserver(updated, i.kube, i.plan.Target.Namespace, i.plan.Target.NamespaceUID)
	if err != nil {
		return receipt, ErrInstall
	}
	defer updatedObserver.Close()
	afterObservation, err := updatedObserver.Observe(ctx)
	if err != nil {
		return receipt, ErrInstall
	}
	afterNative, _, err := afterObservation.Data(ctx)
	if err != nil || !originalC1OnlyDedicatedMaterialChanged(beforeNative, afterNative, keyName, roleName) {
		return receipt, ErrInstall
	}
	finalRole, err := vault.data(ctx, "/v1/auth/"+role.AuthMount+"/role/"+role.Role, root)
	if err != nil {
		return receipt, ErrInstall
	}
	finalRole, err = originalPublicationObjectCanonical(finalRole)
	if err != nil || !bytes.Equal(finalRole, actualRole) {
		return receipt, ErrInstall
	}
	finalPolicy, err := vault.data(ctx, "/v1/sys/policies/acl/"+role.Policy, root)
	var policy struct{ Name, Policy string }
	if err != nil || json.Unmarshal(finalPolicy, &policy) != nil || policy.Name != role.Policy || policy.Policy != acl {
		return receipt, ErrInstall
	}
	finalTrust, err := vault.data(ctx, "/v1/auth/"+original.JWTMount+"/config", root)
	if err != nil {
		return receipt, ErrInstall
	}
	finalTrust, err = originalPublicationObjectCanonical(finalTrust)
	if err != nil || !bytes.Equal(finalTrust, actualTrust) || auth() != nil {
		return receipt, ErrInstall
	}
	afterMetadata, err := originalC1VaultMetadata(ctx, vault, root, original.JWTMount, afterNative)
	if err != nil || !originalC1OnlyOwnedMetadataChanged(beforeMetadata, afterMetadata, original.JWTMount, keyName, roleName) {
		return receipt, ErrInstall
	}
	afterRaw, err := canonical(afterMetadata)
	if err != nil {
		return receipt, ErrInstall
	}
	afterPin := BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, "c1-provider-metadata.after.json"), SHA256: hash(afterRaw)}
	updatedRaw, err := canonical(updated)
	if err != nil {
		return receipt, ErrInstall
	}
	updatedPin := BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, "c1-installed-vault-observer.private.json"), SHA256: hash(updatedRaw)}
	selection.PreAdoptionVaultDependencies[0].InstalledObserver = updatedPin
	selectionRaw, err := canonical(selection)
	if err != nil {
		return receipt, ErrInstall
	}
	writerPin := BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, "c1-vault-writer-selection.json"), SHA256: hash(selectionRaw)}
	if auth() != nil || writeNewFiles(o.OutputDirectory, map[string][]byte{"c1-installed-vault-observer.private.json": updatedRaw, "c1-vault-writer-selection.json": selectionRaw, "c1-provider-metadata.after.json": afterRaw}) != nil {
		return receipt, ErrInstall
	}
	material := OriginalC1EvidenceMaterial{Version: "original-c1-evidence-material.v1", PlanSHA256: i.planHash, EnrollmentSHA256: enrollment.DocumentSHA256, Source: o, Binding: actor, ProviderScope: scope, Transit: transport, RuntimeJWT: BootstrapSourceFilePin{File: jwtFile, SHA256: hash(jwt)}, InstalledObserver: updatedPin, WriterSelection: writerPin, BeforeMetadata: beforePin, AfterMetadata: afterPin, KeyMetadataSHA256: hash(metadata), PolicySHA256: hash([]byte(acl)), RoleSHA256: hash(actualRole), JWTTrustSHA256: hash(actualTrust), ObservedAt: time.Now().UTC(), Until: until}
	raw, err = canonical(material)
	if err != nil {
		return receipt, ErrInstall
	}
	signature := ed25519.Sign(issuer, append([]byte(originalC1EvidenceMaterialDomain), raw...))
	if auth() != nil || writeNewFiles(o.OutputDirectory, map[string][]byte{"c1-evidence.material.json": raw, "c1-evidence.material.signature": signature}) != nil {
		return receipt, ErrInstall
	}
	for name, expected := range map[string][]byte{"c1-evidence.material.json": raw, "c1-evidence.material.signature": signature} {
		b, e := ReadPrivateFile(filepath.Join(o.OutputDirectory, name), 262144)
		if e != nil || !bytes.Equal(b, expected) {
			return receipt, ErrInstall
		}
	}
	receipt.State = "original_dedicated_evidence_materials_issued_not_producer_or_adoption"
	receipt.InstalledObserver = updatedPin
	receipt.WriterSelection = writerPin
	receipt.Material = BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, "c1-evidence.material.json"), SHA256: hash(raw)}
	receipt.Signature = BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, "c1-evidence.material.signature"), SHA256: hash(signature)}
	return receipt, nil
}

func originalC1DedicatedKey(raw []byte, name string) bool {
	// Explicit JSON tags for provider snake_case fields; never accept omitted
	// restrictive settings by treating Go zero values as provider observations.
	var data struct {
		Name       string                     `json:"name"`
		Type       string                     `json:"type"`
		Derived    bool                       `json:"derived"`
		Exportable bool                       `json:"exportable"`
		Backup     bool                       `json:"allow_plaintext_backup"`
		Deletion   bool                       `json:"deletion_allowed"`
		Convergent bool                       `json:"convergent_encryption"`
		Latest     int64                      `json:"latest_version"`
		MinEncrypt int64                      `json:"min_encryption_version"`
		MinDecrypt int64                      `json:"min_decryption_version"`
		Keys       map[string]json.RawMessage `json:"keys"`
	}
	valid := originalPublicationFields(raw, "name", "type", "derived", "exportable", "allow_plaintext_backup", "deletion_allowed", "convergent_encryption", "latest_version", "min_encryption_version", "min_decryption_version", "keys") && json.Unmarshal(raw, &data) == nil && data.Name == name && data.Type == "aes256-gcm96" && data.Derived && !data.Exportable && !data.Backup && !data.Deletion && !data.Convergent && data.Latest == 1 && data.MinEncrypt == 0 && data.MinDecrypt == 1 && len(data.Keys) == 1 && len(data.Keys["1"]) > 0
	if !valid {
		return false
	}
	value := bytes.TrimSpace(data.Keys["1"])
	if len(value) == 0 || value[0] < '0' || value[0] > '9' {
		return false
	}
	var timestamp json.Number
	if json.Unmarshal(value, &timestamp) != nil {
		return false
	}
	created, err := timestamp.Int64()
	return err == nil && created > 0
}

// Check all projected pre-existing native keys/roles, allowing ONLY the exact
// original installer-created dedicated key/role addition. Provider physical
// scope is checked separately; whole metadata hashes necessarily change.
func originalC1OnlyDedicatedMaterialChanged(before, after owner.InstalledVaultDependencyData, key, role string) bool {
	strip := func(v owner.InstalledVaultDependencyData) owner.InstalledVaultDependencyData {
		v.MetadataSHA256 = ""
		keys := make([]owner.InstalledVaultKey, 0, len(v.Keys))
		for _, k := range v.Keys {
			if k.Name != key {
				keys = append(keys, k)
			}
		}
		v.Keys = keys
		roles := make([]owner.InstalledVaultRole, 0, len(v.Roles))
		for _, r := range v.Roles {
			if r.Name != role {
				roles = append(roles, r)
			}
		}
		v.Roles = roles
		return v
	}
	return reflect.DeepEqual(strip(before), strip(after))
}
