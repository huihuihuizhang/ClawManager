package install

import (
	"bytes"
	owner "clawreef/internal/systembackupinstallationowner"
	a "clawreef/internal/systembackupkekadapter"
	"context"
	"crypto/ed25519"
	"encoding/json"
	authn "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"path/filepath"
	"reflect"
	"time"
)

// Query never creates/reissues a key, role, policy, token or signed material.
// A lost final reply is recovered ONLY from the exact retained signed files,
// original enrollment/Until, real running Pod and actual native metadata.
// A partial issue is deliberately not completed by guessing missing files.
func (i *Installer) QueryOriginalC1EvidenceMaterial(ctx context.Context, password []byte, enrollment EnrollmentPin, directory string) (OriginalC1EvidenceMaterialReceipt, error) {
	var zero OriginalC1EvidenceMaterialReceipt
	if i == nil || ctx == nil || ctx.Err() != nil || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	op, err := i.authenticate(ctx, password)
	if err != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	state, now, err := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if err != nil || state.cas != (HeadCAS{}) {
		return zero, ErrInstall
	}
	raw, err := ReadPrivateFile(filepath.Join(directory, "c1-evidence.material.json"), 262144)
	if err != nil {
		return OriginalC1EvidenceMaterialReceipt{Version: "original-c1-evidence-material-result.v1", State: "original_partial_materials_no_reissue_retain_intent_and_sent_files"}, ErrInstall
	}
	signature, err := ReadPrivateFile(filepath.Join(directory, "c1-evidence.material.signature"), 64)
	var m OriginalC1EvidenceMaterial
	if err != nil || !ed25519.Verify(i.public, append([]byte(originalC1EvidenceMaterialDomain), raw...), signature) || decodeExact(raw, &m) != nil || m.Version != "original-c1-evidence-material.v1" || m.PlanSHA256 != i.planHash || m.EnrollmentSHA256 != enrollment.DocumentSHA256 || m.Source.OutputDirectory != directory || !now.Before(m.Until) || m.Until.After(m.Source.Until) || now.Before(m.ObservedAt) {
		return zero, ErrInstall
	}
	actor, err := i.originalPublicationActor(ctx, m.Source.ControllerDeployment, m.Source.ControllerPodName)
	if err != nil || actor != m.Binding {
		return zero, ErrInstall
	}
	for _, pin := range []BootstrapSourceFilePin{m.Source.WriterSelection, m.InstalledObserver, m.WriterSelection, m.RuntimeJWT, m.BeforeMetadata, m.AfterMetadata} {
		b, e := readBootstrapSourcePin(pin, 262144)
		clear(b)
		if e != nil {
			return zero, ErrInstall
		}
	}
	cfgRaw, err := readBootstrapSourcePin(m.InstalledObserver, 262144)
	var cfg owner.InstalledVaultDependencyConfig
	if err != nil || decodeExact(cfgRaw, &cfg) != nil || cfg.EvidenceWrap == nil || !reflect.DeepEqual(cfg.EvidenceWrap.Transit, m.Transit.Transit) || cfg.EvidenceWrap.Role.Role != m.Transit.Role || cfg.EvidenceWrap.Role.Policy != m.Transit.Policy || cfg.EvidenceWrap.Role.Audience != m.Transit.Audience || cfg.EvidenceWrap.Role.PodUID != actor.PodUID {
		return zero, ErrInstall
	}
	selectedRaw, err := readBootstrapSourcePin(m.WriterSelection, 262144)
	var selection OriginalWriterSetSelection
	if err != nil || decodeExact(selectedRaw, &selection) != nil || len(selection.PreAdoptionVaultDependencies) != 1 || selection.PreAdoptionVaultDependencies[0].InstalledObserver != m.InstalledObserver {
		return zero, ErrInstall
	}
	scope, err := ObserveInstalledVaultProviderScope(ctx, i.db, i.kube, i.plan.Target, selection.PreAdoptionVaultDependencies[0].Workload, cfg.Endpoint)
	if err != nil || !reflect.DeepEqual(scope, m.ProviderScope) {
		return zero, ErrInstall
	}
	observer, err := owner.NewInstalledVaultDependencyObserver(cfg, i.kube, i.plan.Target.Namespace, i.plan.Target.NamespaceUID)
	if err != nil {
		return zero, ErrInstall
	}
	defer observer.Close()
	observation, err := observer.Observe(ctx)
	if err != nil {
		return zero, ErrInstall
	}
	if _, _, err = observation.Data(ctx); err != nil {
		return zero, ErrInstall
	}
	root, err := originalPublicationOwnerToken(m.Source.VaultOwnerMaterial, m.Source.VaultOwnerMaterialIsInitJSON)
	if err != nil {
		return zero, ErrInstall
	}
	defer clear(root)
	v, err := newOriginalPublicationVault(cfg.Endpoint, cfg.CAPEM, cfg.CASHA256)
	if err != nil {
		return zero, ErrInstall
	}
	defer v.close()
	if v.root(ctx, root) != nil || v.health(ctx, cfg.ClusterID) != nil {
		return zero, ErrInstall
	}
	metadata, err := v.data(ctx, "/v1/transit/keys/"+m.Transit.Transit.KeyName, root)
	if err != nil || !originalC1DedicatedKey(metadata, m.Transit.Transit.KeyName) || hash(metadata) != m.KeyMetadataSHA256 {
		return zero, ErrInstall
	}
	policyRaw, err := v.data(ctx, "/v1/sys/policies/acl/"+m.Transit.Policy, root)
	var policy struct{ Name, Policy string }
	acl, ae := a.EvidenceVaultRuntimeACL(m.Transit.Transit, "evidence_dek_wrap")
	if err != nil || ae != nil || json.Unmarshal(policyRaw, &policy) != nil || policy.Name != m.Transit.Policy || policy.Policy != acl || hash([]byte(acl)) != m.PolicySHA256 {
		return zero, ErrInstall
	}
	roleRaw, err := v.data(ctx, "/v1/auth/"+m.Transit.Mount+"/role/"+m.Transit.Role, root)
	if err != nil {
		return zero, ErrInstall
	}
	roleRaw, err = originalPublicationObjectCanonical(roleRaw)
	if err != nil || hash(roleRaw) != m.RoleSHA256 {
		return zero, ErrInstall
	}
	trustRaw, err := v.data(ctx, "/v1/auth/"+m.Transit.Mount+"/config", root)
	if err != nil {
		return zero, ErrInstall
	}
	trustRaw, err = originalPublicationObjectCanonical(trustRaw)
	if err != nil || hash(trustRaw) != m.JWTTrustSHA256 {
		return zero, ErrInstall
	}
	jwt, err := readBootstrapSourcePin(m.RuntimeJWT, 16384)
	if err != nil {
		return zero, ErrInstall
	}
	defer clear(jwt)
	tr, err := i.kube.AuthenticationV1().TokenReviews().Create(ctx, &authn.TokenReview{Spec: authn.TokenReviewSpec{Token: string(jwt), Audiences: []string{m.Transit.Audience}}}, metav1.CreateOptions{})
	if err != nil || !tr.Status.Authenticated || tr.Status.Error != "" || tr.Status.User.Username != m.Transit.Subject || tr.Status.User.UID != actor.ServiceAccountUID || !reflect.DeepEqual(tr.Status.Audiences, []string{m.Transit.Audience}) || !reflect.DeepEqual([]string(tr.Status.User.Extra["authentication.kubernetes.io/pod-uid"]), []string{actor.PodUID}) {
		return zero, ErrInstall
	}
	if op.authority(ctx, enrollment) != nil || !time.Now().Before(m.Until) {
		return zero, ErrInstall
	}
	current, _, err := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if err != nil || current.cas != state.cas {
		return zero, ErrInstall
	}
	check, err := ReadPrivateFile(filepath.Join(directory, "c1-evidence.material.json"), 262144)
	if err != nil || !bytes.Equal(check, raw) {
		return zero, ErrInstall
	}
	return OriginalC1EvidenceMaterialReceipt{Version: "original-c1-evidence-material-result.v1", State: "original_dedicated_evidence_materials_current_original_files_verified", Key: m.Transit.Transit.Key, Material: BootstrapSourceFilePin{File: filepath.Join(directory, "c1-evidence.material.json"), SHA256: hash(raw)}, Signature: BootstrapSourceFilePin{File: filepath.Join(directory, "c1-evidence.material.signature"), SHA256: hash(signature)}, InstalledObserver: m.InstalledObserver, WriterSelection: m.WriterSelection}, nil
}
