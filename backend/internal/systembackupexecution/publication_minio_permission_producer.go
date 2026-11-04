package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"sort"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	"k8s.io/client-go/kubernetes"
)

type MinIOPermissionPolicyPlan struct {
	Purpose, PolicyName, NormalizedPolicySHA256 string
	Policy                                      json.RawMessage
}
type minioPermissionProductionInputs struct {
	definition    install.MinIOPermissionDefinition
	configuration minioPermissionConfiguration
	grant         minioPermissionGrant
	target        PublicationTargetMaterials
	catalog       PublicationCatalogMaterials
	uses          []minioPermissionUse
	observer      nativePublicationCredential
	window        publicationDependencyWindow
}

func (p *minioPermissionProductionInputs) clear() {
	for i := range p.uses {
		p.uses[i].credential = nativePublicationCredential{}
	}
	p.observer = nativePublicationCredential{}
}

func readMinIOPermissionProductionInputs(file, sha string) (*minioPermissionProductionInputs, error) {
	raw, err := install.ReadSourceMaterialFile(file)
	if err != nil {
		return nil, minioPermissionFailure("producer-original-definition")
	}
	d, err := install.DecodeMinIOPermissionDefinition(raw, sha)
	if err != nil {
		return nil, minioPermissionFailure("producer-original-definition")
	}
	p := &minioPermissionProductionInputs{definition: d}
	g, err := ce.Canonical(d.Grant)
	if err != nil || decodePublicationCanonical(g, &p.grant) != nil {
		return nil, minioPermissionFailure("producer-original-grant")
	}
	profile, ok := minioNativeProfile(p.grant.Profile)
	if !ok {
		return nil, minioPermissionFailure("producer-native-profile")
	}
	raw, err = pinnedDeploymentFile(d.ConfigFile, d.ConfigSHA256, 262144)
	if err != nil || len(raw) == 0 {
		return nil, minioPermissionFailure("producer-original-config")
	}
	raw, err = pinnedDeploymentFile(d.TargetFile, d.TargetSHA256, 65536)
	if err != nil || decodeProviderDeploymentJSON(raw, &p.target) != nil || p.target.validate() != nil || p.target.InstallationID != d.Grant.Installation || p.target.Root != d.Grant.Installation+"/" || p.target.RemoteStagingRoot == "" {
		return nil, minioPermissionFailure("producer-original-target")
	}
	p.catalog, err = loadPinnedPublicationCatalog(p.target)
	if err != nil {
		return nil, err
	}
	// Catalog roots are under Installation/, also the artifact root. Distinct
	// buckets are required to prevent artifact PutObject from covering catalog.
	if p.catalog.Bucket == p.target.Bucket {
		return nil, minioPermissionFailure("producer-distinct-catalog-bucket")
	}
	provider := p.grant.Provider
	if provider.Endpoint != p.target.Endpoint || provider.Endpoint != p.catalog.Endpoint || provider.Region != p.target.Region || provider.Region != p.catalog.Region || provider.CASHA256 != p.target.CASHA256 || provider.CASHA256 != p.catalog.CASHA256 {
		return nil, minioPermissionFailure("producer-original-provider")
	}
	p.configuration = minioPermissionConfiguration{Version: profile.Source, Installation: d.Grant.Installation, Namespace: d.Grant.Namespace, NamespaceUID: d.Grant.NamespaceUID, MinimumEpoch: 1, ObserverCredentialFile: d.ObserverCredentialFile, ObserverCredentialSHA256: d.ObserverCredentialSHA256, ObserverAccountSHA256: d.ObserverAccountSHA256, ObserverPolicyName: d.ObserverPolicyName, ObserverPolicySHA256: d.ObserverPolicySHA256}
	if p.window.include(time.Now(), d.Grant.NotBefore, d.Grant.Until) != nil {
		return nil, minioPermissionFailure("producer-original-window")
	}
	r := &MinIOPublicationPermissionReader{configuration: p.configuration}
	p.uses, err = r.originalUses(time.Now(), p.grant, p.target, p.catalog, &p.window)
	if err != nil {
		p.clear()
		return nil, err
	}
	p.observer, err = loadNativePublicationCredential(d.ObserverCredentialFile, d.ObserverCredentialSHA256)
	if err != nil || p.observer.SessionToken != "" || hash([]byte(p.observer.AccessKey)) != d.ObserverAccountSHA256 || p.window.include(time.Now(), p.observer.NotBefore, p.observer.Until) != nil {
		p.clear()
		return nil, minioPermissionFailure("producer-original-observer")
	}
	return p, nil
}

func minioPermissionObserverRulesV2(uses []minioPermissionUse) []minioPermissionRule {
	seen := map[string]bool{}
	for _, u := range uses {
		seen[u.bucket] = true
	}
	arns := []string{}
	for bucket := range seen {
		arns = append(arns, "arn:aws:s3:::"+bucket)
	}
	sort.Strings(arns)
	return []minioPermissionRule{{[]string{"admin:GetUser", "admin:GetPolicy", "admin:ServerInfo"}, []string{"*"}}, {[]string{"s3:GetBucketPolicy", "s3:GetBucketVersioning"}, arns}}
}

// Pure local policy rendering. These are exact requested policies, not an
// existence, successful installation or effective-permission observation.
// Policies use no IDs/Sids/conditions; normalized pins survive native set order.
func PlanOriginalMinIOPermissionPolicies(file, sha string) ([]MinIOPermissionPolicyPlan, error) {
	p, err := readMinIOPermissionProductionInputs(file, sha)
	if err != nil {
		return nil, err
	}
	defer p.clear()
	out := []MinIOPermissionPolicyPlan{}
	appendPolicy := func(purpose, name string, rules []minioPermissionRule) error {
		statements := []map[string]any{}
		for _, rule := range rules {
			actions, resources := append([]string(nil), rule.Actions...), append([]string(nil), rule.Resources...)
			sort.Strings(actions)
			sort.Strings(resources)
			statements = append(statements, map[string]any{"Effect": "Allow", "Action": actions, "Resource": resources})
		}
		sort.Slice(statements, func(i, j int) bool {
			a, _ := ce.Canonical(statements[i])
			b, _ := ce.Canonical(statements[j])
			return bytes.Compare(a, b) < 0
		})
		raw, e := ce.Canonical(map[string]any{"Version": "2012-10-17", "Statement": statements})
		if e != nil {
			return e
		}
		out = append(out, MinIOPermissionPolicyPlan{purpose, name, hash(raw), raw})
		return nil
	}
	for _, u := range p.uses {
		rules, e := minioPermissionObjectRulesV2(u.principal.Purpose, u.bucket, u.root, u.staging)
		if e != nil {
			return nil, e
		}
		if e = appendPolicy(u.principal.Purpose, u.principal.PolicyName, rules); e != nil {
			return nil, e
		}
	}
	if err = appendPolicy("observer", p.configuration.ObserverPolicyName, minioPermissionObserverRulesV2(p.uses)); err != nil {
		return nil, err
	}
	return out, nil
}

type MinIOOriginalPermissionObservation struct {
	Version, DefinitionSHA256, Profile, ServerVersion, ServerCommit string
	CheckedAt, NotBefore, Until                                     time.Time
	NativeSourcesSHA256, ResourcesSHA256                            string
}

func observeOriginalMinIOPermissions(ctx context.Context, kube kubernetes.Interface, p *minioPermissionProductionInputs, sha string) (MinIOOriginalPermissionObservation, error) {
	return observeOriginalMinIOPermissionsWithRecovery(ctx, kube, p, sha, nil)
}
func observeOriginalMinIOPermissionsWithRecovery(ctx context.Context, kube kubernetes.Interface, p *minioPermissionProductionInputs, sha string, recovery *minioRecoverySession) (MinIOOriginalPermissionObservation, error) {
	var zero MinIOOriginalPermissionObservation
	if p == nil {
		return zero, minioPermissionFailure("producer-native-profile")
	}
	profile, ok := minioNativeProfile(p.grant.Profile)
	if !ok || ctx == nil || ctx.Err() != nil || kube == nil {
		return zero, minioPermissionFailure("producer-original-context")
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if recovery != nil {
		var bounded context.CancelFunc
		ctx, bounded = context.WithDeadline(ctx, recovery.until)
		defer bounded()
	}
	ctx, stop := context.WithDeadline(ctx, p.window.until)
	defer stop()
	resource, err := minioCurrentRecoveryResources(ctx, kube, p.configuration, p.grant.Provider, recovery)
	if err != nil {
		return zero, err
	}
	native, err := newMinioPermissionHTTP(p.grant.Provider, p.observer)
	if err != nil {
		return zero, err
	}
	defer native.close()
	first, err := native.collectNativeProfile(ctx, p.configuration, p.uses, p.grant.Profile)
	if err != nil {
		return zero, err
	}
	guard, err := minioEffectiveGuardAllV2(ctx, p.grant.Provider, p.configuration, p.uses, p.observer)
	if err != nil {
		return zero, err
	}
	tailGuard, err := minioEffectiveGuardAllV2(ctx, p.grant.Provider, p.configuration, p.uses, p.observer)
	if err != nil || tailGuard != guard {
		return zero, minioPermissionFailure("producer-effective-tail-drift")
	}
	tail, err := native.collectNativeProfile(ctx, p.configuration, p.uses, p.grant.Profile)
	if err != nil || tail != first {
		return zero, minioPermissionFailure("producer-native-tail-drift")
	}
	tailResource, err := minioCurrentRecoveryResources(ctx, kube, p.configuration, p.grant.Provider, recovery)
	if err != nil || tailResource != resource || !time.Now().Before(p.window.until) || ctx.Err() != nil {
		return zero, minioPermissionFailure("producer-resource-tail-drift")
	}
	return MinIOOriginalPermissionObservation{"original-minio-current-source-observation.v2", sha, profile.Permission, profile.ServerVersion, profile.ServerCommit, time.Now().UTC(), p.window.notBefore, p.window.until, hash([]byte(first + "/" + guard)), resource}, nil
}

// Reads the six actual credentials, current named/effective policies, owner
// predicate, exact running release, both buckets and original Kubernetes UIDs.
// It creates no accounts/policies/records and signs nothing.
func ObserveOriginalMinIOPermissions(ctx context.Context, kube kubernetes.Interface, file, sha string) (MinIOOriginalPermissionObservation, error) {
	p, err := readMinIOPermissionProductionInputs(file, sha)
	if err != nil {
		return MinIOOriginalPermissionObservation{}, err
	}
	defer p.clear()
	observed, err := observeOriginalMinIOPermissions(ctx, kube, p, sha)
	if err != nil {
		return MinIOOriginalPermissionObservation{}, err
	}
	tail, err := readMinIOPermissionProductionInputs(file, sha)
	if err != nil {
		return MinIOOriginalPermissionObservation{}, err
	}
	tail.clear()
	return observed, nil
}

type MinIOPermissionProductionReceipt struct {
	Version, File, SHA256, DefinitionSHA256, GrantSHA256, HeadSHA256 string
	GrantUID, HeadUID                                                string
	Epoch                                                            uint64
}

// Offline owner-only producer. Existing authenticated enrollment plus the
// existing private key issue declarations; real native GETs supply evidence.
// No credentials/users/policies are created here. It never mounts a private
// signing key into the controller or substitutes a task-generated trust pin.
func ProduceOriginalMinIOPermissionSource(ctx context.Context, owner *install.Installer, kube kubernetes.Interface, password []byte, enrollment install.EnrollmentPin, file, sha, keyFile, directory string) (MinIOPermissionProductionReceipt, error) {
	var zero MinIOPermissionProductionReceipt
	if ctx == nil || owner == nil || kube == nil || ctx.Err() != nil {
		return zero, minioPermissionFailure("producer-context")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, minioPermissionFailure("producer-bounded-context")
	}
	if install.CheckNewMinIOPermissionDirectory(directory) != nil {
		return zero, minioPermissionFailure("producer-new-private-output")
	}
	issuer, err := owner.PrepareMinIOPermissionIssue(ctx, password, enrollment, file, sha)
	if err != nil {
		return zero, err
	}
	p, err := readMinIOPermissionProductionInputs(file, sha)
	if err != nil {
		return zero, err
	}
	defer p.clear()
	first, err := observeOriginalMinIOPermissions(ctx, kube, p, sha)
	if err != nil {
		return zero, err
	}
	key, err := install.ReadPrivateFile(keyFile, ed25519.PrivateKeySize)
	if err != nil {
		return zero, minioPermissionFailure("producer-existing-key")
	}
	defer clear(key)
	if issuer.Recheck(ctx) != nil {
		return zero, minioPermissionFailure("producer-owner-before-commit")
	}
	committed, err := issuer.CreateOriginal(ctx, key)
	if err != nil {
		return zero, err
	}
	// Reopen all actual credential/target/catalog/definition files after commit.
	lastInputs, err := readMinIOPermissionProductionInputs(file, sha)
	if err != nil {
		return zero, install.ErrCommitUnknown
	}
	defer lastInputs.clear()
	last, err := observeOriginalMinIOPermissions(ctx, kube, lastInputs, sha)
	if err != nil || first.NativeSourcesSHA256 != last.NativeSourcesSHA256 || first.ResourcesSHA256 != last.ResourcesSHA256 || issuer.Recheck(ctx) != nil {
		return zero, install.ErrCommitUnknown
	}
	d := p.definition
	profile, ok := minioNativeProfile(p.grant.Profile)
	if !ok {
		return zero, install.ErrCommitUnknown
	}
	cfg := minioEffectivePermissionConfiguration{Version: profile.Source, Installation: d.Grant.Installation, Namespace: d.Grant.Namespace, NamespaceUID: d.Grant.NamespaceUID, Issuer: committed.Issuer, MinimumEpoch: committed.Epoch, Grant: minioPermissionObject{Name: committed.Grant.Name, UID: committed.Grant.UID}, Head: minioPermissionObject{Name: committed.Head.Name, UID: committed.Head.UID}, GrantSHA256: committed.GrantSHA256, ObserverCredentialFile: d.ObserverCredentialFile, ObserverCredentialSHA256: d.ObserverCredentialSHA256, ObserverAccountSHA256: d.ObserverAccountSHA256, ObserverPolicyName: d.ObserverPolicyName, ObserverPolicySHA256: d.ObserverPolicySHA256}
	raw, err := ce.Canonical(cfg)
	if err != nil || install.SaveMinIOPermissionStartup(directory, raw) != nil {
		return zero, install.ErrCommitUnknown
	}
	path := filepath.Join(directory, "minio-permission.source.json")
	r, err := newMinIOProfilePermissionReader(MinIOPublicationPermissionInput{path, hash(raw)}, p.grant.Profile)
	if err != nil {
		return zero, install.ErrCommitUnknown
	}
	if _, err = minioCurrentProfileOwner(r, p.grant.Profile, ctx, kube, time.Now()); err != nil {
		return zero, install.ErrCommitUnknown
	}
	return MinIOPermissionProductionReceipt{"original-minio-permission-source-installed.v2", path, hash(raw), sha, committed.GrantSHA256, committed.HeadSHA256, committed.Grant.UID, committed.Head.UID, committed.Epoch}, nil
}
