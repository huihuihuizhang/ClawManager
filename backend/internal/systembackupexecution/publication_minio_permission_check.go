package systembackupexecution

import (
	"context"
	"errors"
	"time"
)

// This proof is constructed only by actual original-owner/Kube/native reads.
// It is not a serialized API proof, task permission or provider-use grant.
type MinIOPublicationPermissionObservation struct {
	checkedAt, notBefore, until             time.Time
	configuration, owner, resources, native string
}

func (o MinIOPublicationPermissionObservation) CheckedAt() time.Time  { return o.checkedAt }
func (o MinIOPublicationPermissionObservation) ValidUntil() time.Time { return o.until }
func (MinIOPublicationPermissionObservation) MarshalJSON() ([]byte, error) {
	return nil, minioPermissionFailure("nonserializable-observation")
}

func (r *MinIOPublicationPermissionReader) CheckCurrent(ctx context.Context, s *DeploymentService) (MinIOPublicationPermissionObservation, error) {
	var zero MinIOPublicationPermissionObservation
	if ctx == nil || ctx.Err() != nil || r == nil || s == nil || s.Runtime == nil || s.Runtime.Owner == nil || s.Forward == nil || s.publisherVerifierDB == nil || r.configuration.Installation != s.Config.InstallationID || r.configuration.Namespace != s.Config.Namespace || r.configuration.NamespaceUID != s.Config.NamespaceUID {
		return zero, minioPermissionFailure("current-composition")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if s.Forward.CheckDeployment(ctx, s.publisherVerifierDB) != nil || s.publicationBinding() != nil {
		return zero, minioPermissionFailure("current-original-deployment")
	}
	store, err := s.publicationStore(ctx)
	if err != nil {
		return zero, err
	}
	defer store.Close()
	catalog, err := s.currentPublicationCatalog(ctx)
	if err != nil {
		return zero, err
	}
	current, err := s.readPublicationDependencySQL(ctx, &store.config, &catalog)
	if err != nil {
		return zero, err
	}
	owner, err := r.originalOwner(ctx, s.Runtime.Owner.Client, current.now)
	if err != nil {
		return zero, err
	}
	if owner.grant.ConfigSHA256 != current.identity.configSHA || owner.grant.Provider.Endpoint != store.config.Endpoint || owner.grant.Provider.Endpoint != catalog.Endpoint || owner.grant.Provider.Region != store.config.Region || owner.grant.Provider.Region != catalog.Region || owner.grant.Provider.CASHA256 != store.config.CASHA256 || owner.grant.Provider.CASHA256 != catalog.CASHA256 {
		return zero, minioPermissionFailure("original-target-config-binding")
	}
	window := owner.window
	if window.include(current.now, current.window.notBefore, current.window.until) != nil {
		return zero, minioPermissionFailure("current-original-window")
	}
	uses, err := r.originalUses(current.now, owner.grant, store.config, catalog, &window)
	if err != nil {
		return zero, err
	}
	defer func() {
		for i := range uses {
			uses[i].credential = nativePublicationCredential{}
		}
	}()
	credential, err := loadNativePublicationCredential(r.configuration.ObserverCredentialFile, r.configuration.ObserverCredentialSHA256)
	if err != nil || hash([]byte(credential.AccessKey)) != r.configuration.ObserverAccountSHA256 || credential.SessionToken != "" || window.include(current.now, credential.NotBefore, credential.Until) != nil {
		return zero, minioPermissionFailure("original-observer-credential")
	}
	callCtx, stop := context.WithDeadline(ctx, window.until)
	defer stop()
	native, err := newMinioPermissionHTTP(owner.grant.Provider, credential)
	credential = nativePublicationCredential{}
	if err != nil {
		return zero, err
	}
	defer native.close()
	resources, err := minioPermissionKubernetes(callCtx, s.Runtime.Owner.Client, r.configuration, owner.grant.Provider)
	if err != nil {
		return zero, err
	}
	first, err := native.collect(callCtx, r.configuration, uses)
	if err != nil {
		return zero, err
	}
	last, err := native.collect(callCtx, r.configuration, uses)
	if err != nil {
		return zero, err
	}
	if first != last {
		return zero, minioPermissionFailure("native-tail-drift")
	}
	lastResources, err := minioPermissionKubernetes(callCtx, s.Runtime.Owner.Client, r.configuration, owner.grant.Provider)
	if err != nil || lastResources != resources {
		return zero, minioPermissionFailure("resource-tail-drift")
	}
	tail, err := s.readPublicationDependencySQL(callCtx, &store.config, &catalog)
	if err != nil {
		return zero, err
	}
	if tail.identity != current.identity || tail.now.Before(current.now) {
		return zero, minioPermissionFailure("current-sql-tail-drift")
	}
	lastOwner, err := r.originalOwner(callCtx, s.Runtime.Owner.Client, tail.now)
	if err != nil || lastOwner.stamp != owner.stamp {
		return zero, minioPermissionFailure("owner-tail-drift")
	}
	// Re-open every original credential; removal/replacement/expiry refuses.
	if _, err = r.originalUses(tail.now, lastOwner.grant, store.config, catalog, &window); err != nil {
		return zero, err
	}
	credential, err = loadNativePublicationCredential(r.configuration.ObserverCredentialFile, r.configuration.ObserverCredentialSHA256)
	if err != nil || window.include(tail.now, credential.NotBefore, credential.Until) != nil {
		return zero, minioPermissionFailure("observer-tail-drift")
	}
	credential = nativePublicationCredential{}
	if window.include(tail.now, tail.window.notBefore, tail.window.until) != nil || !tail.now.Before(window.until) || !time.Now().Before(window.until) || callCtx.Err() != nil {
		return zero, minioPermissionFailure("original-window-expired")
	}
	// These real source reads establish a bounded configuration observation.
	// They do not supply a complete native runtime/effective-policy oracle.
	return MinIOPublicationPermissionObservation{checkedAt: tail.now, notBefore: window.notBefore, until: window.until, configuration: r.input.SHA256, owner: owner.stamp, resources: resources, native: first}, minioPermissionFailure("native-effective-policy-engine-runtime-unavailable")
}

func (r *MinIOPublicationPermissionReader) originalUses(now time.Time, g minioPermissionGrant, target PublicationTargetMaterials, catalog PublicationCatalogMaterials, window *publicationDependencyWindow) ([]minioPermissionUse, error) {
	if len(g.Principals) != 5 {
		return nil, minioPermissionFailure("complete-five-principals")
	}
	expected := []struct{ purpose, identity, version, file, sha, bucket, root, staging string }{
		{"artifact_read", target.ReadIdentityHash, target.ReadRefVersion, target.ReadCredentialFile, target.ReadCredentialSHA256, target.Bucket, target.Root, target.RemoteStagingRoot},
		{"artifact_write", target.WriteIdentityHash, target.WriteRefVersion, target.WriteCredentialFile, target.WriteCredentialSHA256, target.Bucket, target.Root, target.RemoteStagingRoot},
		{"artifact_delete", target.DeleteIdentityHash, target.DeleteRefVersion, target.DeleteCredentialFile, target.DeleteCredentialSHA256, target.Bucket, target.Root, target.RemoteStagingRoot},
		{"catalog_read", catalog.ReadIdentityHash, catalog.ReadRefVersion, catalog.ReadCredentialFile, catalog.ReadCredentialSHA256, catalog.Bucket, catalog.Root, ""},
		{"catalog_append", catalog.AppendIdentityHash, catalog.AppendRefVersion, catalog.AppendCredentialFile, catalog.AppendCredentialSHA256, catalog.Bucket, catalog.Root, ""},
	}
	byPurpose := map[string]minioPermissionPrincipal{}
	accounts := map[string]bool{}
	for _, p := range g.Principals {
		if byPurpose[p.Purpose].Purpose != "" || !formalCandidateDigest(p.AccountSHA256) || !formalCandidateDigest(p.PolicySHA256) || !minioPermissionName(p.PolicyName) || accounts[p.AccountSHA256] || p.AccountSHA256 == r.configuration.ObserverAccountSHA256 {
			return nil, minioPermissionFailure("original-principal-separation")
		}
		byPurpose[p.Purpose] = p
		accounts[p.AccountSHA256] = true
	}
	out := []minioPermissionUse{}
	for _, e := range expected {
		p := byPurpose[e.purpose]
		if p.Purpose != e.purpose || p.IdentityHash != e.identity || p.RefVersion != e.version {
			return nil, minioPermissionFailure("original-principal-reference")
		}
		credential, err := loadNativePublicationCredential(e.file, e.sha)
		if err != nil || credential.SessionToken != "" || hash([]byte(credential.AccessKey)) != p.AccountSHA256 || window.include(now, credential.NotBefore, credential.Until) != nil {
			return nil, minioPermissionFailure("original-principal-credential")
		}
		out = append(out, minioPermissionUse{p, credential, e.bucket, e.root, e.staging})
	}
	return out, nil
}

// Explicit new entry; the frozen C5 and publication loop remain unchanged.
// D may select this only after independent owner source installation. A missing
// C5 dependency other than the known provider source is never excused.
func (s *DeploymentService) CheckPublicationDependenciesWithMinIO(ctx context.Context, input MinIOPublicationPermissionInput) (PublicationDependencyObservation, error) {
	base, err := s.CheckPublicationDependencies(ctx)
	if err != nil && !errors.Is(err, ErrPublicationProviderPermissionObservationMissing) {
		return PublicationDependencyObservation{}, err
	}
	if base.checkedAt.IsZero() {
		return PublicationDependencyObservation{}, minioPermissionFailure("base-dependency-observation")
	}
	r, err := NewMinIOPublicationPermissionReader(input)
	if err != nil {
		return PublicationDependencyObservation{}, err
	}
	observed, err := r.CheckCurrent(ctx, s)
	if err != nil {
		return PublicationDependencyObservation{}, err
	}
	window := publicationDependencyWindow{base.notBefore, base.until}
	if observed.checkedAt.Before(base.checkedAt) || window.include(observed.checkedAt, observed.notBefore, observed.until) != nil || !observed.checkedAt.Before(window.until) {
		return PublicationDependencyObservation{}, minioPermissionFailure("combined-original-window")
	}
	return PublicationDependencyObservation{checkedAt: observed.checkedAt, notBefore: window.notBefore, until: window.until}, nil
}
