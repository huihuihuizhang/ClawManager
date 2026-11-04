package systembackupexecution

import (
	"context"
	"errors"
	"time"
)

// Explicit September source candidate. Existing April sources and
// C5/main-loop wiring remain unchanged. Exact live version/image compatibility remains
// a prerequisite. This returns only a private bounded source observation, not
// permission to publish a task or a guarantee of future S3 operation success.
func (r *MinIOPublicationPermissionReader) CheckCurrentEffectiveSeptember(ctx context.Context, s *DeploymentService) (MinIOPublicationPermissionObservation, error) {
	var zero MinIOPublicationPermissionObservation
	if ctx == nil || ctx.Err() != nil || r == nil || s == nil || s.Runtime == nil || s.Runtime.Owner == nil || s.Forward == nil || s.publisherVerifierDB == nil || r.configuration.Installation != s.Config.InstallationID || r.configuration.Namespace != s.Config.Namespace || r.configuration.NamespaceUID != s.Config.NamespaceUID {
		return zero, minioPermissionFailure("effective-current-composition")
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if s.Forward.CheckDeployment(ctx, s.publisherVerifierDB) != nil || s.publicationBinding() != nil {
		return zero, minioPermissionFailure("effective-current-original-deployment")
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
	if catalog.Bucket == store.config.Bucket {
		return zero, minioPermissionFailure("v2-distinct-catalog-bucket")
	}
	current, err := s.readPublicationDependencySQL(ctx, &store.config, &catalog)
	if err != nil {
		return zero, err
	}
	owner, err := r.effectiveOwnerSeptember(ctx, s.Runtime.Owner.Client, current.now)
	if err != nil {
		return zero, err
	}
	recovery, err := prepareMinIORecoverySession(ctx, s.publisherVerifierDB, s.runtimeReadinessRecovery, r.input)
	if err != nil {
		return zero, err
	}
	lineage, err := s.readOriginalMinIOEnableLineage(ctx, recovery, owner.grant.ConfigSHA256, current.identity.version, current.identity.configSHA)
	if err != nil {
		return zero, err
	}
	p := owner.grant.Provider
	if (owner.grant.ConfigSHA256 != current.identity.configSHA && lineage == "") || p.Endpoint != store.config.Endpoint || p.Endpoint != catalog.Endpoint || p.Region != store.config.Region || p.Region != catalog.Region || p.CASHA256 != store.config.CASHA256 || p.CASHA256 != catalog.CASHA256 {
		return zero, minioPermissionFailure("effective-original-target-config")
	}
	window := owner.window
	if recovery != nil {
		record, e := recovery.proof.Record()
		if e != nil || window.include(current.now, record.NotBefore, record.Until) != nil {
			return zero, minioPermissionFailure("recovery-original-window")
		}
	}
	if window.include(current.now, current.window.notBefore, current.window.until) != nil {
		return zero, minioPermissionFailure("effective-original-window")
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
		return zero, minioPermissionFailure("effective-original-observer")
	}
	ctx, stop := context.WithDeadline(ctx, window.until)
	defer stop()
	native, err := newMinioPermissionHTTP(p, credential)
	credential = nativePublicationCredential{}
	if err != nil {
		return zero, err
	}
	defer native.close()
	resources, err := minioCurrentRecoveryResources(ctx, s.Runtime.Owner.Client, r.configuration, p, recovery)
	if err != nil {
		return zero, err
	}
	// Each full pass brackets actual self policy with original observer source
	// reads. These bind enabled regular-user status, exact original mappings,
	// named policy hash, bucket policy/versioning and exact upstream version.
	first, err := native.collectSeptember(ctx, r.configuration, uses)
	if err != nil {
		return zero, err
	}
	// Paired native self-policy and forbidden-help GETs cover ALL six accounts.
	selfFirst, err := minioEffectiveGuardAllV2(ctx, p, r.configuration, uses, native.credential)
	if err != nil {
		return zero, err
	}
	selfLast, err := minioEffectiveGuardAllV2(ctx, p, r.configuration, uses, native.credential)
	if err != nil || selfLast != selfFirst {
		return zero, minioPermissionFailure("v2-effective-owner-guard-tail-drift")
	}
	last, err := native.collectSeptember(ctx, r.configuration, uses)
	if err != nil || last != first {
		return zero, minioPermissionFailure("effective-native-tail-drift")
	}
	lastResources, err := minioCurrentRecoveryResources(ctx, s.Runtime.Owner.Client, r.configuration, p, recovery)
	if err != nil || lastResources != resources {
		return zero, minioPermissionFailure("effective-process-resource-tail-drift")
	}
	tail, err := s.readPublicationDependencySQL(ctx, &store.config, &catalog)
	if err != nil {
		return zero, err
	}
	if tail.identity != current.identity || tail.now.Before(current.now) {
		return zero, minioPermissionFailure("effective-sql-tail-drift")
	}
	lastOwner, err := r.effectiveOwnerSeptember(ctx, s.Runtime.Owner.Client, tail.now)
	if err != nil || lastOwner.stamp != owner.stamp {
		return zero, minioPermissionFailure("effective-owner-tail-drift")
	}
	lastRecovery, err := prepareMinIORecoverySession(ctx, s.publisherVerifierDB, s.runtimeReadinessRecovery, r.input)
	if err != nil || !sameMinIORecoverySession(recovery, lastRecovery) {
		return zero, minioPermissionFailure("recovery-current-sql-tail")
	}
	lastLineage, err := s.readOriginalMinIOEnableLineage(ctx, lastRecovery, lastOwner.grant.ConfigSHA256, tail.identity.version, tail.identity.configSHA)
	if err != nil || lastLineage != lineage {
		return zero, minioPermissionFailure("recovery-lineage-tail")
	}
	tailUses, err := r.originalUses(tail.now, lastOwner.grant, store.config, catalog, &window)
	for i := range tailUses {
		tailUses[i].credential = nativePublicationCredential{}
	}
	if err != nil {
		return zero, err
	}
	credential, err = loadNativePublicationCredential(r.configuration.ObserverCredentialFile, r.configuration.ObserverCredentialSHA256)
	if err != nil || hash([]byte(credential.AccessKey)) != r.configuration.ObserverAccountSHA256 || credential.SessionToken != "" || window.include(tail.now, credential.NotBefore, credential.Until) != nil {
		return zero, minioPermissionFailure("effective-observer-tail-drift")
	}
	credential = nativePublicationCredential{}
	if window.include(tail.now, tail.window.notBefore, tail.window.until) != nil || !time.Now().Before(window.until) || ctx.Err() != nil {
		return zero, minioPermissionFailure("effective-original-window-expired")
	}
	return MinIOPublicationPermissionObservation{checkedAt: tail.now, notBefore: window.notBefore, until: window.until, configuration: r.input.SHA256, owner: owner.stamp, resources: resources, native: hash([]byte(first + "/" + selfFirst))}, nil
}

func (s *DeploymentService) CheckPublicationDependenciesWithMinIOEffectiveSeptember(ctx context.Context, input MinIOPublicationPermissionInput) (PublicationDependencyObservation, error) {
	base, err := s.CheckPublicationDependencies(ctx)
	if err != nil && !errors.Is(err, ErrPublicationProviderPermissionObservationMissing) {
		return PublicationDependencyObservation{}, err
	}
	if base.checkedAt.IsZero() {
		return PublicationDependencyObservation{}, minioPermissionFailure("effective-base-observation")
	}
	r, err := NewMinIOSeptemberEffectivePublicationPermissionReader(input)
	if err != nil {
		return PublicationDependencyObservation{}, err
	}
	observed, err := r.CheckCurrentEffectiveSeptember(ctx, s)
	if err != nil {
		return PublicationDependencyObservation{}, err
	}
	window := publicationDependencyWindow{base.notBefore, base.until}
	if observed.checkedAt.Before(base.checkedAt) || window.include(observed.checkedAt, observed.notBefore, observed.until) != nil {
		return PublicationDependencyObservation{}, minioPermissionFailure("effective-combined-original-window")
	}
	return PublicationDependencyObservation{checkedAt: observed.checkedAt, notBefore: window.notBefore, until: window.until}, nil
}
