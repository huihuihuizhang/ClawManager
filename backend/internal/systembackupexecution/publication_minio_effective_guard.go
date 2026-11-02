package systembackupexecution

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
)

// The S3 owner predicate also includes ParentUser==root. AccountInfo's root
// switch uses AccountName after its derived-user classification instead.
// Do not assume arbitrary stored credentials make these predicates equivalent.
// A ConfigUpdate-gated help GET discriminates this branch without a storage
// operation that could itself fail AccessDenied. It returns only static help
// on success, never config values. Normal narrow accounts must get genuine
// native JSON AccessDenied. No ConfigUpdate right is installed or added.
const minioEffectiveOwnerGuardPath = "/minio/admin/v3/help-config-kv"

func minioEffectiveAdminAccessDenied(raw []byte) error {
	if len(raw) == 0 || len(raw) > 8192 || minioPermissionUniqueJSON(raw) != nil {
		return minioPermissionFailure("effective-discriminator-response")
	}
	var fields map[string]string
	if json.Unmarshal(raw, &fields) != nil {
		return minioPermissionFailure("effective-discriminator-json")
	}
	allowed := map[string]bool{"Code": true, "Message": true, "Key": true, "BucketName": true, "Resource": true, "Region": true, "RequestId": true, "HostId": true, "ActualObjectSize": true, "RangeRequested": true}
	for key := range fields {
		if !allowed[key] {
			return minioPermissionFailure("effective-discriminator-unknown-field")
		}
	}
	if fields["Code"] != "AccessDenied" || fields["Message"] == "" || fields["Resource"] != minioEffectiveOwnerGuardPath || fields["RequestId"] == "" || fields["HostId"] == "" || fields["BucketName"] != "" || fields["Key"] != "" {
		return minioPermissionFailure("effective-discriminator-not-access-denied")
	}
	return nil
}

func minioEffectiveSelfWithOwnerGuard(ctx context.Context, p minioPermissionProvider, credential nativePublicationCredential, accountSHA, policySHA, bucket string, rules []minioPermissionRule) (string, error) {
	if hash([]byte(credential.AccessKey)) != accountSHA || credential.SessionToken != "" || bucket == "" || strings.ContainsAny(bucket, "/\\?#\r\n") {
		return "", minioPermissionFailure("effective-discriminator-original-account")
	}
	ctx, cancel := context.WithDeadline(ctx, credential.Until)
	defer cancel()
	native, err := newMinioPermissionHTTP(p, credential)
	if err != nil {
		return "", err
	}
	defer native.close()
	self, err := native.effectiveSelfPolicy(ctx, credential.AccessKey, policySHA, rules)
	if err != nil {
		return "", err
	}
	raw, status, err := native.get(ctx, minioEffectiveOwnerGuardPath, url.Values{"subSys": {"policy_plugin"}, "key": {""}})
	if err != nil || status != http.StatusForbidden || minioEffectiveAdminAccessDenied(raw) != nil {
		return "", minioPermissionFailure("effective-owner-bypass-discriminator")
	}
	stable, _ := ce.Canonical([]string{accountSHA, policySHA, self, bucket, "admin:ConfigUpdate:help-config-kv:AccessDenied"})
	return hash(stable), nil
}

func minioEffectiveGuardAll(ctx context.Context, p minioPermissionProvider, cfg minioPermissionConfiguration, uses []minioPermissionUse, observer nativePublicationCredential) (string, error) {
	if len(uses) != 5 {
		return "", minioPermissionFailure("effective-discriminator-complete-principals")
	}
	stamps := []string{}
	for _, use := range uses {
		rules, err := minioPermissionObjectRules(use.principal.Purpose, use.bucket, use.root, use.staging)
		if err != nil {
			return "", err
		}
		stamp, err := minioEffectiveSelfWithOwnerGuard(ctx, p, use.credential, use.principal.AccountSHA256, use.principal.PolicySHA256, use.bucket, rules)
		if err != nil {
			return "", err
		}
		stamps = append(stamps, stamp)
	}
	buckets := map[string]bool{}
	for _, use := range uses {
		buckets[use.bucket] = true
	}
	resources := []string{}
	for bucket := range buckets {
		resources = append(resources, "arn:aws:s3:::"+bucket)
	}
	// Policy validation compares sets, so metadata bucket ordering is irrelevant.
	rules := []minioPermissionRule{{[]string{"admin:GetUser", "admin:GetPolicy", "admin:ServerInfo"}, []string{"*"}}, {[]string{"s3:GetBucketPolicy", "s3:GetBucketVersioning"}, resources}}
	stamp, err := minioEffectiveSelfWithOwnerGuard(ctx, p, observer, cfg.ObserverAccountSHA256, cfg.ObserverPolicySHA256, uses[0].bucket, rules)
	if err != nil {
		return "", err
	}
	stamps = append(stamps, stamp)
	raw, _ := ce.Canonical(stamps)
	return hash(raw), nil
}

// Supersedes bare CheckCurrentEffective's incomplete owner-predicate proof.
// Both full native snapshots must agree and bracket the six authenticated
// self-policy + forbidden metadata GET pairs. No write, restart or new role.
func (r *MinIOPublicationPermissionReader) CheckCurrentEffectiveGuarded(ctx context.Context, s *DeploymentService) (MinIOPublicationPermissionObservation, error) {
	var zero MinIOPublicationPermissionObservation
	if ctx == nil || ctx.Err() != nil {
		return zero, minioPermissionFailure("effective-guard-context")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	first, err := r.CheckCurrentEffective(ctx, s)
	if err != nil {
		return zero, err
	}
	window := publicationDependencyWindow{first.notBefore, first.until}
	ctx, stop := context.WithDeadline(ctx, window.until)
	defer stop()
	store, err := s.publicationStore(ctx)
	if err != nil {
		return zero, err
	}
	defer store.Close()
	catalog, err := s.currentPublicationCatalog(ctx)
	if err != nil {
		return zero, err
	}
	owner, err := r.effectiveOwner(ctx, s.Runtime.Owner.Client, time.Now())
	if err != nil || owner.stamp != first.owner || window.include(time.Now(), owner.window.notBefore, owner.window.until) != nil {
		return zero, minioPermissionFailure("effective-guard-original-owner")
	}
	uses, err := r.originalUses(time.Now(), owner.grant, store.config, catalog, &window)
	if err != nil {
		return zero, err
	}
	defer func() {
		for i := range uses {
			uses[i].credential = nativePublicationCredential{}
		}
	}()
	observer, err := loadNativePublicationCredential(r.configuration.ObserverCredentialFile, r.configuration.ObserverCredentialSHA256)
	if err != nil || window.include(time.Now(), observer.NotBefore, observer.Until) != nil {
		return zero, minioPermissionFailure("effective-guard-original-observer")
	}
	ctx, credentialsStop := context.WithDeadline(ctx, window.until)
	defer credentialsStop()
	guard, err := minioEffectiveGuardAll(ctx, owner.grant.Provider, r.configuration, uses, observer)
	observer = nativePublicationCredential{}
	if err != nil {
		return zero, err
	}
	last, err := r.CheckCurrentEffective(ctx, s)
	if err != nil {
		return zero, err
	}
	if first.configuration != last.configuration || first.owner != last.owner || first.resources != last.resources || first.native != last.native || last.checkedAt.Before(first.checkedAt) || window.include(last.checkedAt, last.notBefore, last.until) != nil || !time.Now().Before(window.until) || ctx.Err() != nil {
		return zero, minioPermissionFailure("effective-guard-original-tail-drift")
	}
	last.notBefore = window.notBefore
	last.until = window.until
	last.native = hash([]byte(last.native + "/" + guard))
	return last, nil
}

func (s *DeploymentService) CheckPublicationDependenciesWithMinIOEffectiveGuarded(ctx context.Context, input MinIOPublicationPermissionInput) (PublicationDependencyObservation, error) {
	base, err := s.CheckPublicationDependencies(ctx)
	if err != nil && !errors.Is(err, ErrPublicationProviderPermissionObservationMissing) {
		return PublicationDependencyObservation{}, err
	}
	if base.checkedAt.IsZero() {
		return PublicationDependencyObservation{}, minioPermissionFailure("effective-guard-base-observation")
	}
	r, err := NewMinIOEffectivePublicationPermissionReader(input)
	if err != nil {
		return PublicationDependencyObservation{}, err
	}
	observed, err := r.CheckCurrentEffectiveGuarded(ctx, s)
	if err != nil {
		return PublicationDependencyObservation{}, err
	}
	window := publicationDependencyWindow{base.notBefore, base.until}
	if observed.checkedAt.Before(base.checkedAt) || window.include(observed.checkedAt, observed.notBefore, observed.until) != nil {
		return PublicationDependencyObservation{}, minioPermissionFailure("effective-guard-combined-window")
	}
	return PublicationDependencyObservation{checkedAt: observed.checkedAt, notBefore: window.notBefore, until: window.until}, nil
}
