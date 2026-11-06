package systembackupexecution

import (
	"context"
	"sort"

	ce "clawreef/internal/systembackupcontrolevidence"
	ma "clawreef/internal/systembackupminioauthority"
)

// v2 adds the exact native DeleteObject action on staging only. The
// application's existing exact-version deletion checks remain mandatory.
const minioPermissionProfileV2 = "minio-2025-04-22-builtin-flat.v2"

func minioPermissionObjectRulesV2(purpose, bucket, root, staging string) ([]minioPermissionRule, error) {
	rules, err := minioPermissionObjectRules(purpose, bucket, root, staging)
	if err != nil {
		return nil, err
	}
	if purpose == "artifact_delete" {
		rules[0].Actions = []string{"s3:DeleteObject", "s3:DeleteObjectVersion"}
	}
	return rules, nil
}

// The patched provider authorizes explicit versions directly. Its artifact
// delete role uses the original staging-only version rule.
func minioPermissionObjectRulesForProfile(permission, purpose, bucket, root, staging string) ([]minioPermissionRule, error) {
	switch permission {
	case ma.DeleteCompatPermissionProfile:
		return minioPermissionObjectRules(purpose, bucket, root, staging)
	case ma.PermissionProfile, ma.SeptemberPermissionProfile:
		return minioPermissionObjectRulesV2(purpose, bucket, root, staging)
	default:
		return nil, minioPermissionFailure("original-policy-profile")
	}
}

func (r *minioPermissionHTTP) collectV2(ctx context.Context, cfg minioPermissionConfiguration, uses []minioPermissionUse) (string, error) {
	stamps := []string{}
	server, err := r.server(ctx)
	if err != nil {
		return "", err
	}
	stamps = append(stamps, server)
	buckets := map[string]bool{}
	for _, use := range uses {
		buckets[use.bucket] = true
	}
	names := []string{}
	for bucket := range buckets {
		names = append(names, bucket)
	}
	sort.Strings(names)
	arns := []string{}
	for _, bucket := range names {
		arns = append(arns, "arn:aws:s3:::"+bucket)
	}
	observerRules := []minioPermissionRule{{[]string{"admin:GetUser", "admin:GetPolicy", "admin:ServerInfo"}, []string{"*"}}, {[]string{"s3:GetBucketPolicy", "s3:GetBucketVersioning"}, arns}}
	observer, err := r.userAndPolicyV2(ctx, r.credential.AccessKey, cfg.ObserverPolicyName, cfg.ObserverPolicySHA256, observerRules)
	if err != nil {
		return "", err
	}
	stamps = append(stamps, observer)
	for _, use := range uses {
		if hash([]byte(use.credential.AccessKey)) != use.principal.AccountSHA256 || use.credential.SessionToken != "" || use.credential.AccessKey == r.credential.AccessKey {
			return "", minioPermissionFailure("original-principal-account")
		}
		rules, err := minioPermissionObjectRulesV2(use.principal.Purpose, use.bucket, use.root, use.staging)
		if err != nil {
			return "", err
		}
		stamp, err := r.userAndPolicyV2(ctx, use.credential.AccessKey, use.principal.PolicyName, use.principal.PolicySHA256, rules)
		if err != nil {
			return "", err
		}
		stamps = append(stamps, stamp)
	}
	for _, bucket := range names {
		stamp, err := r.bucket(ctx, bucket)
		if err != nil {
			return "", err
		}
		stamps = append(stamps, stamp)
	}
	raw, _ := ce.Canonical(stamps)
	return hash(raw), nil
}

func minioEffectiveGuardAllV2(ctx context.Context, p minioPermissionProvider, cfg minioPermissionConfiguration, uses []minioPermissionUse, observer nativePublicationCredential) (string, error) {
	return minioEffectiveGuardAllForProfile(ctx, p, cfg, uses, observer, ma.PermissionProfile)
}

func minioEffectiveGuardAllForProfile(ctx context.Context, p minioPermissionProvider, cfg minioPermissionConfiguration, uses []minioPermissionUse, observer nativePublicationCredential, permission string) (string, error) {
	if len(uses) != 5 {
		return "", minioPermissionFailure("effective-discriminator-complete-principals")
	}
	stamps := []string{}
	for _, use := range uses {
		rules, err := minioPermissionObjectRulesForProfile(permission, use.principal.Purpose, use.bucket, use.root, use.staging)
		if err != nil {
			return "", err
		}
		stamp, err := minioEffectiveSelfWithOwnerGuardV2(ctx, p, use.credential, use.principal.AccountSHA256, use.principal.PolicySHA256, use.bucket, rules)
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
	stamp, err := minioEffectiveSelfWithOwnerGuardV2(ctx, p, observer, cfg.ObserverAccountSHA256, cfg.ObserverPolicySHA256, uses[0].bucket, rules)
	if err != nil {
		return "", err
	}
	stamps = append(stamps, stamp)
	raw, _ := ce.Canonical(stamps)
	return hash(raw), nil
}
