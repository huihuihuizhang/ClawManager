package systembackupexecution

import (
	ce "clawreef/internal/systembackupcontrolevidence"
	"context"
	"sort"
)

func (r *minioPermissionHTTP) collectBuiltinFlat(ctx context.Context, cfg minioPermissionConfiguration, uses []minioPermissionUse, permission string) (string, error) {
	stamps := []string{}
	server, err := r.serverBuiltinFlat(ctx, permission)
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
		rules, err := minioPermissionObjectRulesForProfile(permission, use.principal.Purpose, use.bucket, use.root, use.staging)
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
