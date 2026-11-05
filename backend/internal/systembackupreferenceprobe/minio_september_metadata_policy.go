package systembackupreferenceprobe

import (
	"context"
	"regexp"
	"sort"
	"strings"

	mn "clawreef/internal/systembackup/minionative"
)

// This path is only for the exact metadata observer rules. Generic evidence
// and channel rules continue through the unchanged normalizer. The fixed
// native September gate precedes wire interpretation, and the original full
// policy hash and exact action/resource verification run after normalization.
func (r *minioPermissionHTTP) normalizedSeptemberMetadataPolicy(ctx context.Context, raw []byte, pin string, rules []minioPermissionRule) ([]byte, error) {
	if !exactSeptemberMetadataRules(rules) {
		return minioPermissionNormalizedPolicyV2(raw, pin, rules)
	}
	if _, e := r.serverSeptember(ctx); e != nil {
		return nil, e
	}
	normalized, e := mn.NormalizeSeptemberMetadataObserverReadback(raw)
	if e != nil {
		return minioPermissionNormalizedPolicyV2(raw, pin, rules)
	}
	return minioPermissionNormalizedPolicyV2(normalized, pin, rules)
}

func exactSeptemberMetadataRules(rules []minioPermissionRule) bool {
	if len(rules) != 2 {
		return false
	}
	admin, bucket := 0, 0
	for _, rule := range rules {
		actions := append([]string(nil), rule.Actions...)
		sort.Strings(actions)
		switch strings.Join(actions, "\x00") {
		case "admin:GetPolicy\x00admin:GetUser\x00admin:ServerInfo":
			if len(rule.Resources) != 1 || rule.Resources[0] != "*" {
				return false
			}
			admin++
		case "s3:GetBucketPolicy\x00s3:GetBucketVersioning":
			if len(rule.Resources) < 1 || len(rule.Resources) > 16 {
				return false
			}
			seen := map[string]bool{}
			for _, resource := range rule.Resources {
				if !septemberMetadataBucketARN.MatchString(resource) || seen[resource] {
					return false
				}
				seen[resource] = true
			}
			bucket++
		default:
			return false
		}
	}
	return admin == 1 && bucket == 1
}

var septemberMetadataBucketARN = regexp.MustCompile(`^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
