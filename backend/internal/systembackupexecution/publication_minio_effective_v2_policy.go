package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
)

// Official pkg/v3.1.0 serializes ActionSet/ResourceSet from maps without
// sorting. v2 pins normalized ORIGINAL policy content, never response order.
// Every field is retained and validated by the closed profile after sorting.
func minioPermissionNormalizedPolicyV2(raw []byte, pin string, rules []minioPermissionRule) ([]byte, error) {
	normalized, err := minioPermissionCanonicalPolicyOrder(raw, false)
	if err != nil {
		return nil, err
	}
	if minioPermissionPolicy(normalized, pin, rules) != nil {
		return nil, minioPermissionFailure("v2-original-normalized-policy")
	}
	return normalized, nil
}

// generatedOnly limits the readback comparison to the native installer's
// exact array-based Allow document. Preserve each statement and reject
// fields or representations the generator does not produce.
func minioPermissionCanonicalPolicyOrder(raw []byte, generatedOnly bool) ([]byte, error) {
	if minioPermissionUniqueJSON(raw) != nil {
		return nil, minioPermissionFailure("v2-policy-json")
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		return nil, minioPermissionFailure("v2-policy-shape")
	}
	var statements []map[string]json.RawMessage
	if json.Unmarshal(doc["Statement"], &statements) != nil {
		return nil, minioPermissionFailure("v2-policy-statements")
	}
	if generatedOnly && (len(doc) != 2 || !bytes.Equal(bytes.TrimSpace(doc["Version"]), []byte(`"2012-10-17"`)) || len(statements) == 0 || len(statements) > 8) {
		return nil, minioPermissionFailure("native-generated-policy-shape")
	}
	canonicalStatements := []json.RawMessage{}
	for _, st := range statements {
		if generatedOnly && (len(st) != 3 || !bytes.Equal(bytes.TrimSpace(st["Effect"]), []byte(`"Allow"`))) {
			return nil, minioPermissionFailure("native-generated-statement-shape")
		}
		for _, key := range []string{"Action", "Resource"} {
			if generatedOnly && !bytes.HasPrefix(bytes.TrimSpace(st[key]), []byte("[")) {
				return nil, minioPermissionFailure("native-generated-policy-set")
			}
			values, err := minioPermissionStrings(st[key])
			if err != nil {
				return nil, err
			}
			sort.Strings(values)
			st[key], err = ce.Canonical(values)
			if err != nil {
				return nil, err
			}
		}
		b, err := ce.Canonical(st)
		if err != nil {
			return nil, err
		}
		canonicalStatements = append(canonicalStatements, b)
	}
	sort.Slice(canonicalStatements, func(i, j int) bool { return bytes.Compare(canonicalStatements[i], canonicalStatements[j]) < 0 })
	var err error
	doc["Statement"], err = ce.Canonical(canonicalStatements)
	if err != nil {
		return nil, err
	}
	normalized, err := ce.Canonical(doc)
	if err != nil {
		return nil, minioPermissionFailure("v2-original-normalized-policy")
	}
	return normalized, nil
}

func (r *minioPermissionHTTP) effectiveSelfPolicyV2(ctx context.Context, account, policySHA string, rules []minioPermissionRule) (string, error) {
	if account == "" || r.credential.AccessKey != account || r.credential.SessionToken != "" {
		return "", minioPermissionFailure("effective-original-self-account")
	}
	raw, status, err := r.get(ctx, "/minio/admin/v3/accountinfo", nil)
	if err != nil || status != http.StatusOK {
		return "", minioPermissionFailure("effective-self-account-info")
	}
	var reply struct {
		AccountName string
		Server      json.RawMessage
		Policy      json.RawMessage
		Buckets     json.RawMessage
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 || fields["AccountName"] == nil || fields["Server"] == nil || fields["Policy"] == nil || fields["Buckets"] == nil || minioPermissionDecode(raw, &reply) != nil || reply.AccountName != account || len(reply.Server) == 0 {
		return "", minioPermissionFailure("effective-original-current-policy")
	}
	normalized, err := r.normalizedBuiltinFlatPolicy(ctx, reply.Policy, policySHA, rules)
	if err != nil {
		return "", err
	}
	reply.Policy = normalized
	// Ignore bounded usage statistics completely; they are neither permission
	// evidence nor completeness tokens. Unknown top-level fields still refuse.
	stable, _ := ce.Canonical(struct {
		Account string
		Policy  json.RawMessage
	}{reply.AccountName, reply.Policy})
	return hash(stable), nil
}

func (r *minioPermissionHTTP) userAndPolicyV2(ctx context.Context, account, policyName, policySHA string, rules []minioPermissionRule) (string, error) {
	raw, status, err := r.get(ctx, "/minio/admin/v3/user-info", url.Values{"accessKey": {account}})
	if err != nil || status != http.StatusOK {
		return "", minioPermissionFailure("native-user-info")
	}
	var user struct {
		AuthInfo *struct {
			Type             string `json:"type"`
			AuthServer       string `json:"authServer"`
			AuthServerUserID string `json:"authServerUserID"`
		} `json:"userAuthInfo,omitempty"`
		SecretKey  string    `json:"secretKey,omitempty"`
		PolicyName string    `json:"policyName,omitempty"`
		Status     string    `json:"status"`
		MemberOf   []string  `json:"memberOf,omitempty"`
		UpdatedAt  time.Time `json:"updatedAt,omitempty"`
	}
	if minioPermissionDecode(raw, &user) != nil || user.SecretKey != "" || user.Status != "enabled" || user.PolicyName != policyName || len(user.MemberOf) != 0 || user.AuthInfo != nil && (user.AuthInfo.Type != "builtin" || user.AuthInfo.AuthServer != "" || user.AuthInfo.AuthServerUserID != account) || user.UpdatedAt.IsZero() {
		return "", minioPermissionFailure("native-builtin-flat-user")
	}
	// Only one exact named policy is supported; commas/extra policies refuse.
	if !minioPermissionName(policyName) {
		return "", minioPermissionFailure("native-policy-name")
	}
	policyRaw, status, err := r.get(ctx, "/minio/admin/v3/info-canned-policy", url.Values{"name": {policyName}, "v": {"2"}})
	if err != nil || status != http.StatusOK {
		return "", minioPermissionFailure("native-policy-info")
	}
	var policy struct {
		PolicyName             string
		Policy                 json.RawMessage
		CreateDate, UpdateDate time.Time
	}
	if minioPermissionDecode(policyRaw, &policy) != nil || policy.PolicyName != policyName || policy.UpdateDate.IsZero() {
		return "", minioPermissionFailure("native-exact-policy")
	}
	normalized, err := r.normalizedBuiltinFlatPolicy(ctx, policy.Policy, policySHA, rules)
	if err != nil {
		return "", err
	}
	policy.Policy = normalized
	stable, _ := ce.Canonical(struct {
		User   any
		Policy any
	}{user, policy})
	return hash(stable), nil
}

func minioEffectiveSelfWithOwnerGuardV2(ctx context.Context, p minioPermissionProvider, credential nativePublicationCredential, accountSHA, policySHA, bucket string, rules []minioPermissionRule) (string, error) {
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
	self, err := native.effectiveSelfPolicyV2(ctx, credential.AccessKey, policySHA, rules)
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
