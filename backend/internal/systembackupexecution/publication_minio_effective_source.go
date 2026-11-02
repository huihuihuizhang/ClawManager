package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// New independent schema: a configuration-engine record/UID is not needed
// to collect the authenticated current native self policies.
type minioEffectivePermissionConfiguration struct {
	Version, Installation, Namespace, NamespaceUID                  string
	Issuer                                                          ed25519.PublicKey
	MinimumEpoch                                                    uint64
	Grant, Head                                                     minioPermissionObject
	GrantSHA256                                                     string
	ObserverCredentialFile, ObserverCredentialSHA256                string
	ObserverAccountSHA256, ObserverPolicyName, ObserverPolicySHA256 string
}

func NewMinIOEffectivePublicationPermissionReader(input MinIOPublicationPermissionInput) (*MinIOPublicationPermissionReader, error) {
	raw, err := pinnedDeploymentFile(input.File, input.SHA256, 65536)
	var cfg minioEffectivePermissionConfiguration
	if err != nil || decodePublicationCanonical(raw, &cfg) != nil || cfg.Version != "minio-publication-effective-permission-source.v1" || cfg.Installation == "" || cfg.Namespace == "" || cfg.NamespaceUID == "" || len(cfg.Issuer) != ed25519.PublicKeySize || cfg.MinimumEpoch == 0 || !formalCandidateDigest(cfg.GrantSHA256) || !formalCandidateDigest(cfg.ObserverCredentialSHA256) || !formalCandidateDigest(cfg.ObserverAccountSHA256) || !formalCandidateDigest(cfg.ObserverPolicySHA256) || !minioPermissionName(cfg.ObserverPolicyName) || !minioPermissionName(cfg.Grant.Name) || !minioPermissionName(cfg.Head.Name) || cfg.Grant.UID == "" || cfg.Head.UID == "" || cfg.Grant.Name == cfg.Head.Name {
		return nil, minioPermissionFailure("effective-independent-source-pin")
	}
	shared := minioPermissionConfiguration{Version: cfg.Version, Installation: cfg.Installation, Namespace: cfg.Namespace, NamespaceUID: cfg.NamespaceUID, Issuer: cfg.Issuer, MinimumEpoch: cfg.MinimumEpoch, Grant: cfg.Grant, Head: cfg.Head, GrantSHA256: cfg.GrantSHA256, ObserverCredentialFile: cfg.ObserverCredentialFile, ObserverCredentialSHA256: cfg.ObserverCredentialSHA256, ObserverAccountSHA256: cfg.ObserverAccountSHA256, ObserverPolicyName: cfg.ObserverPolicyName, ObserverPolicySHA256: cfg.ObserverPolicySHA256}
	return &MinIOPublicationPermissionReader{input: input, configuration: shared}, nil
}

// Supersedes only the configuration/oracle part of the frozen candidate.
// For this exact upstream release, AccountInfoHandler (1244..1438) reads the
// authenticated caller's current IAM cache. It returns built-in consoleAdmin
// for root OR an active AuthZ plugin (including legacy OPA), otherwise merges
// PolicyDBGet(account, cred.Groups...). consoleAdmin cannot satisfy our closed
// exact policy subset. Derived credentials are independently refused by the
// original named GetUserInfo and exact self AccountName checks.
//
// This is NOT the SDK's BucketAccess.Read/Write summary, an arbitrary JSON
// policy upload, a config-report signature, or a statement that all external
// identity providers are globally disabled. Normal current long-term users
// can read their own accountinfo without installing extra admin rights.
func (r *minioPermissionHTTP) effectiveSelfPolicy(ctx context.Context, account, policySHA string, rules []minioPermissionRule) (string, error) {
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
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 || fields["AccountName"] == nil || fields["Server"] == nil || fields["Policy"] == nil || fields["Buckets"] == nil || minioPermissionDecode(raw, &reply) != nil || reply.AccountName != account || len(reply.Server) == 0 || minioPermissionPolicy(reply.Policy, policySHA, rules) != nil {
		return "", minioPermissionFailure("effective-original-current-policy")
	}
	// Ignore bounded usage statistics completely; they are neither permission
	// evidence nor completeness tokens. Unknown top-level fields still refuse.
	stable, _ := ce.Canonical(struct {
		Account string
		Policy  json.RawMessage
	}{reply.AccountName, reply.Policy})
	return hash(stable), nil
}

func minioEffectiveAccounts(ctx context.Context, p minioPermissionProvider, uses []minioPermissionUse) (string, error) {
	if len(uses) != 5 {
		return "", minioPermissionFailure("effective-complete-five-principals")
	}
	stamps := []string{}
	for _, use := range uses {
		if use.credential.SessionToken != "" || hash([]byte(use.credential.AccessKey)) != use.principal.AccountSHA256 {
			return "", minioPermissionFailure("effective-original-credential")
		}
		rules, err := minioPermissionObjectRules(use.principal.Purpose, use.bucket, use.root, use.staging)
		if err != nil {
			return "", err
		}
		native, err := newMinioPermissionHTTP(p, use.credential)
		if err != nil {
			return "", err
		}
		// Credential lifetime is an actual request deadline, including reads.
		callCtx, cancel := context.WithDeadline(ctx, use.credential.Until)
		stamp, err := native.effectiveSelfPolicy(callCtx, use.credential.AccessKey, use.principal.PolicySHA256, rules)
		cancel()
		native.close()
		if err != nil {
			return "", err
		}
		stamps = append(stamps, stamp)
	}
	raw, _ := ce.Canonical(stamps)
	return hash(raw), nil
}

func minioEffectiveObserver(ctx context.Context, r *minioPermissionHTTP, cfg minioPermissionConfiguration, uses []minioPermissionUse) (string, error) {
	seen := map[string]bool{}
	for _, use := range uses {
		seen[use.bucket] = true
	}
	resources := []string{}
	for bucket := range seen {
		resources = append(resources, "arn:aws:s3:::"+bucket)
	}
	sort.Strings(resources)
	rules := []minioPermissionRule{{[]string{"admin:GetUser", "admin:GetPolicy", "admin:ServerInfo"}, []string{"*"}}, {[]string{"s3:GetBucketPolicy", "s3:GetBucketVersioning"}, resources}}
	return r.effectiveSelfPolicy(ctx, r.credential.AccessKey, cfg.ObserverPolicySHA256, rules)
}

// Read the ORIGINAL externally pinned permission owner and current revocable
// head. EngineSHA256 is intentionally not used as a permission assertion in
// this source: current effective policy comes from actual native self reads.
// This method neither creates a source nor signs/enrolls a grant or head.
func (r *MinIOPublicationPermissionReader) effectiveOwner(ctx context.Context, k kubernetes.Interface, now time.Time) (minioPermissionOwnerState, error) {
	var out minioPermissionOwnerState
	if ctx == nil || ctx.Err() != nil || r == nil || k == nil {
		return out, minioPermissionFailure("effective-owner-source")
	}
	current, err := NewMinIOEffectivePublicationPermissionReader(r.input)
	if err != nil {
		return out, err
	}
	want, _ := ce.Canonical(r.configuration)
	got, _ := ce.Canonical(current.configuration)
	if string(want) != string(got) {
		return out, minioPermissionFailure("effective-source-pin-drift")
	}
	cfg := r.configuration
	ns, err := k.CoreV1().Namespaces().Get(ctx, cfg.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != cfg.NamespaceUID || ns.DeletionTimestamp != nil {
		return out, minioPermissionFailure("effective-original-namespace")
	}
	read := func(ref minioPermissionObject, domain string, dst any) ([]byte, string, error) {
		cm, err := k.CoreV1().ConfigMaps(cfg.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil || cm.Namespace != cfg.Namespace || string(cm.UID) != ref.UID || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || len(cm.Data) != 1 || len(cm.BinaryData) != 1 {
			return nil, "", minioPermissionFailure("effective-owner-object")
		}
		raw := []byte(cm.Data["record.json"])
		sig := cm.BinaryData["signature"]
		if len(raw) == 0 || len(raw) > 32768 || decodePublicationCanonical(raw, dst) != nil || !ed25519.Verify(cfg.Issuer, append([]byte(domain), raw...), sig) {
			return nil, "", minioPermissionFailure("effective-owner-signature")
		}
		return raw, cm.ResourceVersion, nil
	}
	g, gv, err := read(cfg.Grant, minioPermissionOwnerDomain, &out.grant)
	if err != nil || hash(g) != cfg.GrantSHA256 {
		return out, minioPermissionFailure("effective-original-owner-grant")
	}
	var head minioPermissionHead
	h, hv, err := read(cfg.Head, minioPermissionHeadDomain, &head)
	if err != nil || head.Version != "minio-permission-head.v1" || head.Installation != cfg.Installation || head.State != "active" || head.GrantSHA256 != cfg.GrantSHA256 || head.Epoch < cfg.MinimumEpoch || out.grant.Version != "minio-permission-grant.v1" || out.grant.Installation != cfg.Installation || out.grant.Namespace != cfg.Namespace || out.grant.NamespaceUID != cfg.NamespaceUID || out.grant.Epoch != head.Epoch || out.grant.Profile != minioPermissionProfile || out.window.include(now, out.grant.NotBefore, out.grant.Until) != nil || out.window.include(now, head.NotBefore, head.Until) != nil {
		return out, minioPermissionFailure("effective-current-owner-head")
	}
	stamp, _ := ce.Canonical([]string{cfg.NamespaceUID, cfg.Grant.UID, cfg.Head.UID, hash(g), hash(h), gv, hv})
	out.stamp = hash(stamp)
	return out, nil
}
