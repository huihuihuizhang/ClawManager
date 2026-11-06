package systembackupreferenceprobe

import (
	ce "clawreef/internal/systembackupcontrolevidence"
	"context"
	"encoding/json"
	"k8s.io/client-go/kubernetes"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Actual native declarations selected by original installer code. Identity
// hashes alone never constitute a native permission observation.
type OriginalFivePrincipal struct {
	Principal             Principal
	Bucket, Root, Staging string
}
type OriginalFiveProfile struct {
	Version, Installation, Namespace, NamespaceUID string
	Provider                                       MinIOProvider
	Observer                                       Principal
	Principals                                     []OriginalFivePrincipal
}

func fiveRules(p OriginalFivePrincipal) ([]minioPermissionRule, error) {
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`).MatchString(p.Bucket) || !prefix(p.Root) || p.Staging != "" && !prefix(p.Staging) {
		return nil, ErrObservation
	}
	resources := []string{"arn:aws:s3:::" + p.Bucket + "/" + p.Root + "*"}
	actions := []string{}
	if strings.HasPrefix(p.Principal.Purpose, "artifact_") && p.Staging != "" {
		resources = append(resources, "arn:aws:s3:::"+p.Bucket+"/"+p.Staging+"*")
	}
	switch p.Principal.Purpose {
	case "artifact_read", "catalog_read":
		actions = []string{"s3:GetObject", "s3:GetObjectVersion"}
	case "artifact_write", "catalog_append":
		actions = []string{"s3:PutObject"}
	case "artifact_delete":
		if p.Staging == "" {
			return nil, ErrObservation
		}
		actions = []string{"s3:DeleteObjectVersion"}
		resources = []string{"arn:aws:s3:::" + p.Bucket + "/" + p.Staging + "*"}
	default:
		return nil, ErrObservation
	}
	sort.Strings(resources)
	return []minioPermissionRule{{actions, resources}}, nil
}
func ValidateOriginalFiveProfile(p OriginalFiveProfile) error {
	if p.Version != "original-five-minio-reference-profile.v1" || p.Installation == "" || p.Namespace == "" || p.NamespaceUID == "" || p.Observer.Purpose != "metadata_observer" || len(p.Principals) != 5 {
		return ErrObservation
	}
	have := map[string]bool{}
	accounts := map[string]bool{}
	files := map[string]bool{}
	principals := []Principal{p.Observer}
	for _, v := range p.Principals {
		if _, err := fiveRules(v); err != nil {
			return err
		}
		principals = append(principals, v.Principal)
	}
	for _, v := range principals {
		if have[v.Purpose] || accounts[v.AccountSHA256] || files[v.Credential.File] || !digest.MatchString(v.AccountSHA256) || !digest.MatchString(v.PolicySHA256) || !digest.MatchString(v.Credential.SHA256) || !name.MatchString(v.PolicyName) || !filepath.IsAbs(v.Credential.File) {
			return ErrObservation
		}
		have[v.Purpose] = true
		accounts[v.AccountSHA256] = true
		files[v.Credential.File] = true
	}
	for _, v := range []string{"artifact_read", "artifact_write", "artifact_delete", "catalog_read", "catalog_append"} {
		if !have[v] {
			return ErrObservation
		}
	}
	return nil
}
func RecheckOriginalFiveFiles(p OriginalFiveProfile) error {
	if ValidateOriginalFiveProfile(p) != nil {
		return ErrObservation
	}
	raw, err := ReadPinned(FilePin{p.Provider.CAFile, p.Provider.CASHA256}, 65536)
	clear(raw)
	if err != nil {
		return ErrObservation
	}
	for _, v := range append([]Principal{p.Observer}, fivePrincipals(p)...) {
		c, err := credential(v.Credential)
		if err != nil || hash([]byte(c.AccessKey)) != v.AccountSHA256 || time.Now().Before(c.NotBefore) || !time.Now().Before(c.Until) {
			return ErrObservation
		}
	}
	return nil
}
func fivePrincipals(p OriginalFiveProfile) []Principal {
	out := []Principal{}
	for _, v := range p.Principals {
		out = append(out, v.Principal)
	}
	return out
}
func observeFivePass(ctx context.Context, p OriginalFiveProfile, creds []nativePublicationCredential) (string, error) {
	r, err := newMinioPermissionHTTP(p.Provider, creds[0])
	if err != nil {
		return "", err
	}
	defer r.close()
	server, err := r.serverOriginalBackupTarget(ctx)
	if err != nil {
		return "", err
	}
	stamps := []string{server}
	bucketSet := map[string]bool{}
	for _, v := range p.Principals {
		bucketSet[v.Bucket] = true
	}
	buckets := []string{}
	for v := range bucketSet {
		buckets = append(buckets, v)
	}
	sort.Strings(buckets)
	arns := []string{}
	for _, v := range buckets {
		arns = append(arns, "arn:aws:s3:::"+v)
	}
	observerRules := []minioPermissionRule{{[]string{"admin:GetUser", "admin:GetPolicy", "admin:ServerInfo"}, []string{"*"}}, {[]string{"s3:GetBucketPolicy", "s3:GetBucketVersioning"}, arns}}
	for j, v := range append([]Principal{p.Observer}, fivePrincipals(p)...) {
		want := observerRules
		bucket := buckets[0]
		if j > 0 {
			want, err = fiveRules(p.Principals[j-1])
			if err != nil {
				return "", err
			}
			bucket = p.Principals[j-1].Bucket
		}
		if hash([]byte(creds[j].AccessKey)) != v.AccountSHA256 {
			return "", ErrObservation
		}
		stamp, err := r.userAndPolicyV2(ctx, creds[j].AccessKey, v.PolicyName, v.PolicySHA256, want)
		if err != nil {
			return "", err
		}
		stamps = append(stamps, stamp)
		self, err := minioEffectiveSelfWithOwnerGuardV2(ctx, p.Provider, creds[j], v.AccountSHA256, v.PolicySHA256, bucket, want)
		if err != nil {
			return "", err
		}
		stamps = append(stamps, self)
	}
	for _, v := range buckets {
		stamp, err := r.bucket(ctx, v)
		if err != nil {
			return "", err
		}
		stamps = append(stamps, stamp)
	}
	raw, err := ce.Canonical(stamps)
	if err != nil {
		return "", err
	}
	return hash(raw), nil
}

// ObserveOriginalFive checks the actual pinned September native contract,
// current Pod/RS/Deployment/SA/Service/node, ALL original separate accounts,
// exact policy documents, effective self-policy, non-owner discriminator,
// bucket policy/versioning, then repeats the full native state and Kube chain.
// It performs named GETs only. It does not certify PutObject protocol support.
func ObserveOriginalFive(ctx context.Context, kube kubernetes.Interface, p OriginalFiveProfile) (*S3Observation, error) {
	if ctx == nil || ctx.Err() != nil || kube == nil || ValidateOriginalFiveProfile(p) != nil {
		return nil, ErrObservation
	}
	raw, err := json.Marshal(p)
	var frozen OriginalFiveProfile
	if err != nil || json.Unmarshal(raw, &frozen) != nil {
		return nil, ErrObservation
	}
	p = frozen
	started := time.Now().UTC().Truncate(time.Microsecond)
	until := started.Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	creds := []nativePublicationCredential{}
	defer func() {
		for j := range creds {
			creds[j] = nativePublicationCredential{}
		}
	}()
	for _, v := range append([]Principal{p.Observer}, fivePrincipals(p)...) {
		c, err := credential(v.Credential)
		if err != nil || started.Before(c.NotBefore) || !started.Before(c.Until) {
			return nil, ErrObservation
		}
		if c.Until.Before(until) {
			until = c.Until
		}
		creds = append(creds, c)
	}
	active, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	chain, err := minioPermissionKubernetes(active, kube, minioPermissionConfiguration{p.Namespace, p.NamespaceUID}, p.Provider)
	if err != nil {
		return nil, err
	}
	first, err := observeFivePass(active, p, creds)
	if err != nil {
		return nil, err
	}
	second, err := observeFivePass(active, p, creds)
	if err != nil || first != second {
		return nil, ErrObservation
	}
	tail, err := minioPermissionKubernetes(active, kube, minioPermissionConfiguration{p.Namespace, p.NamespaceUID}, p.Provider)
	if err != nil || chain != tail || active.Err() != nil || !time.Now().Before(until) || RecheckOriginalFiveFiles(p) != nil {
		return nil, ErrObservation
	}
	identity, _ := ce.Canonical([]string{chain, first})
	o := &S3Observation{identity: hash(identity), started: started, until: until}
	o.origin = o
	return o, nil
}
