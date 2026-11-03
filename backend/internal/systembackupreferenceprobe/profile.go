// Package systembackupreferenceprobe observes existing provider permissions.
// It cannot authorize configuration writes, issue task grants or alter providers.
package systembackupreferenceprobe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	ev "clawreef/internal/systembackupevidence"
	"k8s.io/client-go/kubernetes"
)

var ErrObservation = errors.New("reference_provider_observation_unavailable")
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var name = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type FilePin struct{ File, SHA256 string }
type ObjectPin struct{ Name, UID string }
type MinIOProvider struct {
	Endpoint, Region, CAFile, CASHA256, SPKISHA256, DeploymentID string
	Deployment, ReplicaSet, Pod, Service, ServiceAccount         ObjectPin
	Container, ImageID, Node, NodeUID                            string
}
type minioPermissionProvider = MinIOProvider
type minioPermissionObject = ObjectPin
type minioPermissionConfiguration struct{ Namespace, NamespaceUID string }
type nativePublicationCredential struct {
	AccessKey    string    `json:"access_key"`
	SecretKey    string    `json:"secret_key"`
	SessionToken string    `json:"session_token"`
	NotBefore    time.Time `json:"not_before"`
	Until        time.Time `json:"until"`
}

// These are separate original credentials. Upload is the actual publication
// SigV4 writer; it is not the controller's x509 identity issuer.
type Principal struct {
	Purpose, AccountSHA256, PolicyName, PolicySHA256 string
	Credential                                       FilePin
}
type S3Profile struct {
	Version, Installation, Namespace, NamespaceUID string
	Provider                                       MinIOProvider
	Observer                                       Principal
	UploadMaterials                                FilePin
	UploadBucket, UploadRoot, UploadStagingRoot    string
	Evidence                                       ev.S3Config
	Principals                                     []Principal
}

// No exported success fields, constructor, decoding or caller-supplied client.
type S3Observation struct {
	origin         *S3Observation
	identity       string
	started, until time.Time
}

func (o *S3Observation) IdentitySHA256() string {
	if o == nil || o.origin != o {
		return ""
	}
	return o.identity
}
func (o *S3Observation) StartedAt() time.Time {
	if o == nil || o.origin != o {
		return time.Time{}
	}
	return o.started
}
func (o *S3Observation) ValidUntil() time.Time {
	if o == nil || o.origin != o {
		return time.Time{}
	}
	return o.until
}
func (*S3Observation) MarshalJSON() ([]byte, error) { return nil, ErrObservation }

func hash(raw []byte) string              { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func formalCandidateDigest(s string) bool { return digest.MatchString(s) }
func minioPermissionName(s string) bool   { return name.MatchString(s) }
func minioPermissionFailure(string) error { return ErrObservation }
func decodeProviderDeploymentJSON(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrObservation
	}
	return nil
}

// Same private-file contract used by the original installer. A pin is data,
// never a substitute for a native credential-authenticated provider read.
func ReadPinned(pin FilePin, limit int64) ([]byte, error) {
	if !filepath.IsAbs(pin.File) || filepath.Clean(pin.File) != pin.File || !digest.MatchString(pin.SHA256) || limit < 1 || limit > 262144 {
		return nil, ErrObservation
	}
	before, e := os.Lstat(pin.File)
	if e != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit || runtime.GOOS == "linux" && before.Mode().Perm()&0077 != 0 {
		return nil, ErrObservation
	}
	f, e := os.Open(pin.File)
	if e != nil {
		return nil, ErrObservation
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return nil, ErrObservation
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	after, se := f.Stat()
	pathAfter, pe := os.Lstat(pin.File)
	if e != nil || se != nil || pe != nil || !os.SameFile(opened, after) || !os.SameFile(after, pathAfter) || !pathAfter.Mode().IsRegular() || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || int64(len(raw)) > limit || hash(raw) != pin.SHA256 {
		clear(raw)
		return nil, ErrObservation
	}
	return raw, nil
}
func pinnedDeploymentFile(path, sha string, limit int64) ([]byte, error) {
	return ReadPinned(FilePin{path, sha}, limit)
}
func credential(pin FilePin) (nativePublicationCredential, error) {
	raw, e := ReadPinned(pin, 16384)
	if e != nil {
		return nativePublicationCredential{}, e
	}
	defer clear(raw)
	var c nativePublicationCredential
	if minioPermissionDecode(raw, &c) != nil || len(c.AccessKey) < 3 || len(c.AccessKey) > 256 || len(c.SecretKey) < 16 || len(c.SecretKey) > 4096 || c.SessionToken != "" || strings.ContainsAny(c.AccessKey, "\x00\r\n") || c.NotBefore.IsZero() || !c.NotBefore.Before(c.Until) {
		return nativePublicationCredential{}, ErrObservation
	}
	return c, nil
}
func prefix(s string) bool {
	return s != "" && !strings.HasPrefix(s, "/") && strings.HasSuffix(s, "/") && !strings.ContainsAny(s, "*?[]\\\x00\r\n") && !strings.Contains(s, "../") && !strings.Contains(s, "//")
}

func rules(p Principal, c S3Profile) ([]minioPermissionRule, error) {
	root, bucket := c.Evidence.Root+"/"+c.Installation+"/", c.Evidence.Bucket
	var actions []string
	switch p.Purpose {
	case "artifact_upload_issuer":
		if !prefix(c.UploadRoot) || !prefix(c.UploadStagingRoot) {
			return nil, ErrObservation
		}
		resources := []string{"arn:aws:s3:::" + c.UploadBucket + "/" + c.UploadRoot + "*", "arn:aws:s3:::" + c.UploadBucket + "/" + c.UploadStagingRoot + "*"}
		sort.Strings(resources)
		return []minioPermissionRule{{[]string{"s3:PutObject"}, resources}}, nil
	case "evidence_read":
		actions = []string{"s3:GetObjectVersion"}
	case "evidence_write":
		actions = []string{"s3:PutObject"}
	case "evidence_delete":
		actions = []string{"s3:DeleteObjectVersion"}
	default:
		return nil, ErrObservation
	}
	if !prefix(root) {
		return nil, ErrObservation
	}
	return []minioPermissionRule{{actions, []string{"arn:aws:s3:::" + bucket + "/" + root + "*"}}}, nil
}

// Validate establishes only immutable material consistency. ObserveS3 performs
// the actual server, user, effective-self policy and versioned-bucket reads.
func ValidateS3Profile(c S3Profile) error {
	if c.Version != "original-six-reference-s3-profile.v1" || c.Installation == "" || c.Installation != c.Evidence.Installation || c.Evidence.Endpoint != c.Provider.Endpoint || c.Evidence.Region != c.Provider.Region || c.Evidence.CASHA256 != c.Provider.CASHA256 || hash(c.Evidence.CAPEM) != c.Evidence.CASHA256 || !digest.MatchString(c.Evidence.Identity) || c.Evidence.Version == "" || c.Evidence.Version == "current" || c.Evidence.Version == "latest" || c.Evidence.Root == "" || strings.HasSuffix(c.Evidence.Root, "/") || len(c.Principals) != 4 || c.Observer.Purpose != "metadata_observer" {
		return ErrObservation
	}
	for _, bucket := range []string{c.UploadBucket, c.Evidence.Bucket} {
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`).MatchString(bucket) || strings.Contains(bucket, "..") {
			return ErrObservation
		}
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`).MatchString(c.Provider.Region) {
		return ErrObservation
	}
	if c.UploadBucket == c.Evidence.Bucket {
		evidenceRoot := c.Evidence.Root + "/" + c.Installation + "/"
		for _, uploadRoot := range []string{c.UploadRoot, c.UploadStagingRoot} {
			if strings.HasPrefix(uploadRoot, evidenceRoot) || strings.HasPrefix(evidenceRoot, uploadRoot) {
				return ErrObservation
			}
		}
	}
	seen := map[string]bool{}
	accounts := map[string]bool{}
	files := map[string]bool{}
	for _, p := range append([]Principal{c.Observer}, c.Principals...) {
		if !digest.MatchString(p.AccountSHA256) || !digest.MatchString(p.PolicySHA256) || !name.MatchString(p.PolicyName) || seen[p.Purpose] || accounts[p.AccountSHA256] || files[p.Credential.File] || !filepath.IsAbs(p.Credential.File) || !digest.MatchString(p.Credential.SHA256) {
			return ErrObservation
		}
		seen[p.Purpose] = true
		accounts[p.AccountSHA256] = true
		files[p.Credential.File] = true
		if p.Purpose != "metadata_observer" {
			if _, e := rules(p, c); e != nil {
				return e
			}
		}
	}
	for _, purpose := range []string{"artifact_upload_issuer", "evidence_read", "evidence_write", "evidence_delete"} {
		if !seen[purpose] {
			return ErrObservation
		}
	}
	return nil
}

func uploadBinding(c S3Profile) error {
	raw, e := ReadPinned(c.UploadMaterials, 65536)
	if e != nil {
		return e
	}
	defer clear(raw)
	if minioPermissionUniqueJSON(raw) != nil {
		return ErrObservation
	}
	var m struct {
		Version      string `json:"schema_version"`
		Installation string `json:"installation_id"`
		Endpoint     string `json:"endpoint"`
		Region       string `json:"region"`
		Bucket       string `json:"bucket"`
		Root         string `json:"root"`
		Staging      string `json:"remote_staging_root"`
		CAFile       string `json:"ca_file"`
		CASHA        string `json:"ca_sha256"`
		WriteFile    string `json:"write_credential_file"`
		WriteSHA     string `json:"write_credential_sha256"`
	}
	if json.Unmarshal(raw, &m) != nil || m.Version != "system-backup-native-publication-s3.v1" || m.Installation != c.Installation || m.Endpoint != c.Provider.Endpoint || m.Region != c.Provider.Region || m.Bucket != c.UploadBucket || m.Root != c.UploadRoot || m.Staging != c.UploadStagingRoot || m.CAFile != c.Provider.CAFile || m.CASHA != c.Provider.CASHA256 {
		return ErrObservation
	}
	for _, p := range c.Principals {
		if p.Purpose == "artifact_upload_issuer" && (p.Credential.File != m.WriteFile || p.Credential.SHA256 != m.WriteSHA) {
			return ErrObservation
		}
	}
	return nil
}

func observeS3Pass(ctx context.Context, c S3Profile, creds []nativePublicationCredential) (string, error) {
	r, e := newMinioPermissionHTTP(c.Provider, creds[0])
	if e != nil {
		return "", e
	}
	defer r.close()
	server, e := r.serverSeptember(ctx)
	if e != nil {
		return "", e
	}
	stamps := []string{server}
	buckets := []string{c.UploadBucket}
	if c.Evidence.Bucket != c.UploadBucket {
		buckets = append(buckets, c.Evidence.Bucket)
	}
	sort.Strings(buckets)
	arns := []string{}
	for _, b := range buckets {
		arns = append(arns, "arn:aws:s3:::"+b)
	}
	observerRules := []minioPermissionRule{{[]string{"admin:GetUser", "admin:GetPolicy", "admin:ServerInfo"}, []string{"*"}}, {[]string{"s3:GetBucketPolicy", "s3:GetBucketVersioning"}, arns}}
	principals := append([]Principal{c.Observer}, c.Principals...)
	for n, p := range principals {
		want := observerRules
		bucket := c.Evidence.Bucket
		if n > 0 {
			want, e = rules(p, c)
			if e != nil {
				return "", e
			}
			if p.Purpose == "artifact_upload_issuer" {
				bucket = c.UploadBucket
			}
		}
		if hash([]byte(creds[n].AccessKey)) != p.AccountSHA256 {
			return "", ErrObservation
		}
		stamp, e := r.userAndPolicyV2(ctx, creds[n].AccessKey, p.PolicyName, p.PolicySHA256, want)
		if e != nil {
			return "", e
		}
		stamps = append(stamps, stamp)
		self, e := minioEffectiveSelfWithOwnerGuardV2(ctx, c.Provider, creds[n], p.AccountSHA256, p.PolicySHA256, bucket, want)
		if e != nil {
			return "", e
		}
		stamps = append(stamps, self)
	}
	for _, b := range buckets {
		stamp, e := r.bucket(ctx, b)
		if e != nil {
			return "", e
		}
		stamps = append(stamps, stamp)
	}
	raw, e := ce.Canonical(stamps)
	if e != nil {
		return "", e
	}
	return hash(raw), nil
}

func ObserveS3(ctx context.Context, kube kubernetes.Interface, c S3Profile) (*S3Observation, error) {
	if ctx == nil || ctx.Err() != nil || kube == nil || c.Namespace == "" || c.NamespaceUID == "" || ValidateS3Profile(c) != nil {
		return nil, ErrObservation
	}
	// Freeze all slice data before I/O. The freshness interval starts now,
	// never after completion and never gets renewed by a later recheck.
	raw, e := json.Marshal(c)
	if e != nil {
		return nil, ErrObservation
	}
	var frozen S3Profile
	if json.Unmarshal(raw, &frozen) != nil {
		return nil, ErrObservation
	}
	c = frozen
	started := time.Now().UTC().Truncate(time.Microsecond)
	until := started.Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	creds := []nativePublicationCredential{}
	defer func() {
		for n := range creds {
			creds[n] = nativePublicationCredential{}
		}
	}()
	for _, p := range append([]Principal{c.Observer}, c.Principals...) {
		key, e := credential(p.Credential)
		if e != nil || started.Before(key.NotBefore) || !started.Before(key.Until) {
			return nil, ErrObservation
		}
		if key.Until.Before(until) {
			until = key.Until
		}
		creds = append(creds, key)
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if uploadBinding(c) != nil {
		return nil, ErrObservation
	}
	chain, e := minioPermissionKubernetes(ctx, kube, minioPermissionConfiguration{c.Namespace, c.NamespaceUID}, c.Provider)
	if e != nil {
		return nil, ErrObservation
	}
	a, e := observeS3Pass(ctx, c, creds)
	if e != nil {
		return nil, ErrObservation
	}
	b, e := observeS3Pass(ctx, c, creds)
	if e != nil || a != b {
		return nil, ErrObservation
	}
	chainTail, e := minioPermissionKubernetes(ctx, kube, minioPermissionConfiguration{c.Namespace, c.NamespaceUID}, c.Provider)
	if e != nil || chain != chainTail || ctx.Err() != nil || !time.Now().Before(until) || RecheckS3Files(c) != nil {
		return nil, ErrObservation
	}
	identity, _ := ce.Canonical([]string{chain, a})
	o := &S3Observation{identity: hash(identity), started: started, until: until}
	o.origin = o
	return o, nil
}

func RecheckS3Files(c S3Profile) error {
	if ValidateS3Profile(c) != nil || uploadBinding(c) != nil {
		return ErrObservation
	}
	for _, p := range append([]Principal{c.Observer}, c.Principals...) {
		raw, e := ReadPinned(p.Credential, 16384)
		clear(raw)
		if e != nil {
			return e
		}
	}
	raw, e := ReadPinned(FilePin{c.Provider.CAFile, c.Provider.CASHA256}, 65536)
	if e != nil {
		return e
	}
	defer clear(raw)
	if !bytes.Equal(raw, c.Evidence.CAPEM) {
		return ErrObservation
	}
	return nil
}

// Retained only by the copied April native helper; the actual observer above
// accepts exclusively the separately pinned September server contract.
const minioPermissionVersion = "2025-04-22T22:12:26Z"
const minioPermissionCommit = "0d7408fc9969caf07de6a8c3a84f9fbb10a6739e"
