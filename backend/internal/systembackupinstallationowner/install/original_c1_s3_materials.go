package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	ev "clawreef/internal/systembackupevidence"
	probe "clawreef/internal/systembackupreferenceprobe"
)

const originalC1S3Domain = "original-enrolled-c1-s3-material.v1\x00"
const originalC1MCRelease = "RELEASE.2025-08-13T08-35-41Z"

type OriginalC1S3Inputs struct {
	CreateFreshBuckets                                                                         bool
	Version                                                                                    string
	ProviderDefinition, RootCredential, MC                                                     BootstrapSourceFilePin
	OutputDirectory, UploadBucket, UploadRoot, UploadStagingRoot, EvidenceBucket, EvidenceRoot string
	Until                                                                                      time.Time
}
type originalC1S3Provider struct {
	Version, Installation, Namespace, NamespaceUID string
	Provider                                       probe.MinIOProvider
}
type originalC1S3Credential struct {
	AccessKey    string    `json:"access_key"`
	SecretKey    string    `json:"secret_key"`
	SessionToken string    `json:"session_token"`
	NotBefore    time.Time `json:"not_before"`
	Until        time.Time `json:"until"`
}
type originalC1S3Material struct {
	Version, PlanSHA256, EnrollmentSHA256                         string
	Source                                                        OriginalC1S3Inputs
	Profile, UploadMaterials, ChannelCredentials, ChannelMaterial BootstrapSourceFilePin
	ChannelPrincipal                                              probe.Principal
	ObservedAt, Until                                             time.Time
}
type OriginalC1S3Receipt struct {
	Version, State                                                                       string
	Material, Signature, S3Profile, UploadMaterials, ChannelCredentials, ChannelMaterial BootstrapSourceFilePin
	ChannelPrincipal                                                                     probe.Principal
	ObservedAt, Until                                                                    time.Time
}
type originalC1S3Upload struct {
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
type originalC1IAMStatement struct {
	Action   []string
	Effect   string
	Resource []string
}

// Policy hashes use the same sorted-set/statement normalization as the real
// native probe. None of these local values is accepted as native success.
func originalC1S3Policy(purpose string, c probe.S3Profile) ([]byte, error) {
	var statements []originalC1IAMStatement
	resource := "arn:aws:s3:::" + c.Evidence.Bucket + "/" + c.Evidence.Root + "/" + c.Installation + "/*"
	switch purpose {
	case "metadata_observer":
		buckets := []string{"arn:aws:s3:::" + c.UploadBucket}
		if c.Evidence.Bucket != c.UploadBucket {
			buckets = append(buckets, "arn:aws:s3:::"+c.Evidence.Bucket)
		}
		sort.Strings(buckets)
		statements = []originalC1IAMStatement{{[]string{"admin:GetPolicy", "admin:GetUser", "admin:ServerInfo"}, "Allow", []string{"*"}}, {[]string{"s3:GetBucketPolicy", "s3:GetBucketVersioning"}, "Allow", buckets}}
	case "artifact_upload_issuer":
		resources := []string{"arn:aws:s3:::" + c.UploadBucket + "/" + c.UploadRoot + "*", "arn:aws:s3:::" + c.UploadBucket + "/" + c.UploadStagingRoot + "*"}
		sort.Strings(resources)
		statements = []originalC1IAMStatement{{[]string{"s3:PutObject"}, "Allow", resources}}
	case "evidence_read":
		statements = []originalC1IAMStatement{{[]string{"s3:GetObjectVersion"}, "Allow", []string{resource}}}
	case "evidence_write":
		statements = []originalC1IAMStatement{{[]string{"s3:PutObject"}, "Allow", []string{resource}}}
	case "evidence_delete":
		statements = []originalC1IAMStatement{{[]string{"s3:DeleteObjectVersion"}, "Allow", []string{resource}}}
	default:
		return nil, ErrInstall
	}
	sort.Slice(statements, func(i, j int) bool {
		a, _ := canonical(statements[i])
		b, _ := canonical(statements[j])
		return bytes.Compare(a, b) < 0
	})
	return canonical(struct {
		Statement []originalC1IAMStatement
		Version   string
	}{statements, "2012-10-17"})
}

type originalC1MCBuffer struct{ bytes.Buffer }

func (b *originalC1MCBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 262144 {
		return 0, io.ErrShortBuffer
	}
	return b.Buffer.Write(p)
}
func originalC1MCPin(pin BootstrapSourceFilePin) error {
	if !bootstrapSourcePinValid(pin) {
		return ErrInstall
	}
	st, e := os.Lstat(pin.File)
	if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 128<<20 || st.Mode().Perm()&0022 != 0 {
		return ErrInstall
	}
	f, e := os.Open(pin.File)
	if e != nil {
		return ErrInstall
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(st, opened) {
		return ErrInstall
	}
	raw, e := io.ReadAll(io.LimitReader(f, (128<<20)+1))
	defer clear(raw)
	after, se := f.Stat()
	path, pe := os.Lstat(pin.File)
	if e != nil || se != nil || pe != nil || !os.SameFile(opened, after) || !os.SameFile(after, path) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || hash(raw) != pin.SHA256 {
		return ErrInstall
	}
	return nil
}

// ProduceOriginalC1S3Material is PRE-config installation, with actual local
// admin + Kube enrollment and native original root. It creates only fresh
// random principals/policies. A partial native write is retained for inspection,
// never overwritten, completed by query, silently rolled back or reissued.
func (i *Installer) ProduceOriginalC1S3Material(ctx context.Context, password []byte, enrollment EnrollmentPin, in OriginalC1S3Inputs, issuerPrivate []byte) (receipt OriginalC1S3Receipt, resultErr error) {
	receipt = OriginalC1S3Receipt{Version: "original-c1-s3-result.v1", State: "rejected_before_native_write"}
	if i == nil || ctx == nil || in.Version != "original-c1-s3-inputs.v1" || privateDirectory(in.OutputDirectory) != nil {
		return receipt, ErrInstall
	}
	entries, e := os.ReadDir(in.OutputDirectory)
	if e != nil || len(entries) != 0 {
		return receipt, ErrInstall
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil {
		return receipt, ErrInstall
	}
	state, now, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if e != nil || state.cas != (HeadCAS{}) || !now.Before(in.Until) || in.Until.Sub(now) > 10*time.Minute {
		return receipt, ErrInstall
	}
	issuer, e := op.privateKey(issuerPrivate)
	if e != nil {
		return receipt, ErrInstall
	}
	defer clear(issuer)
	raw, e := readBootstrapSourcePin(in.ProviderDefinition, 262144)
	var d originalC1S3Provider
	if e != nil || decodeExact(raw, &d) != nil || d.Version != "original-minio-source-provider-input.v1" || d.Installation != i.plan.Target.InstallationID || d.Namespace != i.plan.Target.Namespace || d.NamespaceUID != i.plan.Target.NamespaceUID {
		return receipt, ErrInstall
	}
	rootRaw, e := readBootstrapSourcePin(in.RootCredential, 16384)
	if e != nil {
		return receipt, ErrInstall
	}
	defer clear(rootRaw)
	var root probe.OriginalS3OwnerCredential
	if decodeExact(rootRaw, &root) != nil || root.Version == "" || len(root.SecretKey) < 8 || now.Before(root.NotBefore) || !now.Before(root.Until) {
		return receipt, ErrInstall
	}
	defer clear(root.SecretKey)
	until := minTime(in.Until, minTime(op.until, root.Until))
	if !now.Before(until) {
		return receipt, ErrInstall
	}
	// Authenticate under the exact caller context; do not replace the context
	// retained by authenticatedOperator with a new timeout wrapper.
	auth := func() error {
		current, t, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
		if e != nil || current.cas != state.cas || !t.Before(until) || !time.Now().Before(until) {
			return ErrInstall
		}
		for _, pin := range []BootstrapSourceFilePin{in.ProviderDefinition, in.RootCredential} {
			b, e := readBootstrapSourcePin(pin, 262144)
			clear(b)
			if e != nil {
				return ErrInstall
			}
		}
		return nil
	}
	if auth() != nil || probe.ObserveOriginalS3OwnerTarget(ctx, i.kube, d.Namespace, d.NamespaceUID, d.Provider, probe.FilePin{File: in.RootCredential.File, SHA256: in.RootCredential.SHA256}) != nil || originalC1MCPin(in.MC) != nil {
		return receipt, ErrInstall
	}
	ca, e := probe.ReadPinned(probe.FilePin{File: d.Provider.CAFile, SHA256: d.Provider.CASHA256}, 65536)
	if e != nil {
		return receipt, ErrInstall
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return receipt, ErrInstall
	}
	id := hex.EncodeToString(nonce[:])
	c := probe.S3Profile{Version: "original-six-reference-s3-profile.v1", Installation: d.Installation, Namespace: d.Namespace, NamespaceUID: d.NamespaceUID, Provider: d.Provider, UploadBucket: in.UploadBucket, UploadRoot: in.UploadRoot, UploadStagingRoot: in.UploadStagingRoot, Evidence: ev.S3Config{Endpoint: d.Provider.Endpoint, Region: d.Provider.Region, Bucket: in.EvidenceBucket, Root: in.EvidenceRoot, Installation: d.Installation, Version: "c1-" + id, CAPEM: ca, CASHA256: d.Provider.CASHA256}}
	identity, _ := canonical(struct {
		Provider                   probe.MinIOProvider
		Installation, Bucket, Root string
	}{d.Provider, d.Installation, in.EvidenceBucket, in.EvidenceRoot})
	c.Evidence.Identity = hash(identity)
	files := map[string][]byte{}
	credentials := map[string]originalC1S3Credential{}
	purposes := []string{"metadata_observer", "artifact_upload_issuer", "evidence_read", "evidence_write", "evidence_delete"}
	for n, purpose := range purposes {
		var secret [32]byte
		if _, e = rand.Read(secret[:]); e != nil {
			return receipt, ErrInstall
		}
		account := "c1_" + id + "_" + string(rune('a'+n))
		cred := originalC1S3Credential{AccessKey: account, SecretKey: hex.EncodeToString(secret[:]), NotBefore: now, Until: until}
		clear(secret[:])
		credentials[purpose] = cred
		b, e := canonical(cred)
		if e != nil {
			return receipt, ErrInstall
		}
		files[purpose+".credential.json"] = b
		policy, e := originalC1S3Policy(purpose, c)
		if e != nil {
			return receipt, ErrInstall
		}
		files[purpose+".policy.json"] = policy
		p := probe.Principal{Purpose: purpose, AccountSHA256: hash([]byte(account)), PolicyName: "c1_" + id + "_p" + string(rune('a'+n)), PolicySHA256: hash(policy), Credential: probe.FilePin{File: filepath.Join(in.OutputDirectory, purpose+".credential.json"), SHA256: hash(b)}}
		if n == 0 {
			c.Observer = p
		} else {
			c.Principals = append(c.Principals, p)
		}
	}
	defer func() {
		for _, b := range files {
			clear(b)
		}
		clear(credentials)
	}()
	if probe.ValidateS3Profile(c) != nil {
		return receipt, ErrInstall
	}
	// Sixth account is independent of the generic exact-four S3 profile.
	var channelSecret [32]byte
	if _, e = rand.Read(channelSecret[:]); e != nil {
		return receipt, ErrInstall
	}
	channelCredential := originalC1S3Credential{AccessKey: "c1_" + id + "_f", SecretKey: hex.EncodeToString(channelSecret[:]), NotBefore: now, Until: until}
	clear(channelSecret[:])
	credentials["c1_channel_upstream"] = channelCredential
	channelRaw, e := canonical(channelCredential)
	if e != nil {
		return receipt, ErrInstall
	}
	files["c1_channel_upstream.credential.json"] = channelRaw
	channelPolicy, e := probe.OriginalS3ChannelPolicy(c)
	if e != nil {
		return receipt, ErrInstall
	}
	files["c1_channel_upstream.policy.json"] = channelPolicy
	channel := probe.Principal{Purpose: "c1_channel_upstream", AccountSHA256: hash([]byte(channelCredential.AccessKey)), PolicyName: "c1_" + id + "_pf", PolicySHA256: hash(channelPolicy), Credential: probe.FilePin{File: filepath.Join(in.OutputDirectory, "c1_channel_upstream.credential.json"), SHA256: hash(channelRaw)}}
	channelTransport, e := probe.OriginalS3ChannelCredentials(channelRaw)
	if e != nil {
		return receipt, ErrInstall
	}
	files["c1-channel.credentials.json"] = channelTransport
	channelPin := BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "c1-channel.credentials.json"), SHA256: hash(channelTransport)}
	upload := originalC1S3Upload{Version: "system-backup-native-publication-s3.v1", Installation: c.Installation, Endpoint: c.Provider.Endpoint, Region: c.Provider.Region, Bucket: c.UploadBucket, Root: c.UploadRoot, Staging: c.UploadStagingRoot, CAFile: c.Provider.CAFile, CASHA: c.Provider.CASHA256, WriteFile: c.Principals[0].Credential.File, WriteSHA: c.Principals[0].Credential.SHA256}
	ub, e := canonical(upload)
	if e != nil {
		return receipt, ErrInstall
	}
	files["c1-upload.materials.json"] = ub
	c.UploadMaterials = probe.FilePin{File: filepath.Join(in.OutputDirectory, "c1-upload.materials.json"), SHA256: hash(ub)}
	profile, e := canonical(c)
	if e != nil {
		return receipt, ErrInstall
	}
	files["c1-s3.profile.json"] = profile
	intent, e := canonical(struct {
		Version            string
		Source             OriginalC1S3Inputs
		Profile            probe.S3Profile
		ChannelPrincipal   probe.Principal
		ChannelCredentials BootstrapSourceFilePin
		Until              time.Time
	}{"original-c1-s3-intent.v1", in, c, channel, channelPin, until})
	if e != nil {
		return receipt, ErrInstall
	}
	files["c1-s3.intent.json"] = intent
	if auth() != nil || writeNewFiles(in.OutputDirectory, files) != nil {
		return receipt, ErrInstall
	}
	mcDir := filepath.Join(in.OutputDirectory, "mc-private")
	certDir := filepath.Join(mcDir, "certs")
	if os.Mkdir(mcDir, 0700) != nil || os.Mkdir(certDir, 0700) != nil || os.Mkdir(filepath.Join(certDir, "CAs"), 0700) != nil || writeNewFiles(filepath.Join(certDir, "CAs"), map[string][]byte{"original.pem": ca}) != nil {
		return receipt, ErrInstall
	}
	endpoint, e := url.Parse(d.Provider.Endpoint)
	if e != nil || endpoint.Scheme != "https" || endpoint.User != nil {
		return receipt, ErrInstall
	}
	endpoint.User = url.UserPassword(root.AccessKey, string(root.SecretKey))
	environment := []string{"MC_HOST_original=" + endpoint.String()}
	for _, name := range []string{"SystemRoot", "WINDIR", "TEMP", "TMP"} {
		if value := os.Getenv(name); value != "" {
			environment = append(environment, name+"="+value)
		}
	}
	run := func(args ...string) ([]map[string]json.RawMessage, error) {
		if auth() != nil || originalC1MCPin(in.MC) != nil {
			return nil, ErrInstall
		}
		b, e := probe.ReadPinned(probe.FilePin{File: d.Provider.CAFile, SHA256: d.Provider.CASHA256}, 65536)
		if e != nil || !bytes.Equal(b, ca) {
			return nil, ErrInstall
		}
		child, cancel := context.WithDeadline(ctx, until)
		defer cancel()
		child, cancel2 := context.WithTimeout(child, 30*time.Second)
		defer cancel2()
		command := append([]string{"--json", "--config-dir", mcDir, "--certs-dir", certDir}, args...)
		cmd := exec.CommandContext(child, in.MC.File, command...)
		cmd.Env = environment
		var output originalC1MCBuffer
		cmd.Stdout = &output
		cmd.Stderr = io.Discard
		if cmd.Run() != nil || auth() != nil || originalC1MCPin(in.MC) != nil {
			return nil, ErrInstall
		}
		var result []map[string]json.RawMessage
		decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
		for len(result) < 512 {
			var row map[string]json.RawMessage
			e := decoder.Decode(&row)
			if e == io.EOF {
				return result, nil
			}
			var status string
			if e != nil || json.Unmarshal(row["status"], &status) != nil || status != "success" {
				return nil, ErrInstall
			}
			result = append(result, row)
		}
		return nil, ErrInstall
	}
	var version originalC1MCBuffer
	cmd := exec.CommandContext(ctx, in.MC.File, "--version")
	cmd.Env = environment
	cmd.Stdout = &version
	cmd.Stderr = io.Discard
	if cmd.Run() != nil || !strings.HasPrefix(version.String(), "mc version "+originalC1MCRelease+" ") || originalC1MCPin(in.MC) != nil {
		return receipt, ErrInstall
	}
	users, e := run("admin", "user", "list", "original")
	if e != nil {
		return receipt, ErrInstall
	}
	policies, e := run("admin", "policy", "list", "original")
	if e != nil {
		return receipt, ErrInstall
	}
	for _, row := range users {
		var account string
		if json.Unmarshal(row["accessKey"], &account) != nil || account == "" {
			return receipt, ErrInstall
		}
		for _, cred := range credentials {
			if account == cred.AccessKey {
				return receipt, ErrInstall
			}
		}
	}
	for _, row := range policies {
		var name string
		if json.Unmarshal(row["policy"], &name) != nil || name == "" {
			return receipt, ErrInstall
		}
		for _, p := range append(append([]probe.Principal{c.Observer}, c.Principals...), channel) {
			if name == p.PolicyName {
				return receipt, ErrInstall
			}
		}
	}
	// Existing mode requires already-versioned buckets. Fresh mode creates only
	// absent buckets and enables versioning there. Existing buckets are never
	// modified. The NEW observer checks actual versioning and bucket policies.
	nativeWrites := false
	defer func() {
		if resultErr != nil && nativeWrites {
			receipt.State = "partial_native_write_retain_intent_no_reissue"
		}
	}()
	if in.CreateFreshBuckets {
		// A successful complete native listing is required before creation.
		// Existing buckets are never mutated or silently reused in this mode.
		rows, e := run("ls", "original/")
		if e != nil {
			return receipt, ErrInstall
		}
		existing := map[string]bool{}
		for _, row := range rows {
			var key, kind string
			if json.Unmarshal(row["key"], &key) != nil || json.Unmarshal(row["type"], &kind) != nil || kind != "folder" || !strings.HasSuffix(key, "/") {
				return receipt, ErrInstall
			}
			existing[strings.TrimSuffix(key, "/")] = true
		}
		buckets := []string{c.UploadBucket}
		if c.Evidence.Bucket != c.UploadBucket {
			buckets = append(buckets, c.Evidence.Bucket)
		}
		for _, bucket := range buckets {
			if existing[bucket] {
				return receipt, ErrInstall
			}
		}
		for _, bucket := range buckets {
			nativeWrites = true
			if _, e = run("mb", "--region", c.Provider.Region, "original/"+bucket); e != nil {
				return receipt, ErrCommitUnknown
			}
			if _, e = run("version", "enable", "original/"+bucket); e != nil {
				return receipt, ErrCommitUnknown
			}
		}
	}
	for _, p := range append(append([]probe.Principal{c.Observer}, c.Principals...), channel) {
		cred := credentials[p.Purpose]
		if cred.AccessKey == root.AccessKey {
			return receipt, ErrInstall
		}
		nativeWrites = true
		if _, e = run("admin", "policy", "create", "original", p.PolicyName, filepath.Join(in.OutputDirectory, p.Purpose+".policy.json")); e != nil {
			return receipt, ErrCommitUnknown
		}
		if auth() != nil || probe.CreateOriginalS3Principal(ctx, i.kube, d.Namespace, d.NamespaceUID, d.Provider, probe.FilePin{File: in.RootCredential.File, SHA256: in.RootCredential.SHA256}, p) != nil || auth() != nil {
			return receipt, ErrCommitUnknown
		}
		if _, e = run("admin", "policy", "attach", "original", p.PolicyName, "--user", cred.AccessKey); e != nil {
			return receipt, ErrCommitUnknown
		}
	}
	receipt.State = "native_accounts_created_verification_pending"
	observation, e := probe.ObserveS3(ctx, i.kube, c)
	if e != nil || observation.IdentitySHA256() == "" || auth() != nil {
		return receipt, ErrInstall
	}
	if e = probe.VerifyOriginalS3NativeOperations(ctx, c, channel, probe.FilePin{File: in.RootCredential.File, SHA256: in.RootCredential.SHA256}); e != nil {
		return receipt, ErrInstall
	}
	observation, e = probe.ObserveS3(ctx, i.kube, c)
	if e != nil || observation.IdentitySHA256() == "" || auth() != nil {
		return receipt, ErrInstall
	}
	// Data selection is created only after all actual native checks above.
	// It introduces no new authority or TTL; the existing owner signs its pin.
	selection, e := originalC1S3ChannelSelection(c, channel, channelPin, until)
	if e != nil {
		return receipt, ErrInstall
	}
	selectionPin := BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "c1-channel.material.json"), SHA256: hash(selection)}
	m := originalC1S3Material{Version: "original-c1-s3-material.v1", PlanSHA256: i.planHash, EnrollmentSHA256: enrollment.DocumentSHA256, Source: in, Profile: BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "c1-s3.profile.json"), SHA256: hash(profile)}, UploadMaterials: BootstrapSourceFilePin{File: c.UploadMaterials.File, SHA256: c.UploadMaterials.SHA256}, ChannelPrincipal: channel, ChannelCredentials: channelPin, ChannelMaterial: selectionPin, ObservedAt: observation.StartedAt(), Until: until}
	material, e := canonical(m)
	if e != nil {
		return receipt, ErrInstall
	}
	signature := ed25519.Sign(issuer, append([]byte(originalC1S3Domain), material...))
	if auth() != nil || writeNewFiles(in.OutputDirectory, map[string][]byte{"c1-s3.material.json": material, "c1-s3.material.signature": signature, "c1-channel.material.json": selection}) != nil {
		return receipt, ErrCommitUnknown
	}
	return i.QueryOriginalC1S3Material(ctx, password, enrollment, in.OutputDirectory)
}

// Query is read-only and reauthenticates enrollment/current owner/native ACL.
// It never uses the administrative root or issues/signs/reconstructs a record.
func (i *Installer) QueryOriginalC1S3Material(ctx context.Context, password []byte, enrollment EnrollmentPin, directory string) (OriginalC1S3Receipt, error) {
	zero := OriginalC1S3Receipt{Version: "original-c1-s3-result.v1", State: "missing_or_partial_material_no_reissue"}
	if i == nil || ctx == nil || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	state, now, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if e != nil || state.cas != (HeadCAS{}) {
		return zero, ErrInstall
	}
	raw, e := ReadPrivateFile(filepath.Join(directory, "c1-s3.material.json"), 262144)
	if e != nil {
		return zero, ErrInstall
	}
	signature, e := ReadPrivateFile(filepath.Join(directory, "c1-s3.material.signature"), 64)
	var m originalC1S3Material
	if e != nil || !ed25519.Verify(i.public, append([]byte(originalC1S3Domain), raw...), signature) || decodeExact(raw, &m) != nil || m.Version != "original-c1-s3-material.v1" || m.PlanSHA256 != i.planHash || m.EnrollmentSHA256 != enrollment.DocumentSHA256 || m.Source.OutputDirectory != directory || now.Before(m.ObservedAt) || !now.Before(m.Until) || m.Until.After(m.Source.Until) {
		return zero, ErrInstall
	}
	definition, e := readBootstrapSourcePin(m.Source.ProviderDefinition, 262144)
	var original originalC1S3Provider
	if e != nil || decodeExact(definition, &original) != nil || original.Installation != i.plan.Target.InstallationID || original.Namespace != i.plan.Target.Namespace || original.NamespaceUID != i.plan.Target.NamespaceUID {
		return zero, ErrInstall
	}
	b, e := readBootstrapSourcePin(m.Profile, 262144)
	var c probe.S3Profile
	if e != nil || decodeExact(b, &c) != nil || c.Provider != original.Provider || c.Installation != i.plan.Target.InstallationID || c.Namespace != i.plan.Target.Namespace || c.NamespaceUID != i.plan.Target.NamespaceUID || c.UploadMaterials.File != m.UploadMaterials.File || c.UploadMaterials.SHA256 != m.UploadMaterials.SHA256 {
		return zero, ErrInstall
	}
	observation, e := probe.ObserveS3(ctx, i.kube, c)
	if e != nil || observation.IdentitySHA256() == "" {
		return zero, ErrInstall
	}
	transport, e := readBootstrapSourcePin(m.ChannelCredentials, 16384)
	if e != nil {
		return zero, ErrInstall
	}
	channelRaw, e := probe.ReadPinned(m.ChannelPrincipal.Credential, 16384)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(channelRaw)
	expected, e := probe.OriginalS3ChannelCredentials(channelRaw)
	defer clear(expected)
	defer clear(transport)
	if e != nil || !bytes.Equal(expected, transport) || probe.ObserveOriginalS3Channel(ctx, c, m.ChannelPrincipal) != nil {
		return zero, ErrInstall
	}
	selection, e := readBootstrapSourcePin(m.ChannelMaterial, 262144)
	if e != nil {
		return zero, ErrInstall
	}
	exact, e := originalC1S3ChannelSelection(c, m.ChannelPrincipal, m.ChannelCredentials, m.Until)
	if e != nil || !bytes.Equal(exact, selection) {
		return zero, ErrInstall
	}
	tail, now, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if e != nil || tail.cas != state.cas || !now.Before(m.Until) || !time.Now().Before(m.Until) {
		return zero, ErrInstall
	}
	return OriginalC1S3Receipt{Version: "original-c1-s3-result.v1", State: "original_s3_materials_issued_and_native_reobserved_not_c1_or_adoption", Material: BootstrapSourceFilePin{File: filepath.Join(directory, "c1-s3.material.json"), SHA256: hash(raw)}, Signature: BootstrapSourceFilePin{File: filepath.Join(directory, "c1-s3.material.signature"), SHA256: hash(signature)}, S3Profile: m.Profile, UploadMaterials: m.UploadMaterials, ChannelCredentials: m.ChannelCredentials, ChannelMaterial: m.ChannelMaterial, ChannelPrincipal: m.ChannelPrincipal, ObservedAt: m.ObservedAt, Until: m.Until}, nil
}

// originalC1S3ChannelSelection only serializes native facts already established
// by the real enrolled owner. R24 owns the shared DATA type; this is not an
// authorization constructor. Query requires exact original bytes and bounds.
func originalC1S3ChannelSelection(c probe.S3Profile, p probe.Principal, transport BootstrapSourceFilePin, until time.Time) ([]byte, error) {
	if probe.ValidateS3Profile(c) != nil || p.Purpose != "c1_channel_upstream" || !digestPattern.MatchString(p.AccountSHA256) || !digestPattern.MatchString(p.PolicySHA256) {
		return nil, ErrInstall
	}
	raw, e := probe.ReadPinned(p.Credential, 16384)
	if e != nil {
		return nil, ErrInstall
	}
	defer clear(raw)
	var credential originalC1S3Credential
	if decodeExact(raw, &credential) != nil || hash([]byte(credential.AccessKey)) != p.AccountSHA256 || credential.SessionToken != "" || credential.NotBefore.IsZero() || !credential.NotBefore.Before(until) || until.After(credential.Until) {
		return nil, ErrInstall
	}
	exact, e := probe.OriginalS3ChannelCredentials(raw)
	if e != nil {
		return nil, ErrInstall
	}
	defer clear(exact)
	actual, e := readBootstrapSourcePin(transport, 16384)
	if e != nil {
		return nil, ErrInstall
	}
	defer clear(actual)
	if !bytes.Equal(exact, actual) {
		return nil, ErrInstall
	}
	identity, e := canonical(struct{ Purpose, Installation, ProviderDeploymentID, Endpoint, Bucket, Root, AccountSHA256, PolicySHA256 string }{"original-c1-channel-upstream", c.Installation, c.Provider.DeploymentID, c.Provider.Endpoint, c.Evidence.Bucket, c.Evidence.Root, p.AccountSHA256, p.PolicySHA256})
	if e != nil {
		return nil, ErrInstall
	}
	selection := OriginalC1ChannelMaterialSelection{Version: "original-c1-channel-native-material.v1", Store: c.Evidence, Write: ev.KeyRef{Identity: hash(identity), Version: "c1-channel-" + p.Credential.SHA256[:32]}, Credentials: transport, NotBefore: credential.NotBefore, Until: until}
	return canonical(selection)
}
