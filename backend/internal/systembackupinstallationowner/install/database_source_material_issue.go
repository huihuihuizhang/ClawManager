package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/worker"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const DatabaseSourceIssueVersion = "original-database-source-issue.v1"

// Independently selected ORIGINAL source data. The concrete issuer capability
// comes from real PrepareSourceMaterialIssue/Begin, never from this JSON.
// Source.Mount.Issuer is compared to the enrolled public pin, not self-trusted.
type DatabaseSourceIssueDefinition struct {
	Version, OriginalDefinitionSHA256, Account string
	Service, ServiceUID                        string
	Port                                       int
	Source                                     worker.FormalSourceMount
}

type DatabaseSourceIssueResult struct {
	Version, DefinitionSHA256, ScopeSHA256 string
	Source                                 worker.FormalSourceMount
	NotBefore, Until                       time.Time
}

// IssueDatabaseSource observes actual original Service + TLS MySQL finite
// account and complete native census before signing this exact DB delegation.
// It is deliberately separate from SignWorkerSource (Redis/Skill only).
// No SQL write, privilege change, enabled config, task or readiness is created.
// Native observation runs outside every control-plane SQL transaction/lock.
func (p *SourceMaterialIssuer) IssueDatabaseSource(ctx context.Context, definitionFile, definitionSHA256 string, issuerPrivate []byte) (DatabaseSourceIssueResult, error) {
	var zero DatabaseSourceIssueResult
	if p == nil || p.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	raw, err := ReadSourceMaterialFile(definitionFile)
	var d DatabaseSourceIssueDefinition
	if err != nil || len(raw) > 262144 || hash(raw) != definitionSHA256 || decodeExact(raw, &d) != nil || d.Version != DatabaseSourceIssueVersion || d.OriginalDefinitionSHA256 != p.intent.DefinitionSHA256 || !bytes.Equal(d.Source.Issuer, p.operator.installer.public) || d.Source.GrantSHA256 != "" || d.Source.Redis != nil || d.Source.Objects != nil || d.Source.RedisScope != nil || len(d.Source.ObjectPrefixes) != 0 || len(d.Source.RedisPrefixes) != 0 || len(d.Source.RedisExcludedPrefixes) != 0 || !digestPattern.MatchString(d.Source.CredentialSHA256) || !filepath.IsAbs(d.Source.GrantFile) || filepath.Clean(d.Source.GrantFile) != d.Source.GrantFile || d.Source.GrantFile == definitionFile || d.Source.GrantFile == p.intent.DefinitionFile || d.Source.GrantFile == d.Source.CredentialFile {
		return zero, ErrInstall
	}
	request, err := p.originalDatabaseSourceRequest()
	if err != nil {
		return zero, ErrInstall
	}
	scope, err := worker.FormalSourceScopeSHA256(worker.Invocation{Request: request}, d.Source)
	if err != nil {
		return zero, ErrInstall
	}
	credentialRaw, err := ReadPrivateFile(d.Source.CredentialFile, 16384)
	if err != nil || hash(credentialRaw) != d.Source.CredentialSHA256 {
		clear(credentialRaw)
		return zero, ErrInstall
	}
	defer clear(credentialRaw)
	var credential worker.DatabaseCredential
	decoder := json.NewDecoder(bytes.NewReader(credentialRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&credential) != nil || decoder.Decode(new(any)) != io.EOF {
		clear(credential.Password)
		return zero, ErrInstall
	}
	defer clear(credential.Password)
	canonicalCredential, err := json.Marshal(credential)
	if err != nil || !bytes.Equal(canonicalCredential, credentialRaw) || credential.Username == "" || credential.Username == "root" || len(credential.Password) == 0 || len(credential.Password) > 4096 || !strings.HasPrefix(d.Account, credential.Username+"@") || d.Account == p.operator.installer.plan.InstallerDatabaseAccount || d.Account == p.intent.DatabaseAccount {
		clear(canonicalCredential)
		return zero, ErrInstall
	}
	clear(canonicalCredential)
	if p.databaseSourceService(ctx, d, request) != nil {
		return zero, ErrInstall
	}
	// All native SQL connection creation, identity/grant reads and definer
	// census calls complete and close before control owner Recheck reacquires
	// its original admin/head prefix. No source callback supplied by a caller.
	freshUntil, err := observeDatabaseSource(ctx, d, request, credential, p.intent.NotBefore, p.intent.Until)
	if err != nil {
		return zero, ErrInstall
	}
	if p.databaseSourceService(ctx, d, request) != nil || p.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	if current, err := ReadSourceMaterialFile(definitionFile); err != nil || hash(current) != definitionSHA256 {
		return zero, ErrInstall
	}
	currentCredential, err := ReadPrivateFile(d.Source.CredentialFile, 16384)
	credentialUnchanged := err == nil && hash(currentCredential) == d.Source.CredentialSHA256
	clear(currentCredential)
	if !credentialUnchanged || ctx.Err() != nil {
		return zero, ErrInstall
	}
	key, err := p.operator.privateKey(issuerPrivate)
	if err != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	grant := worker.FormalSourceGrant{Version: worker.FormalSourceGrantVersion, InstallationID: p.intent.InstallationID, ConfigSHA256: p.intent.ConfigSHA256, WorkerNamespace: p.intent.Namespace, WorkerServiceAccountUID: p.intent.WorkerServiceAccountUID, Operation: "capture-database", ScopeSHA256: scope, CredentialSHA256: d.Source.CredentialSHA256, NotBefore: p.intent.NotBefore, Until: p.intent.Until}
	record, err := json.Marshal(grant)
	if err != nil {
		return zero, ErrInstall
	}
	signed, err := json.Marshal(worker.SignedFormalSourceGrant{Record: record, Signature: ed25519.Sign(key, append([]byte(worker.FormalSourceGrantDomain), record...))})
	if err != nil || p.Recheck(ctx) != nil || !time.Now().Before(freshUntil) {
		return zero, ErrInstall
	}
	if writeDatabaseSourceGrant(d.Source.GrantFile, signed) != nil {
		return zero, ErrInstall
	}
	actual, err := ReadSourceMaterialFile(d.Source.GrantFile)
	if err != nil || !bytes.Equal(actual, signed) || p.Recheck(ctx) != nil || !time.Now().Before(freshUntil) {
		return zero, ErrInstall
	}
	if current, err := ReadSourceMaterialFile(definitionFile); err != nil || hash(current) != definitionSHA256 {
		return zero, ErrInstall
	}
	currentCredential, err = ReadPrivateFile(d.Source.CredentialFile, 16384)
	credentialUnchanged = err == nil && hash(currentCredential) == d.Source.CredentialSHA256
	clear(currentCredential)
	if !credentialUnchanged {
		return zero, ErrInstall
	}
	d.Source.GrantSHA256 = hash(signed)
	if ctx.Err() != nil || time.Now().Before(p.intent.NotBefore) || !time.Now().Before(p.intent.Until) || !time.Now().Before(freshUntil) {
		return zero, ErrInstall
	}
	return DatabaseSourceIssueResult{Version: "original-database-source-issued.v1", DefinitionSHA256: definitionSHA256, ScopeSHA256: scope, Source: d.Source, NotBefore: grant.NotBefore, Until: grant.Until}, nil
}

func (p *SourceMaterialIssuer) originalDatabaseSourceRequest() (worker.Request, error) {
	var zero worker.Request
	raw, err := ReadSourceMaterialFile(p.intent.DefinitionFile)
	if err != nil || hash(raw) != p.intent.DefinitionSHA256 {
		return zero, ErrInstall
	}
	// Original production definitions use Go struct canonical order, while
	// installer issue inputs use JCS. Validate JSON/duplicate keys, then extract
	// only the exact ORIGINAL DB operation; do not reinterpret either codec.
	canonicalJSON, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return zero, ErrInstall
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(canonicalJSON, &top) != nil {
		return zero, ErrInstall
	}
	check := func(key, expected string) bool {
		var actual string
		return json.Unmarshal(top[key], &actual) == nil && actual == expected
	}
	if !check("Version", "original-six-part-source-material-definition.v1") || !check("ConfigSHA256", p.intent.ConfigSHA256) || !check("CoreSHA256", p.intent.DeploymentConfigSHA256) || !check("ForwardGrantSHA256", p.intent.CaptureGrantSHA256) {
		return zero, ErrInstall
	}
	var materials map[string]json.RawMessage
	if json.Unmarshal(top["Materials"], &materials) != nil {
		return zero, ErrInstall
	}
	var operations map[string]json.RawMessage
	if json.Unmarshal(materials["Operations"], &operations) != nil {
		return zero, ErrInstall
	}
	var operation map[string]json.RawMessage
	if json.Unmarshal(operations["capture-database"], &operation) != nil {
		return zero, ErrInstall
	}
	var request worker.Request
	decoder := json.NewDecoder(bytes.NewReader(operation["Request"]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.Operation != "" && request.Operation != "capture-database" || request.Database == nil || request.Database.Name != p.intent.Database || request.Database.ServerUUID != p.intent.ServerUUID || request.Database.SourceScope != domain.BusinessTableSourceScope || request.Database.SchemaCensus == nil || request.Database.SchemaCensus.Validate() != nil || request.SourceRedis != nil || request.Teams != nil || request.TeamWorkspace != nil || request.Resources != nil || request.ControlEvidence != nil || request.CaptureDescription != nil || request.SkillObjects != nil || request.SkillWorkspace != nil {
		return zero, ErrInstall
	}
	request.Operation = "capture-database"
	if request.RuntimePolicy != nil || request.WorkBuddyIdentity != nil || request.Database.SkillsRestore != nil || request.Database.InputFormat != "" || len(request.Database.Placements) != 0 || len(request.Database.TeamPlacements) != 0 || len(request.Database.Configs) != 0 {
		return zero, ErrInstall
	}
	return request, nil
}

func (p *SourceMaterialIssuer) databaseSourceService(ctx context.Context, d DatabaseSourceIssueDefinition, r worker.Request) error {
	if d.Service == "" || d.ServiceUID == "" || d.Port < 1 || d.Port > 65535 {
		return ErrInstall
	}
	ns, err := p.operator.installer.kube.CoreV1().Namespaces().Get(ctx, p.intent.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != p.intent.NamespaceUID || ns.DeletionTimestamp != nil {
		return ErrInstall
	}
	svc, err := p.operator.installer.kube.CoreV1().Services(p.intent.Namespace).Get(ctx, d.Service, metav1.GetOptions{})
	if err != nil || string(svc.UID) != d.ServiceUID || svc.Namespace != p.intent.Namespace || svc.DeletionTimestamp != nil || svc.Spec.ExternalName != "" {
		return ErrInstall
	}
	host := d.Service + "." + p.intent.Namespace + ".svc"
	if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
		ip := net.ParseIP(svc.Spec.ClusterIP)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			return ErrInstall
		}
		host = svc.Spec.ClusterIP
	}
	found := false
	for _, port := range svc.Spec.Ports {
		if int(port.Port) == d.Port && port.Protocol == corev1.ProtocolTCP {
			found = true
		}
	}
	if !found || r.Database.Address != net.JoinHostPort(host, strconv.Itoa(d.Port)) {
		return ErrInstall
	}
	return nil
}
