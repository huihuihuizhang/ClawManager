package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"clawreef/internal/buildinfo"
	"clawreef/internal/systembackup/team"

	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This original material selects the reviewed files-only codec and independent
// finite Team object roots. It never borrows the Skills credential or roots.
type productionTeamObjectsSource struct {
	Codec, SchemaSHA256 string
	Source              worker.FormalSourceMount
}

type productionTeamZeroCensus struct {
	Mode, Codec, SchemaSHA256, ScopeSHA256, CensusSHA256 string
	AppVersion, GitCommit                                string
	Writers                                              []productionTeamWriterBuild
	Versions                                             int
}

// A result is returned only by the concrete native census above. This codec
// never fabricates ownership for a nonempty provider: it refuses such a source.
func (c *productionTeamZeroCensus) objects() []team.ObjectRef { return []team.ObjectRef{} }

func (x *bootstrapSourceRegistryReader) bindObservedTeamSource(f *bootstrapSourceSQLFacts, clients *productionMetadataClients, census *productionTeamZeroCensus) error {
	if census == nil || f == nil || f.inventory.TeamFacts == nil || clients == nil || clients.API == nil || x.checkPhysical(x.physical) != nil {
		return install.ErrInstall
	}
	redis := x.materials.Discovery.Redis
	mapping := team.AutomaticStorageMapping{RedisID: redis.Policy.Source.ID, RedisServerID: redis.ServerID, RedisDatabase: redis.Policy.DB, Claims: []team.SharedClaimIdentity{}, Objects: census.objects()}
	for _, fact := range f.inventory.TeamFacts.Teams {
		if fact.PVC == "" {
			continue
		}
		if fact.Namespace != x.config.Namespace {
			return install.ErrInstall
		}
		claim, err := clients.API.CoreV1().PersistentVolumeClaims(fact.Namespace).Get(x.physical, fact.PVC, metav1.GetOptions{})
		if err != nil || claim.UID == "" || claim.DeletionTimestamp != nil || claim.Spec.VolumeName == "" {
			return install.ErrInstall
		}
		pv, err := clients.API.CoreV1().PersistentVolumes().Get(x.physical, claim.Spec.VolumeName, metav1.GetOptions{})
		if err != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Name != fact.PVC || pv.Spec.ClaimRef.Namespace != fact.Namespace || x.checkPhysical(x.physical) != nil {
			return install.ErrInstall
		}
		mapping.Claims = append(mapping.Claims, team.SharedClaimIdentity{Namespace: fact.Namespace, PVC: fact.PVC, UID: string(claim.UID)})
	}
	users, owners := map[int]bool{}, map[int]int{}
	for _, id := range f.inventory.Users {
		users[id] = true
	}
	for _, instance := range f.inventory.Instances {
		owners[instance.ID] = instance.UserID
	}
	observed, err := team.BindAutomaticStorage(x.physical, *f.inventory.TeamFacts, mapping, users, owners)
	if err != nil {
		return install.ErrInstall
	}
	f.inventory.Teams = observed
	return nil
}

func validateTeamObjectsSource(m productionCaptureMaterials) error {
	p := m.TeamObjects
	if p == nil {
		if op, ok := m.Operations["capture-team-objects"]; ok && op.Request.Teams != nil {
			return d.ErrNotReady
		}
		return nil // Only structural eligibility; live SQL/build/Pod reads below remain mandatory.
	}
	if p.Codec != team.SharedFileSourceVersion || p.SchemaSHA256 != team.SchemaSHA256() {
		return d.ErrNotReady
	}
	if p.Source.Objects == nil || p.Source.Redis != nil || p.Source.CredentialFile == m.Objects.CredentialFile || p.Source.CredentialSHA256 == m.Objects.CredentialSHA256 || p.Source.GrantFile == m.Objects.GrantFile || p.Source.GrantFile == m.Redis.GrantFile {
		return d.ErrNotReady
	}
	if _, err := worker.TeamObjectsSourceScopeSHA256(p.Source); err != nil {
		return d.ErrNotReady
	}
	for n, a := range p.Source.ObjectPrefixes {
		for _, b := range p.Source.ObjectPrefixes[n+1:] {
			if a.Bucket == b.Bucket && (strings.HasPrefix(a.Prefix, b.Prefix) || strings.HasPrefix(b.Prefix, a.Prefix)) {
				return d.ErrNotReady
			}
		}
		for _, b := range m.Objects.ObjectPrefixes {
			if a.Bucket == b.Bucket && (strings.HasPrefix(a.Prefix, b.Prefix) || strings.HasPrefix(b.Prefix, a.Prefix)) {
				return d.ErrNotReady
			}
		}
	}
	return nil
}

// Private concrete bootstrap authority, not an injected coverage callback.
type bootstrapTeamSourceAuthority struct {
	reader *bootstrapSourceRegistryReader
}

func (bootstrapTeamSourceAuthority) sourceMetadataReadAuthority() {}
func (a bootstrapTeamSourceAuthority) Recheck(ctx context.Context) error {
	return a.reader.checkPhysical(ctx)
}

// SQL's complete closed reference codec and two actual whole-version listings
// are both required. Any non-delete version is unowned in this files-only codec
// and refuses the inventory. Deletion markers are retained and compared too.
func readTeamZeroCensus(ctx context.Context, m productionCaptureMaterials, files *team.SharedFileSource, authority sourceMetadataReadAuthority, config DeploymentConfig, clients *productionMetadataClients, saved *productionTeamZeroCensus) (*productionTeamZeroCensus, error) {
	if ctx == nil || authority == nil || validateTeamObjectsSource(m) != nil || files == nil || files.Codec != team.SharedFileSourceVersion || files.SchemaSHA256 != team.SchemaSHA256() || files.References == nil || authority.Recheck(ctx) != nil {
		return nil, d.ErrNotReady
	}
	p := m.TeamObjects
	if buildinfo.Version == "" || buildinfo.Version == "dev" || buildinfo.Commit == "unknown" || files.AppVersion != buildinfo.Version || files.GitCommit != buildinfo.Commit {
		return nil, d.ErrNotReady
	}
	if clients == nil || clients.API == nil {
		return nil, d.ErrNotReady
	}
	writers, err := observeTeamWriterBuild(ctx, clients.API, config, m, saved)
	if err != nil {
		return nil, err
	}
	if p == nil {
		result := &productionTeamZeroCensus{Mode: "files-only-no-object-scope", Codec: files.Codec, SchemaSHA256: files.SchemaSHA256, AppVersion: buildinfo.Version, GitCommit: buildinfo.Commit, Writers: writers}
		if authority.Recheck(ctx) != nil {
			return nil, d.ErrNotReady
		}
		return result, nil
	}
	credential, err := readMetadataSourceCredential(p.Source)
	if err != nil {
		return nil, err
	}
	defer clear(credential.Password)
	defer clear(credential.SecretKey)
	defer clear(credential.SessionToken)
	if credential.AccessKey == "" || len(credential.SecretKey) == 0 || credential.Username != "" || len(credential.Password) != 0 {
		return nil, d.ErrNotReady
	}
	tls, err := sourceMetadataTLS(*p.Source.Objects)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tls, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 32768, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client, err := minio.New(p.Source.Objects.Address, &minio.Options{Secure: true, Creds: credentials.NewStaticV4(credential.AccessKey, string(credential.SecretKey), string(credential.SessionToken)), Transport: sourceMetadataTransport{authority, p.Source.Objects.Address, transport}})
	if err != nil {
		return nil, d.ErrNotReady
	}
	type entry struct {
		Bucket, Prefix, Key, Version string
		Latest                       bool
	}
	observe := func() ([]entry, error) {
		entries := []entry{}
		for _, prefix := range p.Source.ObjectPrefixes {
			if authority.Recheck(ctx) != nil {
				return nil, d.ErrNotReady
			}
			v, e := client.GetBucketVersioning(ctx, prefix.Bucket)
			if e != nil || !v.Enabled() {
				return nil, d.ErrNotReady
			}
			listCtx, cancel := context.WithCancel(ctx)
			seen := map[string]bool{}
			for obj := range client.ListObjects(listCtx, prefix.Bucket, minio.ListObjectsOptions{Prefix: prefix.Prefix, Recursive: true, WithVersions: true}) {
				key := obj.Key + "\x00" + obj.VersionID
				if obj.Err != nil || !strings.HasPrefix(obj.Key, prefix.Prefix) || obj.VersionID == "" || obj.VersionID == "null" || !obj.IsDeleteMarker || len(entries) >= 100000 || seen[key] || authority.Recheck(ctx) != nil {
					cancel()
					return nil, d.ErrNotReady
				}
				seen[key] = true
				entries = append(entries, entry{prefix.Bucket, prefix.Prefix, obj.Key, obj.VersionID, obj.IsLatest})
			}
			e = listCtx.Err()
			cancel()
			if e != nil || authority.Recheck(ctx) != nil {
				return nil, d.ErrNotReady
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			a, b := entries[i], entries[j]
			return a.Bucket+"\x00"+a.Prefix+"\x00"+a.Key+"\x00"+a.Version < b.Bucket+"\x00"+b.Prefix+"\x00"+b.Key+"\x00"+b.Version
		})
		return entries, nil
	}
	a, err := observe()
	if err != nil {
		return nil, err
	}
	b, err := observe()
	if err != nil || !reflect.DeepEqual(a, b) {
		return nil, d.ErrNotReady
	}
	scope, err := worker.TeamObjectsSourceScopeSHA256(p.Source)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	return &productionTeamZeroCensus{Mode: "selected-finite-object-scope", Codec: p.Codec, SchemaSHA256: p.SchemaSHA256, ScopeSHA256: scope, CensusSHA256: hash(raw), Versions: len(b), AppVersion: buildinfo.Version, GitCommit: buildinfo.Commit, Writers: writers}, nil
}

// Capture's independent controller source authority binds the complete material
// scope; the separate worker Teams grant is additionally checked here. Bootstrap
// collection runs earlier under its opaque source-owner authoring authority and
// does not require a future PartsRegistry/grant to discover the original zero.
func (a *originalSourceMetadataAuthority) teamZeroCensus(ctx context.Context, files *team.SharedFileSource, clients *productionMetadataClients, saved *productionTeamZeroCensus) (*productionTeamZeroCensus, error) {
	m := a.service.captureMaterials
	if m == nil || validateTeamObjectsSource(*m) != nil || a.Recheck(ctx) != nil {
		return nil, d.ErrNotReady
	}
	if m.TeamObjects == nil {
		return readTeamZeroCensus(ctx, *m, files, captureMetadataReadAccess(a), a.service.Config, clients, saved)
	}
	p := m.TeamObjects.Source
	raw, err := pinnedDeploymentFile(p.GrantFile, p.GrantSHA256, 65536)
	var signed worker.SignedFormalSourceGrant
	var grant worker.FormalSourceGrant
	scope, e := worker.TeamObjectsSourceScopeSHA256(p)
	if err != nil || e != nil || decodeMetadataCanonical(raw, &signed) != nil || decodeMetadataCanonical(signed.Record, &grant) != nil || len(p.Issuer) != ed25519.PublicKeySize || !ed25519.Verify(p.Issuer, append([]byte(worker.FormalSourceGrantDomain), signed.Record...), signed.Signature) || grant.Version != worker.FormalSourceGrantVersion || grant.Operation != "capture-team-objects" || grant.InstallationID != a.input.Authority.InstallationID || grant.ConfigSHA256 != a.input.Authority.ConfigSHA256 || grant.WorkerNamespace != a.service.Config.Namespace || grant.WorkerServiceAccountUID != a.service.Config.Security.ServiceAccountUID || grant.ScopeSHA256 != scope || grant.CredentialSHA256 != p.CredentialSHA256 || grant.Revoked || grant.NotBefore.IsZero() || time.Now().Before(grant.NotBefore) || !time.Now().Before(grant.Until) || grant.Until.Sub(grant.NotBefore) > 24*time.Hour {
		return nil, d.ErrNotReady
	}
	result, err := readTeamZeroCensus(ctx, *m, files, captureMetadataReadAccess(a), a.service.Config, clients, saved)
	if err != nil || a.Recheck(ctx) != nil {
		return nil, d.ErrNotReady
	}
	current, err := pinnedDeploymentFile(p.GrantFile, p.GrantSHA256, 65536)
	if err != nil || !bytes.Equal(current, raw) || !time.Now().Before(grant.Until) {
		return nil, d.ErrNotReady
	}
	return result, nil
}
