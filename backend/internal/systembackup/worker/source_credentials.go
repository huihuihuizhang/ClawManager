package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	source "clawreef/internal/systembackup"
	k "clawreef/internal/systembackupkms"
	sh "clawreef/internal/systembackupskillhub"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const FormalSourceGrantVersion = "system-backup-original-source-grant.v1"
const FormalSourceGrantDomain = "system-backup-original-capture-source.v1\x00"

// Source owner delegation is independent of KEK Generate authority. It freezes
// the original source scope and deployment worker identity, without future
// Invocation/Job/Pod hashes or a task-specific credential approval step.
type FormalSourceGrant struct {
	Version                                  string `json:"schema_version"`
	InstallationID, ConfigSHA256             string
	WorkerNamespace, WorkerServiceAccountUID string
	Operation, ScopeSHA256, CredentialSHA256 string
	NotBefore, Until                         time.Time
	Revoked                                  bool
}
type SignedFormalSourceGrant struct{ Record, Signature []byte }
type SourceTLSMapping struct {
	Address, ServerName, CAFile, CASHA256 string
}
type FormalSourceMount struct {
	GrantFile, GrantSHA256           string
	Issuer                           ed25519.PublicKey
	CredentialFile, CredentialSHA256 string
	Redis, Objects                   *SourceTLSMapping
	RedisScope                       *RedisSourceBoundary
	ObjectPrefixes                   []ObjectSourcePrefix
	RedisPrefixes                    []string `json:",omitempty"`
	RedisExcludedPrefixes            []string `json:",omitempty"`
}
type RedisSourceBoundary struct {
	ID, ServerID string
	Database     int
	KeyPrefix    string
}
type ObjectSourcePrefix struct{ Bucket, Prefix string }
type formalSourceCredential struct {
	Username     string `json:"username,omitempty"`
	Password     []byte `json:"password,omitempty"`
	AccessKey    string `json:"access_key,omitempty"`
	SecretKey    []byte `json:"secret_key,omitempty"`
	SessionToken []byte `json:"session_token,omitempty"`
}

// FormalSourceScopeSHA256 binds actual endpoint/TLS/source identity and finite
// Teams keys/versions. Per-task bounds and writer checkpoints remain in the
// original Invocation; they cannot widen a source owner's delegation.
func FormalSourceScopeSHA256(i Invocation, m FormalSourceMount) (string, error) {
	var scope any
	if redis := i.Request.SourceRedis; redis != nil {
		boundary := m.RedisScope
		if !validSourceRedisRequest(i.Request) || m.Redis == nil || m.Objects != nil || len(m.ObjectPrefixes) != 0 || boundary == nil || boundary.ID != redis.Policy.Source.ID || boundary.ServerID != redis.ServerID || boundary.Database != redis.Policy.DB || boundary.KeyPrefix != "" || !reflect.DeepEqual(m.RedisPrefixes, redis.Policy.Prefixes) || !reflect.DeepEqual(m.RedisExcludedPrefixes, redis.ExcludePrefixes) {
			return "", ErrRequest
		}
		scope = struct {
			Operation                                        string
			Mapping                                          *SourceTLSMapping
			Boundary                                         *RedisSourceBoundary
			Prefixes, ExcludedPrefixes                       []string
			SourceID, SourceVersion, SourceSHA256, TTLPolicy string
		}{i.Request.Operation, m.Redis, boundary, m.RedisPrefixes, m.RedisExcludedPrefixes, redis.Policy.Source.ID, redis.Policy.Source.Version, redis.Policy.Source.SHA256, redis.Policy.TTLPolicy}
	} else if len(m.RedisPrefixes) != 0 || len(m.RedisExcludedPrefixes) != 0 {
		return "", ErrRequest
	} else if d := i.Request.Database; d != nil {
		if m.Redis != nil || m.Objects != nil || m.RedisScope != nil || len(m.ObjectPrefixes) != 0 || !validDatabaseSpec(d) {
			return "", ErrRequest
		}
		scope = struct{ Operation, Address, Database, ServerUUID, TLSServerName, CA string }{i.Request.Operation, d.Address, d.Name, d.ServerUUID, d.TLSServerName, sourceDigest(d.RootCA)}
	} else if t := i.Request.Teams; t != nil {
		if (t.Redis != nil) != (m.Redis != nil) || (len(t.Objects) > 0) != (m.Objects != nil) {
			return "", ErrRequest
		}
		if t.Redis != nil {
			b := m.RedisScope
			if b == nil || b.ID != t.Redis.ID || b.ServerID != t.Redis.ServerID || b.Database != t.Redis.Database || b.KeyPrefix != "claw:team:" || len(m.ObjectPrefixes) != 0 || t.Redis.Validate() != nil {
				return "", ErrRequest
			}
		} else {
			if m.RedisScope != nil || len(m.ObjectPrefixes) == 0 || len(m.ObjectPrefixes) > 32 {
				return "", ErrRequest
			}
			seen := map[string]bool{}
			for _, b := range m.ObjectPrefixes {
				key := b.Bucket + "\x00" + b.Prefix
				if b.Bucket == "" || !utf8.ValidString(key) || seen[key] || !strings.HasSuffix(b.Prefix, "/") || strings.TrimSuffix(b.Prefix, "/") == "" || path.IsAbs(b.Prefix) || path.Clean(b.Prefix) != strings.TrimSuffix(b.Prefix, "/") || strings.ContainsAny(b.Bucket+b.Prefix, "*?\\\r\n\x00") {
					return "", ErrRequest
				}
				seen[key] = true
			}
			for _, ref := range t.Objects {
				found := false
				for _, b := range m.ObjectPrefixes {
					found = found || (ref.Bucket == b.Bucket && strings.HasPrefix(ref.Key, b.Prefix))
				}
				if !found || ref.Validate() != nil {
					return "", ErrRequest
				}
			}
		}
		scope = struct {
			Operation                    string
			RedisScope                   *RedisSourceBoundary
			ObjectPrefixes               []ObjectSourcePrefix
			RedisMapping, ObjectsMapping *SourceTLSMapping
		}{i.Request.Operation, m.RedisScope, m.ObjectPrefixes, m.Redis, m.Objects}
	} else if s := i.Request.SkillObjects; s != nil {
		if !validSkillObjectRequest(i.Request) || m.Objects == nil || m.Redis != nil || m.RedisScope != nil || !validObjectSourcePrefixes(m.ObjectPrefixes) {
			return "", ErrRequest
		}
		for _, object := range s.Objects {
			if !objectSourceAllowed(m.ObjectPrefixes, s.Bucket, s.Prefix+"/"+object.Key) {
				return "", ErrRequest
			}
		}
		// Empty current keysets still bind the exact owned provider root.
		if !objectSourceAllowed(m.ObjectPrefixes, s.Bucket, s.Prefix+"/") {
			return "", ErrRequest
		}
		scope = struct {
			Operation      string
			ObjectPrefixes []ObjectSourcePrefix
			ObjectsMapping *SourceTLSMapping
		}{i.Request.Operation, m.ObjectPrefixes, m.Objects}
	} else {
		return "", ErrRequest
	}
	raw, err := json.Marshal(scope)
	if err != nil {
		return "", ErrRequest
	}
	return sourceDigest(raw), nil
}
func sourceDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

type FormalCaptureSources struct {
	SourceRedis   *source.RedisClient
	Database      *sql.DB
	Teams         *TeamCaptureSources
	objects       *minio.Client
	invocation    Invocation
	invocationSHA string
	mount         FormalSourceMount
	job           *CaptureKeyJob
	identity      k.JobIdentity
	grant         FormalSourceGrant
	until         time.Time
	transport     *http.Transport
	closed        atomic.Bool
}

func (s *FormalCaptureSources) ValidUntil() time.Time {
	if s == nil || s.closed.Load() {
		return time.Time{}
	}
	return s.until
}
func (s *FormalCaptureSources) Close() {
	if s == nil || !s.closed.CompareAndSwap(false, true) {
		return
	}
	if s.Database != nil {
		s.Database.Close()
	}
	if s.Teams != nil && s.Teams.Redis != nil {
		s.Teams.Redis.Close()
	}
	if s.SourceRedis != nil {
		s.SourceRedis.Close()
	}
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
}
func readPinnedSourceFile(path, digest string, max int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !keyUseHash.MatchString(digest) {
		return nil, ErrNotReady
	}
	raw, err := resourceMountedFile(path, private, max)
	if err != nil || sourceDigest(raw) != digest {
		clear(raw)
		return nil, ErrNotReady
	}
	return raw, nil
}

func (s *FormalCaptureSources) readGrant(ctx context.Context) (FormalSourceGrant, error) {
	var zero FormalSourceGrant
	if s == nil || s.closed.Load() || ctx == nil || ctx.Err() != nil || s.job == nil || s.job.original == nil || s.job.original.Identity() != s.identity || !time.Now().Before(s.until) {
		return zero, ErrNotReady
	}
	raw, err := readPinnedSourceFile(s.mount.GrantFile, s.mount.GrantSHA256, 65536, false)
	if err != nil {
		return zero, err
	}
	defer clear(raw)
	var signed SignedFormalSourceGrant
	if !uniqueFormalJSON(raw) || decodeBounded(bytes.NewReader(raw), &signed, 65536) != nil || len(signed.Record) == 0 || len(signed.Record) > 32768 || !ed25519.Verify(s.mount.Issuer, append([]byte(FormalSourceGrantDomain), signed.Record...), signed.Signature) {
		return zero, ErrNotReady
	}
	var grant FormalSourceGrant
	if !uniqueFormalJSON(signed.Record) || decodeBounded(bytes.NewReader(signed.Record), &grant, 32768) != nil {
		return zero, ErrNotReady
	}
	scope, err := FormalSourceScopeSHA256(s.invocation, s.mount)
	now := time.Now()
	if err != nil || grant.Version != FormalSourceGrantVersion || grant.InstallationID != s.invocation.ProviderKey.Request.Context.InstallationID || grant.ConfigSHA256 != s.invocation.FormalCapture.SourceConfigSHA256 || !keyUseHash.MatchString(grant.ConfigSHA256) || grant.WorkerNamespace != s.identity.Namespace || grant.WorkerServiceAccountUID != s.identity.ServiceAccountUID || grant.Operation != s.invocation.Request.Operation || grant.ScopeSHA256 != scope || grant.CredentialSHA256 != s.mount.CredentialSHA256 || grant.Revoked || grant.NotBefore.IsZero() || now.Before(grant.NotBefore) || !now.Before(grant.Until) || grant.Until.Sub(grant.NotBefore) > 24*time.Hour {
		return zero, ErrNotReady
	}
	return grant, nil
}
func (s *FormalCaptureSources) Authorize(ctx context.Context, i Invocation) error {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return ErrNotReady
	}
	raw, err := json.Marshal(i)
	if err != nil || sourceDigest(raw) != s.invocationSHA {
		return ErrNotReady
	}
	grant, err := s.readGrant(ctx)
	if err != nil || grant != s.grant {
		return ErrNotReady
	}
	credential, err := readPinnedSourceFile(s.mount.CredentialFile, s.mount.CredentialSHA256, 16384, true)
	clear(credential)
	if err != nil {
		return ErrNotReady
	}
	return ctx.Err()
}

// Only the concrete original control-backed CaptureKeyJob can open a source.
// No supplied callback can synthesize Job/SA identity or substitute KEK tokens.
func OpenFormalCaptureSources(ctx context.Context, i Invocation, job *CaptureKeyJob, mount *FormalSourceMount) (result *FormalCaptureSources, resultErr error) {
	if ctx == nil || ctx.Err() != nil || !validFormalInvocation(i) || mount == nil || job == nil || job.original == nil || job.original.invocation.FormalCapture == nil || job.original.invocation.FormalCapture.SourceConfigSHA256 != i.FormalCapture.SourceConfigSHA256 || job.access != *i.ProviderKey || len(mount.Issuer) != ed25519.PublicKeySize || i.FormalCapture.PermitDelivery == nil || bytes.Equal(mount.Issuer, i.FormalCapture.PermitDelivery.Issuer) || !keyUseHash.MatchString(mount.GrantSHA256) || !keyUseHash.MatchString(mount.CredentialSHA256) {
		return nil, ErrNotReady
	}
	originalHash, _ := job.original.invocation.Hash()
	invocationHash, _ := i.Hash()
	if originalHash != invocationHash || job.Recheck(ctx) != nil {
		return nil, ErrNotReady
	}
	raw, err := json.Marshal(struct {
		Invocation Invocation
		Mount      FormalSourceMount
	}{i, *mount})
	var frozen struct {
		Invocation Invocation
		Mount      FormalSourceMount
	}
	if err != nil || json.Unmarshal(raw, &frozen) != nil {
		return nil, ErrNotReady
	}
	s := &FormalCaptureSources{invocation: frozen.Invocation, invocationSHA: invocationHash, mount: frozen.Mount, job: job, identity: job.original.Identity(), until: job.until}
	defer func() {
		if resultErr != nil {
			s.Close()
		}
	}()
	grant, err := s.readGrant(ctx)
	if err != nil {
		return nil, ErrNotReady
	}
	s.grant = grant
	if grant.Until.Before(s.until) {
		s.until = grant.Until
	}
	ctx, cancel := context.WithDeadline(ctx, s.until)
	defer cancel()
	credentialRaw, err := readPinnedSourceFile(s.mount.CredentialFile, s.mount.CredentialSHA256, 16384, true)
	if err != nil {
		return nil, ErrNotReady
	}
	defer clear(credentialRaw)
	var credential formalSourceCredential
	if !uniqueFormalJSON(credentialRaw) || decodeBounded(bytes.NewReader(credentialRaw), &credential, 16384) != nil {
		return nil, ErrNotReady
	}
	defer clear(credential.Password)
	defer clear(credential.SecretKey)
	defer clear(credential.SessionToken)
	switch i.Request.Operation {
	case "capture-database":
		if credential.Username == "" || len(credential.Password) == 0 || credential.AccessKey != "" || len(credential.SecretKey) != 0 || len(credential.SessionToken) != 0 || mount.Redis != nil || mount.Objects != nil {
			return nil, ErrNotReady
		}
		s.Database, err = OpenDatabase(i.Request.Database, &DatabaseCredential{Username: credential.Username, Password: credential.Password})
		if err != nil {
			return nil, ErrNotReady
		}
		var account, role, database, uuid string
		if s.Database.QueryRowContext(ctx, "SELECT CURRENT_USER(),CURRENT_ROLE(),DATABASE(),@@server_uuid").Scan(&account, &role, &database, &uuid) != nil || !strings.HasPrefix(account, credential.Username+"@") || role != "NONE" || database != i.Request.Database.Name || uuid != i.Request.Database.ServerUUID {
			return nil, ErrNotReady
		}
	case "capture-source-redis", "capture-team-redis":
		if (i.Request.SourceRedis == nil && (i.Request.Teams == nil || i.Request.Teams.Redis == nil)) || mount.Redis == nil || mount.Objects != nil || credential.Username == "" || len(credential.Password) == 0 || credential.AccessKey != "" || len(credential.SecretKey) != 0 || len(credential.SessionToken) != 0 {
			return nil, ErrNotReady
		}
		tlsConfig, err := sourceTLS(*mount.Redis)
		if err != nil {
			return nil, err
		}
		database, serverID := 0, ""
		if i.Request.SourceRedis != nil {
			database, serverID = i.Request.SourceRedis.Policy.DB, i.Request.SourceRedis.ServerID
		} else {
			database, serverID = i.Request.Teams.Redis.Database, i.Request.Teams.Redis.ServerID
		}
		client, err := source.ConnectRedis(ctx, source.RedisOptions{Address: mount.Redis.Address, Username: credential.Username, Password: string(credential.Password), Database: database, TLS: tlsConfig, MaxReplyBytes: 64 << 20})
		if err != nil {
			return nil, ErrNotReady
		}
		if i.Request.SourceRedis != nil {
			s.SourceRedis = client
		} else {
			s.Teams = &TeamCaptureSources{Redis: client, Authorize: s.Authorize}
		}
		id, actualDatabase, err := client.Identity(ctx)
		if err != nil || id != serverID || actualDatabase != database {
			return nil, ErrNotReady
		}
	case "capture-team-objects", "capture-skill-objects":
		if (i.Request.SkillObjects == nil && (i.Request.Teams == nil || len(i.Request.Teams.Objects) == 0)) || mount.Objects == nil || mount.Redis != nil || credential.Username != "" || len(credential.Password) != 0 || credential.AccessKey == "" || len(credential.SecretKey) == 0 {
			return nil, ErrNotReady
		}
		tlsConfig, err := sourceTLS(*mount.Objects)
		if err != nil {
			return nil, err
		}
		s.transport = &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 32768, DisableCompression: true}
		transport := pinnedSourceTransport{host: mount.Objects.Address, transport: s.transport}
		client, err := minio.New(mount.Objects.Address, &minio.Options{Secure: true, Creds: credentials.NewStaticV4(credential.AccessKey, string(credential.SecretKey), string(credential.SessionToken)), Transport: transport})
		if err != nil {
			return nil, ErrNotReady
		}
		s.objects = client
		if i.Request.Teams != nil {
			s.Teams = &TeamCaptureSources{Objects: client, Authorize: s.Authorize}
		}
	default:
		return nil, ErrNotReady
	}
	if s.Authorize(ctx, i) != nil || job.Recheck(ctx) != nil {
		return nil, ErrNotReady
	}
	return s, nil
}

func (s *FormalCaptureSources) SkillObjects() (*SkillObjectCaptureSources, error) {
	if s == nil || s.closed.Load() || s.objects == nil || s.invocation.Request.SkillObjects == nil {
		return nil, ErrNotReady
	}
	spec := s.invocation.Request.SkillObjects
	reader, err := sh.NewS3VersionReaderWithMetadata(s.objects, spec.Bucket, spec.Prefix, spec.UserMetadataAllowlist)
	if err != nil {
		return nil, ErrNotReady
	}
	return &SkillObjectCaptureSources{Reader: reader, Authorize: s.Authorize}, nil
}
func validObjectSourcePrefixes(prefixes []ObjectSourcePrefix) bool {
	if len(prefixes) == 0 || len(prefixes) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, b := range prefixes {
		key := b.Bucket + "\x00" + b.Prefix
		if b.Bucket == "" || !utf8.ValidString(key) || seen[key] || !strings.HasSuffix(b.Prefix, "/") || strings.TrimSuffix(b.Prefix, "/") == "" || path.IsAbs(b.Prefix) || path.Clean(b.Prefix) != strings.TrimSuffix(b.Prefix, "/") || strings.ContainsAny(b.Bucket+b.Prefix, "*?\\\r\n\x00") {
			return false
		}
		seen[key] = true
	}
	return true
}
func objectSourceAllowed(prefixes []ObjectSourcePrefix, bucket, key string) bool {
	for _, b := range prefixes {
		if b.Bucket == bucket && strings.HasPrefix(key, b.Prefix) {
			return true
		}
	}
	return false
}

func sourceTLS(mapping SourceTLSMapping) (*tls.Config, error) {
	if mapping.Address == "" || mapping.ServerName == "" || strings.ContainsAny(mapping.Address+mapping.ServerName, "/\\@?#\r\n\x00 ") {
		return nil, ErrNotReady
	}
	parsed, err := url.Parse("https://" + mapping.Address)
	if err != nil || parsed.Host != mapping.Address || parsed.Hostname() == "" {
		return nil, ErrNotReady
	}
	ca, err := readPinnedSourceFile(mapping.CAFile, mapping.CASHA256, 65536, false)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, ErrNotReady
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: mapping.ServerName}, nil
}

type pinnedSourceTransport struct {
	host      string
	transport *http.Transport
}

func (p pinnedSourceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != p.host || r.URL.User != nil {
		return nil, ErrNotReady
	}
	return p.transport.RoundTrip(r)
}
