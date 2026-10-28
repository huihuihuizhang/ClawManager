package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	ev "clawreef/internal/systembackupevidence"
	sec "clawreef/internal/systembackupsecurity"
)

var errDownloadDeployment = errors.New("download runtime deployment unavailable")
var downloadDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var downloadUser = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)

// Public deployment pins. Credentials are read only from the existing
// registration mounts or projected token paths; no HTTP DTO uses this type.
type downloadDeployment struct {
	SchemaVersion             string                `json:"schema_version"`
	RegistrationRuntimeSHA256 string                `json:"registration_runtime_sha256"`
	ServerUUID                string                `json:"server_uuid"`
	Database                  string                `json:"database"`
	Installation              string                `json:"installation_id"`
	DatabaseUser              string                `json:"database_user"`
	GrantsFile                string                `json:"grants_file"`
	GrantsSHA256              string                `json:"grants_sha256"`
	ConfigVersion             int64                 `json:"config_version"`
	ConfigSHA256              string                `json:"config_sha256"`
	Root                      string                `json:"root"`
	Store                     downloadReferencePins `json:"store"`
	Read                      downloadReferencePins `json:"read"`
	AuthorityUntil            time.Time             `json:"authority_until"`
	MaterialsUntil            time.Time             `json:"materials_until"`
	AuditMinimumRetainUntil   time.Time             `json:"audit_minimum_retain_until"`
	LargeSmokeBytes           int64                 `json:"large_smoke_bytes"`
	AdmissionReservationBytes int                   `json:"admission_reservation_bytes"`
	ResultReservationBytes    int                   `json:"result_reservation_bytes"`
	JournalPath               string                `json:"journal_path"`
	JournalMaxBytes           int64                 `json:"journal_max_bytes"`
	S3                        downloadS3Pins        `json:"s3"`
	STS                       downloadSTSPins       `json:"sts"`
	Transit                   []downloadTransitPins `json:"transit"`
}

type downloadS3Pins struct {
	Endpoint string `json:"endpoint"`
	Region   string `json:"region"`
	Bucket   string `json:"bucket"`
	CAFile   string `json:"ca_file"`
	CASHA256 string `json:"ca_sha256"`
}
type downloadReferencePins struct {
	Identity string `json:"identity_hash"`
	Version  string `json:"version"`
}

func (p downloadReferencePins) key() ev.KeyRef {
	return ev.KeyRef{Identity: p.Identity, Version: p.Version}
}

type downloadSTSPins struct {
	Endpoint  string `json:"endpoint"`
	RoleARN   string `json:"role_arn"`
	Issuer    string `json:"issuer"`
	Audience  string `json:"audience"`
	Subject   string `json:"subject"`
	TokenFile string `json:"token_file"`
	CAFile    string `json:"ca_file"`
	CASHA256  string `json:"ca_sha256"`
}
type downloadTransitPins struct {
	Endpoint   string                `json:"endpoint"`
	Key        downloadReferencePins `json:"key"`
	KeyName    string                `json:"key_name"`
	KeyVersion uint32                `json:"key_version"`
	Mount      string                `json:"mount"`
	Role       string                `json:"role"`
	Policy     string                `json:"policy"`
	Audience   string                `json:"audience"`
	TokenFile  string                `json:"token_file"`
	CAFile     string                `json:"ca_file"`
	CASHA256   string                `json:"ca_sha256"`
}

func deploymentBytes(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errDownloadDeployment
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errDownloadDeployment
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, errDownloadDeployment
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errDownloadDeployment
	}
	return raw, nil
}
func pinnedDeploymentBytes(path, digest string, limit int64) ([]byte, error) {
	if !downloadDigest.MatchString(digest) {
		return nil, errDownloadDeployment
	}
	raw, err := deploymentBytes(path, limit)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, errDownloadDeployment
	}
	return raw, nil
}

// Reject duplicate/case-alias keys, lossy Unicode and trailing JSON before the
// typed closed decoder. Limit depth independently of the bounded file size.
func strictDeploymentJSON(raw []byte, target any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' || !utf8.Valid(raw) {
		return errDownloadDeployment
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errDownloadDeployment
		}
		token, err := d.Token()
		if err != nil {
			return errDownloadDeployment
		}
		if s, ok := token.(string); ok && strings.ContainsRune(s, utf8.RuneError) {
			return errDownloadDeployment
		}
		if delim, ok := token.(json.Delim); ok {
			if delim != '{' && delim != '[' {
				return errDownloadDeployment
			}
			keys := map[string]bool{}
			for d.More() {
				if delim == '{' {
					key, err := d.Token()
					s, ok := key.(string)
					if err != nil || !ok || keys[s] || s == "" || strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
						return errDownloadDeployment
					}
					keys[s] = true
				}
				if walk(depth+1) != nil {
					return errDownloadDeployment
				}
			}
			end, err := d.Token()
			if err != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
				return errDownloadDeployment
			}
		}
		return nil
	}
	if walk(0) != nil {
		return errDownloadDeployment
	}
	if _, err := d.Token(); err != io.EOF {
		return errDownloadDeployment
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return errDownloadDeployment
	}
	return nil
}

type loadedDownload struct {
	application *ev.DownloadApplication
	sessions    *sec.SQLLoginSessions
	digest      string
}

func (l *loadedDownload) Close() {
	if l != nil {
		l.application.Close()
		l.sessions.Close()
	}
}

func loadDownloadDeployment(ctx context.Context, base *sec.RegistrationApplication, downloadDB *sql.DB, path, digest, baseDigest, sqlUser string) (*loadedDownload, error) {
	if ctx == nil || ctx.Err() != nil || base == nil || base.DB == nil || downloadDB == nil || downloadDB == base.DB {
		return nil, errDownloadDeployment
	}
	raw, err := pinnedDeploymentBytes(path, digest, 65536)
	if err != nil {
		return nil, err
	}
	var c downloadDeployment
	if strictDeploymentJSON(raw, &c) != nil {
		return nil, errDownloadDeployment
	}
	b := base.Config
	if c.SchemaVersion != "system-backup-download-deployment.v1" || !downloadDigest.MatchString(baseDigest) || c.RegistrationRuntimeSHA256 != baseDigest || c.ServerUUID != b.ExpectedServerUUID || c.Database != b.ExpectedDatabase || c.Installation != b.InstallationID || c.ConfigVersion != b.ConfigVersion || !downloadUser.MatchString(c.DatabaseUser) || strings.EqualFold(c.DatabaseUser, "root") || c.DatabaseUser != sqlUser {
		return nil, errDownloadDeployment
	}
	if err = checkDownloadDatabasePins(ctx, downloadDB, c); err != nil {
		return nil, err
	}
	ca, err := pinnedDeploymentBytes(c.S3.CAFile, c.S3.CASHA256, 262144)
	if err != nil {
		return nil, err
	}
	store := ev.S3Config{Endpoint: c.S3.Endpoint, Region: c.S3.Region, Bucket: c.S3.Bucket, Root: c.Root, Installation: c.Installation, Identity: c.Store.Identity, Version: c.Store.Version, CAPEM: ca, CASHA256: c.S3.CASHA256}
	ca, err = pinnedDeploymentBytes(c.STS.CAFile, c.STS.CASHA256, 262144)
	if err != nil {
		return nil, err
	}
	sts := ev.S3STSConfig{Store: store, Endpoint: c.STS.Endpoint, RoleARN: c.STS.RoleARN, Issuer: c.STS.Issuer, Audience: c.STS.Audience, CAPEM: ca, CASHA256: c.STS.CASHA256}
	if len(c.Transit) == 0 || len(c.Transit) > 128 {
		return nil, errDownloadDeployment
	}
	transit := make([]ev.DownloadTransitConfig, 0, len(c.Transit))
	for _, p := range c.Transit {
		ca, err = pinnedDeploymentBytes(p.CAFile, p.CASHA256, 262144)
		if err != nil {
			return nil, err
		}
		transit = append(transit, ev.DownloadTransitConfig{Transit: ev.TransitConfig{Endpoint: p.Endpoint, Installation: c.Installation, KeyName: p.KeyName, Key: p.Key.key(), KeyVersion: p.KeyVersion, CAPEM: ca, CASHA256: p.CASHA256}, Mount: p.Mount, Role: p.Role, Policy: p.Policy, Issuer: c.STS.Issuer, Audience: p.Audience, Subject: c.STS.Subject, TokenFile: p.TokenFile})
	}
	identity := sec.DatabaseIdentity{ServerUUID: c.ServerUUID, Database: c.Database}
	materials, err := sec.NewConfigMutationSecurityFiles(c.Installation, identity, b.RegistryDirectory, b.NonceDirectory)
	if err != nil {
		return nil, errDownloadDeployment
	}
	capacity, err := sec.NewConfigMutationCapacity(identity, b.CapacityReportFile, c.LargeSmokeBytes)
	if err != nil {
		return nil, errDownloadDeployment
	}
	secret, err := deploymentBytes(b.JWTSecretFile, 1024)
	if err != nil {
		return nil, err
	}
	defer func() {
		for n := range secret {
			secret[n] = 0
		}
	}()
	auth, ok := base.API.Registration.Auth.(sec.JWTRegistrationAuthenticator)
	if !ok || len(secret) < 32 || subtle.ConstantTimeCompare(secret, auth.Secret) != 1 {
		return nil, errDownloadDeployment
	}
	sessions, err := sec.NewSQLLoginSessions(downloadDB, identity, c.Installation, secret)
	if err != nil {
		return nil, errDownloadDeployment
	}
	app, err := ev.NewDownloadApplication(ev.DownloadApplicationConfig{Authority: ev.DownloadAuthorityConfig{Registry: ev.SQLRegistry{DB: downloadDB, Installation: c.Installation, ServerUUID: c.ServerUUID, Database: c.Database}, JWTSecret: secret, ConfigVersion: c.ConfigVersion, ConfigSHA256: c.ConfigSHA256, RBACVersion: b.RBACRegistryVersion, RBACSHA256: b.RBACRegistrySHA256, RegistryDirectory: b.RegistryDirectory, Root: c.Root, Store: c.Store.key(), Read: c.Read.key(), Issuer: c.STS.Issuer, Audience: c.STS.Audience, Subject: c.STS.Subject, TokenFile: c.STS.TokenFile, ExpiresAt: c.AuthorityUntil},
		S3: sts, Transit: transit, Sessions: sessions, Materials: materials, Capacity: capacity, ProofIssuer: base.API.TOTP.Issuer.Key.Issuer, AdmissionReservationBytes: c.AdmissionReservationBytes, ResultReservationBytes: c.ResultReservationBytes, MaterialsUntil: c.MaterialsUntil, AuditMinimumRetainUntil: c.AuditMinimumRetainUntil, JournalPath: c.JournalPath, JournalMaxBytes: c.JournalMaxBytes})
	if err != nil {
		sessions.Close()
		return nil, errDownloadDeployment
	}
	return &loadedDownload{application: app, sessions: sessions, digest: digest}, nil
}
