package systembackupsecurity

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// This adapter covers versioned S3 external-action presence only. Other
// provider/resource profiles fail closed until their ownership adapter exists.
type S3ExternalActionObserver struct {
	DB                                                                     *sql.DB
	DatabaseIdentity                                                       *DatabaseIdentity
	InstallationID, Issuer, Endpoint, Bucket, Prefix, ProviderIdentityHash string
	client                                                                 *s3ReadClient
}

func NewS3ExternalActionObserver(db *sql.DB, installation, issuer, endpoint, bucket, prefix, identity, accessKey, secretKey string, ca []byte) (*S3ExternalActionObserver, error) {
	u, err := url.Parse(endpoint)
	if db == nil || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || bucket == "" || prefix == "" || !strings.HasSuffix(prefix, "/") || !providerHashPattern.MatchString(identity) || accessKey == "" || secretKey == "" {
		return nil, ErrRegistrationUnavailable
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, ErrRegistrationUnavailable
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: 10 * time.Second, MaxIdleConnsPerHost: 4, DisableCompression: true}
	client := &s3ReadClient{endpoint: endpoint, access: accessKey, secret: secretKey, http: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	return &S3ExternalActionObserver{DB: db, InstallationID: installation, Issuer: issuer, Endpoint: endpoint, Bucket: bucket, Prefix: prefix, ProviderIdentityHash: identity, client: client}, nil
}

// Location hash draft: SHA-256 of restricted canonical JSON
// {bucket,endpoint,key}. The same function is used by observation and by the
// transaction's trusted binding; it never uses the submitted proof's hash.
func (o S3ExternalActionObserver) binding(ctx context.Context, tx *sql.Tx, target ProviderProofTarget) (ProviderProofBinding, string, error) {
	b := ProviderProofBinding{}
	if target.TargetType != "external_action" || !providerIDPatterns["external_action"].MatchString(target.TargetPublicID) {
		return b, "", ErrRegistrationUnavailable
	}
	var action, key, finalKey, state, checksum, identity string
	var length, version int64
	var observed sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT action_type,action_key,final_key,state,payload_sha256,content_length,row_version,observed_version FROM system_backup_v2_external_actions WHERE origin_installation_id=? AND public_id=? FOR UPDATE`, o.InstallationID, target.TargetPublicID).Scan(&action, &key, &finalKey, &state, &checksum, &length, &version, &observed)
	if err != nil || !contains([]string{"manifest_put", "marker_put", "acceptance_put"}, action) || !contains([]string{"request_sent", "provider_unreachable", "confirmed_present"}, state) || !strings.HasPrefix(finalKey, o.Prefix) || length < 1 || length > 262144 || !providerHashPattern.MatchString(checksum) {
		return b, "", ErrRegistrationUnavailable
	}
	// Match the configured provider identity under the locked active config.
	err = tx.QueryRowContext(ctx, `SELECT c.artifact_write_identity_hash FROM system_backup_v2_configs c JOIN system_backup_v2_installation_state i ON i.origin_installation_id=c.origin_installation_id AND i.active_config_version=c.version WHERE c.origin_installation_id=? FOR UPDATE`, o.InstallationID).Scan(&identity)
	if err != nil || identity != o.ProviderIdentityHash {
		return b, "", ErrRegistrationUnavailable
	}
	actionHash := registrationHash(key)
	location := registrationHash(string(providerCanonical(map[string]any{"endpoint": o.Endpoint, "bucket": o.Bucket, "key": finalKey})))
	b = ProviderProofBinding{Target: target, RowVersion: version, Issuer: o.Issuer, ProofType: "provider_presence", ProviderIdentityHash: identity, LocationHash: location, ActionKeyHash: &actionHash, ObservedChecksum: &checksum, ContentLength: &length, ObservedState: "present_sealed", AllowAttestedObservedVersion: !observed.Valid}
	if observed.Valid {
		v := observed.String
		b.ObservedVersion = &v
	}
	return b, finalKey, nil
}
func (o S3ExternalActionObserver) TargetBinding(ctx context.Context, tx *sql.Tx, target ProviderProofTarget) (ProviderProofBinding, error) {
	b, _, err := o.binding(ctx, tx, target)
	return b, err
}
func (o S3ExternalActionObserver) Observe(ctx context.Context, target ProviderProofTarget, expected int64) (ProviderObservation, error) {
	empty := ProviderObservation{}
	if o.DB == nil || o.client == nil {
		return empty, ErrRegistrationUnavailable
	}
	// Keep config/target locks across a bounded read so the signed observation
	// cannot be assembled from different target/config generations.
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, err := o.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, ErrRegistrationUnavailable
	}
	defer tx.Rollback()
	if o.DatabaseIdentity != nil {
		if err = o.DatabaseIdentity.check(ctx, tx); err != nil {
			return empty, err
		}
	}
	if lockRegistrationInstallations(ctx, tx) != nil {
		return empty, ErrRegistrationUnavailable
	}
	if _, err = lockRegistrationConfig(ctx, tx, o.InstallationID); err != nil {
		return empty, err
	}
	b, key, err := o.binding(ctx, tx, target)
	if err != nil {
		return empty, err
	}
	if b.RowVersion != expected {
		return empty, &ProviderProofError{Code: ProviderVersionConflict}
	}
	options := s3VersionOptions{}
	if b.ObservedVersion != nil {
		options.VersionID = *b.ObservedVersion
	}
	info, err := o.client.StatObject(ctx, o.Bucket, key, options)
	if err != nil || info.VersionID == "" || info.VersionID == "null" || info.Size != *b.ContentLength {
		return empty, ErrRegistrationUnavailable
	}
	object, err := o.client.GetObject(ctx, o.Bucket, key, s3VersionOptions{VersionID: info.VersionID})
	if err != nil {
		return empty, ErrRegistrationUnavailable
	}
	defer object.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(object, *b.ContentLength+1))
	if err != nil || size != *b.ContentLength || hex.EncodeToString(hash.Sum(nil)) != *b.ObservedChecksum {
		return empty, &ProviderProofError{Code: ProviderChecksumMismatch}
	}
	b.ObservedVersion = &info.VersionID
	b.AllowAttestedObservedVersion = false
	observed := time.Now().UTC()
	if tx.Commit() != nil {
		return empty, ErrRegistrationUnavailable
	}
	return ProviderObservation{Binding: b, ObservedAt: observed}, nil
}
