package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"
)

// File paths are deployment-owned, not accepted by any API. The entire
// runtime file is SHA-256 pinned by a separate deployment environment value.
type RegistrationRuntimeConfig struct {
	ExpectedServerUUID      string `json:"expected_server_uuid"`
	ExpectedDatabase        string `json:"expected_database"`
	InstallationID          string `json:"installation_id"`
	ConfigVersion           int64  `json:"config_version"`
	RegistryDirectory       string `json:"registry_directory"`
	NonceDirectory          string `json:"nonce_directory"`
	CapacityReportFile      string `json:"capacity_report_file"`
	ProviderRegistryVersion string `json:"provider_registry_version"`
	ProviderRegistrySHA256  string `json:"provider_registry_sha256"`
	StrongRegistryVersion   string `json:"strong_registry_version"`
	StrongRegistrySHA256    string `json:"strong_registry_sha256"`
	RBACRegistryVersion     string `json:"rbac_registry_version"`
	RBACRegistrySHA256      string `json:"rbac_registry_sha256"`
	ProviderKeyID           string `json:"provider_key_id"`
	ProviderKeyVersion      string `json:"provider_key_version"`
	StrongKeyID             string `json:"strong_key_id"`
	StrongKeyVersion        string `json:"strong_key_version"`
	TransitEndpoint         string `json:"transit_endpoint"`
	TransitCAFile           string `json:"transit_ca_file"`
	ProviderTransitKey      string `json:"provider_transit_key"`
	StrongTransitKey        string `json:"strong_transit_key"`
	ProviderTokenFile       string `json:"provider_token_file"`
	StrongTokenFile         string `json:"strong_token_file"`
	JWTSecretFile           string `json:"jwt_secret_file"`
	TOTPEncryptionKeyFile   string `json:"totp_encryption_key_file"`
	S3Endpoint              string `json:"s3_endpoint"`
	S3Bucket                string `json:"s3_bucket"`
	S3Prefix                string `json:"s3_prefix"`
	S3IdentityHash          string `json:"s3_identity_hash"`
	S3CAFile                string `json:"s3_ca_file"`
	S3AccessKeyFile         string `json:"s3_access_key_file"`
	S3SecretKeyFile         string `json:"s3_secret_key_file"`
}

type RegistrationApplication struct {
	API       RegistrationAPI
	Config    RegistrationRuntimeConfig
	Authority PinnedRegistrationAuthority
	DB        *sql.DB
}
type configuredAuthority struct {
	PinnedRegistrationAuthority
	expected RegistrationConfig
	database DatabaseIdentity
}

func (a configuredAuthority) Authorize(ctx context.Context, tx *sql.Tx, actor RegistrationActor, target ProviderProofTarget, c RegistrationConfig) error {
	if err := a.database.check(ctx, tx); err != nil {
		return err
	}
	if !sameRuntimeConfig(a.expected, c) {
		return ErrRegistrationUnavailable
	}
	return a.PinnedRegistrationAuthority.Authorize(ctx, tx, actor, target, c)
}

// Lock permission/configuration for the entire MFA operation. Before first
// bootstrap only deployment-pinned v1 authorization is accepted. Once any
// active configuration exists its current pins must match this process; a
// rotation/revocation cannot leave the old bootstrap grant usable for MFA.
func (a configuredAuthority) AuthorizeMFA(ctx context.Context, tx *sql.Tx, actor RegistrationActor) error {
	if err := a.database.check(ctx, tx); err != nil {
		return err
	}
	if err := lockRegistrationInstallations(ctx, tx); err != nil {
		return err
	}
	var version int64
	err := tx.QueryRowContext(ctx, "SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", a.InstallationID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		if a.expected.Version != 1 {
			return ErrRegistrationUnavailable
		}
		// Orphan config rows are not a fresh installation/bootstrap grant.
		err = tx.QueryRowContext(ctx, "SELECT version FROM system_backup_v2_configs WHERE origin_installation_id=? ORDER BY version LIMIT 1 FOR UPDATE", a.InstallationID).Scan(&version)
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrRegistrationUnavailable
		}
		return a.AuthorizeRole(actor, a.expected)
	}
	if err != nil {
		return ErrRegistrationUnavailable
	}
	c, err := lockRegistrationConfig(ctx, tx, a.InstallationID)
	if err != nil || !sameRuntimeConfig(a.expected, c) {
		return ErrRegistrationUnavailable
	}
	return a.AuthorizeRole(actor, c)
}
func sameRuntimeConfig(a, b RegistrationConfig) bool {
	return a.Version == b.Version && a.ProviderRegistryVersion == b.ProviderRegistryVersion && a.ProviderRegistrySHA256 == b.ProviderRegistrySHA256 && a.StrongAuthRegistryVersion == b.StrongAuthRegistryVersion && a.StrongAuthRegistrySHA256 == b.StrongAuthRegistrySHA256 && a.RBACRegistryVersion == b.RBACRegistryVersion && a.RBACRegistrySHA256 == b.RBACRegistrySHA256
}
func (c RegistrationRuntimeConfig) expected() RegistrationConfig {
	return RegistrationConfig{Version: c.ConfigVersion, ProviderRegistryVersion: c.ProviderRegistryVersion, ProviderRegistrySHA256: c.ProviderRegistrySHA256, StrongAuthRegistryVersion: c.StrongRegistryVersion, StrongAuthRegistrySHA256: c.StrongRegistrySHA256, RBACRegistryVersion: c.RBACRegistryVersion, RBACRegistrySHA256: c.RBACRegistrySHA256}
}

func LoadRegistrationApplication(db *sql.DB, path, digest string) (*RegistrationApplication, error) {
	raw, err := boundedFile(path, 32768)
	if err != nil {
		return nil, err
	}
	var c RegistrationRuntimeConfig
	if db == nil || decodePinnedRegistry(raw, digest, &c) != nil || c.ConfigVersion < 1 || c.InstallationID == "" || c.ProviderTransitKey == c.StrongTransitKey {
		return nil, ErrRegistrationUnavailable
	}
	databaseIdentity := DatabaseIdentity{ServerUUID: c.ExpectedServerUUID, Database: c.ExpectedDatabase}
	probe, done := context.WithTimeout(context.Background(), 10*time.Second)
	err = databaseIdentity.check(probe, db)
	done()
	if err != nil {
		return nil, err
	}
	files := RegistrationFiles{RegistryDirectory: c.RegistryDirectory, NonceDirectory: c.NonceDirectory}
	providerRaw, err := files.RegistryBytes("provider_proof_issuers", c.ProviderRegistryVersion, c.ProviderRegistrySHA256)
	if err != nil {
		return nil, err
	}
	pr, err := DecodeProviderIssuerRegistry(providerRaw, c.ProviderRegistryVersion, c.ProviderRegistrySHA256, time.Now().UTC())
	if err != nil || pr.Scope.InstallationID != c.InstallationID {
		return nil, ErrRegistrationUnavailable
	}
	var pk ProviderProofKey
	for _, k := range pr.resolvedKeys() {
		if k.KeyID == c.ProviderKeyID && k.KeyVersion == c.ProviderKeyVersion {
			pk = k
		}
	}
	strongRaw, err := files.RegistryBytes("strong_auth_issuers", c.StrongRegistryVersion, c.StrongRegistrySHA256)
	if err != nil {
		return nil, err
	}
	sr, err := DecodeStrongAuthIssuerRegistry(strongRaw, c.StrongRegistryVersion, c.StrongRegistrySHA256, time.Now().UTC())
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	var sk StrongAuthRegistryKey
	for _, k := range sr.Keys {
		if k.KeyID == c.StrongKeyID && k.KeyVersion == c.StrongKeyVersion {
			if sk.KeyID != "" {
				return nil, ErrRegistrationUnavailable
			}
			sk = k
		}
	}
	now := time.Now().UTC()
	if pk.KeyID == "" || pk.Revoked || now.Before(pk.NotBefore) || !now.Add(5*time.Minute).Before(pk.NotAfter) || sk.KeyID == "" || sk.Purpose != "strong_auth_issuer" || sk.Revoked || now.Before(sk.NotBefore) || !now.Add(5*time.Minute).Before(sk.NotAfter) || !contains(sk.Policy.Methods, "totp") || !contains(sk.Policy.AMR, "otp") {
		return nil, ErrRegistrationUnavailable
	}
	for _, p := range pr.Keys {
		for _, s := range sr.Keys {
			if bytes.Equal(p.PublicKey, s.PublicKey) {
				return nil, ErrRegistrationUnavailable
			}
		}
	}
	ca, err := boundedFile(c.TransitCAFile, 65536)
	if err != nil {
		return nil, err
	}
	providerToken, err := boundedFile(c.ProviderTokenFile, 4096)
	if err != nil {
		return nil, err
	}
	strongToken, err := boundedFile(c.StrongTokenFile, 4096)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(providerToken), bytes.TrimSpace(strongToken)) {
		return nil, ErrRegistrationUnavailable
	}
	ps, err := NewTransitSigner(c.TransitEndpoint, c.ProviderTransitKey, pk.KeyVersion, string(bytes.TrimSpace(providerToken)), ca, pk.PublicKey)
	if err != nil {
		return nil, err
	}
	ss, err := NewTransitSigner(c.TransitEndpoint, c.StrongTransitKey, sk.KeyVersion, string(bytes.TrimSpace(strongToken)), ca, sk.PublicKey)
	if err != nil {
		return nil, err
	}
	s3CA, err := boundedFile(c.S3CAFile, 65536)
	if err != nil {
		return nil, err
	}
	access, err := boundedFile(c.S3AccessKeyFile, 1024)
	if err != nil {
		return nil, err
	}
	secret, err := boundedFile(c.S3SecretKeyFile, 4096)
	if err != nil {
		return nil, err
	}
	observer, err := NewS3ExternalActionObserver(db, c.InstallationID, pk.Issuer, c.S3Endpoint, c.S3Bucket, c.S3Prefix, c.S3IdentityHash, string(bytes.TrimSpace(access)), string(bytes.TrimSpace(secret)), s3CA)
	if err != nil {
		return nil, err
	}
	observer.DatabaseIdentity = &databaseIdentity
	encryption, err := boundedFile(c.TOTPEncryptionKeyFile, 32)
	if err != nil {
		return nil, err
	}
	box, err := NewTOTPSecretBox(encryption)
	wipeSecret(encryption)
	if err != nil {
		return nil, err
	}
	jwtSecret, err := boundedFile(c.JWTSecretFile, 1024)
	if err != nil || len(jwtSecret) < 32 {
		return nil, ErrRegistrationUnavailable
	}
	totp := SQLTOTPService{DB: db, DatabaseIdentity: &databaseIdentity, InstallationID: c.InstallationID, Box: box, Issuer: StrongAuthProofIssuer{Key: sk, Audience: sr.Audience, Signer: ss, Lifetime: 2 * time.Minute}}
	authority := PinnedRegistrationAuthority{InstallationID: c.InstallationID, RegistryBytes: files.RegistryBytes, TargetBinding: observer.TargetBinding, NonceKeys: files.NonceKeys, ReserveMetadata: RegistrationCapacity{ReportFile: c.CapacityReportFile}.Reserve}
	authority.CheckSessionAndVisibility = func(ctx context.Context, tx *sql.Tx, actor RegistrationActor, target ProviderProofTarget) error {
		if err := CheckRegistrationSession(ctx, tx, c.InstallationID, actor); err != nil {
			return err
		}
		_, err := observer.TargetBinding(ctx, tx, target)
		return err
	}
	actual := configuredAuthority{PinnedRegistrationAuthority: authority, expected: c.expected(), database: databaseIdentity}
	totp.Authorize = actual.AuthorizeMFA
	service := ProviderRegistrationService{DB: db, InstallationID: c.InstallationID, Authority: actual}
	app := &RegistrationApplication{Config: c, Authority: authority, DB: db}
	app.API = RegistrationAPI{Registration: ProviderRegistrationHTTP{Auth: JWTRegistrationAuthenticator{Secret: jwtSecret}, Service: service}, TOTP: totp, Attestation: ProviderAttestationService{Scope: pr.Scope, Key: pk, Observer: observer, Signer: ps, Lifetime: 2 * time.Minute}}
	app.API.AuthorizeObservation = func(ctx context.Context, a RegistrationActor, target ProviderProofTarget) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return ErrRegistrationUnavailable
		}
		defer tx.Rollback()
		if lockRegistrationInstallations(ctx, tx) != nil {
			return ErrRegistrationUnavailable
		}
		cfg, err := lockRegistrationConfig(ctx, tx, c.InstallationID)
		if err != nil {
			return err
		}
		if err = actual.Authorize(ctx, tx, a, target, cfg); err != nil {
			return err
		}
		return tx.Commit()
	}
	return app, nil
}

// CheckActivation reads the actual active config, all required nonce secrets,
// issuer/RBAC bytes, UTC clock and runtime schema. It does not fabricate a
// config row or switch versions outside the config-mutation protocol.
func (a *RegistrationApplication) CheckActivation(ctx context.Context) error {
	tx, err := a.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	defer tx.Rollback()
	if err = (DatabaseIdentity{ServerUUID: a.Config.ExpectedServerUUID, Database: a.Config.ExpectedDatabase}).check(ctx, tx); err != nil {
		return err
	}
	if lockRegistrationInstallations(ctx, tx) != nil {
		return ErrRegistrationUnavailable
	}
	cfg, err := lockRegistrationConfig(ctx, tx, a.Config.InstallationID)
	if err != nil || !sameRuntimeConfig(a.Config.expected(), cfg) {
		return ErrRegistrationUnavailable
	}
	var now time.Time
	var offset int64
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&now, &offset) != nil || offset != 0 {
		return ErrRegistrationUnavailable
	}
	versions, err := retainedNonceVersions(ctx, tx, cfg.NonceKeyVersion, now)
	if err != nil {
		return err
	}
	if _, err = a.Authority.NonceKeys(ctx, tx, cfg, versions); err != nil {
		return err
	}
	for _, table := range []string{"system_backup_v2_totp_credentials", "system_backup_v2_admin_sessions", "system_backup_v2_admin_revocations", "system_backup_v2_metadata_reservations"} {
		var count int
		if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", table).Scan(&count) != nil || count != 1 {
			return ErrRegistrationUnavailable
		}
	}
	// This test reservation is rolled back. No control state changes on probes.
	if err = a.Authority.ReserveCapacity(ctx, tx, cfg, 8192); err != nil {
		return err
	}
	return nil
}
