package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
)

// This is deliberately separate from the controller's observer account. The
// release's GET get-config-kv requires admin:ConfigUpdate and is encrypted.
// Only an existing original configuration owner's private mc alias may be
// used. This code never installs privileges, creates aliases or invokes set.
// The official pinned mc owns madmin signing/decryption; no imitation encrypted
// JSON fixture or custom encryption implementation is accepted here.
type MinIOOriginalOwnerConfigurationInput struct{ File, SHA256 string }

type minioOriginalOwnerConfiguration struct {
	Version, Installation                                                string
	MCFile, MCSHA256, ConfigDir, ConfigSHA256, Alias, OwnerAccountSHA256 string
	SigningKeyFile, SigningKeySHA256                                     string
	Issuer                                                               ed25519.PublicKey
	Provider                                                             minioPermissionProvider
	NotBefore, Until                                                     time.Time
}

const minioOwnerMCRelease = "RELEASE.2025-04-16T18-13-26Z"

// Partial evidence contains no approval bit, configuration values, credentials
// or serializable permission proof. A successful configuration read still
// returns the explicit runtime-oracle error below. It cannot issue an engine
// grant/head or make CheckCurrent pass.
type MinIOOriginalOwnerConfigurationObservation struct {
	checkedAt               time.Time
	input, server, response string
	record, signature       []byte
}

func (o MinIOOriginalOwnerConfigurationObservation) CheckedAt() time.Time { return o.checkedAt }
func (o MinIOOriginalOwnerConfigurationObservation) ConfigurationResponseSHA256() string {
	return o.response
}
func (MinIOOriginalOwnerConfigurationObservation) MarshalJSON() ([]byte, error) {
	return nil, minioPermissionFailure("nonserializable-owner-configuration")
}

// The signed record explicitly says configuration-observation. It has no
// effective-permission, enabled-engine or successful-publication assertion.
func (o MinIOOriginalOwnerConfigurationObservation) SignedConfigurationRecord() ([]byte, []byte) {
	return append([]byte(nil), o.record...), append([]byte(nil), o.signature...)
}

type minioOwnerConfigKV struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	EnvOverride *struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"envOverride,omitempty"`
}
type minioOwnerConfigTarget struct {
	SubSystem string               `json:"subSystem"`
	Target    string               `json:"target,omitempty"`
	KV        []minioOwnerConfigKV `json:"kv"`
}

// Parse the complete mc response, including all named targets and environment
// overrides. It is a configuration observation, NOT runtime/effective IAM.
func minioOwnerConfigResponse(raw []byte, subsystem string) (string, error) {
	var message struct {
		Status string                   `json:"status"`
		Config []minioOwnerConfigTarget `json:"config"`
	}
	if len(raw) > 262144 || minioPermissionDecode(raw, &message) != nil || message.Status != "success" || len(message.Config) == 0 || len(message.Config) > 32 {
		return "", minioPermissionFailure("owner-config-complete-response")
	}
	targets := map[string]bool{}
	for _, target := range message.Config {
		if target.SubSystem != subsystem || targets[target.Target] || len(target.KV) == 0 || len(target.KV) > 128 {
			return "", minioPermissionFailure("owner-config-targets")
		}
		targets[target.Target] = true
		keys := map[string]bool{}
		for _, kv := range target.KV {
			if kv.Key == "" || keys[kv.Key] || len(kv.Value) > 16384 {
				return "", minioPermissionFailure("owner-config-keys")
			}
			keys[kv.Key] = true
			if kv.EnvOverride != nil && (!strings.HasPrefix(kv.EnvOverride.Name, "MINIO_"+strings.ToUpper(subsystem)+"_") || len(kv.EnvOverride.Value) > 16384) {
				return "", minioPermissionFailure("owner-config-environment")
			}
		}
	}
	canonical, err := ce.Canonical(message)
	if err != nil {
		return "", minioPermissionFailure("owner-config-canonical")
	}
	return hash(canonical), nil
}

type minioOwnerBoundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *minioOwnerBoundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, minioPermissionFailure("owner-command-response-limit")
	}
	return b.Buffer.Write(p)
}

func minioOwnerCommand(ctx context.Context, cfg minioOriginalOwnerConfiguration, args ...string) ([]byte, error) {
	// Require the already installed CA at the official mc config location.
	// Do not create trust files or accept another client certificate/config.
	certs := filepath.Join(cfg.ConfigDir, "certs")
	entries, err := os.ReadDir(certs)
	if err != nil || len(entries) != 1 || entries[0].Name() != "CAs" || !entries[0].IsDir() {
		return nil, minioPermissionFailure("owner-existing-mc-trust")
	}
	entries, err = os.ReadDir(filepath.Join(certs, "CAs"))
	if err != nil || len(entries) != 1 || entries[0].IsDir() {
		return nil, minioPermissionFailure("owner-existing-mc-trust")
	}
	caFile := filepath.Join(certs, "CAs", entries[0].Name())
	if _, err := pinnedDeploymentFile(caFile, cfg.Provider.CASHA256, 65536); err != nil {
		return nil, minioPermissionFailure("owner-mc-ca-pin")
	}
	if _, err := pinnedDeploymentFile(cfg.MCFile, cfg.MCSHA256, 128<<20); err != nil {
		return nil, minioPermissionFailure("owner-mc-binary-pin")
	}
	command := exec.CommandContext(ctx, cfg.MCFile, args...)
	// No MC_HOST_*, proxies, TLS-disable or credential environment overrides.
	// Absolute binary/config paths are mandatory. Do not inherit arbitrary env.
	for _, name := range []string{"SystemRoot", "WINDIR", "TEMP", "TMP"} {
		if value, ok := os.LookupEnv(name); ok {
			command.Env = append(command.Env, name+"="+value)
		}
	}
	var output minioOwnerBoundedOutput
	output.limit = 262144
	command.Stdout = &output
	command.Stderr = io.Discard
	if command.Run() != nil || ctx.Err() != nil {
		return nil, minioPermissionFailure("owner-authenticated-config-get")
	}
	if _, err := pinnedDeploymentFile(cfg.MCFile, cfg.MCSHA256, 128<<20); err != nil {
		return nil, minioPermissionFailure("owner-mc-binary-drift")
	}
	if _, err := pinnedDeploymentFile(caFile, cfg.Provider.CASHA256, 65536); err != nil {
		return nil, minioPermissionFailure("owner-mc-ca-drift")
	}
	return output.Bytes(), nil
}

// ObserveMinIOOriginalOwnerConfiguration connects to the ORIGINAL owner's
// already installed mc configuration. No callback or caller-supplied Passed
// observation substitutes for the authenticated GETs. Missing authority is a
// refusal, never an instruction to broaden the controller observer policy.
// This candidate cannot yet prove the running engine's complete effective
// state; even after real reads it returns partial evidence AND an error.
func ObserveMinIOOriginalOwnerConfiguration(ctx context.Context, input MinIOOriginalOwnerConfigurationInput) (MinIOOriginalOwnerConfigurationObservation, error) {
	var zero MinIOOriginalOwnerConfigurationObservation
	if ctx == nil || ctx.Err() != nil {
		return zero, minioPermissionFailure("owner-context")
	}
	initial, err := pinnedDeploymentFile(input.File, input.SHA256, 65536)
	var cfg minioOriginalOwnerConfiguration
	if err != nil || decodePublicationCanonical(initial, &cfg) != nil || cfg.Version != "minio-original-owner-configuration-source.v1" || cfg.Installation == "" || !minioPermissionName(cfg.Alias) || !formalCandidateDigest(cfg.OwnerAccountSHA256) || !formalCandidateDigest(cfg.SigningKeySHA256) || len(cfg.Issuer) != ed25519.PublicKeySize || !filepath.IsAbs(cfg.SigningKeyFile) || !filepath.IsAbs(cfg.ConfigDir) || !filepath.IsAbs(cfg.MCFile) || filepath.Clean(cfg.ConfigDir) != cfg.ConfigDir || filepath.Clean(cfg.MCFile) != cfg.MCFile || cfg.NotBefore.After(time.Now()) || !time.Now().Before(cfg.Until) || cfg.Until.Sub(cfg.NotBefore) > time.Minute {
		return zero, minioPermissionFailure("owner-independent-input")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ctx, deadline := context.WithDeadline(ctx, cfg.Until)
	defer deadline()
	observedAt := time.Now().UTC()
	configFile := filepath.Join(cfg.ConfigDir, "config.json")
	readAlias := func() (nativePublicationCredential, error) {
		raw, err := readPrivate(configFile, 65536)
		if err != nil || hash(raw) != cfg.ConfigSHA256 || minioPermissionUniqueJSON(raw) != nil {
			return nativePublicationCredential{}, minioPermissionFailure("owner-existing-private-alias")
		}
		defer clear(raw)
		var document struct {
			Version string `json:"version"`
			Aliases map[string]struct {
				URL          string `json:"url"`
				AccessKey    string `json:"accessKey"`
				SecretKey    string `json:"secretKey"`
				SessionToken string `json:"sessionToken,omitempty"`
				API          string `json:"api"`
				Path         string `json:"path"`
			} `json:"aliases"`
		}
		if minioPermissionDecode(raw, &document) != nil || document.Version != "10" {
			return nativePublicationCredential{}, minioPermissionFailure("owner-alias-version")
		}
		alias, ok := document.Aliases[cfg.Alias]
		if !ok || alias.URL != cfg.Provider.Endpoint || alias.API != "S3v4" || alias.AccessKey == "" || alias.SecretKey == "" || alias.SessionToken != "" || hash([]byte(alias.AccessKey)) != cfg.OwnerAccountSHA256 {
			return nativePublicationCredential{}, minioPermissionFailure("owner-alias-binding")
		}
		return nativePublicationCredential{AccessKey: alias.AccessKey, SecretKey: alias.SecretKey, NotBefore: cfg.NotBefore, Until: cfg.Until}, nil
	}
	credential, err := readAlias()
	if err != nil {
		return zero, err
	}
	native, err := newMinioPermissionHTTP(cfg.Provider, credential)
	credential = nativePublicationCredential{}
	if err != nil {
		return zero, err
	}
	defer native.close()
	server, err := native.server(ctx)
	if err != nil {
		return zero, err
	}
	version, err := minioOwnerCommand(ctx, cfg, "--version")
	if err != nil || !strings.HasPrefix(string(version), "mc version "+minioOwnerMCRelease+" ") {
		return zero, minioPermissionFailure("owner-mc-version")
	}
	subsystems := []string{"policy_plugin", "policy_opa", "identity_openid", "identity_ldap", "identity_tls", "identity_plugin"}
	collect := func() (string, error) {
		stamps := []string{}
		for _, subsystem := range subsystems {
			if _, err := readAlias(); err != nil {
				return "", err
			}
			raw, err := minioOwnerCommand(ctx, cfg, "--airgap", "--json", "--config-dir", cfg.ConfigDir, "admin", "config", "get", cfg.Alias, subsystem)
			if err != nil {
				return "", err
			}
			stamp, err := minioOwnerConfigResponse(raw, subsystem)
			clear(raw)
			if err != nil {
				return "", err
			}
			stamps = append(stamps, stamp)
		}
		raw, _ := ce.Canonical(stamps)
		return hash(raw), nil
	}
	first, err := collect()
	if err != nil {
		return zero, err
	}
	tail, err := collect()
	if err != nil || first != tail {
		return zero, minioPermissionFailure("owner-config-tail-drift")
	}
	lastServer, err := native.server(ctx)
	if err != nil || lastServer != server {
		return zero, minioPermissionFailure("owner-server-tail-drift")
	}
	if _, err := readAlias(); err != nil {
		return zero, err
	}
	if _, err := pinnedDeploymentFile(input.File, input.SHA256, 65536); err != nil || ctx.Err() != nil || !time.Now().Before(cfg.Until) {
		return zero, minioPermissionFailure("owner-source-tail-drift")
	}
	key, err := readPrivate(cfg.SigningKeyFile, ed25519.PrivateKeySize)
	if err != nil || len(key) != ed25519.PrivateKeySize || hash(key) != cfg.SigningKeySHA256 || len(cfg.Issuer) != ed25519.PublicKeySize || !bytes.Equal(ed25519.PrivateKey(key).Public().(ed25519.PublicKey), cfg.Issuer) {
		clear(key)
		return zero, minioPermissionFailure("original-configuration-owner-signing-key")
	}
	defer clear(key)
	until := cfg.Until
	if bound := observedAt.Add(30 * time.Second); bound.Before(until) {
		until = bound
	}
	if !time.Now().Before(until) {
		return zero, minioPermissionFailure("owner-configuration-window")
	}
	record, err := ce.Canonical(minioPermissionEngine{Version: "minio-owner-configuration-observation.v1", Installation: cfg.Installation, Endpoint: cfg.Provider.Endpoint, DeploymentID: cfg.Provider.DeploymentID, ServerVersion: minioPermissionVersion, ServerCommit: minioPermissionCommit, SourceMethod: "minio-admin-v3/get-config-kv:identity+policy", NativeResponseSHA256: first, ObservedAt: observedAt, Until: until})
	if err != nil {
		return zero, minioPermissionFailure("owner-configuration-record")
	}
	signature := ed25519.Sign(ed25519.PrivateKey(key), append([]byte(minioPermissionEngineDomain), record...))
	return MinIOOriginalOwnerConfigurationObservation{checkedAt: time.Now().UTC(), input: input.SHA256, server: server, response: first, record: record, signature: signature}, minioPermissionFailure("native-effective-policy-engine-runtime-unavailable")
}
