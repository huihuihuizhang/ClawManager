package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

type EnabledForwardReceipt struct {
	Version       string
	Grant, Config BootstrapSourceFilePin
	ConfigVersion uint64
}

// ReissueExecutionIdentity requires BOTH the authenticated committed enable
// and the actual private key of the old independently trusted execution issuer.
// It preserves the entire old grant including every action, key and deadline;
// only the SQL configuration version/hash change. It never edits old files.
func (p *OriginalEnabledPublication) ReissueExecutionIdentity(ctx context.Context, runtimeDB *sql.DB, old *c.PinnedExecutionIdentity, oldFile BootstrapSourceFilePin, keyDirectory, directory string, issuerPrivate []byte) (EnabledForwardReceipt, error) {
	var zero EnabledForwardReceipt
	if p == nil || runtimeDB == nil || old == nil || privateDirectory(directory) != nil || p.Recheck(ctx) != nil || old.CheckDeployment(ctx, runtimeDB) != nil || oldFile.SHA256 != old.GrantSHA256() {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(oldFile, 65536)
	if e != nil {
		return zero, ErrInstall
	}
	g := old.DeploymentBinding()
	target := p.operator.installer.plan.Target
	if g.ConfigVersion != 1 || g.ConfigSHA256 != hash(p.original) || g.InstallationID != target.InstallationID || g.ServerUUID != target.ServerUUID || g.Database != target.Database || p.floor.Before(g.NotBefore) || !p.floor.Before(g.ExpiresAt) {
		return zero, ErrInstall
	}
	if _, e := p.operator.installer.checkOriginalRuntimeSQLPeer(ctx, runtimeDB, g.DatabaseAccount); e != nil {
		return zero, ErrInstall
	}
	next, e := signEnabledForward(raw, g, p.version, p.configSHA, issuerPrivate)
	if e != nil {
		return zero, ErrInstall
	}
	config, version, configSHA, e := p.Configuration(ctx)
	if e != nil {
		return zero, ErrInstall
	}
	// Authenticate the original file once more before any output is visible.
	again, e := readBootstrapSourcePin(oldFile, 65536)
	if e != nil || !bytes.Equal(again, raw) || old.CheckDeployment(ctx, runtimeDB) != nil || p.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	grantPin := BootstrapSourceFilePin{File: filepath.Join(directory, "enabled-forward.grant.json"), SHA256: hash(next)}
	configPin := BootstrapSourceFilePin{File: filepath.Join(directory, "enabled-config.json"), SHA256: configSHA}
	if writeNewFiles(directory, map[string][]byte{"enabled-forward.grant.json": next, "enabled-config.json": config}) != nil {
		return zero, ErrInstall
	}
	// Use the unchanged normal reader and SQL workload check on real outputs.
	key := ed25519.PrivateKey(issuerPrivate)
	fresh, e := c.NewPinnedExecutionIdentity(grantPin.File, grantPin.SHA256, keyDirectory, key.Public().(ed25519.PublicKey))
	if e != nil || fresh.CheckDeployment(ctx, runtimeDB) != nil || old.CheckDeployment(ctx, runtimeDB) != nil || p.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	if _, e := p.operator.installer.checkOriginalRuntimeSQLPeer(ctx, runtimeDB, g.DatabaseAccount); e != nil || fresh.CheckDeployment(ctx, runtimeDB) != nil || p.Recheck(ctx) != nil || !p.floor.Before(g.ExpiresAt) || !time.Now().Before(g.ExpiresAt) {
		return zero, ErrInstall
	}
	return EnabledForwardReceipt{Version: "original-enabled-forward-result.v1", Grant: grantPin, Config: configPin, ConfigVersion: version}, nil
}

func signEnabledForward(raw []byte, old c.ExecutionGrant, version uint64, configSHA string, issuerPrivate []byte) ([]byte, error) {
	if len(issuerPrivate) != ed25519.PrivateKeySize || version != 2 || old.ConfigVersion != 1 || !digestPattern.MatchString(configSHA) || configSHA == old.ConfigSHA256 {
		return nil, ErrInstall
	}
	key := ed25519.NewKeyFromSeed(issuerPrivate[:ed25519.SeedSize])
	defer clear(key)
	if !bytes.Equal(key, issuerPrivate) {
		return nil, ErrInstall
	}
	var envelope struct {
		Payload   string `json:"payload_base64"`
		Signature string `json:"signature_base64"`
	}
	if decodeOriginalExecutionJSON(raw, &envelope) != nil {
		return nil, ErrInstall
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if e != nil || len(payload) > 32768 {
		return nil, ErrInstall
	}
	signature, e := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if e != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), payload, signature) {
		return nil, ErrInstall
	}
	var actual c.ExecutionGrant
	if decodeOriginalExecutionJSON(payload, &actual) != nil || !reflect.DeepEqual(actual, old) {
		return nil, ErrInstall
	}
	actual.ConfigVersion = version
	actual.ConfigSHA256 = configSHA
	payload, e = canonical(actual)
	if e != nil {
		return nil, ErrInstall
	}
	envelope.Payload = base64.StdEncoding.EncodeToString(payload)
	envelope.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))
	return canonical(envelope)
}

// Same structural/EOF boundary as the original execution grant reader. The
// existing issuer signed exact json.Marshal bytes, which need not be JCS.
func decodeOriginalExecutionJSON(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInstall
	}
	return nil
}
