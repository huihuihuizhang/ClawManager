package systembackupexecution

import (
	c "clawreef/internal/systembackupcontroller"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type admissionConnector struct {
	now     time.Time
	account string
}

func (a admissionConnector) Connect(context.Context) (driver.Conn, error) {
	return admissionConn{a}, nil
}
func (a admissionConnector) Driver() driver.Driver { return admissionDriver{a} }

type admissionDriver struct{ a admissionConnector }

func (a admissionDriver) Open(string) (driver.Conn, error) { return admissionConn{a.a}, nil }

type admissionConn struct{ a admissionConnector }

func (a admissionConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (a admissionConn) Close() error              { return nil }
func (a admissionConn) Begin() (driver.Tx, error) { return nil, errors.New("unexpected transaction") }
func (a admissionConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	if q != "SELECT UTC_TIMESTAMP(6),CURRENT_USER(),@@server_uuid,DATABASE()" {
		return nil, errors.New("capture privilege probe prohibited")
	}
	return &admissionRows{values: []driver.Value{a.a.now, a.a.account, "server", "backup"}}, nil
}

type admissionRows struct{ values []driver.Value }

func (*admissionRows) Columns() []string { return []string{"now", "account", "server", "database"} }
func (*admissionRows) Close() error      { return nil }
func (r *admissionRows) Next(out []driver.Value) error {
	if r.values == nil {
		return io.EOF
	}
	copy(out, r.values)
	r.values = nil
	return nil
}

func TestDeploymentDatabaseAdmissionUsesSignedRecoveryWithoutCapturePrivileges(t *testing.T) {
	for _, fault := range []string{"", "expired-forward", "valid-forward", "expired", "account", "config", "purpose", "key", "signature"} {
		t.Run(fault, func(t *testing.T) {
			cfg := testDeploymentConfiguration(t)
			cfg.InstallationID = "installation_" + strings.Repeat("a", 32)
			cfg.ControllerOwner = "controller-a"
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			cfg.RecoveryGrant = GrantReference{filepath.Join(cfg.KeyDirectory, "recovery.json"), base64.StdEncoding.EncodeToString(pub)}
			cfg.ForwardGrant = GrantReference{filepath.Join(cfg.KeyDirectory, "absent.json"), base64.StdEncoding.EncodeToString(pub)}
			write := func(path string, raw []byte) {
				t.Helper()
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			raw, _ := json.Marshal(cfg)
			configHash := hash(raw)
			write(cfg.ProfileFile, raw)
			now := time.Now().UTC()
			key := []byte(strings.Repeat("k", 32))
			g := c.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: cfg.InstallationID, ControllerOwner: cfg.ControllerOwner, DatabaseAccount: "backup_controller@localhost", ServerUUID: "server", Database: "backup", ConfigVersion: 1, ConfigSHA256: strings.Repeat("b", 64), ProfileSHA256: strings.Repeat("c", 64), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Actions: []string{"recover"}, RecordKeys: []c.ExecutionRecordKey{{Ref: "record-v1", SHA256: hash(key)}}, DeploymentConfigSHA256: configHash}
			account := g.DatabaseAccount
			switch fault {
			case "expired":
				g.NotBefore = now.Add(-2 * time.Hour)
				g.ExpiresAt = now.Add(-time.Hour)
			case "account":
				account = "other@localhost"
			case "config":
				g.DeploymentConfigSHA256 = strings.Repeat("d", 64)
			case "purpose":
				g.Actions = []string{"capture"}
			case "key":
				key[0] = 'x'
			}
			write(filepath.Join(cfg.KeyDirectory, "record-v1"), key)
			body, _ := json.Marshal(g)
			sig := ed25519.Sign(priv, body)
			if fault == "signature" {
				sig[0] ^= 1
			}
			envelope, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(body), "signature_base64": base64.StdEncoding.EncodeToString(sig)})
			write(cfg.RecoveryGrant.Path, envelope)
			forwardHash := strings.Repeat("f", 64)
			if fault == "expired-forward" || fault == "valid-forward" {
				fg := g
				fg.Actions = []string{"prepare", "capture", "issue_worker"}
				fg.WorkerIssuerSHA256 = strings.Repeat("e", 64)
				if fault == "expired-forward" {
					fg.NotBefore, fg.ExpiresAt = now.Add(-2*time.Hour), now.Add(-time.Hour)
					fg.DeploymentConfigSHA256 = strings.Repeat("9", 64)
					fg.ProfileSHA256 = strings.Repeat("8", 64)
				}
				fb, _ := json.Marshal(fg)
				fe, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(fb), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, fb))})
				write(cfg.ForwardGrant.Path, fe)
				forwardHash = hash(fe)
			}
			db := sql.OpenDB(admissionConnector{now, account})
			defer db.Close()
			// Even requested forward mode must fall back when its file is absent.
			for _, enabled := range []bool{false, true} {
				// Enabled-publication locators survive an ordinary restart.
				// Recovery must not need their source/signing files to exist.
				for _, selected := range []*EnabledPublicationStartupFiles{nil, {
					Forward:         OriginalEnabledSourcePin{File: cfg.ForwardGrant.Path, SHA256: forwardHash},
					OriginalForward: OriginalEnabledSourcePin{File: cfg.ForwardGrant.Path, SHA256: forwardHash},
				}} {
					err = CheckDeploymentDatabaseWithInputs(context.Background(), db, cfg.ProfileFile, configHash, forwardHash, hash(envelope),
						enabled, DeploymentStartupInputs{EnabledPublication: selected})
					allowed := fault == "" || fault == "expired-forward" || (fault == "valid-forward" && !enabled)
					if (err == nil) != allowed {
						t.Fatalf("enabled=%v selected=%v fault=%s: %v", enabled, selected != nil, fault, err)
					}
					if allowed {
						s := &DeploymentService{Config: cfg, ConfigDigest: configHash, ForwardEnabled: enabled,
							originalSourceForward: &c.PinnedExecutionIdentity{}, enabledPublicationFiles: &EnabledPublicationStartupFiles{}}
						if err := s.loadDeploymentIdentities(context.Background(), db, forwardHash, hash(envelope), selected); err != nil ||
							s.ForwardEnabled || s.Forward != s.Recovery || s.originalSourceForward != nil || s.enabledPublicationFiles != nil {
							t.Fatal("recovery retained stale forward metadata", err)
						}
					}
				}
			}
		})
	}
}
