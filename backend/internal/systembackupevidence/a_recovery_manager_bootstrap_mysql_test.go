//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type recoveryBootstrapAuditProbe struct {
	stages     []string
	failIntent bool
	failResult bool
}

func (a *recoveryBootstrapAuditProbe) AppendRecoveryManagerAudit(_ context.Context, record RecoveryManagerExternalAuditRecord) error {
	a.stages = append(a.stages, record.Stage)
	if record.Stage == "intent" && a.failIntent || record.Stage == "result" && a.failResult {
		return errors.New("injected independent audit failure")
	}
	return nil
}

func TestRecoveryManagerBootstrapMySQL(t *testing.T) {
	db, _ := dProducerMySQLDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, peerFixture, config := systemPeerFixture(t)
	var server, database string
	mustSQL(t, db.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database))
	scope := config.Scope
	scope.ServerUUID, scope.Database = pd.ServerUUID(server), pd.Database(database)
	mapping := RecoveryManagerPeerConfig{Scope: scope, IssuerIdentityHash: strings.Repeat("d", 64), Subject: "recovery-manager",
		ClientCAPEM: config.ClientCAPEM, ClientCASHA256: config.ClientCASHA256,
		CertificateSHA256: config.CertificateSHA256, ExpiresAt: config.ExpiresAt}
	auth, err := NewRecoveryManagerPeerAuthenticator(mapping)
	mustSQL(t, err)
	t.Cleanup(auth.Close)
	peer, err := auth.AuthenticateRequest(peerFixture.request)
	mustSQL(t, err)
	var now time.Time
	mustSQL(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	facts, err := auth.Check(ctx, peer, scope, now)
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_installation_state
(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key)
VALUES (?,1,UTC_TIMESTAMP(6),'k8s-cluster')`, string(scope.Installation))
	mustSQL(t, err)
	doc := recoveryManagerBootstrapDocument{SchemaVersion: recoveryManagerBootstrapVersion, GrantID: "first-manager-20261010",
		Scope: scope, BootstrapIdentityHash: strings.Repeat("a", 64), ManagerIdentityHash: facts.IdentityHash,
		IssuerIdentityHash: facts.IssuerIdentityHash, CredentialBindingHash: facts.CredentialBindingHash,
		ReasonHash: strings.Repeat("b", 64), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
		AuthorizedUntil: now.Add(time.Minute), ReadFence: true, WriteFence: true, ManageDeployment: true}
	raw, err := json.Marshal(doc)
	mustSQL(t, err)
	path := filepath.Join(t.TempDir(), "manager-grant.json")
	mustSQL(t, os.WriteFile(path, raw, 0600))
	sum := sha256.Sum256(raw)
	pin := hex.EncodeToString(sum[:])
	grant, err := ReadRecoveryManagerBootstrapGrant(path, pin)
	mustSQL(t, err)
	audit := &recoveryBootstrapAuditProbe{failIntent: true}
	service := RecoveryManagerBootstrapService{DB: db, Scope: scope, BootstrapIdentityHash: doc.BootstrapIdentityHash,
		GrantPath: path, GrantSHA256: pin, Authenticator: auth, ExternalAudit: audit}
	if err := service.RegisterFirst(ctx, peer, grant); !errors.Is(err, ErrUnavailable) {
		t.Fatal("independent intent audit failure accepted", err)
	}
	key, err := pd.RecoveryScopeKey(scope)
	mustSQL(t, err)
	assertRecoveryBootstrapDB(t, ctx, db, key, 0, 0)
	audit.failIntent, audit.failResult = false, true
	if err := service.RegisterFirst(ctx, peer, grant); !errors.Is(err, ErrRecoveryManagerCommitUnknown) {
		t.Fatal("post-commit independent result audit failure was not unknown", err)
	}
	assertRecoveryBootstrapDB(t, ctx, db, key, 1, 2)
	if err := service.RegisterFirst(ctx, peer, grant); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate first-manager registration accepted", err)
	}
	assertRecoveryBootstrapDB(t, ctx, db, key, 1, 2)
	if len(audit.stages) != 4 || audit.stages[0] != "intent" || audit.stages[1] != "intent" || audit.stages[2] != "result" || audit.stages[3] != "intent" {
		t.Fatalf("unexpected external audit sequence: %v", audit.stages)
	}
}

func assertRecoveryBootstrapDB(t *testing.T, ctx context.Context, db *sql.DB, key []byte, managers, audits int) {
	t.Helper()
	var got int
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_recovery_managers WHERE scope_key=?", key).Scan(&got))
	if got != managers {
		t.Fatalf("manager rows=%d, want %d", got, managers)
	}
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs WHERE action LIKE 'system_backup.recovery_manager_bootstrap.%'").Scan(&got))
	if got != audits {
		t.Fatalf("bootstrap audit rows=%d, want %d", got, audits)
	}
}
