package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/hex"
	"reflect"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

const historicalDeploymentSelect = `SELECT origin_installation_id,workload_identity_hash,issuer_identity_hash,subject_hash,management_issuer_identity_hash,actor_identity_hash,admission_hash,client_ca_sha256,certificate_sha256,stat_profile_hash,enabled,deployment_epoch,authorized_until,row_version FROM system_backup_v2_recovery_deployments WHERE scope_key=? AND origin_installation_id=?`

// SystemHistoricalDeploymentGuard owns A's L0/L1a deployment admission. It
// never reads the original active configuration or grants provider access.
// D separately locks the exact L2 revocation row after A admits this row.
type SystemHistoricalDeploymentGuard struct {
	scope            pd.Scope
	scopeKey         []byte
	profile          string
	managementIssuer string
	row              historicalDeploymentRow
	locked           bool
}

type historicalDeploymentRow struct {
	origin        string
	workload      []byte
	issuer        []byte
	subject       []byte
	managerIssuer []byte
	actor         []byte
	admission     []byte
	clientCA      []byte
	certificate   []byte
	profile       []byte
	enabled       bool
	epoch         int64
	until         time.Time
	version       int64
}

func NewSystemHistoricalDeploymentGuard(scope pd.Scope, profileHash, managementIssuerHash string) (*SystemHistoricalDeploymentGuard, error) {
	if !digestPattern.MatchString(profileHash) || !digestPattern.MatchString(managementIssuerHash) {
		return nil, ErrInvalid
	}
	key, err := pd.RecoveryScopeKey(scope)
	if err != nil || len(key) != 32 {
		return nil, ErrInvalid
	}
	return &SystemHistoricalDeploymentGuard{scope: scope, scopeKey: key, profile: profileHash, managementIssuer: managementIssuerHash}, nil
}

// Lock takes the existing global installation scan and exact L0 parent lock,
// then the current L1a deployment row. An absent installation or deployment
// fails closed, including when a prior configuration is inactive.
func (g *SystemHistoricalDeploymentGuard) Lock(ctx context.Context, tx pd.SQL) error {
	if g == nil || g.locked || tx == nil || ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	rows, err := tx.QueryContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE")
	if err != nil {
		return ErrUnavailable
	}
	count, found := 0, false
	for rows.Next() {
		var installation string
		if rows.Scan(&installation) != nil {
			rows.Close()
			return ErrUnavailable
		}
		count++
		if count > 10000 {
			rows.Close()
			return ErrDenied
		}
		found = found || installation == string(g.scope.Installation)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	if !found {
		return ErrDenied
	}
	var installation string
	if err := tx.QueryRowContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", string(g.scope.Installation)).Scan(&installation); err != nil || installation != string(g.scope.Installation) {
		return ErrDenied
	}
	row, err := readHistoricalDeployment(ctx, tx, g.scopeKey, string(g.scope.Installation), true)
	if err != nil || !row.valid(g) {
		return ErrDenied
	}
	g.row, g.locked = row, true
	return nil
}

func readHistoricalDeployment(ctx context.Context, tx pd.ReadSQL, scopeKey []byte, installation string, lock bool) (historicalDeploymentRow, error) {
	query := historicalDeploymentSelect
	if lock {
		query += " FOR UPDATE"
	}
	var row historicalDeploymentRow
	err := tx.QueryRowContext(ctx, query, scopeKey, installation).Scan(
		&row.origin, &row.workload, &row.issuer, &row.subject, &row.managerIssuer,
		&row.actor, &row.admission, &row.clientCA, &row.certificate, &row.profile,
		&row.enabled, &row.epoch, &row.until, &row.version,
	)
	if err != nil {
		return historicalDeploymentRow{}, err
	}
	return row, nil
}

func (r historicalDeploymentRow) valid(g *SystemHistoricalDeploymentGuard) bool {
	if g == nil || r.origin != string(g.scope.Installation) || !r.enabled || r.epoch < 1 || r.version < 1 || !systemPeerTime(r.until) ||
		!equalHistoricalDigest(r.profile, g.profile) || !equalHistoricalDigest(r.managerIssuer, g.managementIssuer) {
		return false
	}
	for _, value := range [][]byte{r.workload, r.issuer, r.subject, r.managerIssuer, r.actor, r.admission, r.clientCA, r.certificate, r.profile} {
		if len(value) != 32 {
			return false
		}
	}
	return true
}

func equalHistoricalDigest(raw []byte, digest string) bool {
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == 32 && bytes.Equal(raw, decoded)
}

// Admit compares the authenticated workload and D's proposed admission to the
// locked row. D must still compare this epoch with its L2 revocation row.
func (g *SystemHistoricalDeploymentGuard) Admit(facts SystemPeerFacts, admission pd.RecoveryAdmission, dbNow time.Time) error {
	if g == nil || !g.locked || !systemPeerTime(dbNow) || !dbNow.Before(g.row.until) ||
		facts.Scope != g.scope || !dbNow.Before(facts.ExpiresAt) ||
		!equalHistoricalDigest(g.row.workload, facts.WorkloadIdentityHash) ||
		!equalHistoricalDigest(g.row.issuer, facts.IssuerIdentityHash) ||
		!equalHistoricalDigest(g.row.subject, facts.SubjectHash) ||
		!equalHistoricalDigest(g.row.actor, facts.ActorIdentityHash) ||
		!equalHistoricalDigest(g.row.admission, facts.AdmissionHash) ||
		!equalHistoricalDigest(g.row.clientCA, facts.ClientCASHA256) ||
		!equalHistoricalDigest(g.row.certificate, facts.CertificateSHA256) ||
		admission.IdentityHash != pd.Hash(facts.WorkloadIdentityHash) || !admission.StatAllowed {
		return ErrDenied
	}
	epoch, err := admission.RevocationEpoch.SQLInt64()
	if err != nil || epoch != g.row.epoch {
		return ErrDenied
	}
	identityUntil, identityErr := admission.IdentityExpiresAt.Time()
	deploymentUntil, deploymentErr := admission.DeploymentExpiresAt.Time()
	if identityErr != nil || deploymentErr != nil || identityUntil.After(facts.ExpiresAt) || !deploymentUntil.Equal(g.row.until) ||
		!dbNow.Before(identityUntil) || !dbNow.Before(deploymentUntil) {
		return ErrDenied
	}
	return nil
}

// Recheck reads only the already locked L1a row during D's FinalGuard. It
// rejects any row/version drift and requires the same workload proof and epoch.
func (g *SystemHistoricalDeploymentGuard) Recheck(ctx context.Context, tx pd.ReadSQL, facts SystemPeerFacts, admission pd.RecoveryAdmission, dbNow time.Time) error {
	if g == nil || !g.locked || tx == nil || ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	row, err := readHistoricalDeployment(ctx, tx, g.scopeKey, string(g.scope.Installation), false)
	if err != nil || !row.valid(g) || !reflect.DeepEqual(row, g.row) {
		return ErrDenied
	}
	return g.Admit(facts, admission, dbNow)
}
