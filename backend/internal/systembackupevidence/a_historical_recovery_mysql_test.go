//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// The SQL policy and provider proof remain synthetic. The mTLS request proof,
// A historical row reconstruction, D recovery transaction and revocation row
// are real in this isolated MySQL test.
type aRecoveryMySQLAuthority struct{ *dRecoveryMySQLAuthority }

type aRecoveryMySQLTrace struct {
	pd.HistoricalRecoveryEnvironment
}

func (e aRecoveryMySQLTrace) PrepareRecovery(ctx context.Context, r pd.RecoveryRequest, op string, finish *pd.RecoveryFinishRequest) (pd.PreparedRecovery, error) {
	p, err := e.HistoricalRecoveryEnvironment.PrepareRecovery(ctx, r, op, finish)
	if err == nil {
		p.Session = aRecoveryMySQLTraceSession{HistoricalRecoverySession: p.Session}
	}
	return p, err
}

type aRecoveryMySQLTraceSession struct{ pd.HistoricalRecoverySession }

func (s aRecoveryMySQLTraceSession) LockEvidence(ctx context.Context, tx pd.SQL, r pd.RecoveryRequest, h pd.HistoricalBindingRecord) (pd.FinishEvidence, error) {
	v, err := s.HistoricalRecoverySession.LockEvidence(ctx, tx, r, h)
	if err != nil {
		return v, fmt.Errorf("A historical L8 original: %w", err)
	}
	return v, nil
}

func (s aRecoveryMySQLTraceSession) Recheck(ctx context.Context, tx pd.ReadSQL, r pd.RecoveryRequest, h pd.HistoricalBindingRecord, now time.Time) error {
	if err := s.HistoricalRecoverySession.Recheck(ctx, tx, r, h, now); err != nil {
		return fmt.Errorf("A historical L10 guard: %w", err)
	}
	return nil
}

func (a *aRecoveryMySQLAuthority) PrepareHistoricalAuthority(ctx context.Context, _ pd.RecoveryRequest, op string, _ *pd.RecoveryFinishRequest) (SystemHistoricalAuthoritySession, ProducerEvidenceChannel, *time.Time, error) {
	var now time.Time
	if err := a.f.db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return nil, ProducerEvidenceChannel{}, nil, err
	}
	copy := *a
	if op == "load" {
		return &copy, a.f.channel, nil, nil
	}
	return &copy, a.f.channel, &now, nil
}

func (a *aRecoveryMySQLAuthority) Authorize(ctx context.Context, tx pd.SQL, r pd.RecoveryRequest, requestHash pd.Hash, op string, facts SystemPeerFacts, binding string) (pd.RecoveryAdmission, error) {
	if facts.Scope != r.Scope || binding != systemHistoricalWorkloadBinding(facts, string(r.EvidenceID)) || op != "load" && op != "claim" && op != "finish" {
		return pd.RecoveryAdmission{}, ErrDenied
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return pd.RecoveryAdmission{}, err
	}
	until := earlier(now.Add(time.Minute), facts.ExpiresAt)
	return pd.RecoveryAdmission{VerifiedRequestHash: requestHash, IdentityHash: pd.Hash(facts.WorkloadIdentityHash), RevocationEpoch: a.epoch, IdentityExpiresAt: systemExecutionStamp(until), DeploymentExpiresAt: systemExecutionStamp(now.Add(time.Minute)), StatAllowed: true, AdditionalCost: "0"}, nil
}

func (a *aRecoveryMySQLAuthority) Recheck(ctx context.Context, tx pd.ReadSQL, _ pd.RecoveryRequest, h pd.HistoricalBindingRecord, admission pd.RecoveryAdmission, now time.Time) error {
	if admission.RevocationEpoch != a.epoch || !now.Before(a.f.until) {
		return ErrDenied
	}
	return a.f.check(ctx, tx, &h)
}

func TestAHistoricalRecoveryMySQL(t *testing.T) {
	t.Run("corrupted_original_rejected", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db, false, true)
		f.advance("pending")
		_, peerFixture, peerConfig := systemPeerFixture(t)
		peerConfig.Scope = f.history.Scope
		auth, err := NewSystemPeerAuthenticator(peerConfig)
		mustSQL(t, err)
		t.Cleanup(auth.Close)
		peer, err := auth.AuthenticateRequest(peerFixture.request)
		mustSQL(t, err)
		dRecoveryMySQLInstallIdentity(t, db, f.history, pd.Hash(auth.workload))
		policy := &aRecoveryMySQLAuthority{dRecoveryMySQLAuthority: &dRecoveryMySQLAuthority{f: f, epoch: "1"}}
		env, err := NewSystemHistoricalRecoveryEnvironment(auth, peer, policy)
		mustSQL(t, err)
		s, err := pd.NewHistoricalRecovery(db, f.history.Scope, aRecoveryMySQLTrace{env})
		mustSQL(t, err)
		chunkWhere := " WHERE evidence_id=(SELECT id FROM system_backup_v2_evidence WHERE public_id=?) AND chunk_index=0"
		var originalNonce []byte
		mustSQL(t, db.QueryRow("SELECT gcm_nonce FROM system_backup_v2_evidence_chunks"+chunkWhere, f.history.Evidence.EvidenceID).Scan(&originalNonce))
		if len(originalNonce) == 0 {
			t.Fatal("missing original A chunk nonce")
		}
		corruptNonce := append([]byte(nil), originalNonce...)
		corruptNonce[0] ^= 0xff
		_, err = db.Exec("UPDATE system_backup_v2_evidence_chunks SET gcm_nonce=?"+chunkWhere, corruptNonce, f.history.Evidence.EvidenceID)
		mustSQL(t, err)
		var now time.Time
		mustSQL(t, db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now))
		r := pd.RecoveryRequest{Scope: f.history.Scope, EvidenceID: f.history.Evidence.EvidenceID, ExpectedEvidenceVersion: "1", Nonce: "mysql-a-recovery-corrupt", ClaimExpiresAt: systemExecutionStamp(now.Add(90 * time.Second)), BudgetUntil: systemExecutionStamp(now.Add(120 * time.Second))}
		if _, _, err = s.LoadHistoricalBinding(context.Background(), r); !errors.Is(err, ErrIntegrity) {
			t.Fatal("historical read did not detect altered original A chunk", err)
		}
	})

	db, _ := dProducerMySQLDB(t)
	f := newDIntegrationFixtureWithDB(t, db, false, true)
	f.advance("pending")
	_, peerFixture, peerConfig := systemPeerFixture(t)
	peerConfig.Scope = f.history.Scope
	auth, err := NewSystemPeerAuthenticator(peerConfig)
	mustSQL(t, err)
	t.Cleanup(auth.Close)
	requestCtx, endRequest := context.WithCancel(peerFixture.request.Context())
	t.Cleanup(endRequest)
	peerFixture.request = peerFixture.request.WithContext(requestCtx)
	peer, err := auth.AuthenticateRequest(peerFixture.request)
	mustSQL(t, err)
	dRecoveryMySQLInstallIdentity(t, db, f.history, pd.Hash(auth.workload))
	policy := &aRecoveryMySQLAuthority{dRecoveryMySQLAuthority: &dRecoveryMySQLAuthority{f: f, epoch: "1"}}
	env, err := NewSystemHistoricalRecoveryEnvironment(auth, peer, policy)
	mustSQL(t, err)
	s, err := pd.NewHistoricalRecovery(db, f.history.Scope, aRecoveryMySQLTrace{env})
	mustSQL(t, err)
	var now time.Time
	mustSQL(t, db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now))
	r := pd.RecoveryRequest{Scope: f.history.Scope, EvidenceID: f.history.Evidence.EvidenceID, ExpectedEvidenceVersion: "1", Nonce: "mysql-a-recovery-claim-1", ClaimExpiresAt: systemExecutionStamp(now.Add(90 * time.Second)), BudgetUntil: systemExecutionStamp(now.Add(120 * time.Second))}
	if _, _, err = s.LoadHistoricalBinding(context.Background(), r); err != nil {
		t.Fatal("live mTLS workload could not load original binding", err)
	}
	dRecoveryMySQLWaitCutoff(t, db, f.history.OwnerWriteExpiresAt)
	claim, err := s.ClaimRecovery(context.Background(), r)
	if err != nil || claim == nil {
		t.Fatal("live mTLS workload could not claim original evidence", err)
	}
	_, err = db.Exec("UPDATE system_backup_v2_producer_recovery_revocations SET revocation_epoch=2,row_version=2,updated_at=UTC_TIMESTAMP(6)")
	mustSQL(t, err)
	var observed time.Time
	mustSQL(t, db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&observed))
	finish := pd.RecoveryFinishRequest{State: "write_unknown", ProofHash: f.policy, ObjectHash: f.history.Evidence.ObjectHash, ObjectBytes: f.history.Evidence.ObjectBytes, ObservedAt: systemExecutionStamp(observed), BudgetUntil: systemExecutionStamp(observed.Add(20 * time.Second))}
	if _, err = s.FinishRecovery(context.Background(), claim, finish); !errors.Is(err, pd.ErrGuardRequired) {
		t.Fatal("changed current revocation epoch accepted", err)
	}
	endRequest()
	if _, _, err = s.LoadHistoricalBinding(context.Background(), r); err == nil {
		t.Fatal("completed mTLS request reused for historical read")
	}
}

var _ SystemHistoricalAuthority = (*aRecoveryMySQLAuthority)(nil)
var _ SystemHistoricalAuthoritySession = (*aRecoveryMySQLAuthority)(nil)
