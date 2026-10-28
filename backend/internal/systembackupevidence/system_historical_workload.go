package systembackupevidence

import (
	"context"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// systemHistoricalWorkloadIntent pins one authenticated recovery workload to
// one original evidence ID and the Stat-only purpose. It is a comparison input
// for a future HistoricalAuthority, not current deployment/revocation admission
// and not a provider credential. Only D's checked transaction may supply the
// scope and DB time to check; D must still lock current authorization and run
// its final Guard before any recovery mutation.
type systemHistoricalWorkloadIntent struct {
	peer       *SystemPeer
	auth       *SystemPeerAuthenticator
	scope      pd.Scope
	evidenceID string
	binding    string
}

func (systemHistoricalWorkloadIntent) MarshalJSON() ([]byte, error) { return nil, ErrAuth }
func (*systemHistoricalWorkloadIntent) UnmarshalJSON([]byte) error  { return ErrAuth }

func newSystemHistoricalWorkloadIntent(ctx context.Context, auth *SystemPeerAuthenticator, peer *SystemPeer, evidenceID string) (*systemHistoricalWorkloadIntent, error) {
	if ctx == nil || ctx.Err() != nil || auth == nil || peer == nil || !idPattern.MatchString(evidenceID) {
		return nil, ErrAuth
	}
	// This is only an initial transport check. The transaction must call check
	// with its own checked scope and DB time; local time cannot authorize SQL.
	now := time.Now().UTC().Truncate(time.Microsecond)
	facts, err := auth.Check(ctx, peer, auth.c.Scope, now)
	if err != nil {
		return nil, ErrAuth
	}
	return &systemHistoricalWorkloadIntent{peer: peer, auth: auth, scope: facts.Scope, evidenceID: evidenceID, binding: systemHistoricalWorkloadBinding(facts, evidenceID)}, nil
}

func systemHistoricalWorkloadBinding(facts SystemPeerFacts, evidenceID string) string {
	return systemPeerHash(struct {
		Domain, EvidenceID, Purpose, Actor, Workload, Issuer, Admission string
		SubjectHash, ClientCA, Certificate                              string
		Scope                                                           pd.Scope
	}{"system-backup-historical-workload.v2", evidenceID, "stat", facts.ActorIdentityHash, facts.WorkloadIdentityHash, facts.IssuerIdentityHash, facts.AdmissionHash, facts.SubjectHash, facts.ClientCASHA256, facts.CertificateSHA256, facts.Scope})
}

func (i *systemHistoricalWorkloadIntent) check(ctx context.Context, scope pd.Scope, evidenceID string, dbNow time.Time) (SystemPeerFacts, string, error) {
	if i == nil || i.auth == nil || i.peer == nil || ctx == nil || ctx.Err() != nil || scope != i.scope || evidenceID != i.evidenceID {
		return SystemPeerFacts{}, "", ErrAuth
	}
	facts, err := i.auth.Check(ctx, i.peer, scope, dbNow)
	if err != nil || !digestPattern.MatchString(i.binding) || systemHistoricalWorkloadBinding(facts, evidenceID) != i.binding {
		return SystemPeerFacts{}, "", ErrAuth
	}
	return facts, i.binding, nil
}
