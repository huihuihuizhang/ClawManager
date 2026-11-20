package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// OriginalC1UnusedDomainRecoveryInputs selects the original signed source and
// the independently read canonical SQL record. The native domain transaction
// must match the live row and establish absence of downstream work itself.
type OriginalC1UnusedDomainRecoveryInputs struct {
	Source, Signature, Domain BootstrapSourceFilePin
	Orphan                    *OriginalC1ExpiredAcquirePins `json:",omitempty"`
}

type OriginalC1ExpiredAcquirePins struct {
	Command                                             BootstrapSourceFilePin
	ReceiptSHA256, GrantSHA256, RunSHA256, TargetSHA256 string
}

type originalC1UnusedDomainRecovery struct {
	source originalC1DomainSource
	record []byte
	issuer ed25519.PublicKey
	input  OriginalC1UnusedDomainRecoveryInputs
	domain pd.DomainRecord
	epoch  pd.Counter
	next   pd.Counter
	orphan *pd.CommandRequest
}

func (s *authenticatedOperator) readOriginalC1UnusedDomainRecovery(in *OriginalC1UnusedDomainRecoveryInputs, enrollment EnrollmentPin, scope pd.Scope, now time.Time) (*originalC1UnusedDomainRecovery, error) {
	if in == nil {
		return nil, nil
	}
	recovery, err := s.readOriginalC1RecoveryAnchor(*in, enrollment, scope, now)
	if err != nil {
		return nil, err
	}
	epoch, err := recovery.domain.Epoch.Uint64()
	if err != nil || epoch < 1 || epoch > 4 || (epoch == 4) != (in.Orphan != nil) {
		return nil, ErrInstall
	}
	if in.Orphan != nil {
		command, err := readC1ExpiredAcquireCommand(in.Orphan, recovery.domain)
		if err != nil {
			return nil, err
		}
		recovery.orphan = &command
	}
	recovery.next = c1counter(epoch + 1)
	// The current row and each signed predecessor must use consecutive
	// original revisions and the same immutable creation timestamp.
	for child := recovery; epoch > 0; epoch-- {
		if !child.matches(child.domain, now) || child.domain.Epoch != c1counter(epoch) || child.domain.CreatedAt != recovery.domain.CreatedAt {
			return nil, ErrInstall
		}
		if epoch == 1 {
			if child.source.Recovery != nil || child.domain.CreatedAt != child.domain.UpdatedAt {
				return nil, ErrInstall
			}
			break
		}
		if child.source.Recovery == nil {
			return nil, ErrInstall
		}
		parent, err := s.readOriginalC1RecoveryAnchor(*child.source.Recovery, enrollment, scope, now)
		if err != nil || parent.input.Orphan != nil || child.source.NotBefore.Before(parent.source.Until.Truncate(time.Microsecond)) {
			return nil, ErrInstall
		}
		child = parent
	}
	return recovery, nil
}

func (s *authenticatedOperator) readOriginalC1RecoveryAnchor(in OriginalC1UnusedDomainRecoveryInputs, enrollment EnrollmentPin, scope pd.Scope, now time.Time) (*originalC1UnusedDomainRecovery, error) {
	raw, err := readBootstrapSourcePin(in.Source, 262144)
	signature, sigErr := readBootstrapSourcePin(in.Signature, ed25519.SignatureSize)
	var source originalC1DomainSource
	if err != nil || sigErr != nil || !ed25519.Verify(s.installer.public, append([]byte(originalC1DomainSourceVersion+"\x00"), raw...), signature) ||
		decodeExact(raw, &source) != nil || source.Version != originalC1DomainSourceVersion ||
		source.PlanSHA256 != s.installer.planHash || source.Enrollment != enrollment || source.Scope != scope ||
		source.ActorID != s.userID || source.Username != s.installer.plan.LocalAdminUsername ||
		source.InstallerAccount != s.installer.plan.InstallerDatabaseAccount ||
		source.NotBefore.IsZero() || !source.Until.After(source.NotBefore) || now.IsZero() || now.Before(source.Until.Truncate(time.Microsecond)) {
		return nil, ErrInstall
	}
	record, err := readBootstrapSourcePin(in.Domain, 16384)
	if err != nil {
		return nil, ErrInstall
	}
	domain, err := pd.DecodeDomainRecordBytes(record, scope)
	if err != nil {
		return nil, ErrInstall
	}
	return &originalC1UnusedDomainRecovery{source: source, record: record, issuer: s.installer.public, input: in, domain: domain, epoch: domain.Epoch}, nil
}

func originalC1UnusedDomainMatches(prior pd.DomainRecord, source originalC1DomainSource, issuer ed25519.PublicKey, epoch pd.Counter, now time.Time) bool {
	expires, expiryErr := prior.AdmissionExpiresAt.Time()
	updated, updateErr := prior.UpdatedAt.Time()
	return expiryErr == nil && updateErr == nil && !now.IsZero() && !now.Before(expires) &&
		!updated.Before(source.NotBefore) && updated.Before(expires) && expires.Equal(source.Until.Truncate(time.Microsecond)) &&
		prior.Scope == source.Scope && prior.State == "open" && prior.Epoch == epoch && prior.RowVersion == epoch &&
		prior.IssuerIdentityHash == pd.Hash(hash(issuer)) &&
		reflect.DeepEqual(prior.Admission, pd.Admission{Unconfigured: &source.Admission})
}

func (r *originalC1UnusedDomainRecovery) matches(prior pd.DomainRecord, now time.Time) bool {
	return originalC1UnusedDomainMatches(prior, r.source, r.issuer, r.epoch, now) && c1RecoveryRecordMatches(prior, r.record)
}

func c1RecoveryRecordMatches(domain pd.DomainRecord, expected []byte) bool {
	stored, err := pd.EncodeStoredRecord(&domain)
	return err == nil && bytes.Equal(expected, stored.Columns["record_bytes"].([]byte))
}

func readC1ExpiredAcquireCommand(pins *OriginalC1ExpiredAcquirePins, domain pd.DomainRecord) (pd.CommandRequest, error) {
	var zero pd.CommandRequest
	for _, digest := range []string{pins.ReceiptSHA256, pins.GrantSHA256, pins.RunSHA256, pins.TargetSHA256} {
		raw, err := hex.DecodeString(digest)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != digest {
			return zero, ErrInstall
		}
	}
	raw, err := readBootstrapSourcePin(pins.Command, 65536)
	if err != nil {
		return zero, ErrInstall
	}
	q, err := pd.DecodeCommand(raw)
	if err != nil || q.Command != "acquire" || q.Expected != nil || q.Next == nil || q.LeaseExpiresAt == nil ||
		q.Scope != domain.Scope || q.ExpectedDomainEpoch != domain.Epoch || q.ExpectedTargetGeneration != "0" ||
		q.Target.Role != "signing" || q.Next.Purpose != "dependency_check" || q.Next.GrantGeneration != "1" ||
		q.ActorIdentityHash != q.Next.SubjectIdentityHash || q.Next.IssuerIdentityHash != domain.IssuerIdentityHash ||
		!reflect.DeepEqual(q.Next.Admission, domain.Admission) || !strings.HasPrefix(string(q.Next.GrantID), "c1-grant-") || !strings.HasPrefix(string(q.Next.RunID), "c1-run-") {
		return zero, ErrInstall
	}
	return q, nil
}

func (r *originalC1UnusedDomainRecovery) lockExpiredAcquire(ctx context.Context, tx pd.ReadSQL, domain pd.DomainRecord, now time.Time) error {
	q, pins := *r.orphan, r.input.Orphan
	digests, err := pd.CommandHashes(q)
	if err != nil {
		return ErrInstall
	}
	check := func(key pd.RecordKey, record any, digest string) bool {
		found, err := pd.ReadOriginalSharedRecord(ctx, tx, domain.Scope, key, record)
		if err != nil || !found {
			return false
		}
		wire, err := pd.EncodeStoredRecord(record)
		return err == nil && hex.EncodeToString(wire.Columns["record_sha256"].([]byte)) == digest
	}
	var receipt pd.CommandReceiptRecord
	var grant pd.GrantRecord
	var run pd.RunRecord
	var target pd.TargetRecord
	// Lock the known command receipt, grant, run and target before the
	// scoped census. The existing native transaction holds the domain.
	if !check(pd.RecordKey{Hash: digests.Key}, &receipt, pins.ReceiptSHA256) ||
		!check(pd.RecordKey{ID: q.Next.GrantID}, &grant, pins.GrantSHA256) ||
		!check(pd.RecordKey{ID: q.Next.RunID}, &run, pins.RunSHA256) ||
		!check(pd.RecordKey{Hash: run.TargetHash}, &target, pins.TargetSHA256) ||
		!originalC1AcquireIsUnused(q, digests, receipt, grant, run, target, now) {
		return ErrInstall
	}
	return nil
}

func originalC1AcquireIsUnused(q pd.CommandRequest, digests pd.CommandDigests, receipt pd.CommandReceiptRecord, grant pd.GrantRecord, run pd.RunRecord, target pd.TargetRecord, now time.Time) bool {
	if q.Next == nil || q.LeaseExpiresAt == nil {
		return false
	}
	next := q.Next
	for _, stamp := range []pd.Timestamp{grant.LeaseExpiresAt, grant.AuthorizationExpiresAt, run.OwnerWriteExpiresAt} {
		until, err := stamp.Time()
		if err != nil || now.Before(until) {
			return false
		}
	}
	return receipt.RequestHash == digests.Request && receipt.ReceiptKeyHash == digests.Key && reflect.DeepEqual(receipt.Request, q) &&
		receipt.Outcome == (pd.CommandExpected{GrantID: next.GrantID, GrantGeneration: "1", GrantRowVersion: "1", RunID: next.RunID, TargetGeneration: "1"}) &&
		grant.GrantID == next.GrantID && grant.DomainEpoch == q.ExpectedDomainEpoch && grant.Generation == "1" && grant.RowVersion == "1" &&
		grant.State == "active" && grant.LeaseExpiresAt == *q.LeaseExpiresAt && grant.AuthorizationExpiresAt == next.AuthorizationExpiresAt &&
		grant.SubjectIdentityHash == next.SubjectIdentityHash && grant.IssuerIdentityHash == next.IssuerIdentityHash &&
		reflect.DeepEqual(grant.Target, q.Target) && reflect.DeepEqual(grant.Host, next.Host) && reflect.DeepEqual(grant.Admission, next.Admission) &&
		run.RunID == next.RunID && run.GrantID == next.GrantID && run.GrantGeneration == "1" && run.TargetGeneration == "1" &&
		run.State == "acquired" && run.RowVersion == "1" && run.ObservedAt == nil && run.ObservationExpiresAt == nil &&
		run.OwnerWriteExpiresAt == next.OwnerWriteExpiresAt && run.InputHash == next.InputHash && run.EvidenceID == next.EvidenceID &&
		target.TargetHash == run.TargetHash && target.CurrentRunID == next.RunID && target.Generation == "1" &&
		target.ResultVersion == "0" && target.RowVersion == "1" && reflect.DeepEqual(target.Target, q.Target)
}

func (r *originalC1UnusedDomainRecovery) lockUnusedPrior(ctx context.Context, tx pd.SQL, prior *pd.DomainRecord) error {
	if prior == nil {
		return ErrInstall
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !r.matches(*prior, now) {
		return ErrInstall
	}
	key, err := pd.RecoveryScopeKey(prior.Scope)
	if err != nil {
		return ErrInstall
	}
	// The native opener already holds the domain row. Allow only the pinned
	// expired acquire when the original receipt confirms no observation.
	var afterExactAcquire string
	if r.orphan != nil {
		if r.lockExpiredAcquire(ctx, tx, *prior, now) != nil {
			return ErrInstall
		}
		afterExactAcquire = " OFFSET 1"
	}
	for _, table := range []string{
		"system_backup_producer_grants",
		"system_backup_producer_targets",
		"system_backup_producer_runs",
		"system_backup_producer_command_receipts",
	} {
		var marker int
		err := tx.QueryRowContext(ctx, "SELECT 1 FROM "+table+" WHERE scope_key=? LIMIT 1"+afterExactAcquire+" FOR SHARE", key).Scan(&marker)
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrInstall
		}
	}
	for _, table := range []string{
		"system_backup_producer_evidence_bindings",
		"system_backup_producer_result_receipts",
		"system_backup_producer_evidence_refs",
	} {
		var marker int
		err := tx.QueryRowContext(ctx, "SELECT 1 FROM "+table+" WHERE scope_key=? LIMIT 1 FOR SHARE", key).Scan(&marker)
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrInstall
		}
	}
	for _, table := range []string{
		"system_backup_installation_owner_grants",
		"system_backup_installation_kek_authority",
		"system_backup_installation_kek_authority_history",
		"system_backup_v2_kek_admissions",
	} {
		var marker int
		err := tx.QueryRowContext(ctx, "SELECT 1 FROM "+table+" WHERE installation_id=? LIMIT 1 FOR SHARE", string(prior.Scope.Installation)).Scan(&marker)
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrInstall
		}
	}
	return nil
}
